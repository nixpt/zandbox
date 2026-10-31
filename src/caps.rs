//! Capability drop.
//!
//! Ported from exosphere `enforcement.rs` `apply_capabilities`
//! (@ `0c35ddec`). exosphere called `caps::drop` per capability and set,
//! which allocates (`caps` builds `HashSet`s) after fork, and swallowed every
//! error. Here the keep-mask and `cap_last_cap` are computed before fork and
//! the child issues raw `prctl`/`capget`/`capset` only.
//!
//! Child sequence: drop the bounding set (needs `CAP_SETPCAP`: works as root
//! or inside a new user namespace; an unprivileged caller without one gets
//! `EPERM`, recorded as `bounding_set_reduced = false`), clear the ambient
//! set, `capset` permitted/effective/inheritable down to the keep-list, raise
//! kept capabilities into the ambient set, and set `no_new_privs`. With
//! `no_new_privs` set and an empty permitted set, an unreduced bounding set
//! cannot be used to regain capabilities through `execve`, so that case is
//! not treated as a failure even in strict mode.

use crate::error::{errno, Error};
use crate::profile::Capability;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CapPlan {
    keep: u64,
    last_cap: u32,
    strict: bool,
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_VERSION_3: u32 = 0x2008_0522;

pub(crate) fn prepare(keep: &[Capability], strict: bool) -> CapPlan {
    let keep_mask = keep.iter().fold(0u64, |m, c| m | c.bitmask());
    let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| {
            caps::all()
                .iter()
                .map(|c| u32::from(c.index()))
                .max()
                .unwrap_or(40)
        });
    CapPlan {
        keep: keep_mask,
        last_cap,
        strict,
    }
}

/// What the child managed to do.
pub(crate) struct CapOutcome {
    pub bounding_reduced: bool,
    pub ambient_raised: bool,
}

impl CapPlan {
    /// Child side. Async-signal-safe: prctl/capget/capset only.
    pub(crate) fn apply(&self) -> Result<CapOutcome, Error> {
        let mut bounding_reduced = true;
        // SAFETY: integer-argument prctls and capget/capset on stack structs.
        unsafe {
            for cap in 0..=self.last_cap.min(63) {
                if self.keep & (1u64 << cap) != 0 {
                    continue;
                }
                if libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) != 0 {
                    match errno() {
                        libc::EINVAL => {} // cap unknown to this kernel
                        _ => bounding_reduced = false,
                    }
                }
            }
            // EINVAL on pre-4.3 kernels without ambient caps: nothing to clear.
            let _ = libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0,
                0,
                0,
            );

            let mut hdr = CapHeader {
                version: CAP_VERSION_3,
                pid: 0,
            };
            let mut data = [CapData::default(); 2];
            if libc::syscall(
                libc::SYS_capget,
                &mut hdr as *mut CapHeader,
                data.as_mut_ptr(),
            ) != 0
            {
                return Err(Error::Child {
                    step: "capget",
                    errno: errno(),
                });
            }
            let held = u64::from(data[0].permitted) | (u64::from(data[1].permitted) << 32);
            let inh = u64::from(data[0].inheritable) | (u64::from(data[1].inheritable) << 32);
            if self.strict && held & self.keep != self.keep {
                return Err(Error::Child {
                    step: "capabilities (keep-list cap not held)",
                    errno: libc::EPERM,
                });
            }
            let perm = held & self.keep;
            let inh = (inh | held) & self.keep;
            for (i, d) in data.iter_mut().enumerate() {
                let shift = 32 * i as u32;
                d.permitted = (perm >> shift) as u32;
                d.effective = (perm >> shift) as u32;
                d.inheritable = (inh >> shift) as u32;
            }
            let mut hdr = CapHeader {
                version: CAP_VERSION_3,
                pid: 0,
            };
            if libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) != 0 {
                return Err(Error::Child {
                    step: "capset",
                    errno: errno(),
                });
            }

            let mut ambient_raised = true;
            for cap in 0..=self.last_cap.min(63) {
                if perm & (1u64 << cap) == 0 {
                    continue;
                }
                if libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    cap as libc::c_ulong,
                    0,
                    0,
                ) != 0
                {
                    if self.strict {
                        return Err(Error::Child {
                            step: "prctl(PR_CAP_AMBIENT_RAISE)",
                            errno: errno(),
                        });
                    }
                    ambient_raised = false;
                }
            }

            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(Error::Child {
                    step: "prctl(PR_SET_NO_NEW_PRIVS)",
                    errno: errno(),
                });
            }
            Ok(CapOutcome {
                bounding_reduced,
                ambient_raised,
            })
        }
    }
}
