//! Landlock filesystem allowlist.
//!
//! Ported from exosphere `enforcement.rs` `apply_landlock` (@ `0c35ddec`),
//! restructured so the ruleset is **built in the parent**: the ruleset fd is
//! created, every path is opened and added there (allocation, `open`, `fstat`
//! — none of it async-signal-safe-sensitive), and the child only calls
//! `prctl(PR_SET_NO_NEW_PRIVS)` + `landlock_restrict_self(fd)`. The fd is
//! `O_CLOEXEC` (the kernel always sets it), so it is inherited across `fork`
//! and closed by `execve`.
//!
//! Changes while porting:
//! * the ABI is probed and access rights follow it: `REFER` (v2) and
//!   `TRUNCATE` (v3) are handled when available (exosphere handled v1 bits
//!   only, so `truncate(2)` stayed allowed under a "read-only" root; its
//!   unused `LL_TRUNCATE` constant was also `1 << 13`, which is `REFER`);
//! * an allowlisted path that cannot be opened is an error in strict mode and
//!   reported in non-strict mode (exosphere skipped it silently);
//! * landlock missing is an error in strict mode and reported otherwise
//!   (exosphere returned `Ok` silently on `ENOSYS`/`EOPNOTSUPP`);
//! * separate read and write allowlists.

use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::error::{errno, Error};
use crate::{Profile, Report};

// Unified syscall numbers (same on x86_64, aarch64, riscv64).
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
const REFER: u64 = 1 << 13; // ABI 2
const TRUNCATE: u64 = 1 << 14; // ABI 3

const READ: u64 = EXECUTE | READ_FILE | READ_DIR;
const WRITE_V1: u64 = WRITE_FILE
    | REMOVE_DIR
    | REMOVE_FILE
    | MAKE_CHAR
    | MAKE_DIR
    | MAKE_REG
    | MAKE_SOCK
    | MAKE_FIFO
    | MAKE_BLOCK
    | MAKE_SYM;

fn write_bits(abi: u32) -> u64 {
    let mut w = WRITE_V1;
    if abi >= 2 {
        w |= REFER;
    }
    if abi >= 3 {
        w |= TRUNCATE;
    }
    w
}

/// Rights valid on a regular file (directory-only rights give `EINVAL`).
fn file_bits(abi: u32) -> u64 {
    let mut f = EXECUTE | WRITE_FILE | READ_FILE;
    if abi >= 3 {
        f |= TRUNCATE;
    }
    f
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Landlock ABI version of the running kernel, or the errno
/// (`ENOSYS`: not built in; `EOPNOTSUPP`: disabled at boot).
pub fn abi_version() -> Result<u32, i32> {
    // SAFETY: the VERSION query takes a NULL attr and size 0.
    let r = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if r < 0 {
        Err(errno())
    } else {
        Ok(r as u32)
    }
}

/// A built ruleset waiting for `landlock_restrict_self` in the child.
#[derive(Debug)]
pub(crate) struct Ruleset {
    fd: OwnedFd,
    pub(crate) abi: u32,
}

/// Parent side: build the ruleset for `profile`. `Ok(None)` when landlock was
/// not requested, or (non-strict) is unavailable.
pub(crate) fn prepare(profile: &Profile, report: &mut Report) -> Result<Option<Ruleset>, Error> {
    if !profile.wants_landlock() {
        return Ok(None);
    }
    let abi = match abi_version() {
        Ok(v) if v >= 1 => v,
        Ok(v) => return skip(profile, report, format!("unexpected ABI version {v}")),
        Err(e) => {
            let why = match e {
                libc::ENOSYS => "kernel built without landlock (ENOSYS)".to_string(),
                libc::EOPNOTSUPP => "landlock disabled at boot (EOPNOTSUPP)".to_string(),
                e => format!("landlock_create_ruleset version probe failed: errno {e}"),
            };
            return skip(profile, report, why);
        }
    };

    let write = write_bits(abi);
    let attr = RulesetAttr {
        handled_access_fs: READ | write,
    };
    // SAFETY: attr is a valid pointer of the size passed.
    let fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(Error::io(
            "landlock_create_ruleset",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fd is a fresh descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let ruleset = Ruleset { fd, abi };

    if profile.readonly_root {
        ruleset.add(Path::new("/"), READ, abi, profile.strict, report)?;
    }
    for p in &profile.read_paths {
        ruleset.add(p, READ, abi, profile.strict, report)?;
    }
    for p in &profile.write_paths {
        ruleset.add(p, READ | write, abi, profile.strict, report)?;
    }
    report.landlock_abi = Some(abi);
    Ok(Some(ruleset))
}

fn skip(profile: &Profile, report: &mut Report, why: String) -> Result<Option<Ruleset>, Error> {
    if profile.strict {
        Err(Error::unavailable("landlock", why))
    } else {
        report.skip("landlock", why);
        Ok(None)
    }
}

impl Ruleset {
    fn add(
        &self,
        path: &Path,
        access: u64,
        abi: u32,
        strict: bool,
        report: &mut Report,
    ) -> Result<(), Error> {
        let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            Error::InvalidProfile(format!("landlock path {path:?} contains a NUL byte"))
        })?;
        // SAFETY: cpath is a valid C string.
        let pfd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if pfd < 0 {
            let e = std::io::Error::last_os_error();
            let why = format!("allowlisted path {} cannot be opened: {e}", path.display());
            if strict {
                return Err(Error::unavailable("landlock", why));
            }
            report.skip("landlock.path", why);
            return Ok(());
        }
        // SAFETY: pfd is a fresh descriptor we own.
        let pfd = unsafe { OwnedFd::from_raw_fd(pfd) };
        let is_dir = std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false);
        let access = if is_dir {
            access
        } else {
            access & file_bits(abi)
        };
        use std::os::fd::AsRawFd;
        let rule = PathBeneathAttr {
            allowed_access: access,
            parent_fd: pfd.as_raw_fd(),
        };
        // SAFETY: rule is a valid pointer; the ruleset fd is ours.
        let r = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                self.fd.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0u32,
            )
        };
        if r != 0 {
            return Err(Error::io(
                format!("landlock_add_rule {}", path.display()),
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    /// Child side. Async-signal-safe: two syscalls.
    pub(crate) fn restrict_self(&self) -> Result<(), Error> {
        use std::os::fd::AsRawFd;
        // SAFETY: plain prctl/syscall with integer arguments.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(Error::Child {
                    step: "prctl(PR_SET_NO_NEW_PRIVS)",
                    errno: errno(),
                });
            }
            if libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, self.fd.as_raw_fd(), 0u32) != 0 {
                return Err(Error::Child {
                    step: "landlock_restrict_self",
                    errno: errno(),
                });
            }
        }
        Ok(())
    }
}
