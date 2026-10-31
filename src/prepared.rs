use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::caps::CapPlan;
use crate::cgroup::{CgroupGuard, CgroupPlan};
use crate::error::{errno, Error};
use crate::landlock::Ruleset;
use crate::profile::{Namespaces, Profile, UserMap};
use crate::seccomp::{self, Architecture};

/// A primitive that was requested but skipped (non-strict mode only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// e.g. `"landlock"`, `"landlock.path"`, `"cgroup"`, `"cgroup.pids"`,
    /// `"seccomp.syscall"`.
    pub primitive: &'static str,
    pub reason: String,
}

/// What [`Profile::prepare`] set up, and what it skipped. Built in the
/// parent; nothing here is known only to the child (see [`Applied`] for that).
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub strict: bool,
    /// Requested primitives that will not be applied. Always empty in strict
    /// mode (strict returns an error instead).
    pub skipped: Vec<Skipped>,
    /// Landlock ABI used, if a ruleset was built.
    pub landlock_abi: Option<u32>,
    /// Number of syscalls the seccomp filter allows, if one was compiled.
    pub seccomp_allowed: Option<usize>,
    /// The per-child cgroup directory, if one was created.
    pub cgroup: Option<PathBuf>,
}

impl Report {
    pub(crate) fn skip(&mut self, primitive: &'static str, reason: impl Into<String>) {
        self.skipped.push(Skipped {
            primitive,
            reason: reason.into(),
        });
    }

    /// Whether everything requested will be applied.
    pub fn complete(&self) -> bool {
        self.skipped.is_empty()
    }
}

/// What [`Prepared::apply_in_child`] did, as seen by the child. Plain flags
/// (no heap data) so it can be built after fork.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Applied {
    /// Namespaces created.
    pub namespaces: Namespaces,
    /// A uid/gid mapping was written for the new user namespace.
    pub user_map_written: bool,
    /// We are the PID-namespace grandchild (PID 1 of the new namespace).
    pub pid_namespace_init: bool,
    /// The task joined its cgroup.
    pub cgroup_joined: bool,
    /// Capabilities were dropped to the keep-list.
    pub capabilities_dropped: bool,
    /// The bounding set was reduced too (needs `CAP_SETPCAP`; see
    /// [`Profile::drop_capabilities`] docs on why `false` is still safe).
    pub bounding_set_reduced: bool,
    /// Every kept capability was raised into the ambient set.
    pub ambient_raised: bool,
    /// Landlock ABI enforced, 0 if no landlock.
    pub landlock_abi: u32,
    /// A seccomp filter was installed.
    pub seccomp_applied: bool,
}

/// A [`Profile`] with everything that allocates or touches the filesystem
/// already done. Create it **before fork** with [`Profile::prepare`]; call
/// [`Prepared::apply_in_child`] **after fork**, in the child.
///
/// Dropping a `Prepared` closes the landlock ruleset fd and removes the
/// cgroup it created (best effort: removal fails while processes remain in
/// it, so keep the `Prepared` alive until the child has exited, or use
/// [`crate::Command`], which hands the cgroup to its [`crate::Child`]).
#[derive(Debug)]
pub struct Prepared {
    flags: libc::c_int,
    namespaces: Namespaces,
    /// (`uid_map` line, `gid_map` line), precomputed.
    user_map: Option<(Vec<u8>, Vec<u8>)>,
    cgroup: Option<CgroupPlan>,
    caps: Option<CapPlan>,
    landlock: Option<Ruleset>,
    seccomp: Option<Vec<libc::sock_filter>>,
    env_clear: bool,
    env: Vec<(OsString, OsString)>,
    report: Report,
}

// SAFETY: sock_filter is plain data; Prepared is only read after construction.
unsafe impl Send for Prepared {}
unsafe impl Sync for Prepared {}

impl Profile {
    /// Do every allocation, probe, path lookup, ruleset build, BPF compile and
    /// cgroup setup — in the parent, before fork.
    ///
    /// In strict mode, returns [`Error::Unavailable`] naming the first
    /// requested primitive this host cannot provide. In non-strict mode those
    /// are listed in [`Prepared::report`] instead.
    pub fn prepare(&self) -> Result<Prepared, Error> {
        let mut report = Report {
            strict: self.strict,
            ..Report::default()
        };
        let ns = self.namespaces;

        // SAFETY: trivial getters.
        let (uid, gid, euid) = unsafe { (libc::getuid(), libc::getgid(), libc::geteuid()) };
        if self.strict
            && euid != 0
            && !ns.user
            && (ns.mount || ns.pid || ns.net || ns.ipc || ns.uts)
        {
            return Err(Error::unavailable(
                "namespaces",
                "creating mount/pid/net/ipc/uts namespaces needs root or a user namespace (user_ns(true))",
            ));
        }
        if self.strict && ns.user && !userns_enabled() {
            return Err(Error::unavailable(
                "user_ns",
                "unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0 or user.max_user_namespaces=0)",
            ));
        }
        let user_map = if ns.user {
            match self.user_map {
                UserMap::Current => Some((
                    format!("{uid} {uid} 1\n").into_bytes(),
                    format!("{gid} {gid} 1\n").into_bytes(),
                )),
                UserMap::Root => Some((
                    format!("0 {uid} 1\n").into_bytes(),
                    format!("0 {gid} 1\n").into_bytes(),
                )),
                UserMap::None => None,
            }
        } else {
            None
        };

        let cgroup = crate::cgroup::prepare(self, &mut report)?;
        let caps = self
            .keep_capabilities
            .as_deref()
            .map(|keep| crate::caps::prepare(keep, self.strict));
        let landlock = crate::landlock::prepare(self, &mut report)?;

        let seccomp = match &self.seccomp {
            None => None,
            Some(spec) => match (Architecture::current(), seccomp::is_supported()) {
                (Some(arch), true) => {
                    let compiled = spec
                        .compile(arch)
                        .map_err(|e| Error::InvalidProfile(format!("seccomp: {e}")))?;
                    if !compiled.unknown.is_empty() {
                        let why = format!("unknown syscall names: {}", compiled.unknown.join(", "));
                        if self.strict {
                            return Err(Error::InvalidProfile(format!("seccomp: {why}")));
                        }
                        report.skip("seccomp.syscall", why);
                    }
                    report.seccomp_allowed = Some(compiled.allowed);
                    Some(compiled.program)
                }
                (arch, _) => {
                    let why = if arch.is_none() {
                        "no syscall table for this architecture"
                    } else {
                        "kernel has no seccomp support"
                    };
                    if self.strict {
                        return Err(Error::unavailable("seccomp", why));
                    }
                    report.skip("seccomp", why);
                    None
                }
            },
        };

        Ok(Prepared {
            flags: ns.clone_flags(),
            namespaces: ns,
            user_map,
            cgroup,
            caps,
            landlock,
            seccomp,
            env_clear: self.env_clear,
            env: self.env.clone(),
            report,
        })
    }
}

fn userns_enabled() -> bool {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    if read("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return false;
    }
    read("/proc/sys/user/max_user_namespaces").as_deref() != Some("0")
}

/// Write `data` to the NUL-terminated `path`. Async-signal-safe.
fn write_file(path: &[u8], data: &[u8], step: &'static str) -> Result<(), Error> {
    debug_assert_eq!(path.last(), Some(&0));
    // SAFETY: path is NUL-terminated; data is a valid buffer.
    unsafe {
        let fd = libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(Error::Child {
                step,
                errno: errno(),
            });
        }
        let r = libc::write(fd, data.as_ptr().cast(), data.len());
        let e = errno();
        libc::close(fd);
        if r != data.len() as isize {
            return Err(Error::Child {
                step,
                errno: if r < 0 { e } else { libc::EIO },
            });
        }
    }
    Ok(())
}

impl Prepared {
    /// What will be applied and what was skipped.
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Whether the child's environment should start empty.
    pub fn env_clear(&self) -> bool {
        self.env_clear
    }

    /// Variables to set in the child's environment. Environment is not
    /// something `pre_exec` can change (std builds `envp` before fork), so
    /// callers wiring their own `Command` must apply these themselves;
    /// [`crate::Command`] does.
    pub fn env_vars(&self) -> &[(OsString, OsString)] {
        &self.env
    }

    /// The per-child cgroup directory, if one was created.
    pub fn cgroup_path(&self) -> Option<&Path> {
        self.cgroup
            .as_ref()
            .and_then(|c| c.guard.as_ref())
            .map(|g| g.path.as_path())
    }

    pub(crate) fn take_cgroup_guard(&mut self) -> Option<CgroupGuard> {
        self.cgroup.as_mut().and_then(|c| c.guard.take())
    }

    /// Apply the sandbox to the calling process. Call it in the child, after
    /// `fork` and before `execve` — e.g. from
    /// [`std::os::unix::process::CommandExt::pre_exec`].
    ///
    /// Async-signal-safe: it performs only syscalls on data prepared earlier
    /// — no allocation, no locks, no logging. The calling process must be
    /// single-threaded (true right after `fork`).
    ///
    /// Order (exosphere's):
    /// 1. **cgroup join** — write `0` to `<cgroup>/cgroup.procs`;
    /// 2. **namespaces** — one `unshare(2)`; then, for a user namespace,
    ///    `setgroups` = `deny` and the uid/gid maps;
    /// 3. **PID-namespace double fork** — if a PID namespace was requested
    ///    the calling process forks again: the grandchild becomes PID 1 of
    ///    the new namespace and continues; the calling process becomes a
    ///    *reaper*: it closes all its fds, waits for the grandchild and exits
    ///    with its status (or re-raises its fatal signal). **The reaper never
    ///    returns from this call.** The grandchild gets
    ///    `PR_SET_PDEATHSIG(SIGKILL)`, so killing the reaper kills the
    ///    workload;
    /// 4. **capabilities** — bounding/ambient/permitted/effective/inheritable
    ///    down to the keep-list, `no_new_privs`;
    /// 5. **landlock** — `landlock_restrict_self` with the prebuilt ruleset;
    /// 6. **seccomp** — last, since it can forbid what comes before it.
    ///
    /// Errors carry the failing step and errno ([`Error::Child`]). Through
    /// `std::process::Command::spawn` only the errno survives.
    pub fn apply_in_child(&self) -> Result<Applied, Error> {
        let mut applied = Applied::default();

        // 1. cgroup
        if let Some(cg) = &self.cgroup {
            applied.cgroup_joined = cg.join()?;
        }

        // 2. namespaces
        if self.flags != 0 {
            // SAFETY: unshare with constant flags.
            if unsafe { libc::unshare(self.flags) } != 0 {
                return Err(Error::Child {
                    step: "unshare",
                    errno: errno(),
                });
            }
            applied.namespaces = self.namespaces;
        }
        if let Some((uid_map, gid_map)) = &self.user_map {
            write_file(
                b"/proc/self/setgroups\0",
                b"deny",
                "write /proc/self/setgroups",
            )?;
            write_file(b"/proc/self/uid_map\0", uid_map, "write /proc/self/uid_map")?;
            write_file(b"/proc/self/gid_map\0", gid_map, "write /proc/self/gid_map")?;
            applied.user_map_written = true;
        }

        // 3. PID namespace: fork so the workload is PID 1 of the new ns.
        if self.namespaces.pid {
            // SAFETY: fork in a single-threaded process; the parent branch
            // below only issues async-signal-safe calls and never returns.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(Error::Child {
                    step: "fork (pid namespace)",
                    errno: errno(),
                });
            }
            if pid > 0 {
                // SAFETY: see reap.
                unsafe { reap(pid) }
            }
            // SAFETY: integer prctl.
            unsafe {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
            }
            applied.pid_namespace_init = true;
        }

        // 4. capabilities
        if let Some(caps) = &self.caps {
            let out = caps.apply()?;
            applied.capabilities_dropped = true;
            applied.bounding_set_reduced = out.bounding_reduced;
            applied.ambient_raised = out.ambient_raised;
        }

        // 5. landlock
        if let Some(rs) = &self.landlock {
            rs.restrict_self()?;
            applied.landlock_abi = rs.abi;
        }

        // 6. seccomp (last)
        if let Some(prog) = &self.seccomp {
            let fprog = libc::sock_fprog {
                len: prog.len() as libc::c_ushort,
                filter: prog.as_ptr() as *mut libc::sock_filter,
            };
            // SAFETY: fprog points at a live, correctly sized program.
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(Error::Child {
                        step: "prctl(PR_SET_NO_NEW_PRIVS)",
                        errno: errno(),
                    });
                }
                if libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    0u32,
                    &fprog as *const libc::sock_fprog,
                ) != 0
                {
                    return Err(Error::Child {
                        step: "seccomp(SECCOMP_SET_MODE_FILTER)",
                        errno: errno(),
                    });
                }
            }
            applied.seccomp_applied = true;
        }

        Ok(applied)
    }
}

/// PID-namespace reaper: close every fd (so the parent's exec-status pipe
/// and any stdout pipes see EOF as soon as the workload execs/exits), wait for
/// `child`, and exit with its status.
///
/// # Safety
/// Must run in a single-threaded forked process.
unsafe fn reap(child: libc::pid_t) -> ! {
    const SYS_CLOSE_RANGE: libc::c_long = 436; // unified number
    if libc::syscall(SYS_CLOSE_RANGE, 0u32, u32::MAX, 0u32) != 0 {
        for fd in 0..4096 {
            libc::close(fd);
        }
    }
    let mut status: libc::c_int = 0;
    loop {
        let r = libc::waitpid(child, &mut status, 0);
        if r == child {
            break;
        }
        if r < 0 && errno() != libc::EINTR {
            libc::_exit(127);
        }
    }
    if libc::WIFEXITED(status) {
        libc::_exit(libc::WEXITSTATUS(status));
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        libc::signal(sig, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
        libc::kill(libc::getpid(), sig);
        libc::_exit(128 + sig);
    }
    libc::_exit(127)
}
