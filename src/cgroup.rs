//! cgroup v2 limits.
//!
//! Ported from exosphere `enforcement.rs` `prepare_cgroup_for_capsule` /
//! `attach_pid_to_cgroup` / `cleanup_cgroup` and the in-child join from
//! `spawner.rs` (EXO-192-4-verify) (@ `0c35ddec`).
//!
//! Changes while porting:
//! * the parent directory is supplied by the caller (exosphere guessed
//!   `user@<uid>.service/app.slice` or `/sys/fs/cgroup/exo`);
//! * a missing parent, a missing controller, a failed `mkdir` or a failed
//!   limit write is an error in strict mode and reported in non-strict mode
//!   (exosphere ignored every limit-write error with `let _ =` and logged
//!   the rest at warn/debug);
//! * controllers that the parent exposes in `cgroup.controllers` but has not
//!   enabled in `cgroup.subtree_control` are enabled (`+pids` etc.);
//! * the child joins by writing `0` to `cgroup.procs` — its own task, no
//!   pid formatting after fork — and does so **first**, before `unshare`, so
//!   the move is checked against the caller's own credentials and the
//!   PID-namespace reaper is inside the cgroup too.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{errno, Error};
use crate::{Profile, Report};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Owns a created cgroup directory; removes it (best effort) on drop.
/// Removal only succeeds once no process is left in it.
#[derive(Debug)]
pub(crate) struct CgroupGuard {
    pub(crate) path: PathBuf,
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[derive(Debug)]
pub(crate) struct CgroupPlan {
    procs: CString,
    strict: bool,
    pub(crate) guard: Option<CgroupGuard>,
}

fn ctrl_name(c: &str) -> &'static str {
    match c {
        "memory" => "cgroup.memory",
        "cpu" => "cgroup.cpu",
        _ => "cgroup.pids",
    }
}

pub(crate) fn prepare(profile: &Profile, report: &mut Report) -> Result<Option<CgroupPlan>, Error> {
    let strict = profile.strict;
    let Some(parent) = profile.cgroup_parent.as_deref() else {
        if profile.wants_cgroup_limits() {
            return Err(Error::InvalidProfile(
                "cgroup limits (memory_max/cpu_max/pids_max) set without cgroup_parent".into(),
            ));
        }
        return Ok(None);
    };
    let fail = |report: &mut Report, prim: &'static str, why: String| {
        if strict {
            Err(Error::unavailable(prim, why))
        } else {
            report.skip(prim, why);
            Ok(None)
        }
    };
    if !parent.join("cgroup.procs").is_file() {
        return fail(
            report,
            "cgroup",
            format!(
                "{} is not a cgroup v2 directory (no cgroup.procs)",
                parent.display()
            ),
        );
    }

    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
    let available = read(&parent.join("cgroup.controllers"));
    let mut enabled = read(&parent.join("cgroup.subtree_control"));
    let has = |list: &str, c: &str| list.split_whitespace().any(|x| x == c);

    let wanted: [(&str, Option<String>, &str); 3] = [
        (
            "memory",
            profile.memory_max.map(|b| b.to_string()),
            "memory.max",
        ),
        (
            "cpu",
            profile.cpu_max.map(|(q, p)| format!("{q} {p}")),
            "cpu.max",
        ),
        ("pids", profile.pids_max.map(|n| n.to_string()), "pids.max"),
    ];
    let mut usable: Vec<(&str, String, &str)> = Vec::new();
    for (ctrl, value, file) in wanted {
        let Some(value) = value else { continue };
        if !has(&enabled, ctrl) {
            if !has(&available, ctrl) {
                let why = format!("controller {ctrl} not available in {}", parent.display());
                if strict {
                    return Err(Error::unavailable(ctrl_name(ctrl), why));
                }
                report.skip(ctrl_name(ctrl), why);
                continue;
            }
            if let Err(e) =
                std::fs::write(parent.join("cgroup.subtree_control"), format!("+{ctrl}"))
            {
                let why = format!(
                    "cannot enable {ctrl} in {}/cgroup.subtree_control: {e}",
                    parent.display()
                );
                if strict {
                    return Err(Error::unavailable(ctrl_name(ctrl), why));
                }
                report.skip(ctrl_name(ctrl), why);
                continue;
            }
            enabled = read(&parent.join("cgroup.subtree_control"));
        }
        usable.push((ctrl, value, file));
    }

    let name = format!(
        "zandbox-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let dir = parent.join(name);
    if let Err(e) = std::fs::create_dir(&dir) {
        return fail(report, "cgroup", format!("mkdir {}: {e}", dir.display()));
    }
    let guard = CgroupGuard { path: dir.clone() };
    for (ctrl, value, file) in usable {
        if let Err(e) = std::fs::write(dir.join(file), &value) {
            let why = format!("write {value:?} to {}/{file}: {e}", dir.display());
            if strict {
                return Err(Error::unavailable(ctrl_name(ctrl), why)); // guard rmdirs
            }
            report.skip(ctrl_name(ctrl), why);
        }
    }
    let procs = CString::new(dir.join("cgroup.procs").as_os_str().as_bytes())
        .map_err(|_| Error::InvalidProfile("cgroup path contains a NUL byte".into()))?;
    report.cgroup = Some(dir);
    Ok(Some(CgroupPlan {
        procs,
        strict,
        guard: Some(guard),
    }))
}

impl CgroupPlan {
    /// Child side: move the calling task into the cgroup. Returns whether it
    /// joined; failure is an error only in strict mode.
    pub(crate) fn join(&self) -> Result<bool, Error> {
        // SAFETY: open/write/close on a precomputed C string and a static buffer.
        unsafe {
            let fd = libc::open(self.procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return self.failed(errno());
            }
            let r = libc::write(fd, b"0".as_ptr().cast(), 1);
            let e = errno();
            libc::close(fd);
            if r != 1 {
                return self.failed(e);
            }
        }
        Ok(true)
    }

    fn failed(&self, errno: i32) -> Result<bool, Error> {
        if self.strict {
            Err(Error::Child {
                step: "cgroup join (write cgroup.procs)",
                errno,
            })
        } else {
            Ok(false)
        }
    }
}
