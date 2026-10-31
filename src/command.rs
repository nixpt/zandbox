use std::ffi::OsStr;
use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output, Stdio};

use crate::cgroup::CgroupGuard;
use crate::error::Error;
use crate::prepared::Report;
use crate::profile::Profile;

/// A [`std::process::Command`] that runs its program inside a [`Profile`].
///
/// `spawn` does, in order: [`Profile::prepare`] (parent, before fork), the
/// environment (`env_clear` + explicit vars, applied to the std `Command` so
/// std builds the child's `envp` with them), and a `pre_exec` hook that calls
/// [`crate::Prepared::apply_in_child`].
///
/// ```no_run
/// use zandbox::{Command, Profile, SeccompProfile};
///
/// let profile = Profile::new()
///     .user_ns(true).pid_ns(true).net_ns(true).mount_ns(true)
///     .drop_capabilities([])
///     .readonly_root(true).allow_write("/tmp/work")
///     .seccomp(SeccompProfile::Default)
///     .env_clear().env("PATH", "/usr/bin:/bin")
///     .strict(true);
/// let out = Command::new("/bin/sh", profile).args(["-c", "echo hi"]).output()?;
/// assert_eq!(out.stdout, b"hi\n");
/// # Ok::<(), zandbox::Error>(())
/// ```
#[derive(Debug)]
pub struct Command {
    inner: std::process::Command,
    profile: Profile,
}

impl Command {
    pub fn new(program: impl AsRef<OsStr>, profile: Profile) -> Self {
        Self {
            inner: std::process::Command::new(program),
            profile,
        }
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.inner.arg(arg);
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }

    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.inner.current_dir(dir);
        self
    }

    pub fn stdin(mut self, cfg: impl Into<Stdio>) -> Self {
        self.inner.stdin(cfg);
        self
    }

    pub fn stdout(mut self, cfg: impl Into<Stdio>) -> Self {
        self.inner.stdout(cfg);
        self
    }

    pub fn stderr(mut self, cfg: impl Into<Stdio>) -> Self {
        self.inner.stderr(cfg);
        self
    }

    /// The underlying std `Command`, for options not mirrored here. Do not
    /// set the environment through it if the profile uses `env_clear` (the
    /// profile's environment is applied at spawn and wins).
    pub fn std_mut(&mut self) -> &mut std::process::Command {
        &mut self.inner
    }

    /// Prepare the profile and spawn.
    pub fn spawn(self) -> Result<Child, Error> {
        let Command { mut inner, profile } = self;
        let mut prepared = profile.prepare()?;
        if prepared.env_clear() {
            inner.env_clear();
        }
        for (k, v) in prepared.env_vars() {
            inner.env(k, v);
        }
        let report = prepared.report().clone();
        let cgroup = prepared.take_cgroup_guard();
        // SAFETY: apply_in_child is async-signal-safe (syscalls only).
        unsafe {
            inner.pre_exec(move || {
                prepared
                    .apply_in_child()
                    .map(|_| ())
                    .map_err(io::Error::from)
            });
        }
        let child = inner.spawn().map_err(Error::Spawn)?;
        Ok(Child {
            inner: child,
            report,
            cgroup,
        })
    }

    /// Spawn, wait, collect stdout/stderr (piped unless configured).
    pub fn output(self) -> Result<Output, Error> {
        let this = self.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = this.spawn()?;
        child.wait_with_output().map_err(Error::Spawn)
    }

    /// Spawn and wait.
    pub fn status(self) -> Result<ExitStatus, Error> {
        let mut child = self.spawn()?;
        child.wait().map_err(Error::Spawn)
    }
}

/// A running sandboxed child.
///
/// With a PID namespace, [`Child::id`] and [`Child::wait`] refer to the
/// reaper process, which exits with the workload's status; killing it kills
/// the workload (`PR_SET_PDEATHSIG`). The cgroup (if any) is removed when the
/// `Child` is dropped, once empty.
#[derive(Debug)]
pub struct Child {
    inner: std::process::Child,
    report: Report,
    cgroup: Option<CgroupGuard>,
}

impl Child {
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.inner.wait()
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    pub fn kill(&mut self) -> io::Result<()> {
        self.inner.kill()
    }

    pub fn wait_with_output(self) -> io::Result<Output> {
        let Child { inner, cgroup, .. } = self;
        let out = inner.wait_with_output();
        drop(cgroup);
        out
    }

    /// What was prepared and what was skipped.
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// The child's cgroup directory, if one was created.
    pub fn cgroup_path(&self) -> Option<&Path> {
        self.cgroup.as_ref().map(|g| g.path.as_path())
    }

    /// Remove the cgroup now (fails with `EBUSY` while processes remain).
    pub fn remove_cgroup(&mut self) -> io::Result<Option<PathBuf>> {
        match self.cgroup.take() {
            None => Ok(None),
            Some(g) => {
                let path = g.path.clone();
                std::mem::forget(g);
                match std::fs::remove_dir(&path) {
                    Ok(()) => Ok(Some(path)),
                    Err(e) => {
                        self.cgroup = Some(CgroupGuard { path });
                        Err(e)
                    }
                }
            }
        }
    }

    /// The underlying std child (stdin/stdout/stderr handles live here).
    pub fn std_mut(&mut self) -> &mut std::process::Child {
        &mut self.inner
    }
}
