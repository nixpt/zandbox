use std::ffi::OsString;
use std::path::PathBuf;

use crate::seccomp::Seccomp;

pub use caps::Capability;

/// Which namespaces to create with `unshare(2)`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct Namespaces {
    pub user: bool,
    pub mount: bool,
    pub pid: bool,
    pub net: bool,
    pub ipc: bool,
    pub uts: bool,
}

impl Namespaces {
    /// All six.
    pub const ALL: Namespaces = Namespaces {
        user: true,
        mount: true,
        pid: true,
        net: true,
        ipc: true,
        uts: true,
    };

    pub fn any(&self) -> bool {
        self.user || self.mount || self.pid || self.net || self.ipc || self.uts
    }

    pub(crate) fn clone_flags(&self) -> libc::c_int {
        let mut f = 0;
        if self.user {
            f |= libc::CLONE_NEWUSER;
        }
        if self.mount {
            f |= libc::CLONE_NEWNS;
        }
        if self.pid {
            f |= libc::CLONE_NEWPID;
        }
        if self.net {
            f |= libc::CLONE_NEWNET;
        }
        if self.ipc {
            f |= libc::CLONE_NEWIPC;
        }
        if self.uts {
            f |= libc::CLONE_NEWUTS;
        }
        f
    }
}

/// How the caller's uid/gid appear inside a new user namespace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum UserMap {
    /// Map the caller's uid/gid to themselves (`1000 → 1000`).
    #[default]
    Current,
    /// Map the caller's uid/gid to 0 (`unshare -r` style).
    Root,
    /// Write no mapping; the process runs as the overflow uid (`nobody`) and
    /// cannot create files. This is what exosphere did.
    None,
}

/// Description of the sandbox to apply. Build it with the methods below,
/// then call [`Profile::prepare`] (before fork) or use [`crate::Command`].
///
/// Default: nothing is applied and the environment is inherited.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct Profile {
    pub(crate) namespaces: Namespaces,
    pub(crate) user_map: UserMap,
    /// `None`: leave capabilities alone. `Some(keep)`: drop everything else.
    pub(crate) keep_capabilities: Option<Vec<Capability>>,
    pub(crate) readonly_root: bool,
    pub(crate) read_paths: Vec<PathBuf>,
    pub(crate) write_paths: Vec<PathBuf>,
    pub(crate) seccomp: Option<Seccomp>,
    pub(crate) cgroup_parent: Option<PathBuf>,
    pub(crate) memory_max: Option<u64>,
    pub(crate) cpu_max: Option<(u64, u64)>,
    pub(crate) pids_max: Option<u64>,
    pub(crate) env_clear: bool,
    pub(crate) env: Vec<(OsString, OsString)>,
    pub(crate) strict: bool,
}

impl Profile {
    /// An empty profile (applies nothing).
    pub fn new() -> Self {
        Self::default()
    }

    // ---- namespaces ---------------------------------------------------

    /// Set all namespace flags at once.
    pub fn namespaces(mut self, ns: Namespaces) -> Self {
        self.namespaces = ns;
        self
    }
    /// New user namespace. Required for every other namespace when not root.
    pub fn user_ns(mut self, on: bool) -> Self {
        self.namespaces.user = on;
        self
    }
    pub fn mount_ns(mut self, on: bool) -> Self {
        self.namespaces.mount = on;
        self
    }
    /// New PID namespace. The workload becomes its PID 1; see
    /// [`crate::Prepared::apply_in_child`] for the double fork this implies.
    pub fn pid_ns(mut self, on: bool) -> Self {
        self.namespaces.pid = on;
        self
    }
    /// New network namespace: only a (down) `lo`, no route anywhere.
    pub fn net_ns(mut self, on: bool) -> Self {
        self.namespaces.net = on;
        self
    }
    pub fn ipc_ns(mut self, on: bool) -> Self {
        self.namespaces.ipc = on;
        self
    }
    pub fn uts_ns(mut self, on: bool) -> Self {
        self.namespaces.uts = on;
        self
    }
    /// uid/gid mapping written for a new user namespace (default
    /// [`UserMap::Current`]).
    pub fn user_map(mut self, map: UserMap) -> Self {
        self.user_map = map;
        self
    }

    // ---- capabilities -------------------------------------------------

    /// Drop every capability (bounding, permitted, effective, inheritable,
    /// ambient) except `keep`, and set `no_new_privs`. Kept capabilities are
    /// raised into the ambient set so they survive `execve`.
    pub fn drop_capabilities(mut self, keep: impl IntoIterator<Item = Capability>) -> Self {
        self.keep_capabilities = Some(keep.into_iter().collect());
        self
    }

    // ---- landlock -----------------------------------------------------

    /// Make the whole filesystem readable and executable but not writable
    /// (landlock). Combine with [`Profile::allow_write`].
    pub fn readonly_root(mut self, on: bool) -> Self {
        self.readonly_root = on;
        self
    }
    /// Allow reading/executing beneath `path` (landlock).
    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_paths.push(path.into());
        self
    }
    /// Allow reading and writing beneath `path` (landlock).
    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.write_paths.push(path.into());
        self
    }

    // ---- seccomp ------------------------------------------------------

    /// Install a seccomp filter (last step before exec).
    pub fn seccomp(mut self, filter: impl Into<Seccomp>) -> Self {
        self.seccomp = Some(filter.into());
        self
    }

    // ---- cgroup v2 ----------------------------------------------------

    /// Create a per-process cgroup beneath `parent`, which must be a cgroup v2
    /// directory delegated to (writable by) the caller.
    pub fn cgroup_parent(mut self, parent: impl Into<PathBuf>) -> Self {
        self.cgroup_parent = Some(parent.into());
        self
    }
    /// `memory.max`, in bytes.
    pub fn memory_max(mut self, bytes: u64) -> Self {
        self.memory_max = Some(bytes);
        self
    }
    /// `cpu.max`: `quota_us` of CPU time per `period_us`.
    pub fn cpu_max(mut self, quota_us: u64, period_us: u64) -> Self {
        self.cpu_max = Some((quota_us, period_us));
        self
    }
    /// `cpu.max` as a percentage of one CPU (exosphere's `cpu_limit_percent`;
    /// period 100 ms).
    pub fn cpu_percent(self, percent: u32) -> Self {
        let period = 100_000u64;
        self.cpu_max(period * u64::from(percent) / 100, period)
    }
    /// `pids.max`. Note: with a PID namespace the reaper process counts too.
    pub fn pids_max(mut self, max: u64) -> Self {
        self.pids_max = Some(max);
        self
    }

    // ---- environment --------------------------------------------------

    /// Start the child with an empty environment (plus [`Profile::env`]).
    pub fn env_clear(mut self) -> Self {
        self.env_clear = true;
        self
    }
    /// Set one variable in the child.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    // ---- mode ---------------------------------------------------------

    /// Strict mode: refuse (return an error naming the primitive) when a
    /// requested primitive is unavailable, instead of skipping it.
    pub fn strict(mut self, on: bool) -> Self {
        self.strict = on;
        self
    }

    // ---- accessors ----------------------------------------------------

    pub fn get_namespaces(&self) -> Namespaces {
        self.namespaces
    }
    pub fn is_strict(&self) -> bool {
        self.strict
    }
    pub(crate) fn wants_landlock(&self) -> bool {
        self.readonly_root || !self.read_paths.is_empty() || !self.write_paths.is_empty()
    }
    pub(crate) fn wants_cgroup_limits(&self) -> bool {
        self.memory_max.is_some() || self.cpu_max.is_some() || self.pids_max.is_some()
    }
}
