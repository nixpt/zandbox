use std::io;

/// Everything zandbox can fail with.
///
/// Only [`Error::Child`] is ever constructed after `fork`; it holds no heap
/// data, so building it is async-signal-safe.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A requested primitive is not available on this host (strict mode), or
    /// cannot be used at all.
    #[error("zandbox: {primitive} unavailable: {reason}")]
    Unavailable {
        primitive: &'static str,
        reason: String,
    },

    /// The profile is inconsistent (e.g. cgroup limits without a parent).
    #[error("zandbox: invalid profile: {0}")]
    InvalidProfile(String),

    /// An I/O operation in the parent (before fork) failed.
    #[error("zandbox: {context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    /// A syscall in the child (after fork) failed.
    #[error("zandbox: in child, {step} failed (errno {errno})")]
    Child { step: &'static str, errno: i32 },

    /// `std::process::Command::spawn` failed. When the failure came from
    /// [`crate::Prepared::apply_in_child`] this carries only the errno: std
    /// passes nothing else back from `pre_exec`.
    #[error("zandbox: spawn failed: {0}")]
    Spawn(#[source] io::Error),
}

impl Error {
    pub(crate) fn unavailable(primitive: &'static str, reason: impl Into<String>) -> Self {
        Error::Unavailable {
            primitive,
            reason: reason.into(),
        }
    }

    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    /// The errno, for [`Error::Child`] (and OS-level `Io`/`Spawn` errors).
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Error::Child { errno, .. } => Some(*errno),
            Error::Io { source, .. } | Error::Spawn(source) => source.raw_os_error(),
            _ => None,
        }
    }
}

impl From<Error> for io::Error {
    /// For `pre_exec` closures. [`Error::Child`] maps to
    /// `io::Error::from_raw_os_error`, which does not allocate.
    fn from(e: Error) -> io::Error {
        match e {
            Error::Child { errno, .. } => io::Error::from_raw_os_error(errno),
            Error::Io { source, .. } | Error::Spawn(source) => source,
            other => io::Error::other(other.to_string()),
        }
    }
}

/// Read errno after a failed libc call. Async-signal-safe.
#[inline]
pub(crate) fn errno() -> i32 {
    // SAFETY: __errno_location returns a valid thread-local pointer.
    unsafe { *libc::__errno_location() }
}
