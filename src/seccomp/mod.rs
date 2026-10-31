//! Seccomp BPF syscall filtering.
//!
//! Ported from exosphere's `exo-seccomp-guard` crate (@ `0c35ddec`). The
//! `SeccompManager` / `CapsuleSyscallFilter` / `SyscallGovernor` types are
//! gone: a filter is described by [`Seccomp`], compiled to BPF by
//! [`Seccomp::compile`] **before fork**, and installed in the child by
//! [`crate::Prepared::apply_in_child`] with a single `seccomp(2)` call.
//!
//! Fixes relative to exosphere:
//!
//! * the program now checks `seccomp_data.arch` first and kills on a
//!   mismatch, and on x86_64 rejects x32-ABI syscall numbers (exosphere's
//!   filter had neither, so an `int 0x80` or x32 syscall bypassed it);
//! * `block` entries are honoured (exosphere stored `blocked_syscalls` and
//!   never read them);
//! * unknown syscall names are reported (exosphere dropped them silently);
//!   in strict mode they are an error;
//! * the deny action is configurable ([`SeccompAction`]); the default is
//!   exosphere's `SECCOMP_RET_KILL_PROCESS`.

pub mod arch;
pub mod builder;
pub mod profiles;

pub use arch::Architecture;
pub use builder::{BpfBuilder, BpfInstruction};

/// Built-in syscall allowlist to start from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SeccompProfile {
    /// exec family, basic I/O, memory management, exit. Most dynamically
    /// linked programs will not even load under it (no `openat`); intended
    /// for code you control that has already done its setup.
    Strict,
    /// What ordinary programs, shells and interpreters need: files, signals,
    /// timers, process and thread creation. No sockets.
    #[default]
    Default,
    /// `Default` plus sockets.
    Application,
    /// `Application` plus system management (`mount`, `chroot`, `reboot`, …).
    Service,
    /// Exactly these syscalls (plus nothing else).
    Allow(Vec<String>),
}

impl SeccompProfile {
    /// The syscall names this profile allows.
    pub fn syscalls(&self) -> Vec<&str> {
        let parts: &[&[&str]] = match self {
            SeccompProfile::Strict => &[profiles::STRICT],
            SeccompProfile::Default => &[profiles::DEFAULT, profiles::ADDED],
            SeccompProfile::Application => &[profiles::DEFAULT, profiles::ADDED, profiles::NETWORK],
            SeccompProfile::Service => &[
                profiles::DEFAULT,
                profiles::ADDED,
                profiles::NETWORK,
                profiles::SYSTEM,
            ],
            SeccompProfile::Allow(names) => return names.iter().map(String::as_str).collect(),
        };
        let mut out: Vec<&str> = parts.iter().flat_map(|p| p.iter().copied()).collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// What a filtered-out syscall does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SeccompAction {
    /// `SECCOMP_RET_KILL_PROCESS`: the whole process dies with `SIGSYS`.
    #[default]
    KillProcess,
    /// `SECCOMP_RET_KILL_THREAD`: the calling thread dies.
    KillThread,
    /// `SECCOMP_RET_TRAP`: deliver `SIGSYS` (catchable).
    Trap,
    /// `SECCOMP_RET_ERRNO`: the syscall fails with this errno (e.g. `EPERM`).
    Errno(u16),
    /// `SECCOMP_RET_LOG`: allow, but log to the audit log.
    Log,
}

impl SeccompAction {
    /// The `SECCOMP_RET_*` value.
    pub fn ret_value(self) -> u32 {
        match self {
            SeccompAction::KillProcess => libc::SECCOMP_RET_KILL_PROCESS,
            SeccompAction::KillThread => libc::SECCOMP_RET_KILL_THREAD,
            SeccompAction::Trap => libc::SECCOMP_RET_TRAP,
            SeccompAction::Errno(e) => libc::SECCOMP_RET_ERRNO | u32::from(e),
            SeccompAction::Log => libc::SECCOMP_RET_LOG,
        }
    }
}

/// A seccomp filter description: a base profile, extra allowed syscalls,
/// syscalls removed from the allowlist, and the deny action.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct Seccomp {
    pub profile: SeccompProfile,
    pub action: SeccompAction,
    pub allow: Vec<String>,
    pub block: Vec<String>,
}

impl From<SeccompProfile> for Seccomp {
    fn from(profile: SeccompProfile) -> Self {
        Seccomp::new(profile)
    }
}

/// Result of [`Seccomp::compile`].
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    /// The BPF program, ready for `SECCOMP_SET_MODE_FILTER`.
    pub program: Vec<libc::sock_filter>,
    /// Number of distinct syscalls allowed.
    pub allowed: usize,
    /// Names from `allow` / `block` / `Allow(..)` that do not resolve on this
    /// architecture.
    pub unknown: Vec<String>,
}

impl Seccomp {
    pub fn new(profile: SeccompProfile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }

    /// Set the action for syscalls that are not allowed.
    pub fn action(mut self, action: SeccompAction) -> Self {
        self.action = action;
        self
    }

    /// Allow one more syscall.
    pub fn allow(mut self, name: impl Into<String>) -> Self {
        self.allow.push(name.into());
        self
    }

    /// Remove a syscall from the allowlist (wins over `allow`).
    pub fn block(mut self, name: impl Into<String>) -> Self {
        self.block.push(name.into());
        self
    }

    /// Build the BPF program for `arch`. Allocates; call before fork.
    ///
    /// Names in a built-in profile that do not exist on `arch` (for example
    /// `open` on aarch64) are skipped silently: the profiles are written for
    /// x86_64 and carry legacy names on purpose. Names the caller supplied are
    /// reported in [`CompiledFilter::unknown`].
    pub fn compile(&self, arch: Architecture) -> Result<CompiledFilter, String> {
        let mut unknown = Vec::new();
        let user_names = matches!(self.profile, SeccompProfile::Allow(_));
        let mut numbers: Vec<u32> = Vec::new();
        for name in self.profile.syscalls() {
            match arch.syscall_number(name) {
                Some(n) => numbers.push(n),
                None if user_names => unknown.push(name.to_string()),
                None => {}
            }
        }
        for name in &self.allow {
            match arch.syscall_number(name) {
                Some(n) => numbers.push(n),
                None => unknown.push(name.clone()),
            }
        }
        let mut blocked = Vec::new();
        for name in &self.block {
            match arch.syscall_number(name) {
                Some(n) => blocked.push(n),
                None => unknown.push(name.clone()),
            }
        }
        numbers.sort_unstable();
        numbers.dedup();
        numbers.retain(|n| !blocked.contains(n));
        if numbers.is_empty() {
            return Err("seccomp allowlist resolves to no syscalls".into());
        }
        // A single conditional jump can skip at most 255 instructions, and
        // each entry is two instructions; the table layout here only ever
        // jumps by 0 or 1, so the only limit is BPF_MAXINSNS.
        let mut b = BpfBuilder::new();
        b.build_allowlist(
            arch.audit_arch(),
            arch == Architecture::X86_64,
            &numbers,
            libc::SECCOMP_RET_ALLOW,
            self.action.ret_value(),
        );
        let program: Vec<libc::sock_filter> = b
            .finish()
            .into_iter()
            .map(|i| libc::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        if program.len() > 4096 {
            return Err(format!(
                "seccomp program has {} instructions (kernel limit 4096)",
                program.len()
            ));
        }
        Ok(CompiledFilter {
            program,
            allowed: numbers.len(),
            unknown,
        })
    }
}

/// Whether the running kernel supports seccomp.
///
/// `prctl(PR_GET_SECCOMP)` reads the caller's current mode without changing
/// it. (exosphere's original probe called `seccomp(op=0)`, which is
/// `SECCOMP_SET_MODE_STRICT` — it *enabled* strict mode; EXO-149. The
/// regression test is ported below.)
pub fn is_supported() -> bool {
    // SAFETY: PR_GET_SECCOMP takes no pointer arguments.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_filter_default() {
        let s = SeccompProfile::Default.syscalls();
        assert!(!s.is_empty());
        assert!(s.contains(&"read"));
        assert!(s.contains(&"write"));
        assert!(s.contains(&"exit"));
        // zandbox addition: process creation must be allowed.
        assert!(s.contains(&"clone3"));
    }

    #[test]
    fn test_create_filter_strict() {
        let s = SeccompProfile::Strict.syscalls();
        assert!(!s.is_empty());
        assert!(s.contains(&"read"));
        // Strict shouldn't have networking by default unless added
        assert!(!s.contains(&"socket"));
    }

    #[test]
    fn test_builder_compilation() {
        let arch = Architecture::current().expect("supported arch");
        let f = Seccomp::new(SeccompProfile::Strict)
            .allow("read")
            .compile(arch)
            .unwrap();
        assert!(!f.program.is_empty());
        assert!(f.unknown.is_empty());
        // arch load, arch check, kill, nr load [, x32 check, deny], table, default
        let table = 2 * f.allowed;
        let prologue = if arch == Architecture::X86_64 { 6 } else { 4 };
        assert_eq!(f.program.len(), prologue + table + 1);
    }

    #[test]
    fn test_block_and_unknown() {
        let arch = Architecture::current().unwrap();
        let base = Seccomp::new(SeccompProfile::Strict).compile(arch).unwrap();
        let f = Seccomp::new(SeccompProfile::Strict)
            .block("write")
            .allow("no_such_syscall")
            .compile(arch)
            .unwrap();
        assert_eq!(f.allowed, base.allowed - 1);
        assert_eq!(f.unknown, vec!["no_such_syscall".to_string()]);
    }

    /// Regression test for EXO-149: the support probe must NOT activate strict mode.
    ///
    /// Runs entirely in a forked child so a buggy probe cannot kill the test harness.
    /// A clean probe → child exits 0. A strict-mode-activating probe → child killed by SIGKILL.
    #[test]
    fn test_is_supported_does_not_restrict_caller() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork() failed");

            if pid == 0 {
                let _ = is_supported();
                // getpid() is not allowed in SECCOMP_MODE_STRICT — reaching this line
                // proves the probe did not activate strict mode.
                libc::getpid();
                libc::_exit(0);
            }

            let mut status: libc::c_int = 0;
            libc::waitpid(pid, &mut status, 0);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "is_supported() restricted the caller — child killed (raw status={status:#x})"
            );
            assert!(
                is_supported(),
                "expected seccomp to be supported on this Linux host"
            );
        }
    }
}
