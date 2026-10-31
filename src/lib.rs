//! zandbox — Linux process sandboxing applied from `pre_exec`.
//!
//! A [`Profile`] describes the sandbox: namespaces, a capability keep-list,
//! a landlock filesystem allowlist, a seccomp filter, cgroup v2 limits, the
//! child's environment, and whether to be **strict** (refuse when a requested
//! primitive is unavailable) or not (skip it and say so in the [`Report`]).
//!
//! Two layers:
//!
//! * [`Command`] — wraps [`std::process::Command`]: prepares the profile,
//!   applies the environment and installs the `pre_exec` hook.
//! * [`Profile::prepare`] → [`Prepared`] → [`Prepared::apply_in_child`] —
//!   for callers that own the fork (tokio's `Command::pre_exec`, a raw
//!   `fork`, a container runtime).
//!
//! # Before fork vs after fork
//!
//! | step | before fork ([`Profile::prepare`]) | after fork ([`Prepared::apply_in_child`]) |
//! |---|---|---|
//! | cgroup | check parent, enable controllers, `mkdir`, write `memory.max` / `cpu.max` / `pids.max` | write `0` to `cgroup.procs` |
//! | namespaces | strict: refuse non-root without user ns, or user ns disabled; format uid/gid map lines | `unshare`; `setgroups`=`deny`, `uid_map`, `gid_map` |
//! | PID namespace | — | `fork`; parent becomes the reaper, child is PID 1 |
//! | capabilities | keep-mask, `cap_last_cap` | `PR_CAPBSET_DROP`, ambient clear, `capget`/`capset`, ambient raise, `no_new_privs` |
//! | landlock | ABI probe, ruleset fd, open + add every path | `no_new_privs`, `landlock_restrict_self` |
//! | seccomp | resolve names, compile BPF | `no_new_privs`, `seccomp(SET_MODE_FILTER)` |
//! | environment | `env_clear` + vars on the std `Command` (std builds `envp`) | — |
//!
//! Everything after fork is a plain syscall on precomputed data: no
//! allocation, no locks, no logging.
//!
//! # Strict vs non-strict
//!
//! | situation | strict | non-strict |
//! |---|---|---|
//! | landlock missing (`ENOSYS`/`EOPNOTSUPP`) | `Error::Unavailable("landlock")` | skipped, in `Report::skipped` |
//! | allowlisted path cannot be opened | `Error::Unavailable("landlock")` | that rule skipped, reported |
//! | cgroup parent missing / not cgroup v2 / `mkdir` fails | `Error::Unavailable("cgroup")` | no cgroup, reported |
//! | controller missing or limit write fails | `Error::Unavailable("cgroup.<ctrl>")` | that limit skipped, reported |
//! | cgroup join fails in the child | spawn fails (errno) | runs outside the cgroup (`Applied::cgroup_joined = false`) |
//! | seccomp unsupported / unknown syscall name | error | skipped / name ignored, reported |
//! | namespaces without root or user ns | `Error::Unavailable("namespaces")` | `unshare` fails with `EPERM` at spawn |
//! | `unshare` fails | spawn fails | spawn fails |
//! | keep-listed capability not held | spawn fails (`EPERM`) | silently not kept |
//! | bounding set can't be reduced (no `CAP_SETPCAP`) | allowed — `no_new_privs` + empty permitted set | same |
//!
//! # Provenance
//!
//! Ported from exosphere @ `0c35ddec`: `crates/exo/daemon/src/enforcement.rs`,
//! the `pre_exec` block of `crates/exo/daemon/src/spawner.rs`, and
//! `crates/exo/seccomp-guard`. Each module's docs list what changed.

#![cfg(target_os = "linux")]
#![warn(missing_debug_implementations)]

mod caps;
mod cgroup;
mod command;
mod error;
pub mod landlock;
mod prepared;
mod profile;
pub mod seccomp;

pub use command::{Child, Command};
pub use error::Error;
pub use prepared::{Applied, Prepared, Report, Skipped};
pub use profile::{Capability, Namespaces, Profile, UserMap};
pub use seccomp::{Seccomp, SeccompAction, SeccompProfile};
