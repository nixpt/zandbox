# Changelog

## 0.1.0 — unreleased

First real version, ported from exosphere @ `0c35ddec`
(`crates/exo/daemon/src/enforcement.rs`, the `pre_exec` path of
`crates/exo/daemon/src/spawner.rs`, `crates/exo/seccomp-guard`).

### Added
- `Profile` builder: namespaces, `UserMap`, `drop_capabilities`, landlock
  (`readonly_root`, `allow_read`, `allow_write`), `seccomp`, cgroup v2
  (`cgroup_parent`, `memory_max`, `cpu_max`/`cpu_percent`, `pids_max`),
  `env_clear`/`env`, `strict`.
- `Profile::prepare` → `Prepared` (before fork) and
  `Prepared::apply_in_child` → `Applied` (after fork, syscalls only).
- `Command` / `Child`: env + prepare + `pre_exec` wiring; the child's cgroup
  is removed when the `Child` is dropped (once empty).
- `Report` of skipped primitives (non-strict); `Error::Unavailable` naming
  the primitive (strict).
- `seccomp` module: `SeccompProfile`, `SeccompAction`, `Seccomp`, BPF
  builder, x86_64/aarch64/riscv64 syscall tables; `landlock::abi_version`.
- Optional `serde` feature for `Profile` and its parts.

### Fixed relative to exosphere
- seccomp: the filter now checks `seccomp_data.arch` (kill on mismatch) and
  rejects x32-ABI syscalls on x86_64; previously a 32-bit or x32 syscall
  bypassed the allowlist.
- seccomp: `Default` lacked `clone`/`clone3`/`fork`/`vfork`, so threaded or
  forking workloads died with SIGSYS; also added `clock_nanosleep`,
  `fadvise64`, xattr calls and the unified-range (424+) syscalls, which the
  x86_64 table did not know at all.
- seccomp: `blocked_syscalls` was stored but never applied; unknown names were
  dropped silently. Bogus aarch64 numbers for `fork`/`vfork`/`dup2`/`pipe`/
  `select` removed.
- landlock: missing landlock and unopenable allowlist paths were skipped
  silently; now an error (strict) or reported (non-strict). Rights follow the
  kernel ABI (`REFER`, `TRUNCATE`); the old unused `LL_TRUNCATE` constant had
  `REFER`'s bit.
- cgroup: limit writes were `let _ =`; a missing parent or controller was a
  log line. Now an error (strict) or reported (non-strict). The parent is
  caller-supplied instead of guessed. The child joins before `unshare`.
- user namespace: no uid/gid map was written, so the workload ran as the
  overflow uid and could not create files.
- capabilities: `caps::drop` allocated after fork and every error was
  swallowed; now raw syscalls on a precomputed mask, `no_new_privs` set,
  kept caps raised to ambient so they survive `execve`.
- PID namespace: the reaper now waits and propagates the workload's exit
  status / signal (exosphere's intermediate exited at once and reported the
  grandchild's pid over a side pipe), and the workload gets
  `PR_SET_PDEATHSIG(SIGKILL)`.

### Not ported
- `profile_from_manifest`, `expand_denied_paths`, `CapsuleManifest`,
  `ScopedCapability` mapping — capsule-manifest policy stays in exosphere.
- `seat_daemon_in_cgroup` and the `user@<uid>.service/app.slice` guess.
- `SyscallGovernor` (applying a filter to another pid was a no-op stub).
- ZPU/GPU device mounts from the spawner's `pre_exec`.
