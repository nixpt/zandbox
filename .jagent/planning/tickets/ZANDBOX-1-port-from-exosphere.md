# ZANDBOX-1 — port the sandbox from exosphere

| Field | Value |
|---|---|
| ID | ZANDBOX-1 |
| Priority | P1 |
| Status | done (awaiting review; not pushed — no remote yet) |
| Owner | satya |
| Branch | `agent/satya/ZANDBOX-1` |
| Base | `main` @ `9eda9ef` |
| Source | exosphere @ `0c35ddec`: `crates/exo/daemon/src/enforcement.rs`, `crates/exo/daemon/src/spawner.rs` (`pre_exec`, env), `crates/exo/seccomp-guard/src/**` |
| Licence | MIT OR Apache-2.0, with the exosphere authors' consent (captain, 2026-10-31) |
| Created | 2026-10-31 |

## Goal

First real zandbox: a standalone crate (deps: `libc`, `caps`, `thiserror`,
optional `serde`) applying namespaces → PID double fork → caps → landlock →
seccomp from `pre_exec`, with cgroup v2 limits, a clean env and a strict mode.
No exosphere types.

## Done when

- [x] `Profile` builder, `Profile::prepare` → `Prepared` (before fork),
      `Prepared::apply_in_child` (after fork, syscalls only), `Command`/`Child`.
- [x] Strict mode returns `Error::Unavailable` naming the primitive;
      non-strict reports skips in `Report`.
- [x] Tests: user+mount+pid ns (PID 1, distinct ns inode), net ns (only `lo`,
      connect to 1.1.1.1 fails), caps empty after drop, landlock (EACCES
      outside, ok inside, read-only root), seccomp (EPERM / SIGSYS / allowed
      works / x32 rejected), env, cgroup `pids_max` (ignored without
      `ZANDBOX_CGROUP_PARENT`), strict refusals; seccomp-guard's unit tests.
- [x] `cargo test`, `cargo clippy --all-targets -- -D warnings`,
      `cargo doc --no-deps` clean.
- [x] README (usage, guarantees, strict table, provenance), CHANGELOG 0.1.0.

## Resolution

Implemented on `agent/satya/ZANDBOX-1`. 6 unit + 21 integration tests pass;
the cgroup test also passes when run inside
`systemd-run --user --scope -p Delegate=yes` (recipe in README). Fixes over
exosphere and the not-ported list are in CHANGELOG.md.

Found while testing: exosphere's seccomp `Default` profile killed GNU `cat`
(`fadvise64`), `sleep` (`clock_nanosleep`) and every fork/thread
(`clone`/`clone3`); the additions were measured with `strace -f`, not guessed.

Follow-ups (not in scope): mount a fresh `/proc` in a pid+mount ns;
report the failing child step through std (only errno survives today);
landlock network rules (ABI 4) and device-ioctl rules (ABI 5).
