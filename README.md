# zandbox

Linux process sandboxing, applied in the child between `fork` and `exec`
(`std::os::unix::process::CommandExt::pre_exec`):

- namespaces (user, mount, pid, net, ipc, uts), with the PID-namespace double fork
- capability drop
- landlock filesystem allowlist
- seccomp BPF syscall filtering
- cgroup v2 memory / cpu / pids limits
- a clean environment
- a **strict** mode that refuses to run when a requested primitive isn't available,
  instead of quietly skipping it

One `IsolationProfile` describes what to apply; callers decide what goes inside.
Intended users: [buckets](https://github.com/nixpt/buckets) (on top of bwrap),
exo-light's subprocess backend, and antarikshya's mandala native adapter.

**Status:** being ported. Not published yet.

## Provenance

The code comes from [exosphere](https://github.com/nixpt/exosphere)
(`crates/exo/daemon/src/enforcement.rs`, the `pre_exec` path of
`crates/exo/daemon/src/spawner.rs`, and `crates/exo/seccomp-guard`), where it was
licensed OCPL-1.1. Its authors relicensed it as MIT OR Apache-2.0 for zandbox on
2026-10-31.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache License 2.0](LICENSE-APACHE)
at your option.
