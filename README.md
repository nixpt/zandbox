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

One `Profile` describes what to apply; callers decide what runs inside.
Intended users: [buckets](https://github.com/nixpt/buckets) (on top of bwrap),
exo-light's subprocess backend, and antarikshya's mandala native adapter.

**Status:** 0.1.0, unreleased (`publish = false`). Linux only.

## Usage

```rust
use zandbox::{Command, Profile, SeccompProfile};

let profile = Profile::new()
    .user_ns(true).mount_ns(true).pid_ns(true).net_ns(true).ipc_ns(true).uts_ns(true)
    .drop_capabilities([])                    // keep none
    .readonly_root(true)                      // landlock: / readable, not writable
    .allow_write("/tmp/work")                 //           ...except here
    .seccomp(SeccompProfile::Default)         // last step before exec
    .cgroup_parent("/sys/fs/cgroup/.../sandboxes") // a delegated cgroup v2 dir
    .pids_max(64).memory_max(256 << 20).cpu_percent(50)
    .env_clear().env("PATH", "/usr/bin:/bin")
    .strict(true);                            // refuse if any of this is unavailable

let out = Command::new("/bin/sh", profile).args(["-c", "echo $$"]).output()?;
assert_eq!(out.stdout, b"1\n");               // PID 1 of its own namespace
```

If you own the fork yourself (tokio's `Command::pre_exec`, a raw `fork`, a
container runtime), use the two-step API:

```rust,ignore
let prepared = profile.prepare()?;            // parent, before fork
// configure env from prepared.env_clear() / prepared.env_vars()
unsafe { cmd.pre_exec(move || prepared.apply_in_child().map(drop).map_err(Into::into)); }
```

`Prepared::report()` says what will be applied and what (non-strict) was
skipped; `apply_in_child` returns an `Applied` with what the child did.

## Guarantees

Everything that allocates, opens paths or probes the kernel happens in
`Profile::prepare`, **before fork**. `Prepared::apply_in_child` runs **after
fork** and only issues syscalls on that precomputed data (no allocation, no
locks, no logging), in this order:

| # | primitive | before fork | after fork | what it guarantees |
|---|---|---|---|---|
| 1 | cgroup v2 | check the parent, enable `pids`/`memory`/`cpu` in its `subtree_control`, `mkdir zandbox-<pid>-<n>`, write `pids.max`/`memory.max`/`cpu.max` | write `0` to `cgroup.procs` | the workload is in its own cgroup with those limits **before** it execs (no spawn/attach race). The PID-namespace reaper is inside too and counts toward `pids.max` |
| 2 | namespaces | format uid/gid map lines | `unshare(2)`; for a user ns: `setgroups=deny`, `uid_map`, `gid_map` (caller's ids mapped to themselves, or to 0 with `UserMap::Root`) | new namespaces of each requested kind. `/proc` is **not** remounted |
| 3 | PID namespace | — | `fork`: the child becomes PID 1 and continues; the caller becomes a reaper that closes all its fds, waits, and exits with the workload's status (re-raising a fatal signal) | the workload is PID 1 of a fresh pid ns. `PR_SET_PDEATHSIG(SIGKILL)`: killing the reaper (`Child::kill`) kills the workload |
| 4 | capabilities | keep-mask, `cap_last_cap` | drop bounding set, clear ambient, `capset` down to the keep-list, raise kept caps to ambient, `no_new_privs` | effective/permitted/inheritable/ambient hold only the keep-list, and `execve` cannot add any |
| 5 | landlock | probe ABI, create ruleset, open and add every allowlisted path | `no_new_privs`, `landlock_restrict_self` | writes (and, for non-`readonly_root` profiles, reads) only beneath allowlisted paths. ABI-aware: `REFER` (v2) and `TRUNCATE` (v3) are handled when the kernel has them. Device ioctls (ABI v5) and network rules (v4) are not handled |
| 6 | seccomp | resolve names, compile BPF | `no_new_privs`, `seccomp(SECCOMP_SET_MODE_FILTER)` | wrong-architecture syscalls kill the process; x32 syscalls (x86_64) and everything outside the allowlist get the deny action (default `KILL_PROCESS`, or `Errno`/`Trap`/`Log`) |
| — | environment | `env_clear` + explicit vars set on the std `Command`, which builds `envp` before fork | — | the child sees exactly the variables you set |

### Strict vs non-strict

| situation | strict | non-strict |
|---|---|---|
| landlock missing (`ENOSYS`/`EOPNOTSUPP`) | `Error::Unavailable { primitive: "landlock" }` | skipped, listed in `Report::skipped` |
| an allowlisted path cannot be opened | `Error::Unavailable { "landlock" }` | that rule skipped, listed |
| cgroup parent missing / not cgroup v2 / `mkdir` fails | `Error::Unavailable { "cgroup" }` | no cgroup, listed |
| controller unavailable or a limit write fails | `Error::Unavailable { "cgroup.pids" \| "cgroup.memory" \| "cgroup.cpu" }` | that limit skipped, listed |
| cgroup join fails in the child | spawn fails with the errno | runs outside the cgroup (`Applied::cgroup_joined == false`) |
| seccomp unsupported, or an unknown syscall name | error | skipped / name ignored, listed |
| mount/pid/net/ipc/uts ns without root or a user ns | `Error::Unavailable { "namespaces" }` | `unshare` fails with `EPERM` at spawn |
| unprivileged user namespaces disabled | `Error::Unavailable { "user_ns" }` | `unshare` fails at spawn |
| `unshare` fails for any other reason | spawn fails | spawn fails |
| a keep-listed capability isn't held | spawn fails (`EPERM`) | not kept |
| bounding set can't be reduced (no `CAP_SETPCAP`, i.e. unprivileged without a user ns) | allowed: `no_new_privs` and an empty permitted set mean `execve` can't use it | same |

Errors raised after fork travel back through std's `pre_exec` channel, which
carries only an errno; `Error::Child { step, errno }` (with the step name) is
what raw `apply_in_child` callers see.

### Seccomp profiles

`Strict` (exec + minimal I/O; most dynamic binaries won't load), `Default`
(files, signals, timers, processes, threads; **no sockets** — programs that
resolve users through NSS, like `id`, open an `AF_UNIX` socket and are killed),
`Application` (`Default` + sockets), `Service` (+ `mount`, `chroot`, …),
`Allow(names)`. Add or remove names with `Seccomp::new(p).allow(..).block(..)`.

## Running the tests

```sh
cargo test
```

Each test applies its sandbox in a child (a program spawned through
`zandbox::Command`, or a raw `fork`) so the test process itself is never
sandboxed. Needs unprivileged user namespaces, landlock and seccomp.

### Running the cgroup test

`cgroup_pids_max_caps_fork_bomb` is `#[ignore]`d unless
`ZANDBOX_CGROUP_PARENT` names a delegated, writable cgroup v2 directory that
has no processes of its own (cgroup v2's "no internal processes" rule). With
systemd:

```sh
systemd-run --user --scope -p Delegate=yes bash -c '
  CG=/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup)
  mkdir $CG/leaf $CG/sandboxes
  echo $$ > $CG/leaf/cgroup.procs                  # move ourselves out of the scope root
  echo "+pids +memory +cpu" > $CG/cgroup.subtree_control
  ZANDBOX_CGROUP_PARENT=$CG/sandboxes cargo test -- --include-ignored'
```

## Provenance

The code comes from [exosphere](https://github.com/nixpt/exosphere) at commit
`0c35ddec`:

- `crates/exo/daemon/src/enforcement.rs` (`EnforcementEngine`, namespaces,
  cgroup v2 setup/attach/cleanup, capability drop, `apply_landlock`)
- `crates/exo/daemon/src/spawner.rs` (the `pre_exec` block: PID-namespace
  double fork and in-child cgroup join; `env_clear` + explicit environment)
- `crates/exo/seccomp-guard/src/**` (BPF builder, syscall tables, profiles)

Its authors consented to it being licensed MIT OR Apache-2.0 in zandbox. What
changed while porting is listed in [CHANGELOG.md](CHANGELOG.md) and in each
module's docs.

## Releasing

Releases are published to crates.io by `.github/workflows/publish.yml` with
[Trusted Publishing](https://crates.io/docs/trusted-publishing) (no long-lived token).

- **One-time setup:** on crates.io, open zandbox → Settings → Trusted Publishing and
  add repository owner `nixpt`, repository `zandbox`, workflow `publish.yml`, no
  environment. Check it with `gh workflow run publish.yml -f verify_auth=true`.
- **A release:** bump `version` in `Cargo.toml`, add the CHANGELOG entry, merge to
  `main`, then push a matching tag:
  `git tag -a v0.2.0 -m "zandbox 0.2.0" && git push origin v0.2.0`.
  The workflow refuses a tag that doesn't match `Cargo.toml`, and skips a version
  that's already on crates.io. It can be re-run by hand with
  `gh workflow run publish.yml -f tag=v0.2.0`.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache License 2.0](LICENSE-APACHE)
at your option.
