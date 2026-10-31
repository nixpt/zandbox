//! Integration tests. Every sandbox is applied in a child process — either a
//! program run through `zandbox::Command`, or a raw `fork` where the child
//! calls `Prepared::apply_in_child` and reports through its exit code — so
//! the test process itself is never sandboxed.

use std::path::PathBuf;
use std::process::Stdio;

use zandbox::{Command, Error, Profile, SeccompAction, SeccompProfile};

// ---------------------------------------------------------------- helpers

#[derive(Debug, PartialEq, Eq)]
enum Exit {
    Code(i32),
    Signal(i32),
}

/// Fork; run `f` in the child (after the caller prepared everything) and
/// `_exit` with its return value.
fn in_child(f: impl FnOnce() -> i32) -> Exit {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(101);
            libc::_exit(code);
        }
        let mut st = 0;
        assert_eq!(libc::waitpid(pid, &mut st, 0), pid);
        if libc::WIFEXITED(st) {
            Exit::Code(libc::WEXITSTATUS(st))
        } else {
            Exit::Signal(libc::WTERMSIG(st))
        }
    }
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn run(program: &str, args: &[&str], profile: Profile) -> std::process::Output {
    Command::new(program, profile)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn")
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn scratch_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("zandbox-test-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---------------------------------------------------------------- namespaces

#[test]
fn user_mount_pid_namespace_child_is_pid1() {
    let own = std::fs::read_link("/proc/self/ns/pid").unwrap();
    let p = Profile::new()
        .user_ns(true)
        .mount_ns(true)
        .pid_ns(true)
        .strict(true);
    let o = run("/bin/sh", &["-c", "echo $$; readlink /proc/self/ns/pid"], p);
    assert!(o.status.success(), "{o:?}");
    let out = stdout(&o);
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("1"), "workload should be PID 1: {out}");
    let ns = lines.next().unwrap();
    assert!(ns.starts_with("pid:["), "{ns}");
    assert_ne!(ns, own.to_str().unwrap(), "pid namespace inode must differ");
}

#[test]
fn pid_namespace_exit_status_propagates() {
    let p = Profile::new().user_ns(true).pid_ns(true);
    let o = run("/bin/sh", &["-c", "exit 7"], p);
    assert_eq!(o.status.code(), Some(7));
}

#[test]
fn user_namespace_maps_current_uid() {
    let uid = unsafe { libc::getuid() };
    let o = run("/usr/bin/id", &["-u"], Profile::new().user_ns(true));
    assert_eq!(stdout(&o).trim(), uid.to_string());
    let o = run(
        "/usr/bin/id",
        &["-u"],
        Profile::new()
            .user_ns(true)
            .user_map(zandbox::UserMap::Root),
    );
    assert_eq!(stdout(&o).trim(), "0");
}

#[test]
fn net_namespace_only_loopback() {
    let p = Profile::new().user_ns(true).net_ns(true).strict(true);
    let o = run("/bin/cat", &["/proc/net/dev"], p);
    assert!(o.status.success(), "{o:?}");
    let ifaces: Vec<String> = stdout(&o)
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next())
        .map(|s| s.trim().to_string())
        .collect();
    assert_eq!(ifaces, vec!["lo".to_string()]);
}

#[test]
fn net_namespace_connect_fails() {
    let prepared = Profile::new()
        .user_ns(true)
        .net_ns(true)
        .strict(true)
        .prepare()
        .unwrap();
    let exit = in_child(|| {
        if prepared.apply_in_child().is_err() {
            return 90;
        }
        unsafe {
            let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if s < 0 {
                return 91;
            }
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 80u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes([1, 1, 1, 1]).to_be(),
                },
                sin_zero: [0; 8],
            };
            let r = libc::connect(
                s,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if r == 0 {
                return 1; // connected: isolation failed
            }
            if errno() == libc::ENETUNREACH {
                0
            } else {
                2
            }
        }
    });
    assert_eq!(exit, Exit::Code(0));
}

// ---------------------------------------------------------------- capabilities

fn cap_lines(o: &std::process::Output) -> Vec<(String, u64)> {
    stdout(o)
        .lines()
        .filter(|l| l.starts_with("Cap"))
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_string(), u64::from_str_radix(v.trim(), 16).unwrap())
        })
        .collect()
}

#[test]
fn caps_effective_empty_after_drop() {
    // Control: root in a user namespace holds capabilities there.
    let o = run(
        "/bin/grep",
        &["^Cap", "/proc/self/status"],
        Profile::new()
            .user_ns(true)
            .user_map(zandbox::UserMap::Root),
    );
    let ctl = cap_lines(&o);
    assert!(
        ctl.iter().any(|(k, v)| k == "CapEff" && *v != 0),
        "control: {ctl:?}"
    );

    // Same, with the drop: every set is empty after exec, including bounding.
    let o = run(
        "/bin/grep",
        &["^Cap", "/proc/self/status"],
        Profile::new()
            .user_ns(true)
            .user_map(zandbox::UserMap::Root)
            .drop_capabilities([])
            .strict(true),
    );
    let caps = cap_lines(&o);
    assert_eq!(caps.len(), 5, "{caps:?}");
    for (k, v) in &caps {
        assert_eq!(*v, 0, "{k} not empty: {caps:?}");
    }
}

#[test]
fn caps_drop_without_user_ns_sets_no_new_privs() {
    let o = run(
        "/bin/grep",
        &["-E", "^(CapEff|NoNewPrivs)", "/proc/self/status"],
        Profile::new().drop_capabilities([]).strict(true),
    );
    let out = stdout(&o);
    assert!(out.contains("NoNewPrivs:\t1"), "{out}");
    assert!(out.contains("CapEff:\t0000000000000000"), "{out}");
}

// ---------------------------------------------------------------- landlock

#[test]
fn landlock_write_allowlist_and_readonly_root() {
    let allowed = scratch_dir("ll-allowed");
    let denied = scratch_dir("ll-denied");
    let profile = Profile::new()
        .readonly_root(true)
        .allow_write(&allowed)
        .strict(true);

    let script = r#"echo ok > "$1/f" || exit 10
echo no > "$2/f" 2>/dev/null && exit 11
cat /etc/passwd > /dev/null || exit 12
exit 0"#;
    // /dev/null is not writable under the policy; give it write access.
    let p = profile.clone().allow_write("/dev/null");
    let o = run(
        "/bin/sh",
        &[
            "-c",
            script,
            "sh",
            allowed.to_str().unwrap(),
            denied.to_str().unwrap(),
        ],
        p,
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(std::fs::read_to_string(allowed.join("f")).unwrap(), "ok\n");
    assert!(!denied.join("f").exists());

    // The denied write fails with EACCES specifically.
    let prepared = profile.prepare().unwrap();
    let target = std::ffi::CString::new(denied.join("g").to_str().unwrap()).unwrap();
    let inside = std::ffi::CString::new(allowed.join("g").to_str().unwrap()).unwrap();
    let exit = in_child(|| {
        if prepared.apply_in_child().is_err() {
            return 90;
        }
        unsafe {
            let fl = libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC;
            if libc::open(target.as_ptr(), fl, 0o644) >= 0 {
                return 1;
            }
            if errno() != libc::EACCES {
                return 2;
            }
            if libc::open(inside.as_ptr(), fl, 0o644) < 0 {
                return 3;
            }
            // read-only root: reading still works
            if libc::open(c"/etc/passwd".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) < 0 {
                return 4;
            }
            0
        }
    });
    assert_eq!(exit, Exit::Code(0));
    let _ = std::fs::remove_dir_all(&allowed);
    let _ = std::fs::remove_dir_all(&denied);
}

#[test]
fn landlock_missing_path_strict_vs_lenient() {
    let missing = "/nonexistent/zandbox/path";
    let err = Profile::new()
        .allow_write(missing)
        .strict(true)
        .prepare()
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Unavailable {
                primitive: "landlock",
                ..
            }
        ),
        "{err}"
    );

    let prepared = Profile::new()
        .readonly_root(true)
        .allow_write(missing)
        .prepare()
        .unwrap();
    let r = prepared.report();
    assert!(r.landlock_abi.is_some());
    assert_eq!(r.skipped.len(), 1, "{r:?}");
    assert_eq!(r.skipped[0].primitive, "landlock.path");
}

// ---------------------------------------------------------------- seccomp

#[test]
fn seccomp_denied_syscall_errno_allowed_works() {
    let prepared = Profile::new()
        .seccomp(
            zandbox::Seccomp::new(SeccompProfile::Strict)
                .action(SeccompAction::Errno(libc::EPERM as u16)),
        )
        .strict(true)
        .prepare()
        .unwrap();
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let exit = in_child(|| {
        if prepared.apply_in_child().is_err() {
            return 90;
        }
        unsafe {
            // getpid is not in Strict
            if libc::syscall(libc::SYS_getpid) != -1 || errno() != libc::EPERM {
                return 1;
            }
            // write is
            if libc::write(fds[1], b"x".as_ptr().cast(), 1) != 1 {
                return 2;
            }
        }
        0
    });
    assert_eq!(exit, Exit::Code(0));
    let mut b = [0u8; 1];
    assert_eq!(unsafe { libc::read(fds[0], b.as_mut_ptr().cast(), 1) }, 1);
    assert_eq!(&b, b"x");
}

#[test]
fn seccomp_denied_syscall_kills_by_default() {
    let prepared = Profile::new()
        .seccomp(SeccompProfile::Strict)
        .prepare()
        .unwrap();
    let exit = in_child(|| {
        if prepared.apply_in_child().is_err() {
            return 90;
        }
        unsafe { libc::syscall(libc::SYS_getpid) };
        0
    });
    assert_eq!(exit, Exit::Signal(libc::SIGSYS));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn seccomp_rejects_x32_abi() {
    // getpid is allowed by Default; its x32 alias must not be.
    let prepared = Profile::new()
        .seccomp(
            zandbox::Seccomp::new(SeccompProfile::Default)
                .action(SeccompAction::Errno(libc::EPERM as u16)),
        )
        .prepare()
        .unwrap();
    let exit = in_child(|| {
        if prepared.apply_in_child().is_err() {
            return 90;
        }
        unsafe {
            if libc::syscall(libc::SYS_getpid) <= 0 {
                return 1;
            }
            if libc::syscall(libc::SYS_getpid | 0x4000_0000) != -1 || errno() != libc::EPERM {
                return 2;
            }
        }
        0
    });
    assert_eq!(exit, Exit::Code(0));
}

#[test]
fn seccomp_default_profile_runs_real_programs() {
    // sh forks for /bin/true: needs clone/clone3 (missing in exosphere's
    // Default); sleep needs clock_nanosleep, GNU cat needs fadvise64.
    let p = Profile::new().seccomp(SeccompProfile::Default).strict(true);
    let o = run(
        "/bin/sh",
        &["-c", "/bin/true && sleep 0.01 && echo ok | cat"],
        p,
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(stdout(&o), "ok\n");
}

// ---------------------------------------------------------------- env

#[test]
fn env_only_explicit_vars() {
    let p = Profile::new()
        .env_clear()
        .env("FOO", "bar")
        .env("ZANDBOX", "1");
    let o = run("/usr/bin/env", &[], p);
    assert!(o.status.success(), "{o:?}");
    let mut vars: Vec<&str> = std::str::from_utf8(&o.stdout).unwrap().lines().collect();
    vars.sort();
    assert_eq!(vars, vec!["FOO=bar", "ZANDBOX=1"]);
}

// ---------------------------------------------------------------- everything at once

#[test]
fn full_profile_strict() {
    let work = scratch_dir("full");
    let p = Profile::new()
        .namespaces(zandbox::Namespaces::ALL)
        .drop_capabilities([])
        .readonly_root(true)
        .allow_write(&work)
        .seccomp(SeccompProfile::Default)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .strict(true);
    let o = run(
        "/bin/sh",
        &[
            "-c",
            "echo $$ > \"$1/pid\"; cat \"$1/pid\"",
            "sh",
            work.to_str().unwrap(),
        ],
        p,
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(stdout(&o), "1\n");
    let _ = std::fs::remove_dir_all(&work);
}

// ---------------------------------------------------------------- strict mode

#[test]
fn strict_refuses_missing_cgroup_parent() {
    let p = Profile::new()
        .cgroup_parent("/sys/fs/cgroup/zandbox-does-not-exist")
        .pids_max(8);
    let err = p.clone().strict(true).prepare().unwrap_err();
    assert!(
        matches!(
            err,
            Error::Unavailable {
                primitive: "cgroup",
                ..
            }
        ),
        "{err}"
    );
    // and Command::spawn refuses before forking anything
    let err = Command::new("/bin/true", p.clone().strict(true))
        .spawn()
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Unavailable {
                primitive: "cgroup",
                ..
            }
        ),
        "{err}"
    );

    // non-strict: runs, and says what it skipped
    let child = Command::new("/bin/true", p).spawn().unwrap();
    let r = child.report().clone();
    assert!(child.wait_with_output().unwrap().status.success());
    assert_eq!(r.skipped.len(), 1, "{r:?}");
    assert_eq!(r.skipped[0].primitive, "cgroup");
    assert!(r.cgroup.is_none());
}

#[test]
fn cgroup_limits_without_parent_is_invalid() {
    let err = Profile::new().pids_max(4).prepare().unwrap_err();
    assert!(matches!(err, Error::InvalidProfile(_)), "{err}");
}

#[test]
fn strict_refuses_namespaces_without_user_ns_when_unprivileged() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root may unshare freely
    }
    let err = Profile::new()
        .net_ns(true)
        .strict(true)
        .prepare()
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Unavailable {
                primitive: "namespaces",
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn strict_refuses_unknown_syscall() {
    let err = Profile::new()
        .seccomp(zandbox::Seccomp::new(SeccompProfile::Default).allow("not_a_syscall"))
        .strict(true)
        .prepare()
        .unwrap_err();
    assert!(matches!(err, Error::InvalidProfile(_)), "{err}");
}

#[test]
fn child_side_error_reaches_spawn() {
    // net ns without user ns, non-strict, unprivileged: unshare fails with
    // EPERM in the child and spawn reports it.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let err = Command::new("/bin/true", Profile::new().net_ns(true))
        .spawn()
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err}");
}

// ---------------------------------------------------------------- cgroup

/// Needs `ZANDBOX_CGROUP_PARENT` = a delegated, writable cgroup v2 directory
/// with no processes of its own. See README "Running the cgroup test".
#[test]
#[ignore = "needs ZANDBOX_CGROUP_PARENT (a delegated cgroup v2 dir)"]
fn cgroup_pids_max_caps_fork_bomb() {
    let parent = std::env::var("ZANDBOX_CGROUP_PARENT").expect("ZANDBOX_CGROUP_PARENT");
    let p = Profile::new()
        .cgroup_parent(&parent)
        .pids_max(5)
        .memory_max(64 << 20)
        .strict(true);
    // `read` is a builtin: report our cgroup without forking, then fork-bomb.
    let script = "read -r cg < /proc/self/cgroup; echo \"$cg\"; \
                  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do sleep 1 & done; wait";
    let mut child = Command::new("/bin/sh", p)
        .args(["-c", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let cg = child.cgroup_path().expect("cgroup created").to_path_buf();
    assert!(child.report().complete(), "{:?}", child.report());
    let status = child.wait().unwrap();
    assert_eq!(
        std::fs::read_to_string(cg.join("pids.max")).unwrap().trim(),
        "5"
    );
    assert_eq!(
        std::fs::read_to_string(cg.join("memory.max"))
            .unwrap()
            .trim(),
        (64u64 << 20).to_string()
    );
    let events = std::fs::read_to_string(cg.join("pids.events")).unwrap();
    let max_hits: u64 = events
        .lines()
        .find_map(|l| l.strip_prefix("max "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(max_hits > 0, "pids.max never hit: {events}");
    let mut out = String::new();
    use std::io::Read;
    child
        .std_mut()
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let name = cg.file_name().unwrap().to_str().unwrap();
    assert!(out.contains(name), "child not in its cgroup: {out}");
    let _ = status;
    assert!(child.remove_cgroup().unwrap().is_some());
    assert!(!cg.exists());
}
