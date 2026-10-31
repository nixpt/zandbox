//! Syscall number tables, by architecture.
//!
//! Ported from exosphere `crates/exo/seccomp-guard/src/seccomp/arch.rs`
//! (@ `0c35ddec`). Changes while porting:
//!
//! * the x86_64 table stopped at `rseq` (334); syscalls from the unified
//!   424+ range (`clone3`, `close_range`, `openat2`, `faccessat2`, …) are now
//!   resolved on every architecture by [`unified_syscall_number`];
//! * the aarch64 table mapped `fork`/`vfork`/`dup2`/`pipe`/`select` to numbers
//!   (1079, 1071, …) that come from the retired asm-generic "deprecated"
//!   range and do not exist on arm64 or riscv64; they now resolve to `None`.

/// Architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Aarch64,
    Riscv64,
}

impl Architecture {
    /// The architecture this crate was compiled for, or `None` when seccomp
    /// filtering is not supported by zandbox on it.
    pub fn current() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            Some(Architecture::X86_64)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Some(Architecture::Aarch64)
        }
        #[cfg(target_arch = "riscv64")]
        {
            Some(Architecture::Riscv64)
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )))]
        {
            None
        }
    }

    /// Resolve a syscall name to its number on this architecture.
    pub fn syscall_number(&self, name: &str) -> Option<u32> {
        let direct = match self {
            Architecture::X86_64 => get_x86_64_syscall_number(name),
            Architecture::Aarch64 => get_aarch64_syscall_number(name),
            Architecture::Riscv64 => get_riscv64_syscall_number(name),
        };
        direct.or_else(|| unified_syscall_number(name))
    }

    /// Get the BPF architecture code (AUDIT_ARCH_*)
    pub fn audit_arch(&self) -> u32 {
        match self {
            Architecture::X86_64 => 0xc000003e,  // AUDIT_ARCH_X86_64
            Architecture::Aarch64 => 0xc00000b7, // AUDIT_ARCH_AARCH64
            Architecture::Riscv64 => 0xc00000f3, // AUDIT_ARCH_RISCV64
        }
    }
}

/// Helper to get syscall number by name for x86_64
pub fn get_x86_64_syscall_number(name: &str) -> Option<u32> {
    match name {
        "read" => Some(0),
        "write" => Some(1),
        "open" => Some(2),
        "close" => Some(3),
        "stat" => Some(4),
        "fstat" => Some(5),
        "lstat" => Some(6),
        "poll" => Some(7),
        "lseek" => Some(8),
        "mmap" => Some(9),
        "mprotect" => Some(10),
        "munmap" => Some(11),
        "brk" => Some(12),
        "rt_sigaction" => Some(13),
        "rt_sigprocmask" => Some(14),
        "rt_sigreturn" => Some(15),
        "ioctl" => Some(16),
        "pread64" => Some(17),
        "pwrite64" => Some(18),
        "readv" => Some(19),
        "writev" => Some(20),
        "access" => Some(21),
        "pipe" => Some(22),
        "select" => Some(23),
        "sched_yield" => Some(24),
        "mremap" => Some(25),
        "msync" => Some(26),
        "mincore" => Some(27),
        "madvise" => Some(28),
        "shmget" => Some(29),
        "shmat" => Some(30),
        "shmctl" => Some(31),
        "dup" => Some(32),
        "dup2" => Some(33),
        "pause" => Some(34),
        "nanosleep" => Some(35),
        "getitimer" => Some(36),
        "alarm" => Some(37),
        "setitimer" => Some(38),
        "getpid" => Some(39),
        "sendfile" => Some(40),
        "socket" => Some(41),
        "connect" => Some(42),
        "accept" => Some(43),
        "sendto" => Some(44),
        "recvfrom" => Some(45),
        "sendmsg" => Some(46),
        "recvmsg" => Some(47),
        "shutdown" => Some(48),
        "bind" => Some(49),
        "listen" => Some(50),
        "getsockname" => Some(51),
        "getpeername" => Some(52),
        "socketpair" => Some(53),
        "setsockopt" => Some(54),
        "getsockopt" => Some(55),
        "clone" => Some(56),
        "fork" => Some(57),
        "vfork" => Some(58),
        "execve" => Some(59),
        "exit" => Some(60),
        "wait4" => Some(61),
        "kill" => Some(62),
        "uname" => Some(63),
        "semget" => Some(64),
        "semop" => Some(65),
        "semctl" => Some(66),
        "shmdt" => Some(67),
        "msgget" => Some(68),
        "msgsnd" => Some(69),
        "msgrcv" => Some(70),
        "msgctl" => Some(71),
        "fcntl" => Some(72),
        "flock" => Some(73),
        "fsync" => Some(74),
        "fdatasync" => Some(75),
        "truncate" => Some(76),
        "ftruncate" => Some(77),
        "getdents" => Some(78),
        "getcwd" => Some(79),
        "chdir" => Some(80),
        "fchdir" => Some(81),
        "rename" => Some(82),
        "mkdir" => Some(83),
        "rmdir" => Some(84),
        "creat" => Some(85),
        "link" => Some(86),
        "unlink" => Some(87),
        "symlink" => Some(88),
        "readlink" => Some(89),
        "chmod" => Some(90),
        "fchmod" => Some(91),
        "chown" => Some(92),
        "fchown" => Some(93),
        "lchown" => Some(94),
        "umask" => Some(95),
        "gettimeofday" => Some(96),
        "getrlimit" => Some(97),
        "getrusage" => Some(98),
        "sysinfo" => Some(99),
        "times" => Some(100),
        "ptrace" => Some(101),
        "getuid" => Some(102),
        "syslog" => Some(103),
        "getgid" => Some(104),
        "setuid" => Some(105),
        "setgid" => Some(106),
        "geteuid" => Some(107),
        "getegid" => Some(108),
        "setpgid" => Some(109),
        "getppid" => Some(110),
        "getpgrp" => Some(111),
        "setsid" => Some(112),
        "setreuid" => Some(113),
        "setregid" => Some(114),
        "getgroups" => Some(115),
        "setgroups" => Some(116),
        "setresuid" => Some(117),
        "getresuid" => Some(118),
        "setresgid" => Some(119),
        "getresgid" => Some(120),
        "getpgid" => Some(121),
        "setfsuid" => Some(122),
        "setfsgid" => Some(123),
        "getsid" => Some(124),
        "capget" => Some(125),
        "capset" => Some(126),
        "rt_sigpending" => Some(127),
        "rt_sigtimedwait" => Some(128),
        "rt_sigqueueinfo" => Some(129),
        "rt_sigsuspend" => Some(130),
        "sigaltstack" => Some(131),
        "utime" => Some(132),
        "mknod" => Some(133),
        "uselib" => Some(134),
        "personality" => Some(135),
        "ustat" => Some(136),
        "statfs" => Some(137),
        "fstatfs" => Some(138),
        "sysfs" => Some(139),
        "getpriority" => Some(140),
        "setpriority" => Some(141),
        "sched_setparam" => Some(142),
        "sched_getparam" => Some(143),
        "sched_setscheduler" => Some(144),
        "sched_getscheduler" => Some(145),
        "sched_get_priority_max" => Some(146),
        "sched_get_priority_min" => Some(147),
        "sched_rr_get_interval" => Some(148),
        "mlock" => Some(149),
        "munlock" => Some(150),
        "mlockall" => Some(151),
        "munlockall" => Some(152),
        "vhangup" => Some(153),
        "modify_ldt" => Some(154),
        "pivot_root" => Some(155),
        "sysctl" => Some(156),
        "prctl" => Some(157),
        "arch_prctl" => Some(158),
        "adjtimex" => Some(159),
        "setrlimit" => Some(160),
        "chroot" => Some(161),
        "sync" => Some(162),
        "acct" => Some(163),
        "settimeofday" => Some(164),
        "mount" => Some(165),
        "umount2" => Some(166),
        "swapon" => Some(167),
        "swapoff" => Some(168),
        "reboot" => Some(169),
        "sethostname" => Some(170),
        "setdomainname" => Some(171),
        "iopl" => Some(172),
        "ioperm" => Some(173),
        "create_module" => Some(174),
        "init_module" => Some(175),
        "delete_module" => Some(176),
        "get_kernel_syms" => Some(177),
        "query_module" => Some(178),
        "quotactl" => Some(179),
        "nfsservctl" => Some(180),
        "getpmsg" => Some(181),
        "putpmsg" => Some(182),
        "afs_syscall" => Some(183),
        "tuxcall" => Some(184),
        "security" => Some(185),
        "gettid" => Some(186),
        "readahead" => Some(187),
        "setxattr" => Some(188),
        "lsetxattr" => Some(189),
        "fsetxattr" => Some(190),
        "getxattr" => Some(191),
        "lgetxattr" => Some(192),
        "fgetxattr" => Some(193),
        "listxattr" => Some(194),
        "llistxattr" => Some(195),
        "flistxattr" => Some(196),
        "removexattr" => Some(197),
        "lremovexattr" => Some(198),
        "fremovexattr" => Some(199),
        "tkill" => Some(200),
        "time" => Some(201),
        "futex" => Some(202),
        "sched_setaffinity" => Some(203),
        "sched_getaffinity" => Some(204),
        "set_thread_area" => Some(205),
        "io_setup" => Some(206),
        "io_destroy" => Some(207),
        "io_getevents" => Some(208),
        "io_submit" => Some(209),
        "io_cancel" => Some(210),
        "get_thread_area" => Some(211),
        "lookup_dcookie" => Some(212),
        "epoll_create" => Some(213),
        "epoll_ctl_old" => Some(214),
        "epoll_wait_old" => Some(215),
        "remap_file_pages" => Some(216),
        "getdents64" => Some(217),
        "set_tid_address" => Some(218),
        "restart_syscall" => Some(219),
        "semtimedop" => Some(220),
        "fadvise64" => Some(221),
        "timer_create" => Some(222),
        "timer_settime" => Some(223),
        "timer_gettime" => Some(224),
        "timer_getoverrun" => Some(225),
        "timer_delete" => Some(226),
        "clock_settime" => Some(227),
        "clock_gettime" => Some(228),
        "clock_getres" => Some(229),
        "clock_nanosleep" => Some(230),
        "exit_group" => Some(231),
        "epoll_wait" => Some(232),
        "epoll_ctl" => Some(233),
        "tgkill" => Some(234),
        "utimes" => Some(235),
        "vserver" => Some(236),
        "mbind" => Some(237),
        "set_mempolicy" => Some(238),
        "get_mempolicy" => Some(239),
        "mq_open" => Some(240),
        "mq_unlink" => Some(241),
        "mq_timedsend" => Some(242),
        "mq_timedreceive" => Some(243),
        "mq_notify" => Some(244),
        "mq_getsetattr" => Some(245),
        "kexec_load" => Some(246),
        "waitid" => Some(247),
        "add_key" => Some(248),
        "request_key" => Some(249),
        "keyctl" => Some(250),
        "ioprio_set" => Some(251),
        "ioprio_get" => Some(252),
        "inotify_init" => Some(253),
        "inotify_add_watch" => Some(254),
        "inotify_rm_watch" => Some(255),
        "migrate_pages" => Some(256),
        "openat" => Some(257),
        "mkdirat" => Some(258),
        "mknodat" => Some(259),
        "fchownat" => Some(260),
        "futimesat" => Some(261),
        "newfstatat" => Some(262),
        "unlinkat" => Some(263),
        "renameat" => Some(264),
        "linkat" => Some(265),
        "symlinkat" => Some(266),
        "readlinkat" => Some(267),
        "fchmodat" => Some(268),
        "faccessat" => Some(269),
        "pselect6" => Some(270),
        "ppoll" => Some(271),
        "unshare" => Some(272),
        "set_robust_list" => Some(273),
        "get_robust_list" => Some(274),
        "splice" => Some(275),
        "tee" => Some(276),
        "sync_file_range" => Some(277),
        "vmsplice" => Some(278),
        "move_pages" => Some(279),
        "utimensat" => Some(280),
        "epoll_pwait" => Some(281),
        "signalfd" => Some(282),
        "timerfd_create" => Some(283),
        "eventfd" => Some(284),
        "fallocate" => Some(285),
        "timerfd_settime" => Some(286),
        "timerfd_gettime" => Some(287),
        "accept4" => Some(288),
        "signalfd4" => Some(289),
        "eventfd2" => Some(290),
        "epoll_create1" => Some(291),
        "dup3" => Some(292),
        "pipe2" => Some(293),
        "inotify_init1" => Some(294),
        "preadv" => Some(295),
        "pwritev" => Some(296),
        "rt_tgsigqueueinfo" => Some(297),
        "perf_event_open" => Some(298),
        "recvmmsg" => Some(299),
        "fanotify_init" => Some(300),
        "fanotify_mark" => Some(301),
        "prlimit64" => Some(302),
        "name_to_handle_at" => Some(303),
        "open_by_handle_at" => Some(304),
        "clock_adjtime" => Some(305),
        "syncfs" => Some(306),
        "sendmmsg" => Some(307),
        "setns" => Some(308),
        "getcpu" => Some(309),
        "process_vm_readv" => Some(310),
        "process_vm_writev" => Some(311),
        "kcmp" => Some(312),
        "finit_module" => Some(313),
        "sched_setattr" => Some(314),
        "sched_getattr" => Some(315),
        "renameat2" => Some(316),
        "seccomp" => Some(317),
        "getrandom" => Some(318),
        "memfd_create" => Some(319),
        "kexec_file_load" => Some(320),
        "bpf" => Some(321),
        "execveat" => Some(322),
        "userfaultfd" => Some(323),
        "membarrier" => Some(324),
        "mlock2" => Some(325),
        "copy_file_range" => Some(326),
        "preadv2" => Some(327),
        "pwritev2" => Some(328),
        "pkey_mprotect" => Some(329),
        "pkey_alloc" => Some(330),
        "pkey_free" => Some(331),
        "statx" => Some(332),
        "io_pgetevents" => Some(333),
        "rseq" => Some(334),
        _ => None,
    }
}

/// Helper to get syscall number by name for aarch64 and riscv64 (asm-generic ABI)
pub fn get_aarch64_syscall_number(name: &str) -> Option<u32> {
    match name {
        // Core I/O
        "read" => Some(63),
        "write" => Some(64),
        "openat" => Some(56),
        "close" => Some(57),
        "lseek" => Some(62),
        "pread64" => Some(67),
        "pwrite64" => Some(68),
        "readv" => Some(65),
        "writev" => Some(66),
        "preadv" => Some(69),
        "pwritev" => Some(70),
        "preadv2" => Some(286),
        "pwritev2" => Some(287),
        "sendfile" => Some(71),
        "ioctl" => Some(29),

        // File management (native asm-generic)
        "getcwd" => Some(17),
        "chdir" => Some(49),
        "fchdir" => Some(50),
        "chroot" => Some(51),
        "fchmod" => Some(52),
        "fchmodat" => Some(53),
        "fchownat" => Some(54),
        "fchown" => Some(55),
        "openat2" => Some(437),
        "mkdirat" => Some(34),
        "mknodat" => Some(33),
        "unlinkat" => Some(35),
        "symlinkat" => Some(36),
        "linkat" => Some(37),
        "renameat" => Some(38),
        "renameat2" => Some(276),
        "readlinkat" => Some(78),
        "newfstatat" => Some(79),
        "fstat" => Some(80),
        "statx" => Some(291),
        "getdents64" => Some(61),
        "faccessat" => Some(48),
        "truncate" => Some(45),
        "ftruncate" => Some(46),
        "fallocate" => Some(47),
        "fsync" => Some(82),
        "fdatasync" => Some(83),
        "statfs" => Some(43),
        "fstatfs" => Some(44),
        "sync" => Some(81),
        "sync_file_range" => Some(84),
        "utimensat" => Some(88),
        "vhangup" => Some(58),

        // Legacy file ops (no native asm-generic number; use *at variants)
        "open" => None,
        "stat" => None,
        "lstat" => None,
        "getdents" => None,
        "rename" => None,
        "mkdir" => None,
        "rmdir" => None,
        "creat" => None,
        "link" => None,
        "unlink" => None,
        "symlink" => None,
        "readlink" => None,
        "chmod" => None,
        "chown" => None,
        "lchown" => None,
        "utime" => None,
        "access" => None,
        "mknod" => None,

        // Memory management
        "mmap" => Some(222),
        "mprotect" => Some(226),
        "munmap" => Some(215),
        "brk" => Some(214),
        "mremap" => Some(216),
        "msync" => Some(227),
        "mincore" => Some(232),
        "madvise" => Some(233),
        "mlock" => Some(228),
        "munlock" => Some(229),
        "mlockall" => Some(230),
        "munlockall" => Some(231),
        "memfd_create" => Some(279),
        "mlock2" => Some(284),
        "remap_file_pages" => Some(234),
        "mbind" => Some(235),
        "get_mempolicy" => Some(236),
        "set_mempolicy" => Some(237),
        "migrate_pages" => Some(238),
        "move_pages" => Some(239),
        "readahead" => Some(213),
        "fadvise64" => Some(223),

        // Process management
        "clone" => Some(220),
        "execve" => Some(221),
        "execveat" => Some(281),
        "exit" => Some(93),
        "exit_group" => Some(94),
        "wait4" => Some(260),
        "waitid" => Some(95),
        "kill" => Some(129),
        "tkill" => Some(130),
        "tgkill" => Some(131),
        "getpid" => Some(172),
        "getppid" => Some(173),
        "getuid" => Some(174),
        "geteuid" => Some(175),
        "getgid" => Some(176),
        "getegid" => Some(177),
        "gettid" => Some(178),
        "sysinfo" => Some(179),
        "prctl" => Some(167),
        "capget" => Some(90),
        "capset" => Some(91),
        "personality" => Some(92),
        "setuid" => Some(146),
        "setgid" => Some(144),
        "setreuid" => Some(145),
        "setregid" => Some(143),
        "setresuid" => Some(147),
        "getresuid" => Some(148),
        "setresgid" => Some(149),
        "getresgid" => Some(150),
        "setfsuid" => Some(151),
        "setfsgid" => Some(152),
        "setpgid" => Some(154),
        "getpgid" => Some(155),
        "getpgrp" => None, // use getpgid
        "getsid" => Some(156),
        "setsid" => Some(157),
        "getgroups" => Some(158),
        "setgroups" => Some(159),
        "uname" => Some(160),
        "getcpu" => Some(168),
        "ptrace" => Some(117),
        "syslog" => Some(116),
        "unshare" => Some(97),
        "setns" => Some(268),
        "acct" => Some(89),
        "prlimit64" => Some(261),
        "getrlimit" => Some(163),
        "setrlimit" => Some(164),
        "getrusage" => Some(165),
        "getpriority" => Some(141),
        "setpriority" => Some(140),
        "times" => Some(153),
        "gettimeofday" => Some(169),
        "settimeofday" => Some(170),

        // Legacy process syscalls: not present on arm64/riscv64 (use clone).
        "fork" => None,
        "vfork" => None,

        // Signals
        "rt_sigaction" => Some(134),
        "rt_sigprocmask" => Some(135),
        "rt_sigreturn" => Some(139),
        "rt_sigpending" => Some(136),
        "rt_sigtimedwait" => Some(137),
        "rt_sigqueueinfo" => Some(138),
        "rt_sigsuspend" => Some(133),
        "rt_tgsigqueueinfo" => Some(240),
        "sigaltstack" => Some(132),

        // Scheduling & timing
        "sched_yield" => Some(124),
        "sched_setscheduler" => Some(119),
        "sched_getscheduler" => Some(120),
        "sched_setparam" => Some(118),
        "sched_getparam" => Some(121),
        "sched_setaffinity" => Some(122),
        "sched_getaffinity" => Some(123),
        "sched_get_priority_max" => Some(125),
        "sched_get_priority_min" => Some(126),
        "sched_rr_get_interval" => Some(127),
        "sched_setattr" => Some(274),
        "sched_getattr" => Some(275),
        "restart_syscall" => Some(128),
        "nanosleep" => Some(101),
        "getitimer" => Some(102),
        "setitimer" => Some(103),
        "clock_settime" => Some(112),
        "clock_gettime" => Some(113),
        "clock_getres" => Some(114),
        "clock_nanosleep" => Some(115),
        "clock_adjtime" => Some(266),
        "timer_create" => Some(107),
        "timer_settime" => Some(110),
        "timer_gettime" => Some(108),
        "timer_getoverrun" => Some(109),
        "timer_delete" => Some(111),
        "timerfd_create" => Some(85),
        "timerfd_settime" => Some(86),
        "timerfd_gettime" => Some(87),
        "adjtimex" => Some(171),

        // Legacy timing (no native asm-generic)
        "alarm" => None,
        "pause" => None,
        "gettimeofday_legacy" => None,

        // Futex & synchronization
        "futex" => Some(98),
        "set_tid_address" => Some(96),
        "set_robust_list" => Some(99),
        "get_robust_list" => Some(100),

        // File descriptors & I/O multiplexing
        "dup" => Some(23),
        "dup3" => Some(24),
        "pipe2" => Some(59),
        "fcntl" => Some(25),
        "flock" => Some(32),
        "inotify_init1" => Some(26),
        "inotify_add_watch" => Some(27),
        "inotify_rm_watch" => Some(28),
        "epoll_create1" => Some(20),
        "epoll_ctl" => Some(21),
        "epoll_pwait" => Some(22),
        "pselect6" => Some(72),
        "ppoll" => Some(73),
        "signalfd4" => Some(74),
        "eventfd2" => Some(19),
        "splice" => Some(76),
        "tee" => Some(77),
        "vmsplice" => Some(75),
        "ioprio_set" => Some(30),
        "ioprio_get" => Some(31),
        "name_to_handle_at" => Some(264),
        "open_by_handle_at" => Some(265),

        // Legacy FD ops (not native on aarch64/riscv64)
        "dup2" => None,
        "pipe" => None,
        "select" => None,
        "poll" => None,
        "epoll_create" => None,
        "epoll_wait" => None,
        "eventfd" => None,
        "signalfd" => None,
        "inotify_init" => None,

        // Networking
        "socket" => Some(198),
        "socketpair" => Some(199),
        "bind" => Some(200),
        "listen" => Some(201),
        "accept" => Some(202),
        "connect" => Some(203),
        "getsockname" => Some(204),
        "getpeername" => Some(205),
        "sendto" => Some(206),
        "recvfrom" => Some(207),
        "setsockopt" => Some(208),
        "getsockopt" => Some(209),
        "shutdown" => Some(210),
        "sendmsg" => Some(211),
        "recvmsg" => Some(212),
        "accept4" => Some(242),
        "recvmmsg" => Some(243),
        "sendmmsg" => Some(269),

        // IPC (SysV)
        "semget" => Some(190),
        "semctl" => Some(191),
        "semtimedop" => Some(192),
        "semop" => Some(193),
        "shmget" => Some(194),
        "shmctl" => Some(195),
        "shmat" => Some(196),
        "shmdt" => Some(197),
        "msgget" => Some(186),
        "msgctl" => Some(187),
        "msgrcv" => Some(188),
        "msgsnd" => Some(189),
        "mq_open" => Some(180),
        "mq_unlink" => Some(181),
        "mq_timedsend" => Some(182),
        "mq_timedreceive" => Some(183),
        "mq_notify" => Some(184),
        "mq_getsetattr" => Some(185),

        // System administration
        "reboot" => Some(142),
        "sethostname" => Some(161),
        "setdomainname" => Some(162),
        "mount" => Some(40),
        "umount2" => Some(39),
        "pivot_root" => Some(41),
        "swapon" => Some(224),
        "swapoff" => Some(225),
        "quotactl" => Some(60),
        "umask" => Some(166),
        "syncfs" => Some(267),

        // x86-only — not available on aarch64/riscv64
        "arch_prctl" => None,
        "iopl" => None,
        "ioperm" => None,

        // Extended attributes
        "setxattr" => Some(5),
        "lsetxattr" => Some(6),
        "fsetxattr" => Some(7),
        "getxattr" => Some(8),
        "lgetxattr" => Some(9),
        "fgetxattr" => Some(10),
        "listxattr" => Some(11),
        "llistxattr" => Some(12),
        "flistxattr" => Some(13),
        "removexattr" => Some(14),
        "lremovexattr" => Some(15),
        "fremovexattr" => Some(16),

        // Async I/O
        "io_setup" => Some(0),
        "io_destroy" => Some(1),
        "io_submit" => Some(2),
        "io_cancel" => Some(3),
        "io_getevents" => Some(4),
        "io_pgetevents" => Some(292),

        // Keys
        "add_key" => Some(217),
        "request_key" => Some(218),
        "keyctl" => Some(219),

        // Misc
        "lookup_dcookie" => Some(18),
        "getrandom" => Some(278),
        "seccomp" => Some(277),
        "bpf" => Some(280),
        "userfaultfd" => Some(282),
        "membarrier" => Some(283),
        "copy_file_range" => Some(285),
        "pkey_mprotect" => Some(288),
        "pkey_alloc" => Some(289),
        "pkey_free" => Some(290),
        "rseq" => Some(293),
        "perf_event_open" => Some(241),
        "fanotify_init" => Some(262),
        "fanotify_mark" => Some(263),
        "process_vm_readv" => Some(270),
        "process_vm_writev" => Some(271),
        "kcmp" => Some(272),
        "finit_module" => Some(273),
        "init_module" => Some(105),
        "delete_module" => Some(106),
        "kexec_load" => Some(104),

        _ => None,
    }
}

/// Syscalls added from Linux 5.1 onward share one number on every
/// architecture (the "unified" 424+ range). Resolved as a fallback by
/// [`Architecture::syscall_number`].
pub fn unified_syscall_number(name: &str) -> Option<u32> {
    match name {
        "pidfd_send_signal" => Some(424),
        "io_uring_setup" => Some(425),
        "io_uring_enter" => Some(426),
        "io_uring_register" => Some(427),
        "open_tree" => Some(428),
        "move_mount" => Some(429),
        "fsopen" => Some(430),
        "fsconfig" => Some(431),
        "fsmount" => Some(432),
        "fspick" => Some(433),
        "pidfd_open" => Some(434),
        "clone3" => Some(435),
        "close_range" => Some(436),
        "openat2" => Some(437),
        "pidfd_getfd" => Some(438),
        "faccessat2" => Some(439),
        "process_madvise" => Some(440),
        "epoll_pwait2" => Some(441),
        "mount_setattr" => Some(442),
        "quotactl_fd" => Some(443),
        "landlock_create_ruleset" => Some(444),
        "landlock_add_rule" => Some(445),
        "landlock_restrict_self" => Some(446),
        "memfd_secret" => Some(447),
        "process_mrelease" => Some(448),
        "futex_waitv" => Some(449),
        "set_mempolicy_home_node" => Some(450),
        "cachestat" => Some(451),
        "fchmodat2" => Some(452),
        "map_shadow_stack" => Some(453),
        "futex_wake" => Some(454),
        "futex_wait" => Some(455),
        "futex_requeue" => Some(456),
        _ => None,
    }
}

/// Helper to get syscall number by name for riscv64.
/// riscv64 uses the same asm-generic ABI as aarch64; numbers are identical.
pub fn get_riscv64_syscall_number(name: &str) -> Option<u32> {
    get_aarch64_syscall_number(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aarch64_syscall_table_coverage() {
        // Core I/O
        assert_eq!(get_aarch64_syscall_number("read"), Some(63));
        assert_eq!(get_aarch64_syscall_number("write"), Some(64));
        assert_eq!(get_aarch64_syscall_number("openat"), Some(56));
        assert_eq!(get_aarch64_syscall_number("close"), Some(57));
        assert_eq!(get_aarch64_syscall_number("mmap"), Some(222));
        assert_eq!(get_aarch64_syscall_number("exit"), Some(93));
        assert_eq!(get_aarch64_syscall_number("exit_group"), Some(94));

        // Memory
        assert_eq!(get_aarch64_syscall_number("munmap"), Some(215));
        assert_eq!(get_aarch64_syscall_number("mprotect"), Some(226));
        assert_eq!(get_aarch64_syscall_number("brk"), Some(214));

        // Signals
        assert_eq!(get_aarch64_syscall_number("rt_sigaction"), Some(134));
        assert_eq!(get_aarch64_syscall_number("rt_sigprocmask"), Some(135));
        assert_eq!(get_aarch64_syscall_number("rt_sigreturn"), Some(139));

        // Networking
        assert_eq!(get_aarch64_syscall_number("socket"), Some(198));
        assert_eq!(get_aarch64_syscall_number("connect"), Some(203));
        assert_eq!(get_aarch64_syscall_number("accept"), Some(202));
        assert_eq!(get_aarch64_syscall_number("bind"), Some(200));

        // Process
        assert_eq!(get_aarch64_syscall_number("clone"), Some(220));
        assert_eq!(get_aarch64_syscall_number("execve"), Some(221));
        assert_eq!(get_aarch64_syscall_number("getpid"), Some(172));
        assert_eq!(get_aarch64_syscall_number("kill"), Some(129));

        // Sync/time
        assert_eq!(get_aarch64_syscall_number("futex"), Some(98));
        assert_eq!(get_aarch64_syscall_number("clock_gettime"), Some(113));
        assert_eq!(get_aarch64_syscall_number("nanosleep"), Some(101));

        // File
        assert_eq!(get_aarch64_syscall_number("getcwd"), Some(17));
        assert_eq!(get_aarch64_syscall_number("fstat"), Some(80));
        assert_eq!(get_aarch64_syscall_number("newfstatat"), Some(79));
        assert_eq!(get_aarch64_syscall_number("getdents64"), Some(61));
        assert_eq!(get_aarch64_syscall_number("openat2"), Some(437));

        // Legacy / x86-only should be None
        assert_eq!(get_aarch64_syscall_number("arch_prctl"), None);
        assert_eq!(get_aarch64_syscall_number("iopl"), None);

        // Retired asm-generic numbers are not real arm64 syscalls.
        assert_eq!(get_aarch64_syscall_number("fork"), None);

        // Unified range resolves on every architecture.
        assert_eq!(Architecture::X86_64.syscall_number("clone3"), Some(435));
        assert_eq!(Architecture::Aarch64.syscall_number("clone3"), Some(435));
        assert_eq!(Architecture::X86_64.syscall_number("openat2"), Some(437));

        // riscv64 delegates to aarch64 table
        assert_eq!(get_riscv64_syscall_number("read"), Some(63));
        assert_eq!(get_riscv64_syscall_number("mmap"), Some(222));
        assert_eq!(get_riscv64_syscall_number("exit"), Some(93));
    }
}
