//! Classic-BPF program builder for seccomp.
//!
//! Ported from exosphere `crates/exo/seccomp-guard/src/seccomp/builder.rs`
//! (@ `0c35ddec`). Added while porting: an architecture check prologue and
//! (x86_64) an x32-ABI rejection, see [`BpfBuilder::build_allowlist`].

/// One classic BPF instruction (same layout as `struct sock_filter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const BPF_JA: u16 = 0x05; // BPF_JMP | BPF_JA
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

/// Offsets into `struct seccomp_data`.
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;

/// x86_64: syscalls issued through the x32 ABI carry this bit in `nr`.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

impl BpfInstruction {
    /// Load the syscall number from `seccomp_data`.
    pub fn load_syscall_nr() -> Self {
        Self::load_abs(SECCOMP_DATA_NR)
    }

    /// Load the `AUDIT_ARCH_*` value from `seccomp_data`.
    pub fn load_arch() -> Self {
        Self::load_abs(SECCOMP_DATA_ARCH)
    }

    fn load_abs(offset: u32) -> Self {
        Self {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    /// Jump `jt` instructions if `A == k`, else `jf`.
    pub fn jmp_eq(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: BPF_JEQ_K,
            jt,
            jf,
            k,
        }
    }

    /// Jump `jt` instructions if `A >= k`, else `jf`.
    pub fn jmp_ge(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: BPF_JGE_K,
            jt,
            jf,
            k,
        }
    }

    /// Return `k` (a `SECCOMP_RET_*` action).
    pub fn ret(k: u32) -> Self {
        Self {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Unconditional jump forward by `k`.
    pub fn jmp(k: u32) -> Self {
        Self {
            code: BPF_JA,
            jt: 0,
            jf: 0,
            k,
        }
    }
}

/// Builds a seccomp BPF program.
#[derive(Debug, Default)]
pub struct BpfBuilder {
    program: Vec<BpfInstruction>,
}

impl BpfBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, instr: BpfInstruction) {
        self.program.push(instr);
    }

    /// Kill the process unless `seccomp_data.arch == audit_arch`; on x86_64
    /// also send x32-ABI syscalls to `deny_action`. Leaves the syscall number
    /// loaded in the accumulator.
    ///
    /// exosphere's builder had no such prologue, so a 32-bit (`int 0x80`) or
    /// x32 syscall was matched against x86_64 numbers — the classic seccomp
    /// allowlist bypass.
    fn arch_prologue(&mut self, audit_arch: u32, x86_64: bool, deny_action: u32) {
        self.push(BpfInstruction::load_arch());
        self.push(BpfInstruction::jmp_eq(audit_arch, 1, 0));
        self.push(BpfInstruction::ret(libc::SECCOMP_RET_KILL_PROCESS));
        self.push(BpfInstruction::load_syscall_nr());
        if x86_64 {
            self.push(BpfInstruction::jmp_ge(X32_SYSCALL_BIT, 0, 1));
            self.push(BpfInstruction::ret(deny_action));
        }
    }

    /// Allowlist program: arch check, then `allow_action` for each number in
    /// `syscall_numbers`, `default_action` for everything else.
    pub fn build_allowlist(
        &mut self,
        audit_arch: u32,
        x86_64: bool,
        syscall_numbers: &[u32],
        allow_action: u32,
        default_action: u32,
    ) {
        self.arch_prologue(audit_arch, x86_64, default_action);
        for &num in syscall_numbers {
            self.push(BpfInstruction::jmp_eq(num, 0, 1));
            self.push(BpfInstruction::ret(allow_action));
        }
        self.push(BpfInstruction::ret(default_action));
    }

    /// Blocklist program: arch check, then `deny_action` for each number in
    /// `syscall_numbers`, `default_action` for everything else.
    pub fn build_blocklist(
        &mut self,
        audit_arch: u32,
        x86_64: bool,
        syscall_numbers: &[u32],
        deny_action: u32,
        default_action: u32,
    ) {
        self.arch_prologue(audit_arch, x86_64, deny_action);
        for &num in syscall_numbers {
            self.push(BpfInstruction::jmp_eq(num, 0, 1));
            self.push(BpfInstruction::ret(deny_action));
        }
        self.push(BpfInstruction::ret(default_action));
    }

    pub fn finish(self) -> Vec<BpfInstruction> {
        self.program
    }
}
