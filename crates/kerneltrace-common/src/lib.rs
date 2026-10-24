//! Wire layout shared by the eBPF probe (`kerneltrace-ebpf`) and the userspace
//! decoder (`kerneltrace-core`).
//!
//! The probe reserves one [`RawEvent`] per kernel event in a BPF ring buffer and
//! fills it in place. Userspace never casts ring-buffer bytes to this struct;
//! it decodes them field by field using the `OFF_*` constants, so a truncated
//! or corrupted record produces an error instead of undefined behaviour.
//!
//! All integers are in the host's native byte order (the kernel and userspace
//! always share it). The layout is `#[repr(C)]` with explicit padding so that
//! the size and every offset are identical on every target, which the tests
//! below assert.

#![no_std]
#![forbid(unsafe_code)]

use core::mem::{offset_of, size_of};

/// Bytes reserved for the task command name (`TASK_COMM_LEN` in the kernel).
pub const COMM_LEN: usize = 16;
/// Bytes reserved for a path. Longer paths are truncated by the probe.
pub const PATH_LEN: usize = 256;

/// A process called `execve`/`execveat` successfully (`sched:sched_process_exec`).
pub const KIND_EXEC: u32 = 1;
/// A task exited (`sched:sched_process_exit`).
pub const KIND_EXIT: u32 = 2;
/// A task entered `openat(2)` (raw tracepoint `sys_enter`, filtered to `openat`).
pub const KIND_OPEN: u32 = 3;

/// Where a 64-bit `openat(2)` call keeps its number and arguments at the raw
/// `sys_enter` tracepoint, whose arguments are `(struct pt_regs *regs, long id)`.
///
/// The probe is built once for `bpfel` and loaded on several architectures,
/// so the loader writes the host's values into the probe's `OPEN_*` globals.
/// Offsets are byte offsets into the kernel's `struct pt_regs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallAbi {
    /// `__NR_openat` in the native (64-bit) syscall table.
    pub openat_nr: u64,
    /// Offset of the register holding `const char *filename` (2nd argument).
    pub path_off: u64,
    /// Offset of the register holding `int flags` (3rd argument).
    pub flags_off: u64,
    /// Offset of a register that tells native from compat (32-bit) tasks...
    pub mode_off: u64,
    /// ...masked with this...
    pub mode_mask: u64,
    /// ...must equal this for a native 64-bit syscall. Compat syscalls use a
    /// different numbering and are not traced (as with `syscalls:sys_enter_openat`).
    pub mode_want: u64,
}

/// x86_64: `pt_regs` is r15, r14, r13, r12, bp, bx, r11, r10, r9, r8, ax, cx,
/// dx, si, di, orig_ax, ip, cs, ... (8 bytes each). Arguments are di, si, dx;
/// `cs` is `__USER_CS` (0x33) for 64-bit tasks and 0x23 for ia32 tasks.
pub const ABI_X86_64: SyscallAbi = SyscallAbi {
    openat_nr: 257,
    path_off: 13 * 8,  // si
    flags_off: 12 * 8, // dx
    mode_off: 17 * 8,  // cs
    mode_mask: 0xffff,
    mode_want: 0x33,
};

/// aarch64: `pt_regs` starts with `regs[31]`, sp, pc, pstate. Arguments are
/// x0, x1, x2; `pstate` has `PSR_MODE32_BIT` (0x10) set for AArch32 tasks.
pub const ABI_AARCH64: SyscallAbi = SyscallAbi {
    openat_nr: 56,
    path_off: 8,
    flags_off: 2 * 8,
    mode_off: 33 * 8, // pstate
    mode_mask: 0x10,
    mode_want: 0,
};

/// Slots of the probe's per-CPU `STATS` counter array (userspace sums the CPUs).
///
/// `bpf_ringbuf_reserve` failed (ring buffer full): the event was lost in the kernel.
pub const STAT_RING_FULL: u32 = 0;
/// A path could not be read (for example an unmapped user page); the event was
/// still emitted, with `path_len = 0`.
pub const STAT_PATH_UNREADABLE: u32 = 1;
/// The `kt_exec` program produced (or tried to produce) an event.
pub const STAT_FIRED_EXEC: u32 = 2;
/// The `kt_exit` program produced (or tried to produce) an event.
pub const STAT_FIRED_EXIT: u32 = 3;
/// The `kt_open` program produced (or tried to produce) an event.
pub const STAT_FIRED_OPEN: u32 = 4;
/// Number of slots in `STATS`.
pub const STAT_SLOTS: u32 = 5;

/// One event record as written into the ring buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawEvent {
    /// `bpf_ktime_get_ns()` at the time of the event (CLOCK_MONOTONIC, ns).
    pub ts_ns: u64,
    /// Kind-specific value: the `flags` argument for `KIND_OPEN`, 0 otherwise.
    pub ret: i64,
    /// One of the `KIND_*` constants.
    pub kind: u32,
    /// Process id (the kernel's tgid).
    pub pid: u32,
    /// Thread id (the kernel's pid).
    pub tid: u32,
    /// Real user id of the task.
    pub uid: u32,
    /// NUL-padded task command name.
    pub comm: [u8; COMM_LEN],
    /// Number of meaningful bytes in `path` (0 when the kind carries no path).
    pub path_len: u32,
    /// Explicit padding so `path` starts at an 8-byte boundary on all targets.
    pub _pad: u32,
    /// Path bytes; only the first `path_len` are meaningful.
    pub path: [u8; PATH_LEN],
}

impl RawEvent {
    /// An all-zero record.
    pub const fn zeroed() -> Self {
        Self {
            ts_ns: 0,
            ret: 0,
            kind: 0,
            pid: 0,
            tid: 0,
            uid: 0,
            comm: [0; COMM_LEN],
            path_len: 0,
            _pad: 0,
            path: [0; PATH_LEN],
        }
    }
}

/// Size of one record in bytes.
pub const RAW_EVENT_SIZE: usize = size_of::<RawEvent>();

/// Byte offset of [`RawEvent::ts_ns`].
pub const OFF_TS_NS: usize = offset_of!(RawEvent, ts_ns);
/// Byte offset of [`RawEvent::ret`].
pub const OFF_RET: usize = offset_of!(RawEvent, ret);
/// Byte offset of [`RawEvent::kind`].
pub const OFF_KIND: usize = offset_of!(RawEvent, kind);
/// Byte offset of [`RawEvent::pid`].
pub const OFF_PID: usize = offset_of!(RawEvent, pid);
/// Byte offset of [`RawEvent::tid`].
pub const OFF_TID: usize = offset_of!(RawEvent, tid);
/// Byte offset of [`RawEvent::uid`].
pub const OFF_UID: usize = offset_of!(RawEvent, uid);
/// Byte offset of [`RawEvent::comm`].
pub const OFF_COMM: usize = offset_of!(RawEvent, comm);
/// Byte offset of [`RawEvent::path_len`].
pub const OFF_PATH_LEN: usize = offset_of!(RawEvent, path_len);
/// Byte offset of [`RawEvent::path`].
pub const OFF_PATH: usize = offset_of!(RawEvent, path);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_stable() {
        assert_eq!(RAW_EVENT_SIZE, 312);
        assert_eq!(core::mem::align_of::<RawEvent>(), 8);
        assert_eq!(OFF_TS_NS, 0);
        assert_eq!(OFF_RET, 8);
        assert_eq!(OFF_KIND, 16);
        assert_eq!(OFF_PID, 20);
        assert_eq!(OFF_TID, 24);
        assert_eq!(OFF_UID, 28);
        assert_eq!(OFF_COMM, 32);
        assert_eq!(OFF_PATH_LEN, 48);
        assert_eq!(OFF_PATH, 56);
        assert_eq!(OFF_PATH + PATH_LEN, RAW_EVENT_SIZE);
    }

    #[test]
    fn syscall_abis_match_kernel_layouts() {
        // Argument registers are 8-byte aligned slots inside pt_regs and the
        // mode register is not an argument register.
        for abi in [ABI_X86_64, ABI_AARCH64] {
            for off in [abi.path_off, abi.flags_off, abi.mode_off] {
                assert_eq!(off % 8, 0);
            }
            assert_ne!(abi.path_off, abi.flags_off);
            assert_ne!(abi.mode_off, abi.path_off);
            assert_eq!(abi.mode_want & !abi.mode_mask, 0);
        }
        // arch/x86/entry/syscalls/syscall_64.tbl, include/uapi/asm-generic/unistd.h
        assert_eq!(ABI_X86_64.openat_nr, 257);
        assert_eq!(ABI_AARCH64.openat_nr, 56);
        // x86_64: si is slot 13, dx slot 12, cs slot 17 (after ip).
        assert_eq!(
            (
                ABI_X86_64.path_off,
                ABI_X86_64.flags_off,
                ABI_X86_64.mode_off
            ),
            (104, 96, 136)
        );
        // aarch64: x1, x2, pstate after regs[31], sp, pc.
        assert_eq!(
            (
                ABI_AARCH64.path_off,
                ABI_AARCH64.flags_off,
                ABI_AARCH64.mode_off
            ),
            (8, 16, 264)
        );
    }

    #[test]
    fn zeroed_is_all_zero() {
        let e = RawEvent::zeroed();
        assert_eq!(e.kind, 0);
        assert!(e.comm.iter().all(|b| *b == 0));
        assert!(e.path.iter().all(|b| *b == 0));
    }
}
