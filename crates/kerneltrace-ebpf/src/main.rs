//! kerneltrace eBPF probe: three tracepoint programs that write
//! [`RawEvent`] records into the `EVENTS` ring buffer.
//!
//! | Program   | Hook                                   | Path captured (if enabled)       |
//! |-----------|----------------------------------------|----------------------------------|
//! | `kt_exec` | tracepoint `sched:sched_process_exec`  | executed filename (kernel string)|
//! | `kt_exit` | tracepoint `sched:sched_process_exit`  | none                             |
//! | `kt_open` | raw tracepoint `sys_enter`, `openat`   | `filename` argument (user string)|
//!
//! Tracepoint field offsets are the stable ones documented in each event's
//! `format` file (see docs/KERNEL_COMPAT.md); this probe does not use BTF/CO-RE.
//!
//! `kt_open` is a raw tracepoint on `sys_enter` rather than a perf-attached
//! `syscalls:sys_enter_openat` program: some kernels (the 7.0.y backport of
//! "tracing: perf: Fix stale head for perf syscall tracing", e.g.
//! 7.0.0-1017-azure) skip BPF programs on `sys_enter_*` events whose syscall
//! reads user memory unless a perf event exists on the *current* CPU, and a
//! tracepoint attachment has a perf event on CPU 0 only. Opens on every other
//! CPU were then never seen. The raw tracepoint does not go through that path.
//!
//! **Status: experimental.** See docs/KERNEL_COMPAT.md for the kernels the
//! live-kernel test has passed on.

#![no_std]
#![no_main]

use aya_ebpf::EbpfContext;
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
};
use aya_ebpf::macros::{map, raw_tracepoint, tracepoint};
use aya_ebpf::maps::{PerCpuArray, RingBuf};
use aya_ebpf::programs::{RawTracePointContext, TracePointContext};
use kerneltrace_common::{
    KIND_EXEC, KIND_EXIT, KIND_OPEN, PATH_LEN, RawEvent, STAT_FIRED_EXEC, STAT_FIRED_EXIT,
    STAT_FIRED_OPEN, STAT_PATH_UNREADABLE, STAT_RING_FULL, STAT_SLOTS,
};

/// 256 KiB ring buffer shared by all programs (must be a power-of-two multiple of the page size).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU counters (see `kerneltrace_common::STAT_*`); per-CPU so the
/// programs never contend or need atomics. Userspace sums the CPUs.
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_SLOTS, 0);

/// Set to 1 by the loader only when the operator enabled `include_paths`.
/// When 0, no path bytes are ever read from the kernel or user memory.
#[unsafe(no_mangle)]
static INCLUDE_PATHS: u8 = 0;

// Host syscall ABI for `kt_open`, written by the loader from
// `kerneltrace_common::SyscallAbi` (see there). The defaults never match a
// syscall, so an object loaded without them reports no open events.
#[unsafe(no_mangle)]
static OPEN_SYSCALL_NR: u64 = u64::MAX;
#[unsafe(no_mangle)]
static OPEN_PATH_OFF: u64 = 0;
#[unsafe(no_mangle)]
static OPEN_FLAGS_OFF: u64 = 0;
#[unsafe(no_mangle)]
static OPEN_MODE_OFF: u64 = 0;
#[unsafe(no_mangle)]
static OPEN_MODE_MASK: u64 = 0;
#[unsafe(no_mangle)]
static OPEN_MODE_WANT: u64 = 1;

// `sched_process_exec`: `__data_loc char[] filename` at offset 8.
const EXEC_FILENAME_LOC: usize = 8;

fn include_paths() -> bool {
    // SAFETY: reading a plain static; volatile so the loader-patched value is
    // not constant-folded away.
    unsafe { core::ptr::read_volatile(&INCLUDE_PATHS) != 0 }
}

fn global(v: &u64) -> u64 {
    // SAFETY: as in `include_paths`.
    unsafe { core::ptr::read_volatile(v) }
}

/// Reads the `u64` at byte offset `off` of the kernel `struct pt_regs` at `regs`.
fn reg(regs: u64, off: u64) -> Option<u64> {
    // SAFETY: the helper validates the kernel pointer and faults safely.
    unsafe { bpf_probe_read_kernel((regs + off) as *const u64) }.ok()
}

fn bump(slot: u32) {
    if let Some(p) = STATS.get_ptr_mut(slot) {
        // SAFETY: the pointer is this CPU's slot of a per-CPU array, and a
        // tracepoint program is not preempted on its CPU while it runs.
        unsafe { *p += 1 };
    }
}

/// Reserves a slot, fills the common header, lets `fill_path` write the path
/// and submits it. If the ring buffer is full the event is dropped here and
/// counted in `STATS[STAT_RING_FULL]`.
fn emit(kind: u32, ret: i64, fill_path: impl FnOnce(&mut [u8; PATH_LEN]) -> u32) {
    bump(match kind {
        KIND_EXEC => STAT_FIRED_EXEC,
        KIND_EXIT => STAT_FIRED_EXIT,
        _ => STAT_FIRED_OPEN,
    });
    let Some(mut entry) = EVENTS.reserve::<RawEvent>(0) else {
        bump(STAT_RING_FULL);
        return;
    };
    let ev = entry.write(RawEvent::zeroed());
    let pid_tgid = bpf_get_current_pid_tgid();
    ev.ts_ns = unsafe { bpf_ktime_get_ns() };
    ev.ret = ret;
    ev.kind = kind;
    ev.pid = (pid_tgid >> 32) as u32;
    ev.tid = pid_tgid as u32;
    ev.uid = bpf_get_current_uid_gid() as u32;
    if let Ok(comm) = bpf_get_current_comm() {
        ev.comm = comm;
    }
    if include_paths() {
        ev.path_len = fill_path(&mut ev.path);
    }
    entry.submit(0);
}

#[tracepoint]
pub fn kt_exec(ctx: TracePointContext) -> u32 {
    emit(KIND_EXEC, 0, |path| {
        // SAFETY: offset taken from the tracepoint's format file.
        let Ok(loc) = (unsafe { ctx.read_at::<u32>(EXEC_FILENAME_LOC) }) else {
            bump(STAT_PATH_UNREADABLE);
            return 0;
        };
        let offset = (loc & 0xffff) as usize;
        // SAFETY: __data_loc offsets are relative to the start of the record.
        let src = unsafe { (ctx.as_ptr() as *const u8).add(offset) };
        match unsafe { bpf_probe_read_kernel_str_bytes(src, path) } {
            Ok(s) => s.len() as u32,
            Err(_) => {
                bump(STAT_PATH_UNREADABLE);
                0
            }
        }
    });
    0
}

#[tracepoint]
pub fn kt_exit(_ctx: TracePointContext) -> u32 {
    // The tracepoint fires for every exiting thread; report only the
    // thread-group leader so one process exit yields one event.
    let pid_tgid = bpf_get_current_pid_tgid();
    if (pid_tgid >> 32) as u32 != pid_tgid as u32 {
        return 0;
    }
    emit(KIND_EXIT, 0, |_| 0);
    0
}

/// Raw `sys_enter(struct pt_regs *regs, long id)`: runs for every syscall on
/// every CPU; everything but native `openat` returns before touching a map.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn kt_open(ctx: RawTracePointContext) -> i32 {
    let regs: u64 = ctx.arg(0);
    let id: u64 = ctx.arg(1);
    if id != global(&OPEN_SYSCALL_NR) {
        return 0;
    }
    match reg(regs, global(&OPEN_MODE_OFF)) {
        Some(mode) if mode & global(&OPEN_MODE_MASK) == global(&OPEN_MODE_WANT) => {}
        _ => return 0,
    }
    // The whole register, as the `sys_enter_openat` record's 8-byte slot held it.
    let flags = reg(regs, global(&OPEN_FLAGS_OFF)).map_or(0, |v| v as i64);
    emit(KIND_OPEN, flags, |path| {
        let Some(ptr) = reg(regs, global(&OPEN_PATH_OFF)) else {
            bump(STAT_PATH_UNREADABLE);
            return 0;
        };
        // SAFETY: the helper validates the user pointer and faults safely.
        match unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, path) } {
            Ok(s) => s.len() as u32,
            Err(_) => {
                bump(STAT_PATH_UNREADABLE);
                0
            }
        }
    });
    0
}

/// GPL-compatible license declaration; the tracing helpers used above are
/// GPL-only. This crate is available under MIT or GPL-2.0 (see Cargo.toml).
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
