//! kerneltrace eBPF probe: three tracepoint programs that write
//! [`RawEvent`] records into the `EVENTS` ring buffer.
//!
//! | Program   | Tracepoint                      | Path captured (if enabled)       |
//! |-----------|---------------------------------|----------------------------------|
//! | `kt_exec` | `sched:sched_process_exec`      | executed filename (kernel string)|
//! | `kt_exit` | `sched:sched_process_exit`      | none                             |
//! | `kt_open` | `syscalls:sys_enter_openat`     | `filename` argument (user string)|
//!
//! Tracepoint field offsets are the stable ones documented in each event's
//! `format` file (see docs/KERNEL_COMPAT.md); this probe does not use BTF/CO-RE.
//!
//! **Status: unverified on real hardware.** CI only proves that it builds.

#![no_std]
#![no_main]

use aya_ebpf::EbpfContext;
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use kerneltrace_common::{KIND_EXEC, KIND_EXIT, KIND_OPEN, PATH_LEN, RawEvent};

/// 256 KiB ring buffer shared by all programs (must be a power-of-two multiple of the page size).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Set to 1 by the loader only when the operator enabled `include_paths`.
/// When 0, no path bytes are ever read from the kernel or user memory.
#[unsafe(no_mangle)]
static INCLUDE_PATHS: u8 = 0;

// `sched_process_exec`: `__data_loc char[] filename` at offset 8.
const EXEC_FILENAME_LOC: usize = 8;
// `sys_enter_openat`: `const char *filename` at 24, `int flags` at 32 (8-byte slots).
const OPENAT_FILENAME: usize = 24;
const OPENAT_FLAGS: usize = 32;

fn include_paths() -> bool {
    // SAFETY: reading a plain static; volatile so the loader-patched value is
    // not constant-folded away.
    unsafe { core::ptr::read_volatile(&INCLUDE_PATHS) != 0 }
}

/// Reserves a slot, fills the common header, lets `fill_path` write the path
/// and returns nothing. If the ring buffer is full the event is dropped here
/// (the kernel-side loss is not counted; see Limitations).
fn emit(kind: u32, ret: i64, fill_path: impl FnOnce(&mut [u8; PATH_LEN]) -> u32) {
    let Some(mut entry) = EVENTS.reserve::<RawEvent>(0) else {
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
            return 0;
        };
        let offset = (loc & 0xffff) as usize;
        // SAFETY: __data_loc offsets are relative to the start of the record.
        let src = unsafe { (ctx.as_ptr() as *const u8).add(offset) };
        match unsafe { bpf_probe_read_kernel_str_bytes(src, path) } {
            Ok(s) => s.len() as u32,
            Err(_) => 0,
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

#[tracepoint]
pub fn kt_open(ctx: TracePointContext) -> u32 {
    // SAFETY: offsets taken from the tracepoint's format file.
    let flags = unsafe { ctx.read_at::<i64>(OPENAT_FLAGS) }.unwrap_or(0);
    emit(KIND_OPEN, flags, |path| {
        let Ok(ptr) = (unsafe { ctx.read_at::<u64>(OPENAT_FILENAME) }) else {
            return 0;
        };
        // SAFETY: the helper validates the user pointer and faults safely.
        match unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, path) } {
            Ok(s) => s.len() as u32,
            Err(_) => 0,
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
