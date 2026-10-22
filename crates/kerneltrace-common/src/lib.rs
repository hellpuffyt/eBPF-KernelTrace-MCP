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
/// A task entered `openat(2)` (`syscalls:sys_enter_openat`).
pub const KIND_OPEN: u32 = 3;

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
    fn zeroed_is_all_zero() {
        let e = RawEvent::zeroed();
        assert_eq!(e.kind, 0);
        assert!(e.comm.iter().all(|b| *b == 0));
        assert!(e.path.iter().all(|b| *b == 0));
    }
}
