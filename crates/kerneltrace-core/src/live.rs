//! Live kernel events from the eBPF probe (Linux only).
//!
//! **Status: experimental.** Integration-tested by
//! `kerneltrace-mcp/tests/live_kernel.rs` (kernels listed in
//! `docs/KERNEL_COMPAT.md`); running it requires a kernel ≥ 5.8, tracefs, and CAP_BPF+CAP_PERFMON (or
//! root). See `docs/KERNEL_COMPAT.md`.
//!
//! # How data moves
//!
//! The probe reserves a [`RawEvent`](kerneltrace_common::RawEvent)-sized slot
//! in a `BPF_MAP_TYPE_RINGBUF` map, fills it in place and submits it. The ring
//! buffer's data pages are memory-mapped into this process, so reading a
//! record does not need a syscall; `RingBuf::next` hands out a borrowed view
//! of the slot. [`decode`](crate::decode::decode) then **copies** the fields
//! into an owned [`Event`](crate::event::Event) and the slot is released when
//! the view is dropped. So the kernel → userspace hop avoids a copy, but the
//! pipeline as a whole is not zero-copy.
//!
//! When the ring buffer is full the kernel's `bpf_ringbuf_reserve` fails and
//! the probe drops the event. The probe counts that loss in its per-CPU
//! `STATS` map, which this source reads and the engine reports as
//! `stats.kernel.ring_full_drops`.

use crate::config::LiveConfig;
use crate::config::Sources;
use crate::error::SourceError;
use crate::source::Source;

/// Where a probe program attaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// A perf-attached tracepoint program on `category:name`.
    TracePoint(&'static str, &'static str),
    /// A raw tracepoint program (`BPF_PROG_TYPE_RAW_TRACEPOINT`) on `name`.
    ///
    /// `kt_open` uses the raw `sys_enter` tracepoint instead of
    /// `syscalls:sys_enter_openat`. A perf-attached program only runs where
    /// the kernel finds a perf event for the event on the current CPU, and
    /// aya opens the one perf event for a tracepoint attachment on CPU 0.
    /// Some kernels with the 7.0.y backport of "tracing: perf: Fix stale head
    /// for perf syscall tracing" (for example 7.0.0-1017-azure) apply that
    /// rule to `sys_enter_*` events whose syscall reads a user string, so
    /// `openat` calls on every CPU but CPU 0 never reached the probe. Raw
    /// tracepoints do not go through perf.
    RawTracePoint(&'static str),
}

/// Program names in the probe object, with the hook each attaches to.
pub const PROGRAMS: [(&str, Hook); 3] = [
    ("kt_exec", Hook::TracePoint("sched", "sched_process_exec")),
    ("kt_exit", Hook::TracePoint("sched", "sched_process_exit")),
    ("kt_open", Hook::RawTracePoint("sys_enter")),
];

/// Names of the probe globals that carry the host's [`SyscallAbi`] to `kt_open`.
///
/// [`SyscallAbi`]: kerneltrace_common::SyscallAbi
pub const OPEN_ABI_GLOBALS: [&str; 6] = [
    "OPEN_SYSCALL_NR",
    "OPEN_PATH_OFF",
    "OPEN_FLAGS_OFF",
    "OPEN_MODE_OFF",
    "OPEN_MODE_MASK",
    "OPEN_MODE_WANT",
];

/// The `openat` ABI of the architecture this binary was built for, or `None`
/// where `kt_open` has no register layout (open events are then refused).
pub fn host_syscall_abi() -> Option<kerneltrace_common::SyscallAbi> {
    if cfg!(target_arch = "x86_64") {
        Some(kerneltrace_common::ABI_X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(kerneltrace_common::ABI_AARCH64)
    } else {
        None
    }
}

/// Name of the ring-buffer map in the probe object.
pub const RING_MAP: &str = "EVENTS";

/// Name of the per-CPU counter map in the probe object (`kerneltrace_common::STAT_*`).
pub const STATS_MAP: &str = "STATS";

/// Name of the probe global that enables path capture (u8, 0 or 1).
pub const INCLUDE_PATHS_GLOBAL: &str = "INCLUDE_PATHS";

/// Loads the probe object, attaches the programs for enabled kinds and
/// returns a [`Source`] reading its ring buffer.
pub fn open(live: &LiveConfig, sources: &Sources) -> Result<Box<dyn Source>, SourceError> {
    imp::open(live, sources)
}

#[cfg(all(target_os = "linux", feature = "live"))]
mod imp {
    use aya::maps::{MapData, PerCpuArray, RingBuf};
    use aya::programs::{RawTracePoint, TracePoint};
    use aya::{Ebpf, EbpfLoader};
    use kerneltrace_common::{
        STAT_FIRED_EXEC, STAT_FIRED_EXIT, STAT_FIRED_OPEN, STAT_PATH_UNREADABLE, STAT_RING_FULL,
    };

    use super::{
        Hook, INCLUDE_PATHS_GLOBAL, OPEN_ABI_GLOBALS, PROGRAMS, RING_MAP, STATS_MAP,
        host_syscall_abi,
    };
    use crate::config::{LiveConfig, Sources};
    use crate::error::SourceError;
    use crate::event::EventKind;
    use crate::source::{KernelCounters, Source};

    struct LiveSource {
        // Keeps programs and links alive; dropping it detaches everything.
        _ebpf: Ebpf,
        ring: RingBuf<MapData>,
        stats: PerCpuArray<MapData, u64>,
    }

    impl LiveSource {
        fn counter(&self, slot: u32) -> Result<u64, SourceError> {
            let per_cpu = self
                .stats
                .get(&slot, 0)
                .map_err(|e| SourceError::Read(format!("{STATS_MAP}[{slot}]: {e}")))?;
            Ok(per_cpu.iter().fold(0u64, |a, v| a.wrapping_add(*v)))
        }
    }

    impl Source for LiveSource {
        fn name(&self) -> &'static str {
            "live"
        }

        fn poll(&mut self, max: usize, sink: &mut dyn FnMut(&[u8])) -> Result<usize, SourceError> {
            let mut n = 0;
            while n < max {
                let Some(item) = self.ring.next() else { break };
                sink(&item);
                n += 1;
            }
            Ok(n)
        }

        fn kernel_counters(&mut self) -> Result<Option<KernelCounters>, SourceError> {
            Ok(Some(KernelCounters {
                ring_full_drops: self.counter(STAT_RING_FULL)?,
                path_unreadable: self.counter(STAT_PATH_UNREADABLE)?,
                fired_exec: self.counter(STAT_FIRED_EXEC)?,
                fired_exit: self.counter(STAT_FIRED_EXIT)?,
                fired_open: self.counter(STAT_FIRED_OPEN)?,
            }))
        }
    }

    pub(super) fn open(
        live: &LiveConfig,
        sources: &Sources,
    ) -> Result<Box<dyn Source>, SourceError> {
        let report = crate::capability::detect();
        if !report.live_supported {
            return Err(SourceError::Unsupported(report.reasons.join("; ")));
        }
        let path = live.ebpf_object.as_deref().ok_or_else(|| {
            SourceError::Start(
                "live mode needs [live] ebpf_object = \"<path to compiled probe>\"".into(),
            )
        })?;
        let include_paths = u8::from(sources.include_paths);
        let abi = match host_syscall_abi() {
            Some(abi) => abi,
            None if sources.enabled(EventKind::Open) => {
                return Err(SourceError::Unsupported(
                    "open events need the x86_64 or aarch64 syscall register layout".into(),
                ));
            }
            // Never used: kt_open is not loaded.
            None => kerneltrace_common::ABI_X86_64,
        };
        let abi_values = [
            abi.openat_nr,
            abi.path_off,
            abi.flags_off,
            abi.mode_off,
            abi.mode_mask,
            abi.mode_want,
        ];
        let mut loader = EbpfLoader::new();
        loader
            .override_global(INCLUDE_PATHS_GLOBAL, &include_paths, true)
            .map_max_entries(RING_MAP, live.ring_buffer_bytes);
        for (name, value) in OPEN_ABI_GLOBALS.into_iter().zip(&abi_values) {
            loader.override_global(name, value, true);
        }
        let mut ebpf = loader
            .load_file(path)
            .map_err(|e| SourceError::Start(format!("loading {path}: {e}")))?;
        for (kind, (prog, hook)) in EventKind::ALL.into_iter().zip(PROGRAMS) {
            if !sources.enabled(kind) {
                continue;
            }
            let program = ebpf
                .program_mut(prog)
                .ok_or_else(|| SourceError::Start(format!("program {prog} not found in object")))?;
            let attached = match hook {
                Hook::TracePoint(category, tracepoint) => {
                    let program: &mut TracePoint = program
                        .try_into()
                        .map_err(|e| SourceError::Start(format!("{prog}: {e}")))?;
                    program
                        .load()
                        .map_err(|e| SourceError::Start(format!("loading {prog}: {e}")))?;
                    program.attach(category, tracepoint).map(drop)
                }
                Hook::RawTracePoint(tracepoint) => {
                    let program: &mut RawTracePoint = program
                        .try_into()
                        .map_err(|e| SourceError::Start(format!("{prog}: {e}")))?;
                    program
                        .load()
                        .map_err(|e| SourceError::Start(format!("loading {prog}: {e}")))?;
                    program.attach(tracepoint).map(drop)
                }
            };
            attached
                .map_err(|e| SourceError::Start(format!("attaching {prog} to {hook:?}: {e}")))?;
        }
        let map = ebpf
            .take_map(RING_MAP)
            .ok_or_else(|| SourceError::Start(format!("map {RING_MAP} not found in object")))?;
        let ring =
            RingBuf::try_from(map).map_err(|e| SourceError::Start(format!("{RING_MAP}: {e}")))?;
        let stats = ebpf.take_map(STATS_MAP).ok_or_else(|| {
            SourceError::Start(format!(
                "map {STATS_MAP} not found in object (probe built from an older version?)"
            ))
        })?;
        let stats = PerCpuArray::try_from(stats)
            .map_err(|e| SourceError::Start(format!("{STATS_MAP}: {e}")))?;
        Ok(Box::new(LiveSource {
            _ebpf: ebpf,
            ring,
            stats,
        }))
    }
}

#[cfg(not(all(target_os = "linux", feature = "live")))]
mod imp {
    use crate::config::{LiveConfig, Sources};
    use crate::error::SourceError;
    use crate::source::Source;

    pub(super) fn open(
        _live: &LiveConfig,
        _sources: &Sources,
    ) -> Result<Box<dyn Source>, SourceError> {
        Err(SourceError::Unsupported(
            crate::capability::detect().reasons.join("; "),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn live_is_refused_off_linux() {
        match open(&LiveConfig::default(), &Sources::default()) {
            Err(SourceError::Unsupported(msg)) => assert!(msg.contains("not Linux"), "{msg}"),
            Err(other) => panic!("unexpected error {other}"),
            Ok(_) => panic!("live mode must not start off Linux"),
        }
    }

    #[test]
    fn program_table_matches_kinds() {
        assert_eq!(PROGRAMS.len(), crate::event::EventKind::ALL.len());
    }

    #[test]
    fn open_uses_raw_sys_enter_not_the_perf_syscall_event() {
        // Regression guard: `syscalls:sys_enter_openat` via perf only runs the
        // program on CPU 0 on some 7.0.y kernels (see `Hook::RawTracePoint`).
        assert_eq!(PROGRAMS[2], ("kt_open", Hook::RawTracePoint("sys_enter")));
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert!(host_syscall_abi().is_some());
        }
    }
}
