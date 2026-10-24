//! Live kernel events from the eBPF probe (Linux only).
//!
//! **Status: experimental.** Integration-tested on two kernels
//! (7.0.0-1017-azure/x86_64, 6.8.0-117-generic/aarch64) by
//! `kerneltrace-mcp/tests/live_kernel.rs`; running it requires a kernel ≥ 5.8, tracefs, and CAP_BPF+CAP_PERFMON (or
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

/// Program names in the probe object, with the tracepoint each attaches to.
pub const PROGRAMS: [(&str, &str, &str); 3] = [
    ("kt_exec", "sched", "sched_process_exec"),
    ("kt_exit", "sched", "sched_process_exit"),
    ("kt_open", "syscalls", "sys_enter_openat"),
];

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
    use aya::programs::TracePoint;
    use aya::{Ebpf, EbpfLoader};
    use kerneltrace_common::{
        STAT_FIRED_EXEC, STAT_FIRED_EXIT, STAT_FIRED_OPEN, STAT_PATH_UNREADABLE, STAT_RING_FULL,
    };

    use super::{INCLUDE_PATHS_GLOBAL, PROGRAMS, RING_MAP, STATS_MAP};
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
        let mut ebpf = EbpfLoader::new()
            .override_global(INCLUDE_PATHS_GLOBAL, &include_paths, true)
            .map_max_entries(RING_MAP, live.ring_buffer_bytes)
            .load_file(path)
            .map_err(|e| SourceError::Start(format!("loading {path}: {e}")))?;
        for (kind, (prog, category, tracepoint)) in EventKind::ALL.into_iter().zip(PROGRAMS) {
            if !sources.enabled(kind) {
                continue;
            }
            let program: &mut TracePoint = ebpf
                .program_mut(prog)
                .ok_or_else(|| SourceError::Start(format!("program {prog} not found in object")))?
                .try_into()
                .map_err(|e| SourceError::Start(format!("{prog}: {e}")))?;
            program
                .load()
                .map_err(|e| SourceError::Start(format!("loading {prog}: {e}")))?;
            program.attach(category, tracepoint).map_err(|e| {
                SourceError::Start(format!("attaching {prog} to {category}:{tracepoint}: {e}"))
            })?;
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
}
