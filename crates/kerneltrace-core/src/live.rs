//! Live kernel events from the eBPF probe (Linux only).
//!
//! **Status: experimental, unverified on real hardware by this project's
//! maintainers at the time of writing.** The code compiles for Linux in CI;
//! running it requires a kernel ≥ 5.8, tracefs, and CAP_BPF+CAP_PERFMON (or
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
//! the probe drops the event; that loss happens in the kernel and is **not**
//! reflected in the userspace counters (see Limitations).

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

/// Name of the probe global that enables path capture (u8, 0 or 1).
pub const INCLUDE_PATHS_GLOBAL: &str = "INCLUDE_PATHS";

/// Loads the probe object, attaches the programs for enabled kinds and
/// returns a [`Source`] reading its ring buffer.
pub fn open(ebpf_object: Option<&str>, sources: &Sources) -> Result<Box<dyn Source>, SourceError> {
    imp::open(ebpf_object, sources)
}

#[cfg(all(target_os = "linux", feature = "live"))]
mod imp {
    use aya::maps::{MapData, RingBuf};
    use aya::programs::TracePoint;
    use aya::{Ebpf, EbpfLoader};

    use super::{INCLUDE_PATHS_GLOBAL, PROGRAMS, RING_MAP};
    use crate::config::Sources;
    use crate::error::SourceError;
    use crate::event::EventKind;
    use crate::source::Source;

    struct LiveSource {
        // Keeps programs and links alive; dropping it detaches everything.
        _ebpf: Ebpf,
        ring: RingBuf<MapData>,
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
    }

    pub(super) fn open(
        ebpf_object: Option<&str>,
        sources: &Sources,
    ) -> Result<Box<dyn Source>, SourceError> {
        let report = crate::capability::detect();
        if !report.live_supported {
            return Err(SourceError::Unsupported(report.reasons.join("; ")));
        }
        let path = ebpf_object.ok_or_else(|| {
            SourceError::Start(
                "live mode needs [live] ebpf_object = \"<path to compiled probe>\"".into(),
            )
        })?;
        let include_paths = u8::from(sources.include_paths);
        let mut ebpf = EbpfLoader::new()
            .override_global(INCLUDE_PATHS_GLOBAL, &include_paths, true)
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
        Ok(Box::new(LiveSource { _ebpf: ebpf, ring }))
    }
}

#[cfg(not(all(target_os = "linux", feature = "live")))]
mod imp {
    use crate::config::Sources;
    use crate::error::SourceError;
    use crate::source::Source;

    pub(super) fn open(
        _ebpf_object: Option<&str>,
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
        match open(None, &Sources::default()) {
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
