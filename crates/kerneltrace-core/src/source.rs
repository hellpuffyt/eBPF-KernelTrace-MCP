//! Event sources.

use serde::Serialize;

use crate::error::SourceError;

/// Counters kept by the eBPF probe itself, summed over all CPUs. They cover
/// what userspace cannot see: events lost because the ring buffer was full.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct KernelCounters {
    /// Events lost in the kernel because the ring buffer was full.
    pub ring_full_drops: u64,
    /// Events emitted without a path because the path could not be read.
    pub path_unreadable: u64,
    /// Events `kt_exec` produced or tried to produce (including drops).
    pub fired_exec: u64,
    /// Events `kt_exit` produced or tried to produce (including drops).
    pub fired_exit: u64,
    /// Events `kt_open` produced or tried to produce (including drops).
    pub fired_open: u64,
}

impl KernelCounters {
    /// All events the probe attempted to emit.
    pub fn fired(&self) -> u64 {
        self.fired_exec + self.fired_exit + self.fired_open
    }
}

/// Something that produces raw ring-buffer records.
///
/// Records are lent to `sink` as byte slices, mirroring how a BPF ring buffer
/// hands out a view of a reserved slot that must be consumed before the slot is
/// released. The sink decodes (copies) what it needs.
pub trait Source: Send {
    /// Short name used in reports (`"synthetic"`, `"live"`).
    fn name(&self) -> &'static str;

    /// Delivers up to `max` records to `sink` and returns how many were
    /// delivered. `Ok(0)` means nothing is available right now.
    fn poll(&mut self, max: usize, sink: &mut dyn FnMut(&[u8])) -> Result<usize, SourceError>;

    /// Kernel-side counters, for sources that have them (the live probe).
    fn kernel_counters(&mut self) -> Result<Option<KernelCounters>, SourceError> {
        Ok(None)
    }
}
