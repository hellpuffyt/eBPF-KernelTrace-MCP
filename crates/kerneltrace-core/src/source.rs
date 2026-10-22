//! Event sources.

use crate::error::SourceError;

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
}
