//! Safe decoding of ring-buffer records.
//!
//! Records are read field by field from a byte slice. Nothing is transmuted, so
//! a short, oversized or corrupted record yields a [`DecodeError`] rather than
//! undefined behaviour. Decoding copies the record into an owned [`Event`];
//! after that the ring-buffer slot can be released.

use kerneltrace_common::{
    COMM_LEN, OFF_COMM, OFF_KIND, OFF_PATH, OFF_PATH_LEN, OFF_PID, OFF_RET, OFF_TID, OFF_TS_NS,
    OFF_UID, PATH_LEN, RAW_EVENT_SIZE, RawEvent,
};

use crate::error::DecodeError;
use crate::event::{Event, EventKind};

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], DecodeError> {
    bytes
        .get(offset..offset + N)
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or(DecodeError::Length {
            actual: bytes.len(),
            expected: RAW_EVENT_SIZE,
        })
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, DecodeError> {
    field::<4>(bytes, offset).map(u32::from_ne_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, DecodeError> {
    field::<8>(bytes, offset).map(u64::from_ne_bytes)
}

/// Converts NUL-terminated kernel bytes to a printable string. Invalid UTF-8 is
/// replaced and control characters become `?`, so the result is safe to log.
fn printable(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Decodes one record. `seq` and `received_ns` are left at 0 for the caller to set.
pub fn decode(bytes: &[u8]) -> Result<Event, DecodeError> {
    if bytes.len() != RAW_EVENT_SIZE {
        return Err(DecodeError::Length {
            actual: bytes.len(),
            expected: RAW_EVENT_SIZE,
        });
    }
    let raw_kind = u32_at(bytes, OFF_KIND)?;
    let kind = EventKind::from_wire(raw_kind).ok_or(DecodeError::UnknownKind(raw_kind))?;
    let path_len = u32_at(bytes, OFF_PATH_LEN)?;
    if path_len as usize > PATH_LEN {
        return Err(DecodeError::PathLen(path_len));
    }
    let comm = field::<COMM_LEN>(bytes, OFF_COMM)?;
    let path = if path_len == 0 {
        None
    } else {
        let start = OFF_PATH;
        let raw = bytes
            .get(start..start + path_len as usize)
            .ok_or(DecodeError::PathLen(path_len))?;
        Some(printable(raw))
    };
    Ok(Event {
        seq: 0,
        ts_ns: u64_at(bytes, OFF_TS_NS)?,
        received_ns: 0,
        kind,
        pid: u32_at(bytes, OFF_PID)?,
        tid: u32_at(bytes, OFF_TID)?,
        uid: u32_at(bytes, OFF_UID)?,
        comm: printable(&comm),
        path,
        ret: field::<8>(bytes, OFF_RET).map(i64::from_ne_bytes)?,
    })
}

/// Serialises a [`RawEvent`] into the exact bytes the probe would write.
/// Used by the synthetic source and by tests.
pub fn encode(raw: &RawEvent) -> [u8; RAW_EVENT_SIZE] {
    let mut out = [0u8; RAW_EVENT_SIZE];
    out[OFF_TS_NS..OFF_TS_NS + 8].copy_from_slice(&raw.ts_ns.to_ne_bytes());
    out[OFF_RET..OFF_RET + 8].copy_from_slice(&raw.ret.to_ne_bytes());
    out[OFF_KIND..OFF_KIND + 4].copy_from_slice(&raw.kind.to_ne_bytes());
    out[OFF_PID..OFF_PID + 4].copy_from_slice(&raw.pid.to_ne_bytes());
    out[OFF_TID..OFF_TID + 4].copy_from_slice(&raw.tid.to_ne_bytes());
    out[OFF_UID..OFF_UID + 4].copy_from_slice(&raw.uid.to_ne_bytes());
    out[OFF_COMM..OFF_COMM + COMM_LEN].copy_from_slice(&raw.comm);
    out[OFF_PATH_LEN..OFF_PATH_LEN + 4].copy_from_slice(&raw.path_len.to_ne_bytes());
    out[OFF_PATH..OFF_PATH + PATH_LEN].copy_from_slice(&raw.path);
    out
}

/// Builds a [`RawEvent`] from friendly values, truncating `comm` to 15 bytes
/// and `path` to [`PATH_LEN`] bytes the way the kernel would.
pub fn raw_event(
    kind: EventKind,
    ts_ns: u64,
    pid: u32,
    tid: u32,
    uid: u32,
    comm: &str,
    path: Option<&str>,
) -> RawEvent {
    let mut raw = RawEvent::zeroed();
    raw.kind = kind.to_wire();
    raw.ts_ns = ts_ns;
    raw.pid = pid;
    raw.tid = tid;
    raw.uid = uid;
    let c = comm.as_bytes();
    let n = c.len().min(COMM_LEN - 1);
    raw.comm[..n].copy_from_slice(&c[..n]);
    if let Some(p) = path {
        let p = p.as_bytes();
        let n = p.len().min(PATH_LEN);
        raw.path[..n].copy_from_slice(&p[..n]);
        raw.path_len = n as u32;
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trip() {
        let raw = raw_event(EventKind::Open, 99, 10, 11, 1000, "cat", Some("/etc/hosts"));
        let ev = decode(&encode(&raw)).expect("decodes");
        assert_eq!(ev.kind, EventKind::Open);
        assert_eq!((ev.ts_ns, ev.pid, ev.tid, ev.uid), (99, 10, 11, 1000));
        assert_eq!(ev.comm, "cat");
        assert_eq!(ev.path.as_deref(), Some("/etc/hosts"));
    }

    #[test]
    fn comm_is_truncated_to_kernel_length() {
        let raw = raw_event(
            EventKind::Exec,
            0,
            1,
            1,
            0,
            "a-very-long-command-name",
            None,
        );
        let ev = decode(&encode(&raw)).expect("decodes");
        assert_eq!(ev.comm, "a-very-long-com");
        assert_eq!(ev.path, None);
    }

    #[test]
    fn rejects_wrong_length() {
        let bytes = encode(&raw_event(EventKind::Exit, 0, 1, 1, 0, "x", None));
        assert_eq!(
            decode(&bytes[..RAW_EVENT_SIZE - 1]),
            Err(DecodeError::Length {
                actual: RAW_EVENT_SIZE - 1,
                expected: RAW_EVENT_SIZE
            })
        );
        let mut long = bytes.to_vec();
        long.push(0);
        assert!(matches!(decode(&long), Err(DecodeError::Length { .. })));
        assert!(matches!(decode(&[]), Err(DecodeError::Length { .. })));
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut raw = raw_event(EventKind::Exit, 0, 1, 1, 0, "x", None);
        raw.kind = 77;
        assert_eq!(decode(&encode(&raw)), Err(DecodeError::UnknownKind(77)));
    }

    #[test]
    fn rejects_oversized_path_len() {
        let mut raw = raw_event(EventKind::Open, 0, 1, 1, 0, "x", Some("/a"));
        raw.path_len = PATH_LEN as u32 + 1;
        assert_eq!(
            decode(&encode(&raw)),
            Err(DecodeError::PathLen(PATH_LEN as u32 + 1))
        );
    }

    #[test]
    fn control_characters_are_neutralised() {
        let raw = raw_event(
            EventKind::Open,
            0,
            1,
            1,
            0,
            "e\x1b[31m",
            Some("/tmp/\nfake\x07"),
        );
        let ev = decode(&encode(&raw)).expect("decodes");
        assert_eq!(ev.comm, "e?[31m");
        assert_eq!(ev.path.as_deref(), Some("/tmp/?fake?"));
    }

    proptest! {
        // Arbitrary bytes must never panic the decoder.
        #[test]
        fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = decode(&bytes);
        }

        // Any well-formed record of exactly the right size with a valid kind and
        // in-range path_len decodes.
        #[test]
        fn valid_records_decode(
            kind in 1u32..=3, pid: u32, tid: u32, uid: u32, ts: u64,
            path_len in 0u32..=PATH_LEN as u32,
            fill in any::<u8>(),
        ) {
            let mut raw = RawEvent::zeroed();
            raw.kind = kind; raw.pid = pid; raw.tid = tid; raw.uid = uid; raw.ts_ns = ts;
            raw.path_len = path_len;
            raw.path = [fill; PATH_LEN];
            raw.comm = [fill; COMM_LEN];
            let ev = decode(&encode(&raw)).expect("valid record");
            prop_assert_eq!(ev.pid, pid);
            prop_assert_eq!(ev.ts_ns, ts);
            prop_assert_eq!(ev.path.is_some(), path_len > 0);
            prop_assert!(ev.comm.chars().count() <= COMM_LEN);
        }
    }
}
