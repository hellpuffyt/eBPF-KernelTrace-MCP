//! Query-time event filters.

use serde::Deserialize;

use crate::event::{Event, EventKind};

/// Selects events. Every populated field must match; empty lists match anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Filter {
    /// Keep only these process ids.
    pub pids: Vec<u32>,
    /// Keep only these command names (exact match).
    pub comms: Vec<String>,
    /// Keep only these kinds.
    pub kinds: Vec<EventKind>,
    /// Keep only events whose path starts with this prefix. Events without a
    /// path never match when this is set.
    pub path_prefix: Option<String>,
    /// Keep only events with `seq` strictly greater than this (for paging).
    pub after_seq: Option<u64>,
    /// Keep only events received at or after this many ns since engine start.
    pub min_received_ns: Option<u64>,
}

impl Filter {
    /// True when `event` passes every populated criterion.
    pub fn matches(&self, event: &Event) -> bool {
        (self.pids.is_empty() || self.pids.contains(&event.pid))
            && (self.comms.is_empty() || self.comms.iter().any(|c| c == &event.comm))
            && (self.kinds.is_empty() || self.kinds.contains(&event.kind))
            && self
                .path_prefix
                .as_deref()
                .is_none_or(|prefix| event.path.as_deref().is_some_and(|p| p.starts_with(prefix)))
            && self.after_seq.is_none_or(|s| event.seq > s)
            && self.min_received_ns.is_none_or(|t| event.received_ns >= t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64, kind: EventKind, pid: u32, comm: &str, path: Option<&str>) -> Event {
        Event {
            seq,
            ts_ns: 0,
            received_ns: seq * 10,
            kind,
            pid,
            tid: pid,
            uid: 0,
            comm: comm.into(),
            path: path.map(Into::into),
            ret: 0,
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        assert!(Filter::default().matches(&ev(1, EventKind::Exit, 1, "a", None)));
    }

    #[test]
    fn criteria_combine_with_and() {
        let f = Filter {
            pids: vec![7],
            kinds: vec![EventKind::Open],
            path_prefix: Some("/etc".into()),
            ..Filter::default()
        };
        assert!(f.matches(&ev(1, EventKind::Open, 7, "cat", Some("/etc/hosts"))));
        assert!(!f.matches(&ev(1, EventKind::Open, 8, "cat", Some("/etc/hosts"))));
        assert!(!f.matches(&ev(1, EventKind::Exec, 7, "cat", Some("/etc/hosts"))));
        assert!(!f.matches(&ev(1, EventKind::Open, 7, "cat", Some("/var/x"))));
        assert!(!f.matches(&ev(1, EventKind::Open, 7, "cat", None)));
    }

    #[test]
    fn paging_and_time_bounds() {
        let f = Filter {
            after_seq: Some(5),
            min_received_ns: Some(70),
            ..Filter::default()
        };
        assert!(!f.matches(&ev(5, EventKind::Exit, 1, "a", None)));
        assert!(!f.matches(&ev(6, EventKind::Exit, 1, "a", None)));
        assert!(f.matches(&ev(7, EventKind::Exit, 1, "a", None)));
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = serde_json::from_str::<Filter>(r#"{"pid": 1}"#);
        assert!(err.is_err());
    }
}
