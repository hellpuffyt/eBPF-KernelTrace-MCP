//! Aggregate views over stored events.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::event::{Event, EventKind};

/// A count for one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Count<K> {
    /// The key (a command name or process id).
    pub key: K,
    /// Number of events.
    pub count: u64,
}

/// Aggregate statistics over a set of events.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    /// Events summarised.
    pub total: u64,
    /// Count per kind.
    pub by_kind: BTreeMap<EventKind, u64>,
    /// Most frequent command names, descending.
    pub top_comms: Vec<Count<String>>,
    /// Most frequent process ids, descending.
    pub top_pids: Vec<Count<u32>>,
    /// Lowest and highest `seq` covered, if any events.
    pub seq_range: Option<(u64, u64)>,
    /// Events per second over the span of `received_ns`, if it is non-zero.
    pub events_per_sec: Option<f64>,
}

fn top<K: Ord + Clone + std::hash::Hash>(counts: HashMap<K, u64>, n: usize) -> Vec<Count<K>> {
    let mut v: Vec<Count<K>> = counts
        .into_iter()
        .map(|(key, count)| Count { key, count })
        .collect();
    // Ties are broken by key so output is deterministic.
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    v.truncate(n);
    v
}

/// Summarises `events`, keeping the `top_n` most frequent comms and pids.
pub fn summarize<'a>(events: impl Iterator<Item = &'a Event>, top_n: usize) -> Summary {
    let mut total = 0u64;
    let mut by_kind = BTreeMap::new();
    let mut comms: HashMap<String, u64> = HashMap::new();
    let mut pids: HashMap<u32, u64> = HashMap::new();
    let mut seq_range: Option<(u64, u64)> = None;
    let mut time_range: Option<(u64, u64)> = None;
    for e in events {
        total += 1;
        *by_kind.entry(e.kind).or_insert(0) += 1;
        *comms.entry(e.comm.clone()).or_insert(0) += 1;
        *pids.entry(e.pid).or_insert(0) += 1;
        seq_range =
            Some(seq_range.map_or((e.seq, e.seq), |(lo, hi)| (lo.min(e.seq), hi.max(e.seq))));
        time_range = Some(
            time_range.map_or((e.received_ns, e.received_ns), |(lo, hi)| {
                (lo.min(e.received_ns), hi.max(e.received_ns))
            }),
        );
    }
    let events_per_sec = time_range.and_then(|(lo, hi)| {
        let span = hi - lo;
        (span > 0).then(|| total as f64 / (span as f64 / 1e9))
    });
    Summary {
        total,
        by_kind,
        top_comms: top(comms, top_n),
        top_pids: top(pids, top_n),
        seq_range,
        events_per_sec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64, kind: EventKind, pid: u32, comm: &str) -> Event {
        Event {
            seq,
            ts_ns: 0,
            received_ns: seq * 500_000_000,
            kind,
            pid,
            tid: pid,
            uid: 0,
            comm: comm.into(),
            path: None,
            ret: 0,
        }
    }

    #[test]
    fn counts_and_ranks() {
        let events = [
            ev(1, EventKind::Exec, 10, "bash"),
            ev(2, EventKind::Open, 10, "bash"),
            ev(3, EventKind::Open, 11, "cat"),
            ev(4, EventKind::Exit, 11, "cat"),
            ev(5, EventKind::Open, 10, "bash"),
        ];
        let s = summarize(events.iter(), 1);
        assert_eq!(s.total, 5);
        assert_eq!(s.by_kind[&EventKind::Open], 3);
        assert_eq!(
            s.top_comms,
            vec![Count {
                key: "bash".to_string(),
                count: 3
            }]
        );
        assert_eq!(s.top_pids, vec![Count { key: 10, count: 3 }]);
        assert_eq!(s.seq_range, Some((1, 5)));
        // 5 events over 2 seconds of received time.
        assert_eq!(s.events_per_sec, Some(2.5));
    }

    #[test]
    fn empty_input() {
        let s = summarize(std::iter::empty(), 5);
        assert_eq!(s.total, 0);
        assert_eq!(s.seq_range, None);
        assert_eq!(s.events_per_sec, None);
    }
}
