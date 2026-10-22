//! In-memory event store with count- and age-based retention.

use std::collections::VecDeque;

use crate::event::Event;
use crate::filter::Filter;

/// Retention limits for an [`EventStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Maximum events kept; the oldest are evicted first.
    pub max_events: usize,
    /// Maximum age in ns, measured on `received_ns`. `None` keeps events until
    /// evicted by count.
    pub max_age_ns: Option<u64>,
}

/// Result of a [`EventStore::query`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    /// Matching events in ascending `seq` order.
    pub events: Vec<Event>,
    /// Total events that matched before `limit` was applied.
    pub matched: usize,
    /// True when `matched > events.len()`.
    pub truncated: bool,
}

/// Ordered, bounded event history.
#[derive(Debug)]
pub struct EventStore {
    events: VecDeque<Event>,
    retention: Retention,
    next_seq: u64,
    evicted_capacity: u64,
    evicted_age: u64,
}

impl EventStore {
    /// Creates an empty store. `max_events` below 1 is raised to 1.
    pub fn new(retention: Retention) -> Self {
        let retention = Retention {
            max_events: retention.max_events.max(1),
            ..retention
        };
        Self {
            events: VecDeque::new(),
            retention,
            next_seq: 1,
            evicted_capacity: 0,
            evicted_age: 0,
        }
    }

    /// Stores an event, assigning its `seq`. Returns the assigned sequence number.
    pub fn insert(&mut self, mut event: Event) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        event.seq = seq;
        if self.events.len() >= self.retention.max_events {
            self.events.pop_front();
            self.evicted_capacity += 1;
        }
        self.events.push_back(event);
        seq
    }

    /// Evicts events older than the age limit relative to `now_ns`.
    pub fn prune(&mut self, now_ns: u64) {
        let Some(max_age) = self.retention.max_age_ns else {
            return;
        };
        let cutoff = now_ns.saturating_sub(max_age);
        while self.events.front().is_some_and(|e| e.received_ns < cutoff) {
            self.events.pop_front();
            self.evicted_age += 1;
        }
    }

    /// Returns matching events.
    ///
    /// Without `filter.after_seq` the *most recent* `limit` matches are
    /// returned (what an operator usually wants). With `after_seq` the
    /// *earliest* `limit` matches after that sequence number are returned, so
    /// callers can page forward without gaps.
    pub fn query(&self, filter: &Filter, limit: usize) -> QueryResult {
        let matching: Vec<&Event> = self.events.iter().filter(|e| filter.matches(e)).collect();
        let matched = matching.len();
        let take = limit.min(matched);
        let slice = if filter.after_seq.is_some() {
            &matching[..take]
        } else {
            &matching[matched - take..]
        };
        QueryResult {
            events: slice.iter().map(|e| (*e).clone()).collect(),
            matched,
            truncated: matched > take,
        }
    }

    /// Iterates over stored events matching `filter`, oldest first.
    pub fn iter_matching<'a>(&'a self, filter: &'a Filter) -> impl Iterator<Item = &'a Event> + 'a {
        self.events.iter().filter(move |e| filter.matches(e))
    }

    /// Number of stored events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Events evicted because `max_events` was reached.
    pub fn evicted_capacity(&self) -> u64 {
        self.evicted_capacity
    }

    /// Events evicted because they exceeded `max_age_ns`.
    pub fn evicted_age(&self) -> u64 {
        self.evicted_age
    }

    /// Highest sequence number assigned so far (0 if none).
    pub fn last_seq(&self) -> u64 {
        self.next_seq - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    fn ev(received_ns: u64, pid: u32) -> Event {
        Event {
            seq: 0,
            ts_ns: received_ns,
            received_ns,
            kind: EventKind::Exit,
            pid,
            tid: pid,
            uid: 0,
            comm: "t".into(),
            path: None,
            ret: 0,
        }
    }

    #[test]
    fn evicts_by_count() {
        let mut s = EventStore::new(Retention {
            max_events: 3,
            max_age_ns: None,
        });
        for i in 0..5 {
            s.insert(ev(i, i as u32));
        }
        assert_eq!(s.len(), 3);
        assert_eq!(s.evicted_capacity(), 2);
        let all = s.query(&Filter::default(), 10);
        assert_eq!(
            all.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [3, 4, 5]
        );
    }

    #[test]
    fn evicts_by_age() {
        let mut s = EventStore::new(Retention {
            max_events: 100,
            max_age_ns: Some(50),
        });
        for t in [0, 40, 60, 90] {
            s.insert(ev(t, 1));
        }
        s.prune(100);
        // cutoff = 50: events received at 0 and 40 go.
        assert_eq!(s.len(), 2);
        assert_eq!(s.evicted_age(), 2);
        s.prune(10); // now earlier than cutoff math: no underflow, nothing evicted
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn query_returns_most_recent_or_pages_forward() {
        let mut s = EventStore::new(Retention {
            max_events: 100,
            max_age_ns: None,
        });
        for i in 0..10 {
            s.insert(ev(i, 1));
        }
        let recent = s.query(&Filter::default(), 3);
        assert_eq!(
            recent.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [8, 9, 10]
        );
        assert_eq!((recent.matched, recent.truncated), (10, true));

        let page = s.query(
            &Filter {
                after_seq: Some(2),
                ..Filter::default()
            },
            3,
        );
        assert_eq!(
            page.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [3, 4, 5]
        );

        let none = s.query(&Filter::default(), 0);
        assert!(none.events.is_empty());
        assert!(none.truncated);
    }
}
