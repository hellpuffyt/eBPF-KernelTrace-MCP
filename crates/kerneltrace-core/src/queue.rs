//! A bounded multi-producer/single-consumer queue with an explicit overflow policy.
//!
//! This sits between the thread that drains the source (the BPF ring buffer in
//! live mode) and the thread that stores events. The source thread must never
//! block — a stalled reader lets the kernel ring buffer fill and the kernel
//! then drops events where we cannot count them — so `push` never waits.
//! When the queue is full the configured [`OverflowPolicy`] decides what to
//! drop, and every drop is counted.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What to do when the queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    /// Discard the incoming item (keeps the oldest history intact).
    DropNewest,
    /// Evict the oldest queued item to make room (keeps the freshest data).
    #[default]
    DropOldest,
}

/// Result of a [`BoundedQueue::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The item was queued without loss.
    Accepted,
    /// The queue was full and the incoming item was discarded.
    DroppedNewest,
    /// The queue was full; the oldest item was discarded and the new one queued.
    DisplacedOldest,
    /// The queue is closed; the item was discarded.
    Closed,
}

struct Inner<T> {
    items: VecDeque<T>,
    closed: bool,
}

/// Bounded queue; see the module docs.
pub struct BoundedQueue<T> {
    inner: Mutex<Inner<T>>,
    ready: Condvar,
    capacity: usize,
    policy: OverflowPolicy,
    dropped_newest: AtomicU64,
    dropped_oldest: AtomicU64,
}

impl<T> BoundedQueue<T> {
    /// Creates a queue holding at most `capacity` items (minimum 1).
    pub fn new(capacity: usize, policy: OverflowPolicy) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Mutex::new(Inner {
                items: VecDeque::with_capacity(capacity),
                closed: false,
            }),
            ready: Condvar::new(),
            capacity,
            policy,
            dropped_newest: AtomicU64::new(0),
            dropped_oldest: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner<T>> {
        // A panic while holding the lock cannot leave `Inner` logically broken
        // (every mutation is a single VecDeque call), so keep going.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Enqueues without ever blocking on a full queue.
    pub fn push(&self, item: T) -> PushOutcome {
        let mut inner = self.lock();
        if inner.closed {
            return PushOutcome::Closed;
        }
        let outcome = if inner.items.len() < self.capacity {
            inner.items.push_back(item);
            PushOutcome::Accepted
        } else {
            match self.policy {
                OverflowPolicy::DropNewest => {
                    self.dropped_newest.fetch_add(1, Ordering::Relaxed);
                    return PushOutcome::DroppedNewest;
                }
                OverflowPolicy::DropOldest => {
                    inner.items.pop_front();
                    inner.items.push_back(item);
                    self.dropped_oldest.fetch_add(1, Ordering::Relaxed);
                    PushOutcome::DisplacedOldest
                }
            }
        };
        drop(inner);
        self.ready.notify_one();
        outcome
    }

    /// Moves up to `max` items into `out`, waiting up to `timeout` for the first
    /// one. Returns the number moved; 0 means timeout or closed-and-empty.
    pub fn pop_batch(&self, out: &mut Vec<T>, max: usize, timeout: Duration) -> usize {
        let mut inner = self.lock();
        if inner.items.is_empty() && !inner.closed {
            inner = self
                .ready
                .wait_timeout_while(inner, timeout, |i| i.items.is_empty() && !i.closed)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let n = inner.items.len().min(max);
        out.extend(inner.items.drain(..n));
        n
    }

    /// Stops accepting items and wakes any waiting consumer. Items already
    /// queued can still be popped.
    pub fn close(&self) {
        self.lock().closed = true;
        self.ready.notify_all();
    }

    /// True once closed and fully drained.
    pub fn is_finished(&self) -> bool {
        let inner = self.lock();
        inner.closed && inner.items.is_empty()
    }

    /// Current number of queued items.
    pub fn len(&self) -> usize {
        self.lock().items.len()
    }

    /// True when nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum number of queued items.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Items discarded on arrival because the queue was full.
    pub fn dropped_newest(&self) -> u64 {
        self.dropped_newest.load(Ordering::Relaxed)
    }

    /// Queued items evicted to make room for newer ones.
    pub fn dropped_oldest(&self) -> u64 {
        self.dropped_oldest.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn drop_newest_keeps_oldest() {
        let q = BoundedQueue::new(2, OverflowPolicy::DropNewest);
        assert_eq!(q.push(1), PushOutcome::Accepted);
        assert_eq!(q.push(2), PushOutcome::Accepted);
        assert_eq!(q.push(3), PushOutcome::DroppedNewest);
        let mut out = Vec::new();
        q.pop_batch(&mut out, 10, Duration::ZERO);
        assert_eq!(out, [1, 2]);
        assert_eq!(q.dropped_newest(), 1);
        assert_eq!(q.dropped_oldest(), 0);
    }

    #[test]
    fn drop_oldest_keeps_newest() {
        let q = BoundedQueue::new(2, OverflowPolicy::DropOldest);
        for i in 1..=5 {
            q.push(i);
        }
        let mut out = Vec::new();
        q.pop_batch(&mut out, 10, Duration::ZERO);
        assert_eq!(out, [4, 5]);
        assert_eq!(q.dropped_oldest(), 3);
    }

    #[test]
    fn close_rejects_pushes_but_allows_draining() {
        let q = BoundedQueue::new(4, OverflowPolicy::DropOldest);
        q.push(1);
        q.close();
        assert_eq!(q.push(2), PushOutcome::Closed);
        assert!(!q.is_finished());
        let mut out = Vec::new();
        assert_eq!(q.pop_batch(&mut out, 10, Duration::from_secs(5)), 1);
        assert!(q.is_finished());
        // Closed and empty: returns immediately instead of waiting 5 s.
        assert_eq!(q.pop_batch(&mut out, 10, Duration::from_secs(5)), 0);
    }

    #[test]
    fn pop_respects_batch_size_and_timeout() {
        let q: BoundedQueue<u32> = BoundedQueue::new(8, OverflowPolicy::DropOldest);
        let mut out = Vec::new();
        assert_eq!(q.pop_batch(&mut out, 4, Duration::from_millis(10)), 0);
        for i in 0..6 {
            q.push(i);
        }
        assert_eq!(q.pop_batch(&mut out, 4, Duration::ZERO), 4);
        assert_eq!(q.len(), 2);
    }

    // Stress: several producers overrun a small queue while one consumer
    // drains it. Every item is either delivered or counted as dropped.
    #[test]
    fn conserves_items_under_contention() {
        for policy in [OverflowPolicy::DropNewest, OverflowPolicy::DropOldest] {
            let q = Arc::new(BoundedQueue::new(64, policy));
            let producers: Vec<_> = (0..4)
                .map(|p| {
                    let q = Arc::clone(&q);
                    thread::spawn(move || {
                        for i in 0..50_000u64 {
                            q.push(p * 1_000_000 + i);
                        }
                    })
                })
                .collect();
            let consumer = {
                let q = Arc::clone(&q);
                thread::spawn(move || {
                    let mut got = 0u64;
                    let mut buf = Vec::new();
                    loop {
                        buf.clear();
                        got += q.pop_batch(&mut buf, 32, Duration::from_millis(5)) as u64;
                        if q.is_finished() {
                            return got;
                        }
                    }
                })
            };
            for p in producers {
                p.join().expect("producer");
            }
            q.close();
            let got = consumer.join().expect("consumer");
            let dropped = q.dropped_newest() + q.dropped_oldest();
            assert_eq!(got + dropped, 200_000, "policy {policy:?}");
        }
    }
}
