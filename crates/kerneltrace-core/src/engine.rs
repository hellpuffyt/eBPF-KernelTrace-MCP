//! The running pipeline: source reader thread → bounded queue → store thread.
//!
//! ```text
//!  Source::poll ──bytes──▶ decode ─▶ kind gate ─▶ sampler ─▶ redactor ─▶ BoundedQueue ─▶ EventStore
//!   (reader thread: never blocks on the queue)                         (store thread)
//! ```
//!
//! Shutdown: [`Engine::shutdown`] (also run on drop) sets a stop flag, the
//! reader exits after its current poll, the queue is closed, the store thread
//! drains what is left, and both threads are joined.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::{Config, Sources};
use crate::decode::decode;
use crate::event::Event;
use crate::filter::Filter;
use crate::queue::{BoundedQueue, PushOutcome};
use crate::redact::Redactor;
use crate::sample::Sampler;
use crate::source::Source;
use crate::store::{EventStore, QueryResult, Retention};
use crate::summary::{Summary, summarize};

const POLL_BATCH: usize = 256;
const IDLE_SLEEP: Duration = Duration::from_millis(5);
const LATENCY_WINDOW: usize = 4096;

/// How the reader paces a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pacing {
    /// Poll as fast as records are available (live ring buffer, benchmarks).
    Unpaced,
    /// Deliver at most this many records per second of wall time (synthetic).
    PerSecond(u64),
}

#[derive(Default)]
struct Counters {
    records: AtomicU64,
    decode_errors: AtomicU64,
    disabled_kind: AtomicU64,
    sampled_out: AtomicU64,
    redacted: AtomicU64,
    source_errors: AtomicU64,
}

/// Fixed-size ring of recent queue latencies (ns), so percentiles are exact
/// over the last [`LATENCY_WINDOW`] events without unbounded memory.
struct LatencyWindow {
    samples: Vec<u64>,
    next: usize,
    max: u64,
}

impl LatencyWindow {
    fn record(&mut self, ns: u64) {
        if self.samples.len() < LATENCY_WINDOW {
            self.samples.push(ns);
        } else {
            self.samples[self.next] = ns;
        }
        self.next = (self.next + 1) % LATENCY_WINDOW;
        self.max = self.max.max(ns);
    }
}

struct Shared {
    start: Instant,
    queue: BoundedQueue<Event>,
    store: Mutex<EventStore>,
    latency: Mutex<LatencyWindow>,
    counters: Counters,
    stop: AtomicBool,
    last_error: Mutex<Option<String>>,
    source_name: &'static str,
}

impl Shared {
    fn now_ns(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn store(&self) -> MutexGuard<'_, EventStore> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Queue-latency percentiles in microseconds over the recent window.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LatencySnapshot {
    /// Samples in the window.
    pub samples: usize,
    /// Median.
    pub p50_us: f64,
    /// 95th percentile.
    pub p95_us: f64,
    /// 99th percentile.
    pub p99_us: f64,
    /// Maximum since start.
    pub max_us: f64,
}

/// Point-in-time pipeline counters.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StatsSnapshot {
    /// Source name.
    pub source: &'static str,
    /// Seconds since the engine started.
    pub uptime_secs: f64,
    /// Raw records read from the source.
    pub records: u64,
    /// Records that failed to decode.
    pub decode_errors: u64,
    /// Decoded events discarded because their kind is disabled.
    pub disabled_kind: u64,
    /// Events discarded by 1-in-N sampling.
    pub sampled_out: u64,
    /// Events whose fields were redacted.
    pub redacted: u64,
    /// Events lost because the queue was full (incoming discarded).
    pub queue_dropped_newest: u64,
    /// Events lost because the queue was full (oldest evicted).
    pub queue_dropped_oldest: u64,
    /// Events waiting in the queue.
    pub queue_len: usize,
    /// Queue capacity.
    pub queue_capacity: usize,
    /// Events currently retained.
    pub stored: usize,
    /// Highest sequence number assigned.
    pub last_seq: u64,
    /// Events evicted by the count limit.
    pub evicted_capacity: u64,
    /// Events evicted by the age limit.
    pub evicted_age: u64,
    /// Source read errors.
    pub source_errors: u64,
    /// Most recent source error, if any.
    pub last_source_error: Option<String>,
    /// Time events spent between decode and storage.
    pub queue_latency: LatencySnapshot,
}

/// A running pipeline. See the module docs.
pub struct Engine {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
    max_query_limit: usize,
}

struct Ingest {
    sources: Sources,
    sampler: Sampler,
    redactor: Redactor,
}

impl Ingest {
    fn handle(&mut self, shared: &Shared, bytes: &[u8]) {
        let c = &shared.counters;
        c.records.fetch_add(1, Ordering::Relaxed);
        let mut event = match decode(bytes) {
            Ok(e) => e,
            Err(_) => {
                c.decode_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        if !self.sources.enabled(event.kind) {
            c.disabled_kind.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.sampler.admit() {
            c.sampled_out.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.redactor.apply(&mut event) {
            c.redacted.fetch_add(1, Ordering::Relaxed);
        }
        event.received_ns = shared.now_ns();
        // Drops are counted inside the queue.
        let _: PushOutcome = shared.queue.push(event);
    }
}

fn reader(shared: Arc<Shared>, mut source: Box<dyn Source>, mut ingest: Ingest, pacing: Pacing) {
    let mut delivered: u64 = 0;
    while !shared.stop.load(Ordering::Acquire) {
        let budget = match pacing {
            Pacing::Unpaced => POLL_BATCH,
            Pacing::PerSecond(rate) => {
                let due = (shared.start.elapsed().as_secs_f64() * rate as f64) as u64;
                due.saturating_sub(delivered).min(POLL_BATCH as u64) as usize
            }
        };
        if budget == 0 {
            thread::sleep(IDLE_SLEEP);
            continue;
        }
        let shared_ref = &shared;
        match source.poll(budget, &mut |bytes| ingest.handle(shared_ref, bytes)) {
            Ok(0) => thread::sleep(IDLE_SLEEP),
            Ok(n) => delivered += n as u64,
            Err(e) => {
                shared
                    .counters
                    .source_errors
                    .fetch_add(1, Ordering::Relaxed);
                *shared
                    .last_error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(e.to_string());
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    shared.queue.close();
}

fn storer(shared: Arc<Shared>) {
    let mut batch = Vec::with_capacity(POLL_BATCH);
    loop {
        batch.clear();
        shared
            .queue
            .pop_batch(&mut batch, POLL_BATCH, Duration::from_millis(50));
        if !batch.is_empty() {
            let now = shared.now_ns();
            {
                let mut lat = shared
                    .latency
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                for e in &batch {
                    lat.record(now.saturating_sub(e.received_ns));
                }
            }
            let mut store = shared.store();
            for e in batch.drain(..) {
                store.insert(e);
            }
            store.prune(now);
        } else if shared.queue.is_finished() {
            return;
        }
    }
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)] as f64 / 1_000.0
}

impl Engine {
    /// Starts the reader and store threads.
    pub fn start(
        config: &Config,
        source: Box<dyn Source>,
        pacing: Pacing,
    ) -> std::io::Result<Self> {
        let limits = &config.limits;
        let max_age_ns =
            (limits.max_age_secs > 0).then(|| limits.max_age_secs.saturating_mul(1_000_000_000));
        let shared = Arc::new(Shared {
            start: Instant::now(),
            queue: BoundedQueue::new(limits.queue_capacity, limits.overflow),
            store: Mutex::new(EventStore::new(Retention {
                max_events: limits.max_events,
                max_age_ns,
            })),
            latency: Mutex::new(LatencyWindow {
                samples: Vec::with_capacity(LATENCY_WINDOW),
                next: 0,
                max: 0,
            }),
            counters: Counters::default(),
            stop: AtomicBool::new(false),
            last_error: Mutex::new(None),
            source_name: source.name(),
        });
        let ingest = Ingest {
            sources: config.sources.clone(),
            sampler: Sampler::new(limits.sample_every),
            redactor: Redactor::new(config.sources.include_paths, &config.redaction),
        };
        let r = Arc::clone(&shared);
        let reader = thread::Builder::new()
            .name("kerneltrace-reader".into())
            .spawn(move || reader(r, source, ingest, pacing))?;
        let s = Arc::clone(&shared);
        let storer = match thread::Builder::new()
            .name("kerneltrace-store".into())
            .spawn(move || storer(s))
        {
            Ok(h) => h,
            Err(e) => {
                shared.stop.store(true, Ordering::Release);
                let _ = reader.join();
                return Err(e);
            }
        };
        Ok(Self {
            shared,
            threads: vec![reader, storer],
            max_query_limit: limits.max_query_limit,
        })
    }

    /// The configured hard cap on query results.
    pub fn max_query_limit(&self) -> usize {
        self.max_query_limit
    }

    /// Queries stored events; `limit` is clamped to the configured maximum.
    pub fn query(&self, filter: &Filter, limit: usize) -> QueryResult {
        let now = self.shared.now_ns();
        let mut store = self.shared.store();
        store.prune(now);
        store.query(filter, limit.min(self.max_query_limit))
    }

    /// Summarises stored events matching `filter`.
    pub fn summarize(&self, filter: &Filter, top_n: usize) -> Summary {
        let now = self.shared.now_ns();
        let mut store = self.shared.store();
        store.prune(now);
        summarize(store.iter_matching(filter), top_n)
    }

    /// Nanoseconds since the engine started (the `received_ns` clock).
    pub fn now_ns(&self) -> u64 {
        self.shared.now_ns()
    }

    /// Current counters.
    pub fn stats(&self) -> StatsSnapshot {
        let s = &self.shared;
        let c = &s.counters;
        let (stored, last_seq, evicted_capacity, evicted_age) = {
            let store = s.store();
            (
                store.len(),
                store.last_seq(),
                store.evicted_capacity(),
                store.evicted_age(),
            )
        };
        let queue_latency = {
            let lat = s.latency.lock().unwrap_or_else(PoisonError::into_inner);
            let mut sorted = lat.samples.clone();
            sorted.sort_unstable();
            LatencySnapshot {
                samples: sorted.len(),
                p50_us: percentile(&sorted, 50.0),
                p95_us: percentile(&sorted, 95.0),
                p99_us: percentile(&sorted, 99.0),
                max_us: lat.max as f64 / 1_000.0,
            }
        };
        StatsSnapshot {
            source: s.source_name,
            uptime_secs: s.start.elapsed().as_secs_f64(),
            records: c.records.load(Ordering::Relaxed),
            decode_errors: c.decode_errors.load(Ordering::Relaxed),
            disabled_kind: c.disabled_kind.load(Ordering::Relaxed),
            sampled_out: c.sampled_out.load(Ordering::Relaxed),
            redacted: c.redacted.load(Ordering::Relaxed),
            queue_dropped_newest: s.queue.dropped_newest(),
            queue_dropped_oldest: s.queue.dropped_oldest(),
            queue_len: s.queue.len(),
            queue_capacity: s.queue.capacity(),
            stored,
            last_seq,
            evicted_capacity,
            evicted_age,
            source_errors: c.source_errors.load(Ordering::Relaxed),
            last_source_error: s
                .last_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            queue_latency,
        }
    }

    /// Stops both threads and waits for them. Idempotent.
    pub fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}
