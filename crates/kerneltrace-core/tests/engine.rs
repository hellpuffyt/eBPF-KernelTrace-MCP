//! Engine behaviour on real threads: flow, accounting, backpressure, limits, pacing.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::thread;
use std::time::{Duration, Instant};

use kerneltrace_core::{Config, Engine, EventKind, Filter, Pacing, StatsSnapshot, SyntheticSource};

fn wait_for(engine: &Engine, pred: impl Fn(&StatsSnapshot) -> bool) -> StatsSnapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s = engine.stats();
        if pred(&s) || Instant::now() > deadline {
            return s;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn synthetic_events_flow_to_the_store() {
    let mut cfg = Config::default();
    cfg.sources.open = true;
    let mut engine = Engine::start(
        &cfg,
        Box::new(SyntheticSource::new(1, 1000, 0)),
        Pacing::Unpaced,
    )
    .expect("start");
    let stats = wait_for(&engine, |s| s.stored >= 1000);
    assert!(stats.stored >= 1000);
    let opens = engine.query(
        &Filter {
            kinds: vec![EventKind::Open],
            ..Filter::default()
        },
        10,
    );
    assert_eq!(opens.events.len(), 10);
    // include_paths is off by default: no path survives.
    assert!(opens.events.iter().all(|e| e.path.is_none()));
    engine.shutdown();
    engine.shutdown(); // idempotent
}

#[test]
fn disabled_kinds_sampling_and_decode_errors_are_counted() {
    let mut cfg = Config::default();
    cfg.limits.sample_every = 2;
    let src = SyntheticSource::new(3, 1000, 5);
    let mut engine = Engine::start(&cfg, Box::new(src), Pacing::Unpaced).expect("start");
    let s = wait_for(&engine, |s| s.records >= 5000);
    engine.shutdown();
    let s2 = engine.stats();
    assert!(s.decode_errors > 0);
    assert!(s.disabled_kind > 0, "open is disabled by default");
    assert!(s.sampled_out > 0);
    // Conservation: every record is accounted for exactly once.
    let admitted = s2.records - s2.decode_errors - s2.disabled_kind - s2.sampled_out;
    let lost = s2.queue_dropped_newest + s2.queue_dropped_oldest;
    assert_eq!(admitted, s2.last_seq + lost + s2.queue_len as u64);
}

#[test]
fn tiny_queue_reports_backpressure_drops() {
    let mut cfg = Config::default();
    cfg.limits.queue_capacity = 1;
    cfg.sources.open = true;
    let mut engine = Engine::start(
        &cfg,
        Box::new(SyntheticSource::new(9, 1, 0)),
        Pacing::Unpaced,
    )
    .expect("start");
    let s = wait_for(&engine, |s| s.queue_dropped_oldest > 0);
    engine.shutdown();
    assert!(s.queue_dropped_oldest > 0, "{s:?}");
}

#[test]
fn query_limit_is_clamped() {
    let mut cfg = Config::default();
    cfg.limits.max_query_limit = 7;
    let mut engine = Engine::start(
        &cfg,
        Box::new(SyntheticSource::new(2, 1, 0)),
        Pacing::Unpaced,
    )
    .expect("start");
    wait_for(&engine, |s| s.stored >= 100);
    assert_eq!(engine.query(&Filter::default(), 1_000_000).events.len(), 7);
    engine.shutdown();
}

#[test]
fn paced_source_respects_rate() {
    let mut cfg = Config::default();
    cfg.sources.open = true;
    let mut engine = Engine::start(
        &cfg,
        Box::new(SyntheticSource::new(2, 1, 0)),
        Pacing::PerSecond(100),
    )
    .expect("start");
    thread::sleep(Duration::from_millis(300));
    engine.shutdown();
    let records = engine.stats().records;
    // ~30 expected; allow generous scheduling slack but catch "unpaced".
    assert!((5..=80).contains(&records), "records = {records}");
}

/// A source that has no records but reports kernel-side counters, like the
/// live probe does; the second read fails once to show the error path.
struct CountingSource {
    reads: u64,
}

impl kerneltrace_core::Source for CountingSource {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn poll(
        &mut self,
        _max: usize,
        _sink: &mut dyn FnMut(&[u8]),
    ) -> Result<usize, kerneltrace_core::SourceError> {
        Ok(0)
    }
    fn kernel_counters(
        &mut self,
    ) -> Result<Option<kerneltrace_core::KernelCounters>, kerneltrace_core::SourceError> {
        self.reads += 1;
        if self.reads == 2 {
            return Err(kerneltrace_core::SourceError::Read("STATS[0]: test".into()));
        }
        Ok(Some(kerneltrace_core::KernelCounters {
            ring_full_drops: self.reads,
            fired_open: 10 * self.reads,
            ..Default::default()
        }))
    }
}

#[test]
fn kernel_counters_are_surfaced_in_stats() {
    let synthetic = Engine::start(
        &Config::default(),
        Box::new(SyntheticSource::new(1, 1000, 0)),
        Pacing::Unpaced,
    )
    .expect("start");
    assert_eq!(
        synthetic.stats().kernel,
        None,
        "synthetic has no kernel side"
    );
    let json = serde_json::to_value(synthetic.stats()).expect("json");
    assert!(json["kernel"].is_null());
    drop(synthetic);

    let mut engine = Engine::start(
        &Config::default(),
        Box::new(CountingSource { reads: 0 }),
        Pacing::Unpaced,
    )
    .expect("start");
    // Refreshed every 100 ms: wait for a few refreshes past the failing one.
    let s = wait_for(&engine, |s| {
        s.kernel.is_some_and(|k| k.ring_full_drops >= 4)
    });
    let k = s.kernel.expect("kernel counters");
    assert!(k.ring_full_drops >= 4, "{s:?}");
    assert_eq!(k.fired_open, 10 * k.ring_full_drops);
    assert_eq!(k.fired(), k.fired_open);
    assert_eq!(
        s.source_errors, 1,
        "a failed counter read is a source error"
    );
    assert!(
        s.last_source_error
            .as_deref()
            .is_some_and(|e| e.contains("STATS[0]"))
    );
    engine.shutdown();
}

/// An unpaced flood far larger than every limit: memory is bounded by
/// `max_events` + `queue_capacity`, and every record is stored or counted.
#[test]
fn flood_stays_within_limits_and_accounts_for_every_record() {
    let mut cfg = Config::default();
    cfg.sources.open = true;
    cfg.limits.max_events = 1000;
    cfg.limits.queue_capacity = 64;
    let mut engine = Engine::start(
        &cfg,
        Box::new(SyntheticSource::new(5, 1, 0)),
        Pacing::Unpaced,
    )
    .expect("start");
    let mut peak_stored = 0;
    let mut peak_queue = 0;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let s = engine.stats();
        peak_stored = peak_stored.max(s.stored);
        peak_queue = peak_queue.max(s.queue_len);
        if s.records >= 300_000 || Instant::now() > deadline {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }
    engine.shutdown();
    let s = engine.stats();
    assert!(s.records >= 100_000, "flood too small: {s:?}");
    assert!(
        peak_stored <= 1000 && s.stored <= 1000,
        "{peak_stored} {s:?}"
    );
    assert!(peak_queue <= 64, "{peak_queue}");
    assert!(s.evicted_capacity > 0);
    let lost = s.queue_dropped_newest + s.queue_dropped_oldest;
    assert_eq!(
        s.records - s.decode_errors - s.disabled_kind - s.sampled_out,
        s.last_seq + lost + s.queue_len as u64
    );
}
