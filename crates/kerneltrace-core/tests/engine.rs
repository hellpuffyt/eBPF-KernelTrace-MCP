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
