//! End-to-end userspace pipeline measurement: synthetic source → decode →
//! sample → redact → bounded queue → store, on real threads.
//!
//! Reports sustained throughput and queue latency percentiles (time from the
//! reader stamping `received_ns` to the store thread inserting the event).
//! This measures userspace only; it does not include kernel probe overhead or
//! ring-buffer wakeups.
//!
//! Run: `cargo run --release -p kerneltrace-core --example pipeline_latency -- [secs] [rate]`
//! (`rate` 0 = unpaced, the default).

use std::time::{Duration, Instant};

use kerneltrace_core::{Config, Engine, Pacing, SyntheticSource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let secs: u64 = args.next().map(|s| s.parse()).transpose()?.unwrap_or(3);
    let rate: u64 = args.next().map(|s| s.parse()).transpose()?.unwrap_or(0);
    let mut cfg = Config::default();
    cfg.sources.open = true;
    cfg.sources.include_paths = true;
    cfg.limits.max_events = 100_000;
    let pacing = if rate == 0 {
        Pacing::Unpaced
    } else {
        Pacing::PerSecond(rate)
    };
    let started = Instant::now();
    let mut engine = Engine::start(&cfg, Box::new(SyntheticSource::new(42, 1000, 0)), pacing)?;
    std::thread::sleep(Duration::from_secs(secs));
    engine.shutdown();
    let elapsed = started.elapsed().as_secs_f64();
    let s = engine.stats();
    println!("duration_s        {elapsed:.2}");
    println!(
        "pacing            {}",
        if rate == 0 {
            "unpaced".to_string()
        } else {
            format!("{rate}/s")
        }
    );
    println!("records           {}", s.records);
    println!("records_per_sec   {:.0}", s.records as f64 / elapsed);
    println!("stored_total      {}", s.last_seq);
    println!("stored_per_sec    {:.0}", s.last_seq as f64 / elapsed);
    println!(
        "queue_dropped     newest={} oldest={}",
        s.queue_dropped_newest, s.queue_dropped_oldest
    );
    println!("redacted          {}", s.redacted);
    let l = &s.queue_latency;
    println!(
        "queue_latency_us  p50={:.1} p95={:.1} p99={:.1} max={:.1} (last {} events)",
        l.p50_us, l.p95_us, l.p99_us, l.max_us, l.samples
    );
    Ok(())
}
