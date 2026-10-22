//! Userspace micro-benchmarks. These say nothing about in-kernel probe cost.

use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use kerneltrace_common::RAW_EVENT_SIZE;
use kerneltrace_core::decode::decode;
use kerneltrace_core::queue::{BoundedQueue, OverflowPolicy};
use kerneltrace_core::redact::{RedactionConfig, Redactor};
use kerneltrace_core::store::{EventStore, Retention};
use kerneltrace_core::{Event, EventKind, Filter, SyntheticSource};

fn records(n: usize) -> Vec<Vec<u8>> {
    let mut s = SyntheticSource::new(42, 1000, 0);
    (0..n).map(|_| s.next_record()).collect()
}

fn events(n: usize) -> Vec<Event> {
    records(n).iter().filter_map(|r| decode(r).ok()).collect()
}

fn bench_decode(c: &mut Criterion) {
    let recs = records(1024);
    let mut g = c.benchmark_group("decode");
    g.throughput(Throughput::Bytes((recs.len() * RAW_EVENT_SIZE) as u64));
    g.bench_function("1024_records", |b| {
        b.iter(|| {
            for r in &recs {
                black_box(decode(black_box(r)).ok());
            }
        })
    });
    g.finish();
}

fn bench_redact(c: &mut Criterion) {
    let evs = events(1024);
    let red = Redactor::new(true, &RedactionConfig::default());
    let mut g = c.benchmark_group("redact");
    g.throughput(Throughput::Elements(evs.len() as u64));
    g.bench_function("1024_events_paths_on", |b| {
        b.iter_batched(
            || evs.clone(),
            |mut v| {
                for e in &mut v {
                    black_box(red.apply(e));
                }
                v
            },
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_queue(c: &mut Criterion) {
    let mut g = c.benchmark_group("queue");
    g.throughput(Throughput::Elements(1024));
    g.bench_function("push_pop_1024_uncontended", |b| {
        let q = BoundedQueue::new(4096, OverflowPolicy::DropOldest);
        let mut out = Vec::with_capacity(1024);
        b.iter(|| {
            for i in 0..1024u64 {
                q.push(black_box(i));
            }
            out.clear();
            q.pop_batch(&mut out, 1024, Duration::ZERO);
            black_box(&out);
        })
    });
    g.finish();
}

fn bench_store(c: &mut Criterion) {
    let evs = events(1024);
    let mut g = c.benchmark_group("store");
    g.throughput(Throughput::Elements(evs.len() as u64));
    g.bench_function("insert_1024_at_capacity_10k", |b| {
        let mut store = EventStore::new(Retention {
            max_events: 10_000,
            max_age_ns: None,
        });
        for e in events(10_000) {
            store.insert(e);
        }
        b.iter_batched(
            || evs.clone(),
            |v| {
                for e in v {
                    store.insert(e);
                }
            },
            BatchSize::SmallInput,
        )
    });
    let mut store = EventStore::new(Retention {
        max_events: 10_000,
        max_age_ns: None,
    });
    for e in events(10_000) {
        store.insert(e);
    }
    let f = Filter {
        kinds: vec![EventKind::Open],
        comms: vec!["bash".into()],
        ..Filter::default()
    };
    g.throughput(Throughput::Elements(10_000));
    g.bench_function("query_scan_10k", |b| {
        b.iter(|| black_box(store.query(black_box(&f), 50)))
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_decode,
    bench_redact,
    bench_queue,
    bench_store
);
criterion_main!(benches);
