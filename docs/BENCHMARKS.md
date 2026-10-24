# Benchmarks

**Scope: userspace only.** These numbers cover decoding, redaction, the queue, the store, and the threaded pipeline fed by the synthetic source. They say **nothing** about the cost of the eBPF probe in the kernel, ring-buffer wake-ups, or overhead on traced processes. Those have not been measured. The probe passes a functional integration test on two kernels (see KERNEL_COMPAT.md), but no overhead benchmark exists yet.

## Environment

| | |
|---|---|
| CPU | Apple M5, 10 cores |
| RAM | 16 GB |
| OS | macOS 27.0.1 |
| Compiler | rustc 1.98.0 (stable), `--release` / Criterion `bench` profile |
| Load | **other heavy builds were running at the same time (load average ≈ 50).** Expect better and less noisy results on an idle machine. |
| Date | 2026-10-22 |

## Criterion micro-benchmarks

Command:

```sh
cargo bench -p kerneltrace-core --bench pipeline -- --warm-up-time 2 --measurement-time 5
```

Output (lower bound / estimate / upper bound):

```text
decode/1024_records     time:   [267.15 µs 287.25 µs 310.64 µs]
                        thrpt:  [980.85 MiB/s 1.0359 GiB/s 1.1138 GiB/s]
redact/1024_events_paths_on
                        time:   [255.42 µs 266.39 µs 278.29 µs]
                        thrpt:  [3.6796 Melem/s 3.8441 Melem/s 4.0092 Melem/s]
queue/push_pop_1024_uncontended
                        time:   [17.053 µs 17.947 µs 18.820 µs]
                        thrpt:  [54.409 Melem/s 57.057 Melem/s 60.048 Melem/s]
store/insert_1024_at_capacity_10k
                        time:   [36.060 µs 37.491 µs 38.994 µs]
                        thrpt:  [26.260 Melem/s 27.313 Melem/s 28.397 Melem/s]
store/query_scan_10k    time:   [55.084 µs 56.386 µs 57.721 µs]
                        thrpt:  [173.25 Melem/s 177.35 Melem/s 181.54 Melem/s]
```

Notes:
- `decode` costs about 280 ns per record, mostly from allocating and sanitising the `comm` and `path` strings. A zero-allocation decode into a fixed-size event is an obvious optimisation, but it has not been done.
- `redact` (~260 ns/event) is dominated by lowercasing each path for the case-insensitive substring rules, which allocates. Cloning the input batch happens in `iter_batched` setup and is not timed.

## End-to-end pipeline

Command:

```sh
cargo run --release -p kerneltrace-core --example pipeline_latency -- 5 0        # unpaced
cargo run --release -p kerneltrace-core --example pipeline_latency -- 5 10000    # 10k events/s
```

Configuration: all kinds enabled, `include_paths = true` (redaction active), queue 4096 `drop_oldest`, `max_events = 100000`.

```text
duration_s        5.00
pacing            unpaced
records           4087808
records_per_sec   817386
stored_total      4077716
stored_per_sec    815368
queue_dropped     newest=0 oldest=10092
redacted          882105
queue_latency_us  p50=9.2 p95=57.0 p99=76.8 max=5080.0 (last 4096 events)
---
duration_s        5.01
pacing            10000/s
records           50010
records_per_sec   9987
stored_total      50010
stored_per_sec    9987
queue_dropped     newest=0 oldest=0
redacted          10913
queue_latency_us  p50=17.5 p95=1370.7 p99=2057.2 max=2586.6 (last 4096 events)
```

How to read this:
- **Queue latency** is the time from the reader stamping `received_ns` to the store thread inserting the event. Percentiles are exact over the last 4096 events; `max` covers the whole run.
- Unpaced, the store thread almost keeps up: 0.25% of events were evicted by `drop_oldest`.
- At 10k events/s the reader delivers in bursts every 5 ms. The millisecond-level p95/p99 reflects thread wake-up delay on a heavily oversubscribed machine (load ≈ 50 on 10 cores). It is not queueing, since nothing was dropped and the queue never filled. Re-measure on an idle machine before drawing conclusions.
- Event loss accounting holds by test (`disabled_kinds_sampling_and_decode_errors_are_counted`): every record is either decode-failed, disabled, sampled out, dropped (counted), queued, or stored.
