# Known limitations

## Verification gaps (honest status)
- **The live eBPF path is verified on two kernels only** (7.0.0-1017-azure/x86_64 and 6.8.0-117-generic/aarch64) by `tests/live_kernel.rs`: load, attach, event correctness for a known workload, redaction and clean detach. Kernels 5.8–6.7, other distributions, lockdown modes other than `none`, and behaviour under heavy load are untested. See KERNEL_COMPAT.md. The earlier intermittent failure on 7.0.0-1017-azure/x86_64 is explained and fixed (see KERNEL_COMPAT.md, "7.0.y kernels").
- The server has been exercised with the project's own stdio client, not yet with a third-party MCP client.
- Benchmarks were taken on one macOS machine under heavy unrelated load (see BENCHMARKS.md).

## Design limitations
- **Kernel-side drops lose events.** If the ring buffer (`[live] ring_buffer_bytes`, default 256 KiB ≈ 840 events) is full, `bpf_ringbuf_reserve` fails and the event is lost inside the probe. The loss is counted in the probe's per-CPU `STATS` map and reported as `stats.kernel.ring_full_drops` (with `fired_exec`/`fired_exit`/`fired_open`, the number of events each program tried to emit, and `path_unreadable`). The counters are refreshed every 100 ms, so they can lag the userspace counters slightly.
- **5 ms polling.** The live reader sleeps 5 ms when the ring is empty instead of waiting on epoll, so it can add up to 5 ms of latency. Throughput is unaffected.
- **Fixed tracepoint offsets** rather than CO-RE/BTF (see KERNEL_COMPAT.md).
- **Deterministic 1-in-N sampling** can alias with periodic workloads.
- **Retention is in memory only.** Events are gone when the process exits. There is no persistence, by design.
- **Queries scan linearly** over at most `max_events` (10k by default; ~56 µs per scan in the benchmark). Very large `max_events` values make queries slower.
- **Redaction is rule-based.** It cannot recognise every secret-bearing path. With `include_paths` on, assume some sensitive paths can still leak, and review your rules.
- **pid namespace.** pids are host-namespace pids. In containers they will not match what `ps` shows inside the container.
- **No authentication on stdio.** The trust boundary is the process that launches the server. There is no network transport.

## Not goals
- Intrusion detection or audit-grade completeness.
- Arbitrary user-supplied BPF programs.
- Any write or kill capability.
