# Known limitations

## Verification gaps (honest status)
- **The live eBPF path has not been run on a real kernel by this project.** Verified so far: the probe compiles and links (`bpf-linker` 0.12.0, nightly rustc), `aya-obj` parses the object and finds the three tracepoint programs, a `BPF_MAP_TYPE_RINGBUF` map and the `.rodata` global, and the userspace `live` module type-checks against aya 0.14 for `x86_64-unknown-linux-gnu`. Loading, attaching and event correctness are untested.
- The server has been exercised with the project's own stdio client, not yet with a third-party MCP client.
- Benchmarks were taken on one macOS machine under heavy unrelated load (see BENCHMARKS.md).

## Design limitations
- **Kernel-side drops are invisible.** If the 256 KiB ring buffer is full, `bpf_ringbuf_reserve` fails and the event is lost inside the probe. A per-CPU drop counter map is planned.
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
