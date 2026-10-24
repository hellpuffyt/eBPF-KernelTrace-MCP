# Good first issues

Each of these is self-contained and has a clear test to write.

1. ~~**Count kernel-side ring-buffer drops.**~~ Done: `STATS` per-CPU map, reported as `stats.kernel.ring_full_drops`. (Original note: add a `PerCpuArray<u64>` map `DROPS` in `crates/kerneltrace-ebpf/src/main.rs`, increment it when `EVENTS.reserve` fails, read and sum it in the `live` source, and surface it as `kernel_dropped` in `stats`. Extend `tests/probe_object.rs` to assert the map exists.)
2. **Replace 5 ms polling with epoll.** `aya::maps::RingBuf` implements `AsRawFd`. Wait on it with `poll(2)` (via the `rustix` crate) with a timeout, so the reader wakes as soon as data arrives.
3. **`--list-tools` flag.** Print the `tools/list` JSON and exit, so people can see the interface without an MCP client. Add a test in `tests/mcp_stdio.rs`.
4. **Decode `openat` flags.** Add a `flags` string field (`"O_WRONLY|O_CREAT"`) for open events, derived from `ret`, with unit tests for common combinations.
5. **Try live mode and report back.** Run the steps in README → "Live mode" on any Linux ≥ 5.8 and open an issue with the kernel version and what happened, good or bad. This is the most valuable contribution right now.
