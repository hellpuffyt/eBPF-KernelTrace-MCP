# Architecture

## Components

| Crate | Target | Role |
|---|---|---|
| `kerneltrace-common` | `no_std`, any | The `#[repr(C)]` `RawEvent` record and its byte offsets. Size (312) and every offset are asserted by tests. |
| `kerneltrace-core` | std, any OS | Decoder, synthetic source, bounded queue, sampler, redactor, store, summaries, capability detection, engine threads, Linux `live` source (feature-gated). `#![forbid(unsafe_code)]`. |
| `kerneltrace-mcp` | std, any OS | CLI and MCP stdio server. `#![forbid(unsafe_code)]`. |
| `kerneltrace-ebpf` | `bpfel-unknown-none` | Three tracepoint programs and the ring-buffer map. Separate workspace (needs nightly + `bpf-linker`). |

## Data flow

```mermaid
sequenceDiagram
  participant K as Kernel probe / SyntheticSource
  participant R as Reader thread
  participant Q as BoundedQueue
  participant S as Store thread
  participant M as MCP server (main thread)
  K->>R: record bytes (borrowed slot)
  R->>R: decode (copy) → kind gate → sample → redact → stamp received_ns
  R->>Q: push (never blocks; overflow policy decides what to drop)
  S->>Q: pop_batch(≤256, wait ≤50 ms)
  S->>S: insert (assign seq), prune by age, record queue latency
  M->>S: query / summarize / stats (short mutex hold)
```

### Why the reader never blocks

In live mode the reader drains the BPF ring buffer. If it blocked on a full queue, the kernel ring buffer would fill up, and `bpf_ringbuf_reserve` would start failing **in the kernel**, where the loss is invisible to userspace. Dropping in userspace instead keeps the loss visible: `queue_dropped_newest` and `queue_dropped_oldest` count it.

### Ring buffer mechanics (accurately)

- The probe calls `bpf_ringbuf_reserve(312 bytes)`, writes the record into the reserved slot, and calls `bpf_ringbuf_submit`. No intermediate per-CPU buffer is involved.
- Userspace maps the ring buffer's consumer and data pages (`aya::maps::RingBuf`). `RingBuf::next()` returns a view of the slot **without a syscall or copy**.
- `decode()` copies the fields into an owned `Event`, which needs heap allocations for `comm` and `path`. When the view is dropped, the consumer position advances and the slot is freed.
- So the kernel→userspace transfer avoids a copy, but the pipeline makes one decode copy per event and later clones events for query results. **Do not describe the whole pipeline as zero-copy.**

### Determinism

The synthetic source uses an in-tree SplitMix64 (checked against reference vectors) and a virtual clock. For a given seed, the sequence of `(ts_ns, kind, pid, tid, uid, comm, path, ret)` is fixed. `received_ns` and `seq` depend on wall-clock timing and on queue drops; the `dump_is_deterministic_for_a_seed` test checks the deterministic part end to end through the binary.

### Shutdown

- **EOF on stdin, SIGINT, SIGTERM/SIGHUP** (via `ctrlc` with its `termination` feature) or **EPIPE on stdout**: the main loop notices within 100 ms and returns.
- `Engine::shutdown` then sets the stop flag. The reader finishes its current poll and closes the queue. The store thread drains what remains, and both threads are joined.
- The stdin reader thread is detached. On a signal it may still be blocked in `read()`, so it ends with the process.

On Windows, `ctrlc` maps Ctrl-C/Ctrl-Break/close to the same path.

## MCP surface

| Method | Behaviour |
|---|---|
| `initialize` | Echoes the client's `protocolVersion` if supported (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`), else answers with the newest. Advertises `tools` only. |
| `ping` | `{}` |
| `tools/list` | 4 tools, each with a JSON Schema (`additionalProperties: false`) and `readOnlyHint: true`. |
| `tools/call` | Unknown tool → JSON-RPC `-32602`. Bad arguments → result with `isError: true`, so the model can correct itself. Success → `structuredContent` plus the same JSON as text content. |
| notifications | Accepted and ignored. |
| arrays (batches) | Rejected with `-32600` (batching was removed from MCP in 2025-06-18). |
