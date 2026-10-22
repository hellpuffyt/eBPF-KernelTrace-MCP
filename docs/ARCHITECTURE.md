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

Supported revisions: `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`. All four were checked against the published specification and schemas on 2026-10-22. The newest published revision, **`2026-07-28`, is not supported**. It is stateless: there is no `initialize`, `ping` is removed, and `server/discover` is mandatory. A 2026-07-28 client probing with `server/discover` gets `-32601` here, which that revision's stdio rules treat as "legacy server, fall back to `initialize`".

| Method | Behaviour |
|---|---|
| `initialize` | Echoes the client's `protocolVersion` if supported, else answers with `2025-11-25`. Advertises `tools` only. Must not appear inside a batch. |
| `ping` | `{}`. Allowed before `initialize`. |
| `tools/list`, `tools/call` before `initialize` | `-32600` "server not initialized: send initialize before …" |
| `tools/list` | 4 tools in a fixed order. Each has a JSON Schema (`additionalProperties: false`, numeric bounds, `maxItems`). Fields depend on the revision (below). |
| `tools/call`, unknown tool or malformed request | JSON-RPC `-32602` in every revision (message lists the available tools). |
| `tools/call`, invalid arguments | Depends on the revision (below). The message names the offending field, e.g. ``invalid arguments for query_events: `pids[1]`: invalid value: integer `4294967296`, expected u32``. |
| notifications | Accepted and ignored. |
| id | Must be a string or an integer (`null` or fractional ids are rejected with `-32600`). |

### Per-revision differences

Derived from each revision's `schema.ts` and `server/tools` page:

| | 2024-11-05 | 2025-03-26 | 2025-06-18 | 2025-11-25 |
|---|---|---|---|---|
| `Tool.annotations` (`readOnlyHint` …) | — | ✓ | ✓ | ✓ |
| `title` on tools / `serverInfo` | — | — | ✓ | ✓ |
| `structuredContent` in results (the JSON is always also in `content[0].text`) | — | — | ✓ | ✓ |
| JSON-RPC batches accepted (max 64 messages) | ✓ | ✓ (spec: MUST) | `-32600` | `-32600` |
| invalid tool arguments reported as | `-32602` | `-32602` | `-32602` | result with `isError: true` |

The 2025-11-25 tools page moved input-validation failures ("value out of range", wrong format) from protocol errors to tool-execution errors, so that models can self-correct. Earlier revisions list "invalid arguments" under protocol errors.

### Input bounds

| Argument | Bound |
|---|---|
| `limit` | 1 … `limits.max_query_limit` (default 500) |
| `top_n` | 1 … 50 |
| `pids`, `comms`, `kinds` | ≤ 64 entries each (filtering is O(entries × stored events)) |
| `pids[]` | 0 … 2³²−1 |
| `path_prefix`, `comms[]` | ≤ 4096 bytes |
| `last_secs` | > 0 and ≤ 1e9 |
| `after_seq` | 0 … 2⁶⁴−1 |
| whole message | ≤ 1 MiB |
