# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Responses are now shaped for the negotiated MCP revision. `annotations` are sent only for 2025-03-26 and later; `title` and `structuredContent` only for 2025-06-18 and later. Previously every client received all of them.
- Revision 2025-03-26 requires servers to accept JSON-RPC batches, but they were rejected. Batches (max 64) are now accepted for 2024-11-05 and 2025-03-26 and rejected for later revisions.
- Invalid tool arguments are JSON-RPC `-32602` errors for revisions up to 2025-06-18 and `isError` tool results for 2025-11-25, as each revision's spec requires. Messages now name the offending field.
- `pids`/`comms`/`kinds` (≤ 64 entries), `path_prefix`/`comms[]` (≤ 4096 bytes) and `last_secs` (≤ 1e9) are bounded, so one query cannot force a scan of 100k filter entries per event.
- `tools/list` and `tools/call` before `initialize`, and requests with `null` or fractional ids, are rejected with `-32600`.

### Added
- `.editorconfig`, `docs/PRODUCTION_READINESS.md`.
- Live-kernel integration test (`tests/live_kernel.rs`) and CI job `live-kernel`. It passes on 7.0.0-1017-azure/x86_64 and 6.8.0-117-generic/aarch64: the first runs of the probe against real kernels.

## [0.1.0] - 2026-10-22

### Added
- `kerneltrace-common`: `no_std` 312-byte `RawEvent` layout with offset/size tests.
- `kerneltrace-core`: safe decoder (property-tested), seeded synthetic source, bounded non-blocking queue with `drop_oldest`/`drop_newest` and drop counters, per-kind gates, deterministic 1-in-N sampler, count/age retention, path redaction (off by default), summaries, capability detection, threaded engine with graceful shutdown.
- `kerneltrace-mcp`: MCP server over stdio (`initialize` with version negotiation, `ping`, `tools/list`, `tools/call`) with read-only tools `capabilities`, `query_events`, `summarize_events`, `stats`; `--dump`, `--capabilities`; 1 MiB message cap; shutdown on EOF/SIGINT/SIGTERM/EPIPE.
- `kerneltrace-ebpf` (experimental, unverified on hardware): Aya tracepoint programs for exec, exit and `openat` writing to a BPF ring buffer; loader-controlled path capture.
- Linux `live` source behind the `live` feature (experimental, unverified on hardware).
- Criterion benchmarks and an end-to-end latency example; docs for architecture, kernel compatibility, limitations and benchmarks.

[Unreleased]: https://github.com/hellpuffyt/eBPF-KernelTrace-MCP/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hellpuffyt/eBPF-KernelTrace-MCP/releases/tag/v0.1.0
