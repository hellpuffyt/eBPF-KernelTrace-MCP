# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
