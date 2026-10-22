# Production readiness

**Tested commit:** `12a7252` (branch `docs/production-readiness`) · **Date:** 2026-10-22 · **Host:** Apple M5, 10 cores, 16 GB, macOS 27.0.1, rustc 1.98.0

**Proposed classification: Partially Verified.** This is a proposal backed by the evidence below; it is not a self-award.
Reason: the userspace pipeline and MCP server are verified for their documented scope (synthetic mode, any OS). The **live eBPF path is not verified**. It needs Linux ≥ 5.8 with BTF and CAP_BPF, which was not available. CI has not yet run on this branch.

## Scope and architecture

A read-only MCP server (stdio) that exposes process exec/exit and `openat` events. A bounded pipeline sits between the source and the server:

synthetic source / eBPF ring buffer → safe decode → kind gate → 1-in-N sampler → redactor → non-blocking bounded queue → store (count and age retention) → 4 read-only tools.

The details are in [ARCHITECTURE.md](ARCHITECTURE.md). Out of scope: auditing or intrusion detection, writes of any kind, network transports.

## Supported platforms and prerequisites

| Use | Platforms | Prerequisites |
|---|---|---|
| Synthetic mode, MCP server, tests | Linux, macOS, Windows (any OS with Rust) | Rust ≥ 1.88 |
| Build the eBPF probe | any host | `nightly-2026-09-17` + `rust-src`, `bpf-linker` 0.12.0 |
| Live mode | Linux only | kernel ≥ 5.8, tracefs, CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN, the probe object |

## Clean-clone setup (exact commands)

```sh
git clone https://github.com/hellpuffyt/eBPF-KernelTrace-MCP && cd eBPF-KernelTrace-MCP
cargo build --release
./target/release/kerneltrace-mcp --capabilities
./target/release/kerneltrace-mcp --dump 5
cargo test
```

## Commands executed and actual outcomes

Development tree, `CARGO_TARGET_DIR` set under `~/Library/Caches`, at `3a7f3e2`/`12a7252`:

| Command | Exit | Outcome |
|---|---|---|
| `cargo fmt --all --check` | 0 | clean |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | 0 | no warnings (macOS host) |
| `cargo clippy --target x86_64-unknown-linux-gnu --all-features --locked -- -D warnings` | 0 | Linux `live` (aya 0.14) source type-checks |
| `cargo test --all-features --locked` | 0 | **71 passed, 0 failed, 1 ignored** (`probe_object`, gated) |
| `KERNELTRACE_EBPF_OBJECT=<obj> cargo test -p kerneltrace-core --test probe_object -- --ignored` | 0 | 1 passed (object parsed by `aya-obj`; 3 tracepoint programs, RINGBUF map, `.rodata`, GPL-compatible license) |
| same, **without** `KERNELTRACE_EBPF_OBJECT` | 101 | FAILED, as required: a missing prerequisite under an explicit run is a failure |
| `cargo build --release` in `crates/kerneltrace-ebpf` (nightly-2026-09-17, bpf-linker 0.12.0) | 0 | 5,008-byte `ELF 64-bit LSB relocatable, eBPF` |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked` | 0 | clean |
| `cargo deny check` | 0 | advisories, bans, licenses, sources ok |
| `cargo audit --db <advisory-db fetched 2026-10-22> --no-fetch` | 0 | 0 vulnerabilities |
| `cargo +1.88 check --all-features --locked` | 0 | MSRV holds (host target) |

Clean clone of `12a7252` into a scratch directory outside the repo, following the steps above literally:

| Step | Exit | Outcome |
|---|---|---|
| `cargo build --release` | 0 | built |
| `kerneltrace-mcp --capabilities` | 0 | `os: macos`, `live_supported: false`, reason "unsupported: not Linux …" |
| `kerneltrace-mcp --dump 5` | 0 | 5 JSON lines |
| `cargo test --locked` | 0 | 71 passed, 0 failed, 1 ignored |
| stdio: `initialize` (2025-11-25), then `query_events {"limit":9999}` | — | `{"isError":true,"content":[{"text":"limit must be between 1 and 500, got 9999"}]}` |

## Test results by layer

| Layer | Where | Count / notes |
|---|---|---|
| Unit | `src/**` in all crates | layout, decoder, queue, sampler, store, redaction, capability, config, PRNG vectors, protocol feature matrix, per-revision dispatch |
| Property | `decode.rs` (proptest) | arbitrary bytes never panic; valid records always decode |
| Stress / concurrency | `queue.rs` `conserves_items_under_contention`; `tests/engine.rs` | 4 producers × 50k items against a 64-slot queue: delivered + counted drops = sent, for both policies |
| Integration | `kerneltrace-core/tests/engine.rs` | real threads: flow, loss accounting, backpressure, limit clamp, pacing |
| End-to-end | `kerneltrace-mcp/tests/mcp_stdio.rs` (9 tests) | spawns the binary; handshake, all tools, paging, redaction, parse errors, 2 MiB message, SIGINT+SIGTERM, determinism, `--capabilities`, live refusal off Linux, bad config, 2025-06-18 errors, 2025-03-26 batch |
| Security | see below | — |
| Artifact | `kerneltrace-core/tests/probe_object.rs` (ignored by default) | run explicitly; passes with the object, fails without |

## Security review

| Check | Result | Evidence |
|---|---|---|
| Secrets / private references in history | none | publication preflight script (all-history scan) |
| Dependency audit | 0 advisories | `cargo audit`, `cargo deny` |
| Unsafe code | `forbid(unsafe_code)` in core and mcp; `unsafe` only in the BPF probe (helper calls) | crate attributes |
| Untrusted strings (comm, paths) → JSON/logs | control characters replaced | `decode::tests::control_characters_are_neutralised` |
| Sensitive data defaults | `open` events and paths off by default; probe does not read path memory unless enabled | `config::tests::defaults_are_conservative`, `paths_absent_by_default` (e2e) |
| Redaction | substring and prefix rules | `redact::tests::*`, e2e `full_session_over_stdio` |
| Resource exhaustion via MCP input | message ≤ 1 MiB; list args ≤ 64; strings ≤ 4096 B; batch ≤ 64; limits bounded | `oversized_message_is_rejected_…`, `invalid_arguments_have_useful_messages_in_every_version`, `batches_follow_the_negotiated_version` |
| Calls before initialize | rejected | `tools_require_initialize` |
| Write/kill capability | none exists; unknown tools are `-32602` | `unknown_tool_is_a_protocol_error_in_every_version` |
| Network exposure | none (stdio only) | design |
| Path traversal / SSRF / injection | not applicable: the only file read is the operator's config and probe path; no URLs, no shell | design |

## CI status

Not yet run for this branch. On `62ae9ad` (before this branch), `lint`, `deny`, `msrv`, and `test` on ubuntu and macos passed, while `test (windows-latest)` failed (aya-obj needs `std::os::fd`). The Windows failure is fixed in `08b605e`, which this branch includes. The `ebpf` job (build the probe with the checksum-pinned bpf-linker and run `probe_object --ignored`) is separate from the portable jobs.

## Performance methodology

Userspace only. Criterion micro-benchmarks plus an end-to-end example, measured under heavy unrelated load. See [BENCHMARKS.md](BENCHMARKS.md). The benchmarks were not re-run for this branch, because the changes do not touch the measured paths.

## Bugs found and fixed (each has a regression test)

| Bug | Fix | Regression test |
|---|---|---|
| Windows build broke on `aya-obj` (`std::os::fd`) | `cfg(unix)` dev-dependency | Windows CI job (`08b605e`) |
| Probe-object check counted as **passed** when the object was missing | `#[ignore]`, FAILS when run without the object | explicit `--ignored` run above (`08b605e`) |
| Fields from newer MCP revisions (`annotations`, `title`, `structuredContent`) sent to older clients | shape output per revision | `results_are_shaped_per_version` |
| Advertised 2025-03-26, but rejected the batches it requires | accept batches for 2024-11-05/2025-03-26 | `batches_follow_the_negotiated_version`, e2e `legacy_revisions_over_stdio` |
| Validation errors reported the same way for all revisions | `-32602` up to 2025-06-18, `isError` for 2025-11-25 | `invalid_arguments_have_useful_messages_in_every_version` |
| Unbounded `pids`/`comms`/`kinds` (O(n·m) scan) | caps of 64 entries and 4096 B | same test (`at most 64 entries`, `4096 bytes`) |
| Tools callable before `initialize`; `null` ids accepted | `-32600` | `tools_require_initialize`, `protocol_errors` |
| SIGTERM not handled (found during development) | `ctrlc` `termination` feature | `signals_shut_down_gracefully` |

## Acceptance checklist

| # | Item | Expected behaviour | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|---|
| 1 | Clean clone builds | `cargo build --release` exits 0 | clean clone of `12a7252` | PASS | exit 0 | README quick start |
| 2 | Test suite | all non-gated tests pass | `cargo test --all-features --locked` | PASS | 71 passed, 0 failed, 1 ignored | all crates |
| 3 | Synthetic mode emits events | `--dump 5` prints 5 events | `kerneltrace-mcp --dump 5` | PASS | 5 lines | `main.rs::dump` |
| 4 | Determinism | same seed → same stream | `dump_is_deterministic_for_a_seed` | PASS | equal | `synthetic.rs` |
| 5 | MCP handshake + tools | initialize / ping / tools/list / tools/call work | `full_session_over_stdio` | PASS | — | `server.rs` |
| 6 | Version negotiation | 4 published revisions; 2026-07-28 not claimed | `negotiates_versions`, `protocol::tests::negotiation` | PASS | 2026-07-28 → answered with 2025-11-25 | `protocol.rs` |
| 7 | Input validation | out-of-range / wrong type / negative / huge / unknown → spec-correct error with field name | `invalid_arguments_have_useful_messages_in_every_version` (19 cases × 4 revisions) | PASS | — | `tools.rs` |
| 8 | Bounded buffering / backpressure | reader never blocks; drops counted | `tiny_queue_reports_backpressure_drops`, `conserves_items_under_contention` | PASS | — | `queue.rs` |
| 9 | Loss accounting | every record accounted for exactly once | `disabled_kinds_sampling_and_decode_errors_are_counted` | PASS | — | `engine.rs` |
| 10 | Sampling / retention | 1-in-N; count and age eviction | `sample::tests`, `store::tests` | PASS | — | `sample.rs`, `store.rs` |
| 11 | Redaction, private by default | no paths unless enabled; secrets redacted | `paths_absent_by_default`, `redact::tests` | PASS | — | `redact.rs` |
| 12 | Malformed input | decoder and protocol never panic | proptest `never_panics`, `protocol_errors`, oversized message | PASS | — | `decode.rs`, `stdio.rs` |
| 13 | Graceful shutdown | EOF, SIGINT, SIGTERM → exit 0 | `signals_shut_down_gracefully`, e2e EOF | PASS | — | `stdio.rs` |
| 14 | Capability detection | clear reason off Linux | `--capabilities`; `live_mode_fails_clearly_off_linux` | PASS | "unsupported: not Linux" | `capability.rs` |
| 15 | Probe builds | BPF object links | `cargo build --release` (probe crate) | PASS | 5,008-byte eBPF ELF | `kerneltrace-ebpf` |
| 16 | Probe object matches loader | programs, map, global, license | `probe_object -- --ignored` | PASS | — | `probe_object.rs` |
| 17 | Lint / docs / deps | clean | fmt, clippy (host and Linux), doc, deny, audit | PASS | all exit 0 | CI `lint`, `deny` |
| 18 | MSRV 1.88 | builds | `cargo +1.88 check` | PASS | exit 0 (host) | CI `msrv` |
| 19 | Live probe loads and attaches | programs attach to the 3 tracepoints; only enabled ones load | CI `live-kernel` → `tests/live_kernel.rs` | **Pending** (job exists, not yet run) | requires Linux ≥ 5.8 with BTF + CAP_BPF | `live.rs` |
| 20 | Live events are correct | exec/exit/open events match real activity (pids, comms, paths, ordering, redaction); clean detach on SIGTERM | CI `live-kernel` → `tests/live_kernel.rs` | **Pending** (job exists, not yet run) | requires Linux ≥ 5.8 with BTF + CAP_BPF | `kerneltrace-ebpf` |
| 21 | Live-mode overhead and loss | measured kernel cost and drop rate | — | **Not verified** | requires Linux ≥ 5.8 with BTF + CAP_BPF; not covered by the CI job | — |
| 22 | Third-party MCP client | works with a real desktop client | — | **Not verified** | no third-party client run | — |
| 23 | CI green on this branch | all jobs pass | GitHub Actions | **Not yet run** | — | `.github/workflows/ci.yml` |

## Known limitations and unresolved risks

See [LIMITATIONS.md](LIMITATIONS.md). The most important ones:
- Live path unverified (items 19–21).
- Kernel-side ring-buffer drops are not counted; a counter is listed in [good-first-issues.md](good-first-issues.md) and is deliberately not implemented here.
- 5 ms polling latency in live mode.
- Fixed tracepoint offsets (no CO-RE).
- MCP revision 2026-07-28 (stateless) not supported.
- Benchmarks were taken under heavy unrelated load.

## Live-kernel CI job (results pending)

The `live-kernel` job in `.github/workflows/ci.yml` runs on a GitHub-hosted `ubuntu-latest` VM, which has passwordless sudo and a BTF-enabled kernel. The job:
1. builds the probe and the `live` binary;
2. records `uname -a`, BTF and tracefs presence, lockdown state, capabilities, and the `--capabilities` report (unprivileged and as root);
3. lists loaded BPF programs through aya's `loaded_programs()` (the kernel's program-id iterator) to prove attach and detach, so no external tool is needed (`bpftool` is only an optional, non-gating diagnostic step);
4. runs the ignored test `crates/kerneltrace-mcp/tests/live_kernel.rs` as root with `--ignored`.

Its first two runs (PR #5, kernels 7.0.0-1017-azure and 6.17.0-1022-azure) failed **before the probe was loaded**, because no runnable `bpftool` existed on those runners. That dependency has been removed. The kernel has **not been exercised yet**; this document will be updated with the real outcome. The test is never run on macOS. It fails, rather than skipping, if root or the probe object is missing.

What the test asserts is listed at the top of `tests/live_kernel.rs`.

## Needed for further verification

- A run of the `live-kernel` CI job (items 19–20). Item 21 still needs a dedicated Linux host or VM (kernel ≥ 5.8, BTF, CAP_BPF+CAP_PERFMON or root) for overhead measurements.
- A desktop MCP client for item 22.
- A GitHub Actions run of this branch for item 23.
