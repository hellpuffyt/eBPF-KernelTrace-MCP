# Production readiness

**Tested commits:** `12a7252` for the portable gates and clean clone (Apple M5, 10 cores, 16 GB, macOS 27.0.1, rustc 1.98.0); `04b4f6a` for the live-kernel test on two Linux kernels (see below) · **Date:** 2026-10-22

**Proposed classification: Partially Verified.** This is a proposal backed by the evidence below; it is not a self-award.
Reason: the userspace pipeline and MCP server are verified for their documented scope (synthetic mode, any OS). The live eBPF path now passes its integration test on **two kernels and two architectures** (7.0.0-1017-azure/x86_64 and 6.8.0-117-generic/aarch64). Still unverified: live-mode overhead and loss under load, older kernels (5.8–6.7), and a third-party MCP client.

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
| 19 | Live probe loads and attaches | programs attach to the 3 tracepoints; only enabled ones load | `tests/live_kernel.rs` (CI `live-kernel`; local arm64 container) | PASS | 7.0.0-1017-azure x86_64 and 6.8.0-117-generic aarch64; `kt_open` absent when open is off | `live.rs` |
| 20 | Live events are correct | exec/exit/open events match real activity (pids, comms, paths, ordering, redaction); clean detach on SIGTERM | `tests/live_kernel.rs` (CI `live-kernel`; local arm64 container) | PASS | both kernels: exact pid/comm/path matches, exec < open < exit, `<redacted>` token path, `decode_errors` 0, no `kt_*` programs after SIGTERM | `kerneltrace-ebpf` |
| 21 | Live-mode overhead and loss | measured kernel cost and drop rate | — | **Not verified** | requires Linux ≥ 5.8 with BTF + CAP_BPF; not covered by the CI job | — |
| 22 | Third-party MCP client | works with a real desktop client | — | **Not verified** | no third-party client run | — |
| 23 | CI green on this branch | all jobs pass | GitHub Actions | **Partially recorded** | `live-kernel` passed on `04b4f6a` (PR #5); the other jobs' status on that commit is not recorded here | `.github/workflows/ci.yml` |

## Known limitations and unresolved risks

See [LIMITATIONS.md](LIMITATIONS.md). The most important ones:
- Live-mode overhead and loss under load are unmeasured (item 21). Only two kernels are verified (items 19–20).
- Kernel-side ring-buffer drops are counted (`stats.kernel.ring_full_drops`, added after this report's tested commit; see the deep-audit addendum below) but the dropped events are lost.
- 5 ms polling latency in live mode.
- Fixed tracepoint offsets (no CO-RE).
- MCP revision 2026-07-28 (stateless) not supported.
- Benchmarks were taken under heavy unrelated load.

## Live-kernel verification

The ignored test `crates/kerneltrace-mcp/tests/live_kernel.rs` runs as root with `--ignored`. It fails, rather than skipping, if root or the probe object is missing, and it never runs on macOS. It proves attach and detach by listing loaded BPF programs through aya's `loaded_programs()` (the kernel's program-id iterator), so no external tool is required.

| Kernel / arch | Where | Commit | Outcome |
|---|---|---|---|
| 7.0.0-1017-azure / x86_64 | CI job `live-kernel` on GitHub-hosted `ubuntu-latest` (PR #5) | `04b4f6a` | **PASS**, 1 passed. Run A: 2 records (exec+exit). Run B: 66 records, 1 redacted. `decode_errors` 0, `source_errors` 0, clean SIGTERM. Figures as reported from the CI log. |
| 6.8.0-117-generic (Ubuntu 24.04) / aarch64 | local Colima VM (2 vCPU, 4 GB), privileged `rust:1.98-bookworm` container, `--pid=host`, tracefs mounted in the container | `04b4f6a` (clean clone) | **PASS**, 1 passed in 1.66 s. Run A: 2 records. Run B: 82 records, 2 redacted. `decode_errors` 0, `source_errors` 0, 0 queue drops, clean SIGTERM, no `kt_*` programs left. |

aarch64 run details:
- BTF 6,968,159 bytes, lockdown `[none]`, `unprivileged_bpf_disabled` = 2.
- The tracepoint `format` files match the probe's fixed offsets (8; 24/32).
- Probe built in the container with `nightly-2026-09-17` and bpf-linker 0.12.0 `aarch64-unknown-linux-musl` (sha256 `5e201e69…3935` verified); 5,008-byte object.
- Command: `KERNELTRACE_EBPF_OBJECT=<obj> cargo test --features live --locked -p kerneltrace-mcp --test live_kernel -- --ignored --nocapture --test-threads=1`.

Earlier CI attempts (kernels 7.0.0-1017-azure and 6.17.0-1022-azure) failed **before the probe was loaded**, because no runnable `bpftool` existed on those runners. Removing that dependency (`04b4f6a`) fixed it. No probe or loader defect has been found so far.

What the test asserts is listed at the top of `tests/live_kernel.rs`.

## Needed for further verification

- A run of the `live-kernel` CI job (items 19–20). Item 21 still needs a dedicated Linux host or VM (kernel ≥ 5.8, BTF, CAP_BPF+CAP_PERFMON or root) for overhead measurements.
- A desktop MCP client for item 22.
- A GitHub Actions run of this branch for item 23.

## Deep-audit addendum (branch `deep-audit`)

- **Kernel-side counters.** The probe now keeps a per-CPU `STATS` map: ring-full drops, unreadable paths, and
  per-program "fired" counts, surfaced as `stats.kernel`. `[live] ring_buffer_bytes` sets the ring size.
- **Flood test (live, arm64 6.8.0-117-generic, Colima, privileged container):** run C of `tests/live_kernel.rs`
  spawns 2000 `/bin/true` processes from 8 threads (bounded, no fork bomb) against a one-page (4096 B) ring.
  Two loops of 30 iterations each passed 30/30; in all 60, `records + ring_full_drops == fired_exec +
  fired_exit + fired_open` exactly (e.g. 491 + 7514 = 8005), retention stayed ≤ `max_events`, and server RSS
  grew by at most 128 KiB during the flood (from 8712 KiB).
- **Missing `open` events on main's `live-kernel` job (x86_64 7.0.0-1017-azure, 2 failures).** The CI logs show
  run B's exec and exit for the `ktcat…` pid with consecutive sequence numbers (in one failure, seq 1 and 2): no
  `open` event from *any* process was stored in that run, so it is not a path-read (`-EFAULT`) problem — the
  probe emits an open event even when the path cannot be read. Not reproduced on arm64 6.8: the unmodified live
  test passed 30/30 in a loop, and the extended one 30/30. Root cause on 7.0 is **not confirmed**. The test now
  first proves `kt_open` runs (`stats.kernel.fired_open > 0` after opening a file itself) and every timeout
  prints the kernel counters, so the next failure will show whether the program never ran (`fired_open = 0`),
  lost events to a full ring (`ring_full_drops`), or lost them in userspace.

