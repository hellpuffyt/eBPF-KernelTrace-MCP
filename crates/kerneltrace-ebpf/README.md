# kerneltrace-ebpf

The in-kernel half of kerneltrace: three tracepoint programs (`kt_exec`, `kt_exit`, `kt_open`) that write fixed-layout `RawEvent` records into a BPF ring buffer named `EVENTS`.

> **Experimental.** Loaded and integration-tested on two kernels (7.0.0-1017-azure/x86_64 and 6.8.0-117-generic/aarch64) by `crates/kerneltrace-mcp/tests/live_kernel.rs`; other kernels are untested (see `docs/KERNEL_COMPAT.md`).

## Build

This crate is its own workspace because it only builds for `bpfel-unknown-none`:

```sh
rustup toolchain install nightly-2026-09-17 --component rust-src   # pinned in rust-toolchain.toml
# bpf-linker: prebuilt binaries at https://github.com/aya-rs/bpf-linker/releases,
# or `cargo install bpf-linker` (needs a system LLVM matching its llvm-* feature)
cargo build --release
# -> target/bpfel-unknown-none/release/kerneltrace-ebpf  (ELF 64-bit LSB relocatable, eBPF)
```

Verified locally with bpf-linker 0.12.0 (prebuilt `aarch64-apple-darwin` release) and rustc 1.100.0-nightly (nightly-2026-09-17, LLVM 23.1.1). Newer nightlies may need a matching bpf-linker. The object can be cross-built on macOS; loading it needs Linux.

## Design

- One reservation per event (`EVENTS.reserve::<RawEvent>()`). The slot is zeroed, then filled, then submitted. If the ring is full the event is dropped in-kernel (not yet counted).
- `INCLUDE_PATHS` is a `.rodata` global. The loader sets it to 1 only when the operator enables `include_paths`. While it is 0, the probe never reads path memory.
- No BTF/CO-RE. Tracepoint fields are read at the fixed offsets listed in `docs/KERNEL_COMPAT.md`.

## License

MIT OR GPL-2.0-only (see `LICENSE-GPL-2.0` here and `LICENSE-MIT` at the repository root). The object declares `Dual MIT/GPL` to the kernel, because the tracing helpers it calls (`bpf_probe_read_*_str`) are GPL-only. `kerneltrace-common`, which this crate includes, is MIT OR Apache-2.0. Its MIT option is GPL-compatible.
