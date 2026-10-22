# Contributing

Thanks for helping. Bug reports, live-kernel test reports, docs fixes and code are all welcome.

## Quick setup

```sh
git clone https://github.com/hellpuffyt/eBPF-KernelTrace-MCP && cd eBPF-KernelTrace-MCP
cargo test          # no privileges needed; runs everywhere
```

Before opening a PR:

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check     # if you changed dependencies
```

If you touch `crates/kerneltrace-ebpf`, also build it (see its README) and run
`KERNELTRACE_EBPF_OBJECT=<object> cargo test -p kerneltrace-core --test probe_object`.

## Ground rules

- **Read-only and least-data stay non-negotiable.** PRs that add write or kill capabilities, arbitrary BPF loading, or that collect new sensitive fields by default will not be merged.
- **No unverified claims.** If you add a benchmark number or a compatibility statement, include the command and environment. If something is untested on real kernels, say so.
- **Keep `kerneltrace-common` layout changes in sync**: update the layout test, the decoder, the probe, and the size/offset docs together.
- Library code avoids `unwrap`/`expect`. `kerneltrace-core` and `kerneltrace-mcp` forbid `unsafe`.
- One logical change per PR; describe what you tested.

Starter tasks: [docs/good-first-issues.md](docs/good-first-issues.md).

By contributing you agree your work is licensed as described in the README (MIT OR Apache-2.0; the eBPF crate MIT OR GPL-2.0-only).
