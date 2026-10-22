## What and why

## How I tested
- [ ] `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] If the probe or `kerneltrace-common` changed: built the probe and ran `tests/probe_object.rs`
- [ ] If live behaviour changed: tested on a real kernel (state version) **or** marked as unverified in docs

## Checklist
- [ ] Docs/CHANGELOG updated where behaviour changed
- [ ] No new sensitive data collected by default; still read-only
