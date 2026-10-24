//! Checks the compiled eBPF probe against what the userspace loader expects:
//! program names and types, the ring-buffer and counter maps, the `INCLUDE_PATHS` global
//! and a GPL-compatible license. Parsing is done with `aya-obj` (the parser
//! aya's loader uses), so this runs on any OS without a kernel.
//!
//! The object must be built first (nightly + bpf-linker, see
//! crates/kerneltrace-ebpf/README.md) and passed in `KERNELTRACE_EBPF_OBJECT`.
//! CI's `ebpf` job does this. The test is `#[ignore]`d by default so a plain
//! `cargo test` reports it as *ignored*, never as passed; run it with
//! `-- --ignored`. With `--ignored` but no object, it fails instead of
//! silently passing. Unix-only, because `aya-obj` does not build on Windows.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use aya_obj::Object;
use aya_obj::ProgramSection;
use kerneltrace_common::STAT_SLOTS;
use kerneltrace_core::live::{
    Hook, INCLUDE_PATHS_GLOBAL, OPEN_ABI_GLOBALS, PROGRAMS, RING_MAP, STATS_MAP,
};

const BPF_MAP_TYPE_RINGBUF: u32 = 27;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;

#[test]
#[ignore = "needs the compiled probe: set KERNELTRACE_EBPF_OBJECT and pass --ignored"]
fn probe_object_matches_loader_expectations() {
    let path = std::env::var_os("KERNELTRACE_EBPF_OBJECT").expect(
        "set KERNELTRACE_EBPF_OBJECT to the compiled probe (see crates/kerneltrace-ebpf/README.md)",
    );
    let bytes = std::fs::read(&path).expect("read probe object");
    let obj = Object::parse(&bytes).expect("aya-obj parses the probe");

    for (name, hook) in PROGRAMS {
        let prog = obj
            .programs
            .get(name)
            .unwrap_or_else(|| panic!("program {name} missing"));
        match hook {
            Hook::TracePoint(..) => assert!(
                matches!(prog.section, ProgramSection::TracePoint),
                "{name} is not a tracepoint program"
            ),
            Hook::RawTracePoint(..) => assert!(
                matches!(prog.section, ProgramSection::RawTracePoint),
                "{name} is not a raw tracepoint program"
            ),
        }
    }
    // The loader overrides these with `must_exist = true`; their names must
    // be in the object's string table.
    for global in OPEN_ABI_GLOBALS.into_iter().chain([INCLUDE_PATHS_GLOBAL]) {
        let needle = [global.as_bytes(), b"\0"].concat();
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "global {global} missing from the object"
        );
    }

    let ring = obj.maps.get(RING_MAP).expect("ring buffer map present");
    assert_eq!(ring.map_type(), BPF_MAP_TYPE_RINGBUF);
    let size = ring.max_entries();
    assert!(
        size.is_power_of_two() && size >= 4096,
        "ring size {size} must be a power-of-two multiple of the page size"
    );

    let stats = obj.maps.get(STATS_MAP).expect("kernel counter map present");
    assert_eq!(stats.map_type(), BPF_MAP_TYPE_PERCPU_ARRAY);
    assert_eq!(stats.max_entries(), STAT_SLOTS);
    assert_eq!(stats.value_size(), 8, "u64 counters");

    assert!(
        obj.maps.keys().any(|k| k.starts_with(".rodata")),
        "{INCLUDE_PATHS_GLOBAL} lives in .rodata so the loader can override it"
    );
    let license = obj.license.to_str().expect("license is UTF-8");
    assert!(
        ["GPL", "Dual MIT/GPL", "Dual BSD/GPL", "GPL v2"].contains(&license),
        "license {license:?}"
    );
}
