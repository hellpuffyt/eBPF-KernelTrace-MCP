//! Checks the compiled eBPF probe against what the userspace loader expects:
//! program names and types, the ring-buffer map, the `INCLUDE_PATHS` global
//! and a GPL-compatible license. Parsing is done with `aya-obj` (the parser
//! aya's loader uses), so this runs on any OS without a kernel.
//!
//! The object must be built first (nightly + bpf-linker, see
//! crates/kerneltrace-ebpf/README.md) and passed in `KERNELTRACE_EBPF_OBJECT`.
//! CI's `ebpf` job does this. Without the variable the test reports that it
//! did not run and passes.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use aya_obj::Object;
use aya_obj::ProgramSection;
use kerneltrace_core::live::{INCLUDE_PATHS_GLOBAL, PROGRAMS, RING_MAP};

const BPF_MAP_TYPE_RINGBUF: u32 = 27;

#[test]
fn probe_object_matches_loader_expectations() {
    let Some(path) = std::env::var_os("KERNELTRACE_EBPF_OBJECT") else {
        eprintln!("NOT RUN: set KERNELTRACE_EBPF_OBJECT to the compiled probe to check it");
        return;
    };
    let bytes = std::fs::read(&path).expect("read probe object");
    let obj = Object::parse(&bytes).expect("aya-obj parses the probe");

    for (name, _category, _tracepoint) in PROGRAMS {
        let prog = obj
            .programs
            .get(name)
            .unwrap_or_else(|| panic!("program {name} missing"));
        assert!(
            matches!(prog.section, ProgramSection::TracePoint),
            "{name} is not a tracepoint program"
        );
    }

    let ring = obj.maps.get(RING_MAP).expect("ring buffer map present");
    assert_eq!(ring.map_type(), BPF_MAP_TYPE_RINGBUF);
    let size = ring.max_entries();
    assert!(
        size.is_power_of_two() && size >= 4096,
        "ring size {size} must be a power-of-two multiple of the page size"
    );

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
