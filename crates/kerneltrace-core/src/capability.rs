//! Detection of what this host can do.
//!
//! The report is advisory: it explains *why* live mode is or is not expected
//! to work. The authoritative test is still loading the probe, which reports
//! its own errors.

use serde::Serialize;

/// Minimum kernel for `BPF_MAP_TYPE_RINGBUF`.
pub const MIN_KERNEL: (u32, u32) = (5, 8);

/// Capability bit numbers from `linux/capability.h`.
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// What the host supports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// `std::env::consts::OS`.
    pub os: &'static str,
    /// Whether this binary was built with the `live` feature.
    pub live_feature_compiled: bool,
    /// True only when every check below passed.
    pub live_supported: bool,
    /// Kernel release string, Linux only.
    pub kernel_release: Option<String>,
    /// Whether `/sys/kernel/btf/vmlinux` exists (informational: the current
    /// probe uses fixed tracepoint offsets and does not need BTF).
    pub btf_available: Option<bool>,
    /// Whether a tracefs `events/` directory is visible (needed to resolve tracepoint ids).
    pub tracefs_available: Option<bool>,
    /// Whether the process has CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN.
    pub privileged: Option<bool>,
    /// Human-readable reasons live mode is unavailable (empty if supported).
    pub reasons: Vec<String>,
    /// Synthetic mode works everywhere.
    pub synthetic_supported: bool,
}

/// Parses `"6.8.0-45-generic"` into `(6, 8)`.
pub fn parse_kernel_release(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Extracts the effective capability mask from `/proc/self/status` text.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
}

/// True if the mask allows loading tracing BPF programs.
pub fn caps_allow_tracing(mask: u64) -> bool {
    let has = |bit: u32| mask & (1u64 << bit) != 0;
    has(CAP_SYS_ADMIN) || (has(CAP_BPF) && has(CAP_PERFMON))
}

/// Builds a report from already-gathered facts. Pure, so it is testable on any OS.
pub fn evaluate(
    os: &'static str,
    live_feature_compiled: bool,
    kernel_release: Option<String>,
    btf_available: Option<bool>,
    tracefs_available: Option<bool>,
    cap_eff: Option<u64>,
) -> Capabilities {
    let mut reasons = Vec::new();
    if os != "linux" {
        reasons.push(format!("unsupported: not Linux (running on {os}); eBPF is a Linux kernel feature. Use synthetic mode."));
    }
    if !live_feature_compiled {
        reasons.push("this binary was built without the `live` feature".to_string());
    }
    if os == "linux" {
        match kernel_release.as_deref().and_then(parse_kernel_release) {
            Some(v) if v >= MIN_KERNEL => {}
            Some((a, b)) => reasons.push(format!(
                "kernel {a}.{b} is older than {}.{} (BPF ring buffer)",
                MIN_KERNEL.0, MIN_KERNEL.1
            )),
            None => reasons.push("could not read the kernel version".to_string()),
        }
        if tracefs_available != Some(true) {
            reasons.push(
                "tracefs not found at /sys/kernel/tracing or /sys/kernel/debug/tracing".to_string(),
            );
        }
        if cap_eff.map(caps_allow_tracing) != Some(true) {
            reasons.push(
                "missing privileges: need CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN (root)"
                    .to_string(),
            );
        }
    }
    Capabilities {
        os,
        live_feature_compiled,
        live_supported: reasons.is_empty(),
        kernel_release,
        btf_available,
        tracefs_available,
        privileged: cap_eff.map(caps_allow_tracing),
        reasons,
        synthetic_supported: true,
    }
}

/// Inspects the running host.
pub fn detect() -> Capabilities {
    let live = cfg!(all(target_os = "linux", feature = "live"));
    if cfg!(target_os = "linux") {
        let read = |p: &str| std::fs::read_to_string(p).ok();
        let exists = |p: &str| std::path::Path::new(p).exists();
        evaluate(
            std::env::consts::OS,
            live,
            read("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()),
            Some(exists("/sys/kernel/btf/vmlinux")),
            Some(
                exists("/sys/kernel/tracing/events") || exists("/sys/kernel/debug/tracing/events"),
            ),
            read("/proc/self/status").as_deref().and_then(parse_cap_eff),
        )
    } else {
        evaluate(std::env::consts::OS, live, None, None, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_releases() {
        assert_eq!(parse_kernel_release("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(
            parse_kernel_release("5.15.167.4-microsoft-standard-WSL2"),
            Some((5, 15))
        );
        assert_eq!(parse_kernel_release("garbage"), None);
    }

    #[test]
    fn parses_capabilities() {
        let status = "Name:\tx\nCapEff:\t000001ffffffffff\n";
        let mask = parse_cap_eff(status).expect("mask");
        assert!(caps_allow_tracing(mask));
        assert!(!caps_allow_tracing(0));
        assert!(caps_allow_tracing((1 << CAP_BPF) | (1 << CAP_PERFMON)));
        assert!(!caps_allow_tracing(1 << CAP_BPF));
    }

    #[test]
    fn non_linux_is_unsupported_with_reason() {
        let c = evaluate("macos", false, None, None, None, None);
        assert!(!c.live_supported);
        assert!(c.synthetic_supported);
        assert!(c.reasons[0].starts_with("unsupported: not Linux"));
    }

    #[test]
    fn linux_checks_each_requirement() {
        let ok = evaluate(
            "linux",
            true,
            Some("6.8.0".into()),
            Some(true),
            Some(true),
            Some(1 << CAP_SYS_ADMIN),
        );
        assert!(ok.live_supported, "{:?}", ok.reasons);
        let old = evaluate(
            "linux",
            true,
            Some("5.4.0".into()),
            Some(true),
            Some(true),
            Some(1 << CAP_SYS_ADMIN),
        );
        assert!(old.reasons.iter().any(|r| r.contains("older than 5.8")));
        let unpriv = evaluate(
            "linux",
            true,
            Some("6.1".into()),
            Some(false),
            Some(true),
            Some(0),
        );
        assert!(
            unpriv
                .reasons
                .iter()
                .any(|r| r.contains("missing privileges"))
        );
        let no_tracefs = evaluate(
            "linux",
            true,
            Some("6.8.0".into()),
            Some(true),
            Some(false),
            Some(1 << CAP_SYS_ADMIN),
        );
        assert!(!no_tracefs.live_supported);
        assert!(
            no_tracefs
                .reasons
                .iter()
                .any(|r| r.contains("tracefs not found"))
        );
        // The probe uses fixed tracepoint offsets, not BTF/CO-RE: missing BTF
        // is reported but does not block live mode.
        let no_btf = evaluate(
            "linux",
            true,
            Some("6.8.0".into()),
            Some(false),
            Some(true),
            Some(1 << CAP_SYS_ADMIN),
        );
        assert!(no_btf.live_supported, "{:?}", no_btf.reasons);
        assert_eq!(no_btf.btf_available, Some(false));
        let not_compiled = evaluate(
            "linux",
            false,
            Some("6.8.0".into()),
            Some(true),
            Some(true),
            Some(1 << CAP_SYS_ADMIN),
        );
        assert!(
            not_compiled
                .reasons
                .iter()
                .any(|r| r.contains("`live` feature"))
        );
    }

    #[test]
    fn detect_runs_on_this_host() {
        let c = detect();
        assert_eq!(c.os, std::env::consts::OS);
        if c.os != "linux" {
            assert!(!c.live_supported);
        }
    }
}
