# Security policy

## Reporting a vulnerability

Please **do not** open a public issue. Report privately via GitHub's private vulnerability reporting:
<https://github.com/hellpuffyt/eBPF-KernelTrace-MCP/security/advisories/new>

Include the version or commit, your platform, reproduction steps and the impact you see. You should get an acknowledgement within 7 days. This is a volunteer project with no bug bounty.

## Supported versions

Only the latest release on `main` receives fixes while the project is at 0.x.

## Scope

In scope: anything that lets an MCP client or a traced process
- obtain data the configuration should exclude (e.g. paths with `include_paths = false`, redaction bypass),
- exhaust memory or CPU beyond the configured limits,
- crash or hang the server with crafted input or kernel records,
- inject control sequences into logs or JSON output,
- cause any write or state change in the kernel or other processes.

Out of scope: events missed because of sampling, drops or the documented limitations (see docs/LIMITATIONS.md). kerneltrace is not a security monitor.
