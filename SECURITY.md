# Security policy

## Reporting a vulnerability

Please **do not** open a public issue. Report privately with GitHub's private vulnerability reporting (the "Report a vulnerability" button on the Security tab; you need to be signed in to GitHub):
<https://github.com/hellpuffyt/eBPF-KernelTrace-MCP/security/advisories/new>

Include the version or commit, your platform, reproduction steps and the impact you see. You should get an acknowledgement within 7 days. This is a volunteer project with no bug bounty.

## Supported versions

Fixes land on `main` and go into the next release. While the project is at 0.x only the latest release is supported; older releases don't get backports.

## Scope

In scope: anything that lets an MCP client or a traced process
- obtain data the configuration should exclude (e.g. paths with `include_paths = false`, redaction bypass),
- exhaust memory or CPU beyond the configured limits,
- crash or hang the server with crafted input or kernel records,
- inject control sequences into logs or JSON output,
- cause any write or state change in the kernel or other processes.

Out of scope: events missed because of sampling, drops or the documented limitations (see docs/LIMITATIONS.md). kerneltrace is not a security monitor.
