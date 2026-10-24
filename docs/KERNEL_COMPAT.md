# Kernel compatibility

## Verified kernels

The live-kernel integration test (`crates/kerneltrace-mcp/tests/live_kernel.rs`) loads the probe, traces known processes and files, checks pids, comms, paths, ordering and redaction over MCP, and checks clean detach after SIGTERM. It has **passed** on:

| Kernel | Arch | Environment | Commit | Result |
|---|---|---|---|---|
| 7.0.0-1017-azure | x86_64 | GitHub-hosted `ubuntu-latest` VM, CI job `live-kernel` (PR #5) | `04b4f6a` | 1 passed. Run A: 2 records (exec+exit). Run B: 66 records, 1 redacted. `decode_errors` 0, `source_errors` 0, clean SIGTERM. **Intermittent:** after merge to main the same job failed twice on this kernel (jobs 119940290509, 119939678398: run B stored exec+exit but no open events); root cause not confirmed — the kernel counters added in this branch will attribute the next failure. |
| 6.8.0-117-generic (Ubuntu 24.04) | aarch64 | local Colima VM (2 vCPU, 4 GB); privileged container with `--pid=host`; BTF present, lockdown `none`, `unprivileged_bpf_disabled` = 2 | `04b4f6a` | 1 passed in 1.66 s. Run A: 2 records, 0 redacted. Run B: 82 records, 2 redacted. `decode_errors` 0, `source_errors` 0, no queue drops, clean SIGTERM, no `kt_*` programs left. |

On 6.8.0-117-generic/aarch64 the tracepoint `format` files match the offsets below exactly: `sched_process_exec` `__data_loc filename` @ 8; `sys_enter_openat` `filename` @ 24, `flags` @ 32.

Not verified: kernels 5.8–6.7, other distributions, kernels with lockdown `integrity`/`confidentiality`, and anything beyond the test's workload (overhead, loss under load). Reports for other kernels are welcome in an issue (kernel version, distro, arch, test output).

### Running in a container

A container works if it is privileged and shares the host pid namespace (`--pid=host`). The probe reports pids from the initial pid namespace, so a container-namespace pid never matches. Mount tracefs inside the container if it isn't already mounted (`mount -t tracefs nodev /sys/kernel/tracing`). `/sys/kernel/btf/vmlinux` is visible in privileged containers.

## Requirements for live mode

| Requirement | Why | Checked by `--capabilities` |
|---|---|---|
| Linux | eBPF is a Linux kernel feature | yes |
| Kernel ≥ 5.8 | `BPF_MAP_TYPE_RINGBUF` was added in 5.8 | yes (from `/proc/sys/kernel/osrelease`) |
| tracefs mounted (`/sys/kernel/tracing` or `/sys/kernel/debug/tracing`) | aya resolves tracepoint ids through `events/<category>/<name>/id` | yes |
| CAP_BPF + CAP_PERFMON (kernel ≥ 5.8), or CAP_SYS_ADMIN | loading BPF programs and attaching tracepoints | yes (from `CapEff` in `/proc/self/status`) |
| GPL-compatible program license | `bpf_probe_read_*_str` and other tracing helpers are GPL-only | the object declares `Dual MIT/GPL` |
| `/sys/kernel/btf/vmlinux` | **not required**: the probe uses fixed offsets, not CO-RE | reported for information |

Lockdown mode (`/sys/kernel/security/lockdown` = `confidentiality`) and some LSM policies can refuse BPF even for root. The loader then fails with the kernel's error message.

## Tracepoints and offsets used

The offsets come from each event's `format` file. They are part of the tracepoint ABI and have been stable for years, but CO-RE would remove the dependency.

| Program | Tracepoint | Fields read | Offset |
|---|---|---|---|
| `kt_exec` | `sched/sched_process_exec` | `__data_loc char[] filename` | 8 |
| `kt_exit` | `sched/sched_process_exit` | none (pid/tid/comm come from helpers) | — |
| `kt_open` | `syscalls/sys_enter_openat` | `const char *filename`, `int flags` | 24, 32 |

To check your kernel:

```sh
sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format
sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
```

`syscalls:*` tracepoints need `CONFIG_FTRACE_SYSCALLS=y`, which most distribution kernels enable.

## Semantics notes

- `kt_exit` fires for every exiting thread. The probe reports an event only when the thread-group leader exits (tid == pid), so one process exit yields one event. The exit code is not read.
- `kt_open` records `openat` **entry**: the attempt, not whether it succeeded. `openat2`, `open` (where it is a distinct syscall) and `creat` are not traced.
- `kt_exec` fires after a successful exec. Failed execs are not visible.
- Paths are truncated to 256 bytes and comm to 15 characters (kernel `TASK_COMM_LEN`).
- Compat (32-bit) syscalls on 64-bit kernels have not been considered or tested.

## Not supported

- Kernels < 5.8 (no ring buffer; perf-buffer fallback not implemented).
- Non-Linux kernels, including Windows eBPF.
- Container-aware fields (cgroup id, namespace pids). pids are as seen from the initial pid namespace.
