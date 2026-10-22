# Kernel compatibility

> **Everything on this page is UNVERIFIED ON HARDWARE.** The probe builds, and `tests/probe_object.rs` checks its program and map layout. It has not yet been loaded into a running kernel by this project. If you run it, please report the result (kernel version, distro, arch) in an issue.

> **Live CI job: results pending.** A `live-kernel` job now exists in `.github/workflows/ci.yml`. It loads the probe on a GitHub-hosted `ubuntu-latest` VM under sudo, traces known processes and a known file, and checks clean detach through aya's loaded-program list. It has not run yet; this page will record the kernel version and outcome once it has.

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
