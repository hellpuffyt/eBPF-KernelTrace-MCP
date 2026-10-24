# Kernel compatibility

## Verified kernels

The live-kernel integration test (`crates/kerneltrace-mcp/tests/live_kernel.rs`) loads the probe, traces known processes and files, checks pids, comms, paths, ordering and redaction over MCP, and checks clean detach after SIGTERM. It has **passed** on:

| Kernel | Arch | Environment | Commit | Result |
|---|---|---|---|---|
| 7.0.0-1017-azure | x86_64 | GitHub-hosted `ubuntu-latest` VM, CI job `live-kernel` (PR #5) | `04b4f6a` | 1 passed. Run A: 2 records (exec+exit). Run B: 66 records, 1 redacted. `decode_errors` 0, `source_errors` 0, clean SIGTERM. **Was intermittent, now fixed:** see "7.0.y kernels: `sys_enter_*` perf programs ran on CPU 0 only" below. With `kt_open` on the raw `sys_enter` tracepoint the test (now also checking every CPU) passed 30/30 on this exact kernel booted under KVM, against 0/55 before. |
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

The `kt_exec` offset comes from the event's `format` file. It is part of the tracepoint ABI and has been stable for years, but CO-RE would remove the dependency.

| Program | Hook | Fields read | Offset |
|---|---|---|---|
| `kt_exec` | tracepoint `sched/sched_process_exec` | `__data_loc char[] filename` | 8 |
| `kt_exit` | tracepoint `sched/sched_process_exit` | none (pid/tid/comm come from helpers) | — |
| `kt_open` | raw tracepoint `sys_enter` (`struct pt_regs *regs, long id`), filtered to `id == __NR_openat` | `filename`, `flags` argument registers; a mode register to skip compat tasks | x86_64: nr 257, `si` 104, `dx` 96, `cs` 136 (== 0x33); aarch64: nr 56, `x1` 8, `x2` 16, `pstate` 264 (bit 0x10 clear) |

The `kt_open` values are per architecture (`kerneltrace_common::SyscallAbi`); the loader writes them into the probe's `OPEN_*` globals, so one probe object serves both architectures. Open events are refused on other architectures.

To check your kernel:

```sh
sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format
```

### 7.0.y kernels: `sys_enter_*` perf programs ran on CPU 0 only

Until this fix `kt_open` was a tracepoint program on `syscalls/sys_enter_openat`. aya attaches a tracepoint program through **one perf event opened on CPU 0** (pid −1, cpu 0); the program normally runs on every CPU anyway because the kernel calls it before looking at per-CPU perf events. The upstream fix "tracing: perf: Fix stale head for perf syscall tracing" (2c2b322acdcc, Cc: stable) adds, in `perf_syscall_enter()`, for syscalls whose trace event reads user memory (`openat`'s filename):

```c
/* The above may have caused a migration */
head = this_cpu_ptr(sys_data->enter_event->perf_events);
if (hlist_empty(head))
        return;
```

Upstream this check comes *after* the BPF program has run (57918341dd19 moved the BPF call earlier). In 7.0.y it lands *before* `perf_call_bpf_enter()`, so on every CPU without a perf event (all but CPU 0) the program is skipped. Ubuntu's 7.0.0-1017-azure (based on 7.0.14) carries it; mainline v7.0 does not. Because the program never runs, the probe's `fired_open` counter cannot see the loss.

Evidence (diagnostic runs on branch `diag/live-intermittent`, the exact kernel packages booted with virtme-ng under KVM on a GitHub runner, 4 vCPUs): with each `cat` pinned to one CPU, opens on CPU 0 arrived 24/24 and on CPUs 1–3 0/66, in 3 of 3 runs; mainline 7.0.0 and 6.18 lost none. `kt_open` now uses the raw `sys_enter` tracepoint, which does not go through perf, and the live test pins its workload to every online CPU and requires each CPU's open.

## Semantics notes

- `kt_exit` fires for every exiting thread. The probe reports an event only when the thread-group leader exits (tid == pid), so one process exit yields one event. The exit code is not read.
- `kt_open` records `openat` **entry**: the attempt, not whether it succeeded. `openat2`, `open` (where it is a distinct syscall) and `creat` are not traced.
- `kt_open` runs on **every** syscall entry (raw `sys_enter`) and returns immediately unless the syscall is `openat`, so it adds a small cost to all syscalls while open events are enabled. It is loaded only when `[sources] open = true`.
- `kt_exec` fires after a successful exec. Failed execs are not visible.
- Paths are truncated to 256 bytes and comm to 15 characters (kernel `TASK_COMM_LEN`).
- Compat (32-bit) syscalls on 64-bit kernels are skipped by `kt_open` (checked via `cs`/`pstate`, as `syscalls:sys_enter_openat` also skipped them); this is not covered by a test.

## Not supported

- Kernels < 5.8 (no ring buffer; perf-buffer fallback not implemented).
- Non-Linux kernels, including Windows eBPF.
- Container-aware fields (cgroup id, namespace pids). pids are as seen from the initial pid namespace.
