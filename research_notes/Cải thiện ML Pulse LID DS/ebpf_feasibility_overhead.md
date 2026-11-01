# Feasibility and per-syscall overhead of richer eBPF features (errno, I/O size, file path, n-gram) for Sentinel Pulse

Scope: Linux 5.15-6.x, x86-64. Criterion: <= 150 ns added per syscall on the hot path, aggregated in kernel per container per 0.5 s window. Researched 2026-11-01. Labels used: **[measured]** = a number someone measured, with its test conditions; **[claim]** = a statement made without data shown; **[code]** = read directly from kernel v6.8 source; **[inference]** = my reasoning, not measured.

## Q1. Hook cost: raw_tp/sys_exit vs tp/syscalls/sys_exit_<name> vs fentry/fexit on vfs_* / do_sys_openat2 / security_file_open vs LSM

### Takeaway
The empty-program cost of attaching is small: about 15 ns for a tracepoint and 24 ns for fentry, against 137 ns for a kprobe. Map work dominates: +20 ns for a simple map and +80 ns for a composite key. The key structural fact is that per-syscall tracepoints (`syscalls:sys_exit_read`) are not separate hooks. They register a handler on the same generic `sys_exit` tracepoint, so every syscall pays a cheap number check and only the selected syscalls run the BPF program. fentry/fexit/LSM on specific kernel functions cost nothing on other syscalls. For Pulse, the cheapest way to get return values and sizes is to hook only the few syscalls or functions that need them, not to add a second global hook.

### Cited Findings
- **[measured]** Cloudflare `ebpf_exporter` benchmark. Workload: `getpid()` loop, baseline 117.3 ns/op. Linux 6.5-rc1 in QEMU on an Apple M1 (arm64, one logical core; not x86-64). Overhead above baseline: tracepoint 15 / 35 / 96 ns, fentry 24 / 42 / 103 ns, kprobe 137 / 160 / 229 ns, for no map / simple map (key = PID) / complex map (key = PID + `time%1024` + 32-byte comm). Uprobe about 1670 ns. Raw tracepoint and fexit were not measured. — [cloudflare/ebpf_exporter benchmark](https://github.com/cloudflare/ebpf_exporter/tree/master/benchmark)
- **[claim, unsourced]** Handbook ranges: tracepoint 10-50 ns, fentry 50-100 ns, kprobe 100-300 ns, with no measurement behind them. — [performance-engineering-handbook](https://github.com/sderosiaux/performance-engineering-handbook/blob/master/06-ebpf-tracing.md)
- **[code, v6.8]** `perf_syscall_exit()` (the handler behind `tp/syscalls/sys_exit_<name>`) is registered with `register_trace_sys_exit(perf_syscall_exit, NULL)` on the generic `sys_exit` tracepoint. On every syscall exit it calls `trace_get_syscall_nr()`, returns early if `!test_bit(syscall_nr, enabled_perf_exit_syscalls)`, and only for enabled syscalls runs `perf_trace_buf_alloc()` and then `perf_call_bpf_exit()`. The BPF program receives a record holding `nr` and `ret`. — [kernel/trace/trace_syscalls.c v6.8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/trace/trace_syscalls.c?h=v6.8)
- **[code, v6.8]** Registering any syscall tracepoint calls `syscall_regfunc()`. When the refcount is first raised, it sets `SYSCALL_WORK_SYSCALL_TRACEPOINT` on every thread (`for_each_process_thread`). `SYSCALL_WORK_ENTER` and `SYSCALL_WORK_EXIT` both include that flag, so every task's syscalls take the entry and exit work path. — [kernel/tracepoint.c v6.8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/tracepoint.c?h=v6.8); [include/linux/entry-common.h v6.8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/linux/entry-common.h?h=v6.8)
- **[claim, kernel maintainers]** Mathieu Desnoyers (Nov 2024): "sys_enter/exit instrumentation is deemed too large to use in production" in some settings. He proposed per-syscall tracepoints as the alternative. Older LTTng threads report that setting the syscall-trace flag on all threads, with no probe registered, already costs as much as full tracing. — [LKML task_prctl_unknown thread](https://lkml.iu.edu/hypermail/linux/kernel/2411.0/08595.html); [lttng-dev 2013](https://lists.lttng.org/pipermail/lttng-dev/2013-October/021529.html)
- **[measured, per-invocation BPF run time only]** BPFence (Galletta, CCS '26 / arXiv 2609.13930) used a BPF-LSM program on `security_file_open`. Setup: Intel i7-1195G7 pinned to the 2.9 GHz base clock, turbo off, Ubuntu 24.04, kernel 6.8.0. Cost was measured with `run_time_ns/run_cnt` over 100k open/close, R=10, against an open/close baseline of 1318 ns/op. Results:
  - target-map check with early return: 61 ± 1 ns
  - integer field, no path: 71 ± 1 ns
  - with `bpf_d_path`: 240 ± 2 ns
  - each extra hash-map lookup: about 19 ns (260 ns at H=1, 432 ns at H=10)

  Caveat: `run_time_ns` covers only the program body. It leaves out trampoline and dispatch cost, so the real added latency is higher. — [arXiv 2609.13930, Table 1, §8.2.1](https://arxiv.org/pdf/2609.13930)
- **[measured, Craun et al., eBPF '24]** "Eliminating eBPF Tracing Overhead on Untraced Processes" shows that processes outside the trace target still pay overhead under post-eBPF, in-eBPF and pre-eBPF filtering. The in-eBPF filtering cost grows with the number of programs per hookpoint and with the number of hookpoints. I could not retrieve the numeric figures; the PDF host refused the connection. — [VTechWorks record](https://vtechworks.lib.vt.edu/items/45dbacb6-99e0-4a97-9d4b-ec71926e4137); [NSF PAR PDF](https://par.nsf.gov/servlets/purl/10569099)
- **[claim]** Kernel maintainers replaced some `bpf_d_path` allowlist targets such as `vfs_getattr` with `security_*` hooks, because the original functions could be inlined and the trampoline would then never fire. — [patchwork bpf_d_path discussion](https://patchwork.ozlabs.org/comment/2532367/)

### Inferences
- **[inference]** Pulse already attaches `raw_tp/sys_enter`, so every task already carries `SYSCALL_TRACEPOINT` work. Adding any `sys_exit` hook (raw or per-syscall) therefore does not add the slow-path entry cost. It adds the exit tracepoint call plus, for the per-syscall form, `trace_get_syscall_nr` + `test_bit`. That should be a few ns per syscall on non-selected syscalls (estimate, not measured). Selected syscalls additionally pay `perf_trace_buf_alloc` + BPF.
- **[inference]** The earlier failed experiment (global `raw_tp/sys_exit` + per-process LRU lookups, +29 to +197 ns) is consistent with these numbers. A global exit program plus an extra hash lookup per syscall (about 19-40 ns per lookup, from the BPFence and Cloudflare figures) on both enter and exit, plus key construction, lands in that range. Most of the cost was probably the extra map lookups, not the hook itself.
- **[inference]** Cheapest design for errno and byte counts:
  - Hook only the syscalls of interest with `tp/syscalls/sys_exit_{read,write,openat,...}`, or with fexit on `vfs_read`/`vfs_write` (these fire only on those calls).
  - Do no per-thread map lookup on exit. Use `bpf_get_current_cgroup_id()` + a per-CPU array or hash slot for the histogram.
  - As a zero-new-hook alternative for requested size, read `count` (args[2]) in the existing `sys_enter` program. That gives requested, not actual, bytes.
- **[inference]** For "errno class for all syscalls", a global exit hook is unavoidable. To keep it under budget, the exit program must be a single per-CPU array increment indexed by (`ret<0`, errno bucket), keyed by cgroup slot. It must not do an LRU lookup; the cgroup slot can be cached from enter only if done without a map, so it is better to call `bpf_get_current_cgroup_id()` again.
- **[inference]** fexit costs more than fentry: the trampoline must call the original function and save its return. No ns figure for fexit was found (see Gaps).

### Gaps
- No published ns figures for `raw_tp` vs `tp_btf` vs `tp/syscalls/sys_exit_*` on x86-64 with identical program bodies. The Cloudflare data is arm64 under QEMU.
- No published ns figure for fexit, and none for LSM hooks including trampoline/dispatch (BPFence measures program body only).
- Craun et al.'s numeric results could not be read (the PDF host refused the connection).
- Recommendation: measure on the lab kernel 6.8 with the existing Pulse microbenchmark harness. Use `bpf_stats_enabled` + `run_time_ns` for program body and syscall-latency deltas for total cost.

## Q2. Getting file paths: bpf_d_path, bpf_probe_read_user_str, dentry walking; prefix hashing; verifier limits

### Takeaway
`bpf_d_path` is allowed only on a small allowlist of functions: `security_file_open`, `security_file_permission`, `security_inode_getattr`, `security_path_truncate`, `vfs_truncate`, `vfs_fallocate`, `dentry_open`, `vfs_getattr`, `filp_close`. It is also allowed on sleepable BPF-LSM hooks, which include `file_open`, and on iterators. One measurement puts it at about 169 ns per call. That is affordable only because it runs per open, not per syscall. An early-return filter before the call drops the cost to about 61-71 ns.

### Cited Findings
- **[code, v6.8]** `btf_allowlist_d_path` = {`security_file_permission`, `security_inode_getattr`, `security_file_open` (under `CONFIG_SECURITY`); `security_path_truncate` (under `CONFIG_SECURITY_PATH`); `vfs_truncate`, `vfs_fallocate`, `dentry_open`, `vfs_getattr`, `filp_close`}. `bpf_d_path_allowed()` returns true for `BPF_TRACE_ITER`; for `BPF_PROG_TYPE_LSM` when `bpf_lsm_is_sleepable_hook()` holds; and otherwise when the attach BTF id is in the allowlist. — [kernel/trace/bpf_trace.c v6.8 L937-964](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/trace/bpf_trace.c?h=v6.8)
- **[code, v6.8]** `sleepable_lsm_hooks` includes `bpf_lsm_file_open` and `bpf_lsm_bprm_check_security`, so `lsm.s/file_open` may call `bpf_d_path`. — [kernel/bpf/bpf_lsm.c v6.8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/bpf/bpf_lsm.c?h=v6.8)
- **[measured]** On `security_file_open`, path resolution with `bpf_d_path` accounts for about 169 ns: 240 ns with the path vs 71 ns without, about 70% of the per-invocation cost. Kernel 6.8, i7-1195G7 at fixed 2.9 GHz. A non-targeted process returning early costs 61 ns. — [arXiv 2609.13930, Table 1](https://arxiv.org/pdf/2609.13930)
- **[measured]** In the same paper's nginx macro-benchmark (1 KB static file, wrk 2 threads × 100 connections, 30 s × 10), an LSM policy with path extraction cut throughput from 155,798 ± 666 to 147,223 ± 436 req/s (−5.5%). Per-invocation BPF cost was 149 ns. — [arXiv 2609.13930, §8.2.1](https://arxiv.org/pdf/2609.13930)
- **[claim]** In a fanotify-BPF discussion on the kernel list, a developer argued that `security_file_open` should stay cheap, and that `d_path()` or dentry walking there makes overhead higher and less predictable. — [LKML fanotify fastpath RFC](https://lkml.rescloud.iu.edu/2411.1/09221.html)
- **[code, v6.8]** Verifier limits: `BPF_COMPLEXITY_LIMIT_INSNS` = 1,000,000 processed instructions per program; `BPF_MAX_LOOPS` = 8 × 1024 × 1024 (`bpf_loop` iteration cap). — [include/linux/bpf.h v6.8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/linux/bpf.h?h=v6.8)
- **[claim]** Some allowlist entries need specific configs; one patch failed CI because `CONFIG_SECURITY_PATH` was unset. — [patchwork comment](https://patchwork.kernel.org/comment/24359993)

### Inferences
- **[inference]** Two options for the open-path feature:
  - **Option A** (cheapest, no new hook): in the existing `sys_enter` program, for `openat`/`openat2` only, run `bpf_probe_read_user_str()` on args[1] into a per-CPU scratch buffer of 64-128 bytes. Hash the first 1-2 `/`-separated components with a bounded loop (for example `for i < 64`, which the verifier unrolls or bounds), then increment a per-cgroup bucket. Cost is paid only on opens.

    Limitations: relative paths (resolved against cwd or dirfd), symlinks, and a TOCTOU-raceable user pointer. For anomaly features (not enforcement) that is acceptable.
  - **Option B** (canonical path): use `fentry/security_file_open` or `lsm/file_open` with `bpf_d_path` into a per-CPU buffer, about 169 ns extra per open. Avoid `bpf_d_path` entirely by walking `file->f_path.dentry->d_parent` for a fixed small depth and hashing `d_name`. This gives a prefix-free "parent directory" hash; its cost was not found.
- **[inference]** Opens are a small fraction of syscalls in most container workloads, so even 240 ns per open, amortized over all syscalls, is likely far below 150 ns per syscall on average. The project criterion, however, is per-syscall on the hot path. The design must state whether the criterion is per hooked call or averaged. An open-heavy microbenchmark would show the full per-open cost.

### Gaps
- No measured ns for `bpf_probe_read_user_str` of a typical path (about 20-60 bytes) on x86-64.
- No measured cost for a bounded dentry walk (depth 2-4) from fentry.
- No public figure for in-kernel path-prefix hashing cost (FNV or jhash over 64 bytes).

## Q3. Per-thread n-gram tracking in maps

### Takeaway
No source measured an in-kernel per-thread n-gram tracker directly. The cost of the map operations it needs is known: about 19 ns per hash lookup on LSM (BPFence), and +20 ns for a simple PID-keyed map vs +81 ns for a composite key on a tracepoint (Cloudflare). Pulse already pays one per-thread LRU lookup for its bigram. A 3- to 7-gram hash can reuse that same lookup by storing packed history in the value, so the n-gram adds no extra map operation.

### Cited Findings
- **[measured]** Each additional BPF hash-map lookup in a BPF-LSM program cost about 19 ns (H=1 → 260 ns, H=10 → 432 ns; kernel 6.8, i7-1195G7 at 2.9 GHz). — [arXiv 2609.13930](https://arxiv.org/pdf/2609.13930)
- **[measured]** On a tracepoint, a PID-keyed map update added 20 ns over an empty program (35 vs 15 ns). A composite key (PID + bucket + 32-byte comm) added 81 ns (96 vs 15 ns). Arm64 QEMU, kernel 6.5-rc1. — [cloudflare/ebpf_exporter benchmark](https://github.com/cloudflare/ebpf_exporter/tree/master/benchmark)
- **[claim, docs]** LRU_HASH and LRU_PERCPU_HASH evict the least-recently-used element when full. They have existed since kernel 4.10. — [kernel docs: BPF_MAP_TYPE_HASH with PERCPU and LRU variants](https://dri.freedesktop.org/docs/drm/bpf/map_hash.html)
- **[code/claim]** The LRU lookup path marks the found element as referenced on every hit, which adds cost compared with a plain hash lookup. — [LRU hash commit](https://git.evolution-x.org/anierin/msm-5.15/commit/29ba732acbee)
- **[measured, unretrieved]** ebpH (Findlay, Carleton) is an eBPF port of the pH per-process syscall-sequence anomaly detector. Its talk reports significant overhead on very short syscalls such as `getppid` (a large percentage), but acceptable overhead on real workloads. Exact numbers were not extracted. — [ebpH talk CCSL 2020](https://www.cisl.carleton.ca/~will/written/talks/ebph-ccsl-2020.pdf)
- **[claim]** A Sungshin University thesis builds n-gram features (n = 5-50) from Tetragon-collected syscall sequences, with n-grams computed in user space. It reports accuracy up to 99.75% for cryptojacking-container detection and includes a latency-overhead study. — [Sungshin repository](https://repository.sungshin.ac.kr/handle/2025.oak/1428)

### Inferences
- **[inference]** Packed history: x86-64 syscall numbers are below 512 (9 bits), so a u64 holds the last 7 syscall numbers (63 bits). On each `sys_enter`, the existing per-thread lookup returns a pointer to the value, and the program does `hist = (hist << 9) | nr`. Masking gives the 3- to 7-grams, and a multiplicative hash such as `(h * 0x9E3779B97F4A7C15) >> (64 - B)` maps them into B-bit bins of a per-cgroup per-CPU array. That is a handful of ALU instructions, likely only a few ns, with no added map lookup. Each n adds one array increment, at roughly 5-15 ns each (estimate, from the "simple map" deltas above).
- **[inference]** Memory: an LRU map of 64K tids × (8-byte key + 8-16-byte value + about 56 bytes of htab element overhead) is a few MB.
- **[inference]** `BPF_MAP_TYPE_TASK_STORAGE` (task-local storage) avoids hashing the tid and is designed for per-task state. It could be cheaper than the LRU hash, but I found no measurement.
- **[inference]** Bins: per-cgroup histograms of 2^B bins per n, for example B = 10 → 1024 bins × 5 values of n × 8 bytes × nCPU per container. On 8 CPUs that is 320 KB per container. Size and n should be chosen with this in mind, or bins should be shared across n with salted hashes.

### Gaps
- No published ns figure for LRU_HASH vs HASH vs TASK_STORAGE lookup on x86-64 (the kernel `bench` and `map_perf_test` exist, but I found no published output).
- No measured overhead for an in-kernel n-gram tracker in a published IDS prototype. SysFlow and BPFroid were not covered due to the tool-call budget.

## Q4. In-kernel aggregation into per-cgroup histograms; ring buffer vs maps

### Takeaway
Ring buffer vs perf buffer: ringbuf is described as faster "for all practical purposes", with manual or batched wakeup as an extra optimization, but the blog gives no numbers. For Pulse's 0.5 s windows, in-kernel per-CPU array or hash aggregation with user-space reads every 0.5 s keeps per-event cost to map increments and avoids event emission entirely. Falco's modern probe, by contrast, stages variable-size events in per-CPU auxiliary maps (128 KiB segments) before ringbuf submission.

### Cited Findings
- **[claim, author of ringbuf]** Ringbuf "beats BPF perfbuf for all practical purposes". Per-CPU perfbuf can theoretically win only at millions of events per second. `BPF_RB_NO_WAKEUP` / `BPF_RB_FORCE_WAKEUP` allow manual notification for extra performance, and adaptive notification is the safe default. No benchmark numbers are given in the post (they are in a kernel selftest). — [nakryiko.com: BPF ring buffer](https://nakryiko.com/posts/bpf-ringbuf/)
- **[claim, docs]** Falco's modern eBPF probe uses BPF ring buffers, configurable either per CPU or as one shared buffer. Variable-size events go through per-CPU auxiliary maps; since 0.45 there are two segments of 128 KiB per possible CPU. The probe uses BPF atomic CAS where the kernel supports it (5.12+). — [Falco docs: kernel event sources](https://falco.org/docs/concepts/event-sources/kernel/)
- **[claim, vendor]** Tetragon: high-volume file monitoring is "almost trivial" in Isovalent's benchmarks because nothing is sent to user space until a policy matches (in-kernel filtering). — [Isovalent: top Tetragon use cases](https://isovalent.com/blog/post/top-tetragon-use-cases/)

### Inferences
- **[inference]** Pulse's current pattern (per-CPU maps keyed by cgroup, read by user space) is already the low-cost design. New features should be added as more counters in the same per-CPU structure. The cgroup slot index should be resolved once per event, and nothing should be emitted per event.
- **[inference]** The cost per added feature is then roughly one per-CPU array increment of a few ns to about 20 ns (from the simple-map deltas). Hash-keyed maps cost more than array-indexed ones; this is an estimate.

### Gaps
- No x86-64 ns figure for a per-CPU array increment vs a ringbuf reserve/submit per event.

## Q5. Published end-to-end overhead of argument-collecting tools (Falco, Tetragon, Tracee) vs count-only probes

### Takeaway
Measured end-to-end overhead depends heavily on the hook and the policy. The single open benchmark covering six tools (kernel 6.12, Oct 2026) shows Falco at +8 to +9% median syscall-latency overhead, but Tetragon's `read` p50 at +1,100% to +2,600% when file policies hook reads. Vendor claims (Tetragon < 2% on exec) are for narrow workloads. LSM-based monitors report 1-17%.

### Cited Findings
- **[measured, single unreviewed GitHub benchmark]** sammonsempes/EBPF-Runtime-Detection-Benchmark. Setup: kernel 6.12.105 (Debian 13), 8 CPUs, 30.9 GiB RAM, Docker 26.1.5, cgroup v2. Tools: Falco 0.45.0, Tetragon 1.7.1, Tracee 0.24.1, KubeArmor 1.7.5, Kunai 0.6.2, Pulsar 0.10.1. Results are p50 deltas vs the same-run baseline, default profile:

  | Tool (default profile) | `openat` p50 | `read` p50 | `connect` p50 | Median syscall latency | Agent CPU |
  |---|---|---|---|---|---|
  | Falco | +36.4% | +7.0% | +10.7% | +8.2% | 30% |
  | Tetragon | −2.3% | +1,123% | — | −1.8% | — |
  | Tracee | +105.6% | +26.8% | +37.3% | +29.3% | 145% |
  | KubeArmor | +204.7% | +56.6% | +78.7% | +63.9% | — |
  | Kunai | +13.7% | +126.2% | — | +13.5% | — |
  | Pulsar | +119.6% | — | — | +27.2% | — |

  Tetragon with the tuned profile reached `read` +2,611%, `openat` +55.6% and a median of +83.6%. The page reports percentages only (no ns), workload parameters are not given, and tuned profiles were written knowing the scenarios. — [EBPF-Runtime-Detection-Benchmark](https://github.com/sammonsempes/EBPF-Runtime-Detection-Benchmark)
- **[measured, cited secondhand]** Her, Kim, Kim, Lee, "An In-Depth Analysis of eBPF-Based System Security Tools in Cloud-Native Environments", IEEE Access 13 (2025) 155588-155604, doi:10.1109/ACCESS.2025.3605432. As cited by BPFence: 9.79% (Tetragon) and 9.96% (Falco) on a per-execution micro-benchmark. I did not read the paper itself. — [cited in arXiv 2609.13930 §8.2.1](https://arxiv.org/pdf/2609.13930)
- **[measured, cited secondhand]** BPFContain reports 12.69-14.31% on Apache and up to 16.76% on micro-benchmarks; BPFBox reports 1.0-15.0% across Phoronix (as summarized by BPFence). — [arXiv 2609.13930](https://arxiv.org/pdf/2609.13930)
- **[measured, vendor]** Tetragon 1.0: process-execution tracing overhead under 2%, reported as 1.68%, or 2.46% when all events are also written to disk as JSON. — [Isovalent Tetragon 1.0 release](https://isovalent.com/blog/post/tetragon-release-10); [InfoQ summary](https://www.infoq.com/news/2023/11/kubernetes-ebpf-tetragon/)
- **[measured]** BPFence LSM policy with path extraction: nginx −5.5% throughput (see Q2). — [arXiv 2609.13930](https://arxiv.org/pdf/2609.13930)
- **[claim, unsourced blogs]** Falco 1-3% CPU and Tetragon <1% to 2-5%; these conflict with each other and with the measured benchmark above. — [decryptiondigest blog](https://www.decryptiondigest.com/blog/ebpf-runtime-security-tools-falco-tetragon); [ARMO blog](https://www.armosec.io/blog/best-ebpf-security-solutions-runtime-protection/)

### Inferences
- **[inference]** Hooking every `read` with an argument-collecting program that does path or policy matching (as Tetragon's file policies do) is the main way tools blow up overhead. Falco's lower `read` delta is consistent with a lighter per-event path.
- **[inference]** For Pulse, `read`/`write` size histograms must therefore be bare per-CPU increments with no string work and no per-thread lookup.

### Gaps
- No published comparison of the same tool in count-only vs argument-collecting modes.
- No p95 numbers were retrieved from the GitHub benchmark (they are said to be in per-run reports).
- The Her et al. paper was not read directly.
- Pixie, Inspektor Gadget and bpftrace overhead figures were not found within the budget.
