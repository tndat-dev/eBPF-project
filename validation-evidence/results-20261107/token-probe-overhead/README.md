# Overhead of the lidds-ml-v3 token probe (protocol `token-probe-overhead-v1` + amendment 1)

Runner `scripts/overhead_ab.sh`, analysis `scripts/analysis/overhead_ab.py`, benchmark `testbed/bench/syscall_bench.c`,
three workers at the same time, 5 rounds, conditions rotated each round. Ablation stage 2 ran on `.234` throughout.

- `*.fexit-run1.jsonl`, `overhead-run1-fexit.json`: first measurement, 07/11 09:47-10:25, token exit by one `fexit`
  trampoline per hooked syscall. Conditions off / filtered / monitored (= A) / tokB / tokC / tokD / tokD_filtered.
- `hookcost.jsonl`, `hookcost2.jsonl`: diagnostic on k8s-worker1 (benchmark not monitored, `PULSE_TOK_SKIP` drops
  named hooks): open + close is slower with the 37 other trampolines attached even when its own three hooks are
  dropped, and costs nothing with every token hook dropped; cause: Tetragon's kprobes on `__x64_sys_openat` route it
  through `arch_ftrace_ops_list_func`, which walks every ftrace_ops (one per trampoline).
- `proof-check-*-worker1.json`: `scripts/token_probe_proof.py` on an uncommitted build, both exit modes: exactly one
  token per syscall, expected token values, seccomp path as the matched proof.
- `*.run2.jsonl`, `overhead-run2.json`: second measurement (amendment 1), `--token-exit sys_exit` default for
  tokB/C/D, plus tokDfx / tokDfx_filtered in fexit mode.
