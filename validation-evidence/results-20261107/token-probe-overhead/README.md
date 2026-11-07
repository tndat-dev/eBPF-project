# Overhead of the lidds-ml-v3 token probe (protocol `token-probe-overhead-v1` + amendment 1)

Runner `scripts/overhead_ab.sh`, analysis `scripts/analysis/overhead_ab.py`, benchmark `testbed/bench/syscall_bench.c`,
three workers at the same time, 5 rounds, conditions rotated each round. Ablation stage 2 ran on `.234` throughout.

- `*.fexit-run1.jsonl`, `overhead-run1-fexit.json`: first measurement, 07/11 09:46-10:23, token exit by one `fexit`
  trampoline per hooked syscall. Conditions off / filtered / monitored (= A) / tokB / tokC / tokD / tokD_filtered.
- `hookcost.jsonl`, `hookcost2.jsonl`: diagnostic on k8s-worker1 (benchmark not monitored, `PULSE_TOK_SKIP` drops
  named hooks): open + close is slower with the 37 other trampolines attached even when its own three hooks are
  dropped, and costs nothing with every token hook dropped; cause: Tetragon's kprobes on `__x64_sys_openat` route it
  through `arch_ftrace_ops_list_func`, which walks every ftrace_ops (one per trampoline).
- `proof-check-*-worker1.json`: `scripts/token_probe_proof.py` on an uncommitted build, both exit modes: exactly one
  token per syscall, expected token values, seccomp path as the matched proof.
- `*.run2.jsonl`, `overhead-run2.json`: second measurement (amendment 1), `--token-exit sys_exit` default for
  tokB/C/D, plus tokDfx / tokDfx_filtered in fexit mode.
- `hookcost3.jsonl`: diagnostic, sys_exit mode, benchmark not monitored: fentry/security_file_open alone costs about
  380 ns per open + close (medians off 8,618, sys_exit 9,585, without that hook 9,205 ns).
- `proof-check-dentry-*-worker1.json`: proof of the dentry-walk build (no fentry), both modes valid.
- `*.run3.jsonl`, `overhead-run3.json`: third measurement (amendment 2), dentry-walk build, sys_exit mode.

Summary, added ns per op over condition A (three workers; `*_vs_monitored` in the JSON):

| mode | run 1 fexit (tokD) | run 2 sys_exit (tokD) | run 3 final (tokD) |
|---|---|---|---|
| getpid | 32-39 | 101-131 | 127-174 |
| read4k | 226-349 | 187-199 | 210-229 |
| openclose | 2,349-2,719 | 1,090-1,459 | 943-1,229 |
| mmapunmap | -143-275 | 331-661 | 413-699 |
| futex | 277-316 | 293-317 | 216-298 |
