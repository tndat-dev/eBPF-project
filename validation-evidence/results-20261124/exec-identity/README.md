# exec-identity-v1 probe checks (24/11)

Protocol `sentinel_pulse/protocol/exec-identity-v1.json` (registered 24/11 16:53 +07). Probe build
`pulse-tokens-prog-bee57bf` (`sentinel_pulse/ebpf/pulse_counter.bpf.c`, `pulse_tokens.bpf.h`,
`pulse_counter_loader.c`, `sentinel_pulse/collector/token_capture.py`).

**Proofs** (workers 1, 3, 4): `token_probe_proof` valid on the three workers (worker1 452,012 tokens = 452,012
syscalls); `scripts/lineage_probe_proof.py` valid on the three workers, with the program checks (sh, ls, cat carried
by the session part; the orphan phase stays session; native threads keep program 0).

**Overhead** (protocol `overhead-ab-v1`, benchmarks getpid, read, futex, open+close, mmap+munmap, forkwait):

- `overhead-ab.json` (`overhead-k8s-worker*.local.jsonl`): the first run had seven conditions over five rounds; its
  order was not balanced and the new build looked 2-9 % slower (18/18 points positive, 3 intervals above 0).
- `overhead2-ab.json` (`overhead2-k8s-worker*.local.jsonl`): balanced rerun with three conditions (off, the final
  build `tokD_base`, the new build `tokD`) over nine rounds: new against final build -2.9 % to +2.7 % over 18
  node x benchmark points, **0/18 95 % intervals above 0**. No measurable added cost.
