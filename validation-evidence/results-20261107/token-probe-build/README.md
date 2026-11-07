# Token probe build of 07/11 (commit 46e9039) on the three workers

`/home/dat/pulse-tokens-20261107/{build,proof,volume}` on k8s-worker1, -3, -4: `make tokens` from the repository
checkout at 46e9039, then:

- `*/START.json`, `*/RESULTS.json`: `scripts/token_probe_proof.py` (sys_exit mode), valid on all three: one token per
  syscall (405,932 / 363,948 / 367,020 calls), expected token values, seccomp path as the matched proof. The worker
  binds a run to this proof (kernel + artifact hashes).
- `*/volume.json`, `*/summary.txt`: `scripts/analysis/token_probe_volume.py` on 150 s of the probe on the real
  production allow-list (82 / 82 / 31 cgroups), no live run active: token lines 290 / 285 / 75 KB/s (gzip about 9x),
  drain median 6 / 6 / 2 ms, max 15 ms, no gram insert failure; per workload median 4-277 distinct grams per window, max
  about 830. First directories decode to container paths (/usr 85,196, /etc 9,420, /proc 5,930 of the opens on
  k8s-worker1); 7,989 opens resolve outside the task's root ("rel": pseudo files reopened through /proc), which the
  offline LID-DS tokens never had.
