# Runtime regression results

Date: 2026-07-22. Cluster: three-node kubeadm, Tetragon 1.6.1 and Cilium
1.19.3. Candidate: phase-stratified V7 trained from 100 Postgres, 100 Nginx and
95 Redis real 30-second windows. Isolation remained deliberately in
audit/dry-run mode.

`runtime_attack.c` was compiled as a static binary and executed inside each of
the monitored Nginx, Redis and Postgres containers. The tests therefore cover
real container syscalls, Tetragon export, all three node streams, event-time
windowing, model inference and alert emission. Invalid arguments and
loopback-only destinations make the generator non-destructive.

| Workload | Scenario | Detected | Score | Kernel-to-alert | Median inference |
|---|---|---:|---:|---:|---:|
| production/nginx | Reverse shell | yes | 1.000 | 58.026 s | 19.499 ms |
| production/nginx | Container escape | yes | 1.000 | 58.214 s | 20.341 ms |
| production/nginx | Cryptomining | yes | 1.000 | 58.213 s | 20.532 ms |
| production/nginx | Privilege escalation | yes | 1.000 | 58.008 s | 18.735 ms |
| production/nginx | Data exfiltration | yes | 1.000 | 57.929 s | 18.608 ms |
| production/redis | Reverse shell | yes | 1.000 | 58.005 s | 22.174 ms |
| production/redis | Container escape | yes | 1.000 | 58.499 s | 21.405 ms |
| production/redis | Cryptomining | yes | 1.000 | 57.141 s | 19.456 ms |
| production/redis | Privilege escalation | yes | 1.000 | 57.851 s | 18.285 ms |
| production/redis | Data exfiltration | yes | 1.000 | 57.934 s | 21.972 ms |
| default/postgres | Reverse shell | yes | 1.000 | 57.084 s | 26.661 ms |
| default/postgres | Container escape | yes | 1.000 | 57.092 s | 30.552 ms |
| default/postgres | Cryptomining | yes | 1.000 | 57.331 s | 25.927 ms |
| default/postgres | Privilege escalation | yes | 1.000 | 58.049 s | 16.520 ms |
| default/postgres | Data exfiltration | yes | 1.000 | 57.835 s | 20.678 ms |

- Detection rate: 15/15 for this immutable regression matrix.
- Latency: median 57.934 s, p95 58.300 s, p99 58.459 s and maximum 58.499 s.
  Requiring two consecutive 30-second windows intentionally bounds latency near
  60 seconds.
- All 15 trials had zero normal alerts before injection, an acknowledged
  in-container start, a zero generator/detector exit code and at least six
  inference callbacks. Independent measured and telemetry latency clocks agreed
  within 0.000306 seconds.
- The runtime binary was removed from the pod after the test, including on
  failure paths.

The independent post-training normal matrix retained 44 observed windows for
each workload. It produced zero detections, zero score-only threshold
exceedances and maxima of 0.2664, 0.6435 and 0.2246 for Postgres, Nginx and
Redis, respectively. A 200-iteration cProfile run measured 31.34 ms mean for a
complete detector callback, including preprocessing, both model diagnostics,
threshold/gate evaluation and telemetry.

After atomic promotion and service restart, a clean 7.5-minute production soak
added 15 windows per workload. All 45 decisions were normal, with no alert,
raw score crossing, behavior-gate crossing or actionable pair. Score maxima
were 0.1515 (Postgres), 0.0842 (Nginx) and 0.0912 (Redis); p99 ingest lag was
below 1.75 seconds. An earlier soak report was deliberately marked invalid
after unit-test telemetry was found in the shared JSONL file; tests were moved
to isolated temporary telemetry paths and the soak was rerun from a fresh
timestamp.

This is evidence for the tested workloads and attack implementations, not a
mathematical guarantee of a universal 0% false-positive rate. Runtime action
requires score >= the per-workload threshold, a workload-conditioned kernel
behavior crossing and two consecutive actionable windows. Online calibration
accepts only windows below the offline threshold and below the behavior gate,
preventing score outliers from poisoning the learned threshold.
