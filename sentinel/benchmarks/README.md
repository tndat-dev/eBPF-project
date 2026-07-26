# Reproducible benchmark protocol

Run the collector on the cluster with `metrics-server` enabled. Record a
no-tracing baseline, Tetragon-only, and full-pipeline phase; never compare a
warm-cache run to a cold run. Store raw command output and the exact git SHA.

Recommended repetitions: 5 runs × 30 seconds for each overhead phase, nginx
`wrk -t4 -c50 -d30s`, and all five attack profiles in each of the three
workloads. Report median and p95/p99, not only averages.

`measure_phase.py` supports both the advisor-requested ApacheBench protocol and
`wrk --latency`. `run_overhead_matrix.sh` executes the three settled phases as a
disconnect-safe transient systemd job and always restores the detector and both
namespaced Tetragon policies. `compare_overhead.py` emits JSON and Markdown with
median effects and deterministic non-parametric bootstrap intervals. Treat
`kubectl top` as a lagged resource snapshot, not request-level causal tracing.
The three overhead phases carry one immutable `experiment_id`; comparison code
refuses to combine stale phase directories from different matrix runs.

`runtime_attack.c` is the preferred end-to-end attack source. Compile it on
the cluster host, copy it into a monitored test pod, and run one named mode for
at least two detector windows. It generates real syscalls inside the container,
while deliberately invalid arguments and loopback-only connections prevent the
test from mounting, escalating privileges, opening a shell, mining, or sending
data off-pod. This distinguishes a kernel-to-model test from the in-process
Python simulator used by unit/regression tests.
