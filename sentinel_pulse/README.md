# V9 Sentinel Pulse

V9 Sentinel Pulse is the isolated one-second ML candidate. It does not overwrite
the frozen V8 models, policy evidence, or production detector.

## Data path

1. `cgroup_resolver.py` maps local production pod/container cgroups from CRI.
2. `pulse_counter.bpf.c` counts every syscall and per-task adjacent transition.
3. `pulse_counter_loader` snapshots cumulative maps every second.
4. `capture.py` computes exact deltas and emits 249-dimensional JSONL features.
5. `train.py` creates one normal-only ExtraTrees temporal model per workload
   and container using a temporal train/calibration split. A sequence is cut
   whenever its cgroup has a gap greater than 1.5 seconds or the preregistered
   traffic regime changes, so history never bridges a transition gap. Decoded
   rows are compacted into contiguous `float32` arrays per sequence instead of
   retaining JSON dictionaries/Python-float lists for the multi-million-row
   campaign.
6. `detect.py` performs one-window decisions and records inference plus
   kernel-window-to-decision latency.

No attack sample is accepted by `train.py`. Keep attack captures in a separate
immutable root and hash the normal dataset/model manifest before blind tests.

## Node build

```bash
cd sentinel_pulse/ebpf
make
sudo python3 -m sentinel_pulse.cgroup_resolver \
  --allow-file /run/sentinel-pulse/allowed-cgroups \
  --metadata-file /run/sentinel-pulse/cgroups.json --once
sudo ./pulse_counter_loader --object pulse_counter.bpf.o \
  --allow-cgroup-file /run/sentinel-pulse/allowed-cgroups \
  --interval-ms 1000
```

The loader refuses to attach when the target file is empty. It has no
host-wide fallback. The task-state error counter and compact-snapshot integrity
counter must stay zero, and resolved target coverage must be complete.

For a worker prepared with clang, bpftool and libbpf headers, the idempotent
node installer builds against that node's BTF and starts only the resolver and
collect-only service:

```bash
sudo SOURCE_ROOT=/home/dat/eBPF-project \
  /home/dat/eBPF-project/sentinel_pulse/install_node.sh
```

The production V8 detector is not stopped or modified by this installer.

Roll out one worker first. After installation, run the bounded canary gate;
only a valid report permits installation on the remaining workers:

```bash
sudo /home/dat/eBPF-project/sentinel_pulse/smoke_node.sh
```

From a terminal that can reach the private cluster, the guarded rollout is:

```bash
./sentinel_pulse/deploy_canary_cluster.sh
```

It does not use `rsync --delete`, does not touch V8, and refuses the remaining
workers unless the canary report has `valid=true`.

`k8s/tetragon-pulse-detail-policy.yaml` is an A/B candidate, not a default
dependency. Never apply it while `sentinel-aims-syscalls` is present: the two
policies hook the same calls and would duplicate detailed events. Pulse exact
counts and ML windows work with the frozen V8 policy left at 1 second.

## Capture and validation

```bash
# On the control plane, start this as a transient/background systemd unit.
# It freezes absolute timestamps before changing the first measured regime.
sudo systemd-run --unit=sentinel-pulse-capture-campaign \
  --property=WorkingDirectory=/home/dat/eBPF-project \
  /home/dat/eBPF-project/sentinel_pulse/run_capture_campaign.sh

sudo ./pulse_counter_loader --object pulse_counter.bpf.o \
  --allow-cgroup-file /run/sentinel-pulse/allowed-cgroups \
  --interval-ms 1000 | \
python -m sentinel_pulse.capture \
  --metadata-file /run/sentinel-pulse/cgroups.json \
  --output pulse-normal.jsonl

python -m sentinel_pulse.validate_capture \
  --capture pulse-normal.jsonl \
  --minimum-rows-per-workload 100 \
  --output pulse-normal.validation.json
```

## Train and dry-run

```bash
python -m sentinel_pulse.assemble_dataset \
  --contract pulse-capture-contract.json \
  --capture k8s-worker1.local=worker1-features.jsonl \
  --capture k8s-worker3.local=worker3-features.jsonl \
  --capture k8s-worker4.local=worker4-features.jsonl \
  --capture-manifest k8s-worker1.local=worker1-capture-manifest.json \
  --capture-manifest k8s-worker3.local=worker3-capture-manifest.json \
  --capture-manifest k8s-worker4.local=worker4-capture-manifest.json \
  --output pulse-normal.jsonl

python -m sentinel_pulse.train \
  --dataset pulse-normal.jsonl \
  --output models-pulse-candidate

python -m sentinel_pulse.detect \
  --model-dir models-pulse-candidate \
  --features pulse-live.jsonl \
  --decisions pulse-decisions.jsonl \
  --alerts pulse-alerts.jsonl

python -m sentinel_pulse.evaluate_normal \
  --decisions pulse-normal-decisions.jsonl \
  --minimum-scored-windows 86400 \
  --minimum-duration-hours 24 \
  --maximum-alerts 0 \
  --output pulse-normal-soak-report.json

python -m sentinel_pulse.finalize_candidate \
  --model-dir models-pulse-candidate \
  --normal-report pulse-normal-soak-report.json \
  --attack-report pulse-blind-latency-report.json \
  --output pulse-candidate-decision.json
```

Blind latency evaluation must use `--injections` in the paper run. The
immutable marker set defines the denominator and prevents an unknown or
duplicated ID from inflating recall.

The default `alpha=1e-4` requires at least 9,999 independent calibration
examples per workload candidate. Training fails closed when the temporal split
cannot provide that p-value resolution. A zero observed alert count is reported
with its Wilson 95% upper bound; it is never described as proof of zero future
false positives.

The finalizer never promotes a detector. Passing creates only an
`eligible_for_overhead_evaluation` decision; counterbalanced overhead,
independent reproduction and manual review remain mandatory.

Promotion requires the gates in `SENTINEL_PULSE_REPORT.md`; successful build or
short smoke testing alone is not a latency, recall, or false-positive claim.
