# Sentinel Pulse

Sentinel Pulse is the isolated one-second ML candidate. It does not overwrite
the frozen V8 models, policy evidence, or production detector.

## Data path

1. `cgroup_resolver.py` maps local production pod/container cgroups from CRI.
2. `pulse_counter.bpf.c` counts every syscall and per-task adjacent transition.
3. `pulse_counter_loader` snapshots cumulative maps every second.
4. `capture.py` computes exact deltas and emits 249-dimensional JSONL features.
   `assemble_dataset.py` then admits only rows fully contained in the four
   measured traffic intervals. Legacy node-manifest v1 called the full
   first-to-last campaign span `in_contract_rows`, including transition gaps;
   the assembler verifies that value as `campaign_span_rows` while deriving
   measured rows independently. Node-manifest v2 uses the corrected field name.
5. `train.py` creates one normal-only ExtraTrees temporal model per workload
   and container using a temporal train/calibration split. A sequence is cut
   whenever its cgroup has a gap greater than 1.5 seconds or the preregistered
   traffic regime changes, so history never bridges a transition gap. Decoded
   rows are compacted into contiguous `float32` arrays per sequence instead of
   retaining JSON dictionaries/Python-float lists for the multi-million-row
   campaign.
6. `detect.py` performs one-window decisions and records inference plus
   kernel-window-to-decision latency. Its JSONL follower detects atomic file
   replacement/truncation and resumes at the beginning of the new capture, so
   collector rotation does not strand the detector on an old inode.
   Runtime history uses the same 1.5-second/regime boundary as training;
   temporal gaps trigger warm-up and non-monotonic source windows fail closed.
   The boundary is checksum-bound in the model manifest and validated again by
   both the live runtime and terminal candidate finalizer.
   Every scored decision carries that manifest SHA-256. Normal and blind-attack
   evaluators reject missing/mixed model identities, and finalization requires
   both reports to match the exact bundle being reviewed.
   Normal-soak duration is measured with unique one-second wall-clock buckets,
   not raw replica window count; every workload must cover at least 95% of its
   24-hour span with zero alerts.

No attack sample is accepted by `train.py`. Keep attack captures in a separate
immutable root and hash the normal dataset/model manifest before blind tests.

If an independent normal soak produces an alert, that candidate is terminally
failed and its complete evidence bundle is frozen. The normal observations may
then become development data for a new semantic policy, but they can never be
counted as a passing evaluation. `extend_semantic_envelope.py` verifies the
bundle index, policy/model/run identities, row totals, alert totals and the
absence of blind markers before extending workload maxima:

```bash
python -m sentinel_pulse.extend_semantic_envelope \
  --base-policy sentinel_pulse/protocol/decision-policy-semantic-v3.json \
  --failure-summary failed-evidence/FAILURE_SUMMARY.json \
  --evidence-checksums failed-evidence/SHA256SUMS \
  --decisions failed-evidence/worker1/decisions.jsonl \
  --decisions failed-evidence/worker4/decisions.jsonl \
  --decisions failed-evidence/worker3/decisions.jsonl \
  --output semantic-envelope-extension-v4.json
```

V4 uses that normal-only extension. It still requires a fresh canary and a new
24-hour independent normal soak before the blind attack interlock can open.

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

Create the frozen candidate environment before training:

```bash
python3 -m venv ~/.venvs/sentinel-pulse
~/.venvs/sentinel-pulse/bin/pip install -r sentinel_pulse/requirements-lock.txt
```

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
  --blind-attack-contract sentinel_pulse/protocol/blind-attack-contract.json \
  --training-contract sentinel_pulse/protocol/pulse500-training-contract.json \
  --output models-pulse-candidate

# After terminal bundle verification, install only as an audit-only canary.
# This creates a separate unprivileged service and never replaces V8.
sudo SOURCE_ROOT=/home/dat/eBPF-project \
  MODEL_SOURCE=/path/to/models-pulse-candidate \
  /home/dat/eBPF-project/sentinel_pulse/install_detector_candidate.sh

python -m sentinel_pulse.detect \
  --model-dir models-pulse-candidate \
  --decision-policy sentinel_pulse/protocol/decision-policy-semantic-v4.json \
  --run-id sentinel-pulse-normal-soak-001 \
  --features pulse-live.jsonl \
  --decisions pulse-decisions.jsonl \
  --alerts pulse-alerts.jsonl

python -m sentinel_pulse.evaluate_normal \
  --decisions pulse-normal-decisions.jsonl \
  --soak-marker SOAK_START.json \
  --minimum-scored-windows 86400 \
  --minimum-duration-hours 24 \
  --maximum-alerts 0 \
  --output pulse-normal-soak-report.json

python -m sentinel_pulse.evaluate_latency \
  --decisions worker1-pulse-blind-decisions.jsonl \
  --decisions worker3-pulse-blind-decisions.jsonl \
  --decisions worker4-pulse-blind-decisions.jsonl \
  --injections pulse-blind-injections.jsonl \
  --kernel-events pulse-blind-tetragon-kernel-events.jsonl \
  --attack-contract sentinel_pulse/protocol/blind-attack-contract.json \
  --expected-injections 450 \
  --output pulse-blind-latency-report.json

python -m sentinel_pulse.finalize_candidate \
  --model-dir models-pulse-candidate \
  --decision-policy sentinel_pulse/protocol/decision-policy-semantic-v4.json \
  --soak-marker SOAK_START.json \
  --normal-report pulse-normal-soak-report.json \
  --attack-report pulse-blind-latency-report.json \
  --output pulse-candidate-decision.json
```

Blind latency evaluation must use both `--injections` and `--kernel-events` in
the paper run. The immutable marker set defines the denominator and prevents an
unknown or duplicated ID from inflating recall. The kernel event file binds
each injection to an independently timestamped Tetragon `process_exec` event;
the evaluator recomputes kernel-to-alert latency from `alerted_at` and refuses
to treat the userspace pre-exec marker as kernel latency. The frozen Pulse contract requires the
complete 18-workload x 5-scenario x 5-trial matrix (450 injections); merely
producing 450 unrelated IDs does not pass.

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
