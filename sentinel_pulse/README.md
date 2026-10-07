# Sentinel Pulse

## Current status

The active observation campaign is `pulse-observation-c1-20261006`.
Its frozen worker runtime/model/policy are separate from the current reporting
checkout. See [live status](../SOAK_OBSERVATION_STATUS.md) and
[incident evidence](../SOAK_INCIDENTS.md); do not use archived checkpoints below
to decide whether a service is running.

The current path is projected exact counters, 500 ms snapshots, 249 features,
three prior windows plus the current window (996 inputs), per-workload/container
ExtraTrees and conformal calibration, followed by the frozen decision policy.
The campaign retains alerts and valid exposure across recovery, does not stop
on quality-budget violations, and does not automatically train/promote.

Read-only progress/alert review of a copied inspection snapshot:

```bash
python -m sentinel_pulse.review_observation \
  --inspection validation-evidence/soak-inspection-20261007/inspection.json
```

This review retains alerts outside admitted normal exposure, reports wall and
bottleneck exposure progress separately, and leaves precision/recall/FPR null.
It does not audit raw seals or replace the campaign coordinator/finalizer.

Syscall selection evidence (ABI, collector/Python order, observed counts and
existing normal-only ablation; no new model fitting):

```bash
python -m sentinel_pulse.verify_syscall_selection \
  --analysis validation-evidence/syscall-analysis-20261006/analysis-worker4.json \
  --ablation validation-evidence/syscall-analysis-20261006/ablation.json
```

See [syscall analysis](../syscall_analysis.md). The 29-call list is an
engineering hypothesis, not a measured optimal subset. The future histogram
and blind comparison plan is `protocol/syscall-selection-evaluation-v1.json`;
it is not executed and does not attach probes/change the frozen active soak.

An isolated exploratory stage is implemented in `syscall_feature_experiment`:
32 retrained variants per workload (full, 29 leave-one-explicit-channel-out,
no explicit channels, and top-16 training frequency proxy plus sensitive
whitelist). It uses copied checksum-bound normal training/context inputs,
requires a clean frozen Git checkout, and never loads/deploys live model
artifacts. All four temporal positions are masked identically. Bins and
aggregates remain, so this is not removal of all information about an ID.
Normal raw-anomaly fractions are not adjudicated FP/precision/attack recall.

```bash
python -m sentinel_pulse.syscall_feature_experiment \
  --inputs /path/to/verified/offline-inputs \
  --output /path/to/new/experiment-run
```

Outputs bind source, inputs, software and masks in `START.json`, preserve
per-context scores/p-values for paired follow-up, and incrementally write
`STATUS.json`/`RESULTS.json`. The independent holdout was already inspected:
this stage is exploratory, not a new blind confirmation or promotion gate.

## Archived checkpoints and legacy contracts

The following old checkpoints are historical, not current status. The run from
2026-10-05 ended early; its old ACTIVE statements and review schedules are not
valid now. Legacy zero-alert gates do not control the current observation
campaign. Old V8 isolation statements describe the original design.

SSH/receipts reviewed on 2026-10-05. Update this block in place, keep raw
evidence separately. **Formal recovery soak is now running in the background**:
`pulse-recovery-formal-c1-20261005`, registered09:06:19 ICT,89880s/node,
diagnostic_only=false. All3 worker legs active/tail ready,0 detector restarts,
dependency health not degraded at START receipt; union21/21 model keys.

Frozen coordinator source remains`1c03987`; model249/history3/alpha0.001
and the21 ExtraTrees models/policy are unchanged. An external source-hashed
capacity guard preregisters used<90%/available>0, probes every30s and limits
unknown observations to60s. No fixed64GiB reserve, deletion or pod shutdown;
no retroactive changes to old85% contracts. It only stops its owned child
and does not issue formal PASS.

The180s/node guard diagnostic completed09:04:50 ICT:23413 decisions,
19812 scored,0 alerts; retain433 suppressed,2791 degraded and810 warming.
3 valid node reports; coordinator12/12 and guard4/4 seal digests match.
Union scored exposure0.93272273workload-hours is NOT24h/key or zero-FPR proof.
Main+guard tests: subset168 host/VM, full host892+20subtests/7skip,
VM933+20subtests; optional dependencies differ.

No formal terminal/PASS or blind attack evidence yet. Kernel-to-alert1–2s
is an **unmeasured target**. Review around10:40 ICT2026-10-06, allowing for
finalization, not guaranteeing success. Blind evaluation/promotion remain
manual and closed.

[Formal START receipt](../validation-evidence/recovery-formal-c1-20261005/START_REMOTE_RECEIPT.json),
[guard diagnostic terminal](../validation-evidence/recovery-capacity-c1-20261005/TERMINAL_REMOTE_RECEIPT.json),
[tests](../validation-evidence/recovery-capacity-c1-20261005/TEST_RECEIPT.json),
[real flow and all249 features](../SENTINEL_PULSE_LUONG_VA_MINH_CHUNG.md).
Historical SSH review 2026-10-04 22:17 ICT: the three-worker recovery coordinator
is deployed on frozen source `dd872e7`. A new 600s/node diagnostic registered
22:16:03 covers a union of21/21 model keys. All3 worker legs active/tail ready,
0 detector restarts; coordinator monitoring, dependency health not degraded.
Parallel bounded probes, audit journals and streaming finalization are wired;
no terminal end-to-end verdict or24h formal PASS yet. Review around22:30 ICT.
Host832 tests +20 subtests pass (7 skips); VM873 +20 pass (optional dependencies
differ). Frozen model/policy unchanged; no automatic blind/promotion.
[Live receipt](../validation-evidence/recovery-fleet-diagnostic-c1-20261004/START_REMOTE_RECEIPT.json),
[lifecycle status](../PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md).

Historical SSH review 2026-10-04 21:40–21:50 ICT: fault diagnostic C1 finished
18:49:02, exit0.19 run +3 registration +177 source checksums verified;
independent replay matches the frozen report.80,084 decisions/78,779 scored
rows/19 keys/0 alerts; preserve769 degraded and536 warming rows. One actual
quarantine-to-clean recovery; final availability0.999437254 passes0.999 floor.
Window-start to post-policy decision p99 1.132s/max1.351s is conditional on
fresh scored rows; excludes output flush and is NOT kernel-to-alert. Candidate
and experiment stopped; control/resolver active. No remaining job for this run.

New formal freshness/attestation installer bridge and worker launcher pass
557 tests +20 subtests on host/VM. The three-worker SSH/systemd coordinator
and end-to-end finalization are not integrated yet; no formal recovery soak
or PASS. Model/calibration/policy unchanged; blind/promotion closed.
[Terminal receipt](../validation-evidence/recovery-fault-smoke-c1-20261004/TERMINAL_REMOTE_RECEIPT.json).

Latest SSH review 2026-10-04: recovery C2 smoke completed; **formal recovery
lifecycle is not integrated and no formal recovery soak is running**.
[Current status/evidence](../PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md).

Checkpoint 2026-10-04: pressure C2 rejected at00:02:31 ICT:179,034 decisions,
one Redis Sentinel alert. Worker4 also failed capture validation (13.209s gap,
availability0.990699). Preserve the alert and verdict; no infrastructure excuse
or FPR-zero claim. All three observers completed with23 verified checksums/node.
Recovery worker installers/unit rendering and a separate runtime smoke evaluator
are implemented; formal recovery lifecycle/exposure integration is still missing.
Old02:10 review schedules below are historical.
[Incident and implementation](../docs/archive/PULSE_PRESSURE_C2_INCIDENT_20261004.md).

Latest checkpoint, 2026-10-03 ~23:40 ICT: opt-in telemetry quarantine/replay
core tested on host/VM (435 tests +20 subtests), frozen source `936d3df`.
NOT yet integrated into the formal operational lifecycle. Frozen model/policy
unchanged. Pressure diagnostic C1 was rejected; its observers failed126 before
sampling. New launcher verifies actual clock samples, sar data and source
hashes. Observer C2 ready3/3 from23:36; ML diagnostic C2 START23:37:48,
7200s, legacy telemetry gates, no recovery enabled. Next terminal review around
02:10 ICT2026-10-04. No FPR/recall/kernel-to-alert claim.
See [recovery implementation and remaining work](../PULSE_TELEMETRY_RECOVERY.md).

Terminal verified 2026-10-03 11:50:47 ICT: projected ML canary completed valid,
114,984 decisions, 21/21 keys, zero alerts/restarts. START 10/10 and FINAL
76/76 checksums verified. Inference p99 30.092 ms; window start to post-model
timestamp p99 1.053 s excludes policy/output, not kernel-to-alert. Candidate
stopped; control collectors restored. Preparing a fresh projected operational
soak with frozen model/policy and collector provenance bound at launch,
resume and every monitor poll. Earlier ACTIVE checkpoints below are historical.

Latest checkpoint (2026-10-03, 10:15 ICT): a new projected-counter ML canary
is active on all three workers with the frozen R10-C1 model/policy. Main
regression passed 375 tests and 20 subtests on host and VM. Control collector
binaries remain checksum-identical; projected binaries are private to the
experiment run. See [ML canary](../docs/archive/PROJECTED_ML_CANARY_20261003.md).
The 10:02 collector-only checkpoint below is historical; ML is no longer
inactive. This new canary is non-formal/audit-only, not an operational pass.

Current update (2026-10-03): R10-C3 was infrastructure-rejected, archived and
stopped; it is not a passing normal/operational gate. Worker1's opt-in projected
counter canary passed a full collector safety review; worker3/4 canaries are
terminal with valid full captures at 09:59 ICT; final source/duration/coverage
reviews passed on both nodes around 10:01 ICT: all three collector safety
reviews passed, 117,412 rows and observed union coverage of 21 keys.
There is no outstanding collector canary/review job. Pulse ML candidate is
inactive, production/control binaries unchanged. Main source regression passed
370 tests and 20 subtests on both host and VM. See
[projected counter evidence](../docs/archive/PROJECTED_COUNTER_CANARY.md).
[Operational soak](../OPERATIONAL_SOAK_RUNBOOK.md) is opt-in and never opens
the legacy blind/promotion interlock. See the
[249-feature layout](../SENTINEL_PULSE_FEATURES_249.md) and
[V8 model retirement](../docs/archive/V8_MODEL_RETIREMENT.md); references to preserving V8
below describe the original isolation design, not currently installed artifacts.

Sentinel Pulse is the isolated one-second ML candidate. It does not overwrite
the frozen V8 models, policy evidence, or production detector.

## Projected collector safety review

`make -C sentinel_pulse/ebpf projected` builds a separate loader/object; the
default target remains legacy. Do not mix the two map ABIs or install the
experimental collector just because a short canary tail is valid.

Review a completed capture with explicit **node-local** expected workload keys,
not the fleet's full 21-key list or a list inferred from observed rows:

```bash
python -m sentinel_pulse.evaluate_projected_counter_canary \
  --run-dir /var/lib/sentinel-pulse-projection-canary/<run-id> \
  --expected-workload-keys /path/to/node-expected-keys.json \
  --output /path/to/fresh-safety-review.json
```

The expectation used for worker1 is registered start metadata intersected with
the frozen manifest keys; its 16-key list and review are under
`validation-evidence/projected-counter-c1-20261002/`. The evaluator rereads raw
capture, binds its checksum and registered artifacts, verifies duration within
2-second startup slack, checks coverage and rejects nonzero integrity/cadence
counters. Output uses exclusive creation. It never trains/promotes a model or
converts collector-only results into ML accuracy/latency evidence.

## Current data path

1. `cgroup_resolver.py` maps local production pod/container cgroups from CRI.
2. The projected eBPF collector counts syscall entry attempts and per-task
   adjacent transitions for allowed production cgroups, with integrity checks.
3. `pulse_counter_projected_loader` snapshots the maps every 500 ms in the
   active observation segments.
4. `capture.py` computes exact deltas and emits 249-dimensional JSONL features.
   `assemble_dataset.py` then admits only rows fully contained in preregistered
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
6. `detect.py` scores temporal contexts and applies the frozen semantic/temporal
   policy. It records inference and feature/window-to-decision timing, not
   measured blind kernel-to-alert latency. Its JSONL follower detects atomic file
   replacement/truncation and resumes at the beginning of the new capture, so
   collector rotation does not strand the detector on an old inode.
   Runtime history uses the same 1.5-second/regime boundary as training;
   temporal gaps trigger warm-up and non-monotonic source windows fail closed.
   The boundary is checksum-bound in the model manifest and validated again by
   both the live runtime and terminal candidate finalizer.
   Every scored decision carries that manifest SHA-256. Normal and blind-attack
   evaluators reject missing/mixed model identities, and finalization requires
   both reports to match the exact bundle being reviewed.
   Current observation exposure is the union of eligible scored intervals
   across replicas/nodes, not raw row counts. Missing intervals remain unknown,
   alerts are retained, and quality-budget failures do not stop the campaign.

No attack sample is accepted by `train.py`. Keep attack captures in a separate
immutable root and hash the normal dataset/model manifest before blind tests.

## Legacy zero-alert evaluation path

The following gates/extensions are kept for reproducibility of older runs.
They are not the control policy of the active observation campaign.

Before another 24-hour normal soak, a 15-minute live-normal coverage preflight
must pass for every workload key. The ingress generator paces requests across
second boundaries at approximately the same steady throughput; the preflight
requires zero alerts/restarts, all expected model workloads, at least 300
seconds of observed span, and at least 95% unique second-bucket coverage per
workload. A coverage failure cannot be fixed by lowering the preregistered 95%
threshold or by tuning the frozen model/policy.

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

Per-CPU map copies can intersect the adjacent `total` and syscall-bin writes
of a hot cgroup. The loader therefore retries a torn read at most 32 times,
with a 50 microsecond phase-changing delay between attempts. It exports the
cumulative diagnostic `snapshot_consistency_retries`; this may be non-zero.
`snapshot_consistency_retry_exhausted` and the resulting
`target_snapshot_gap` remain hard integrity failures and may never be waived
by the telemetry-availability budget.

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

# Fail closed before fitting if alpha cannot be represented for every workload.
python -m sentinel_pulse.audit_calibration_coverage \
  --dataset pulse-normal.jsonl \
  --history 3 \
  --alpha 0.001 \
  --window-seconds 0.5 \
  --output pulse-calibration-coverage.json

python -m sentinel_pulse.freeze_training_contract \
  --dataset pulse-normal.jsonl \
  --blind-attack-contract sentinel_pulse/protocol/blind-attack-contract.json \
  --candidate-id sentinel-pulse-500ms-candidate-a2-pilot \
  --evidence-class nonformal_runtime_compatibility_pilot \
  --history 3 \
  --alpha 0.001 \
  --window-seconds 0.5 \
  --output pulse-training-contract.json

python -m sentinel_pulse.train \
  --dataset pulse-normal.jsonl \
  --blind-attack-contract sentinel_pulse/protocol/blind-attack-contract.json \
  --training-contract pulse-training-contract.json \
  --output models-pulse-candidate

python -m sentinel_pulse.calibrate_semantic_envelope \
  --dataset pulse-normal.jsonl \
  --output semantic-envelope-calibration.json

python -m sentinel_pulse.build_semantic_policy \
  --calibration semantic-envelope-calibration.json \
  --model-manifest models-pulse-candidate/manifest.json \
  --training-contract pulse-training-contract.json \
  --base-policy sentinel_pulse/protocol/decision-policy-semantic-v4.json \
  --policy-name pulse-normal-envelope-one-window \
  --evidence-class nonformal_runtime_compatibility_pilot \
  --output decision-policy-pulse.json

# If a later model accidentally drops a temporal control that was already
# frozen from earlier normal-only evidence, transfer only that control
# structure.  The target model, score calibration, and semantic maxima remain
# unchanged.  This command does not consume the rejected target holdout and
# the resulting candidate must repeat independent canary/formal validation.
python -m sentinel_pulse.build_prior_confirmation_policy \
  --base-policy decision-policy-pulse.json \
  --confirmation-template \
    sentinel_pulse/protocol/decision-policy-temporal-b7.json \
  --policy-name sentinel-pulse-500ms-r9-c2 \
  --output decision-policy-r9-c2.json

# manifest.json records source_clean, the porcelain status, and a SHA-256 over
# the complete tracked diff plus every untracked source file. A dirty pilot is
# therefore explicit and reproducible; it must never be described as a clean
# release candidate merely because source_git_commit matches a tagged commit.
# Contract v2 additionally refuses training if that source fingerprint changes
# after the read-only contract is frozen.
# Decision-policy schema v2 binds the normal dataset, semantic calibration,
# model, training contract and base-policy checksums directly. It rejects an
# incomplete workload envelope and records that blind outcomes were not used.

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

For a bounded non-formal live-normal canary, finalize each worker only after
the finite 500 ms collector exits, then archive each immutable run directory
under its Kubernetes node name. Aggregate the archived raw decisions with:

```bash
python -m sentinel_pulse.aggregate_live_canary \
  --node-root k8s-worker1.local=/evidence/nodes/k8s-worker1.local \
  --node-root k8s-worker3.local=/evidence/nodes/k8s-worker3.local \
  --node-root k8s-worker4.local=/evidence/nodes/k8s-worker4.local \
  --expected-model "$MODEL_MANIFEST_SHA256" \
  --expected-policy "$DECISION_POLICY_SHA256" \
  --output /evidence/AGGREGATE.v2.json
```

The v2 aggregator verifies every per-node checksum manifest, model/policy
identity, decision count, zero detector restarts, and `node_name` on every
scored decision. Legacy warming rows may lack provenance; current runtime code
now emits node/pod/container identity for warming and collect-only rows too.
This aggregate is still a short non-formal normal observation and explicitly
does not create an FPR, recall, or promotion claim.

For a formal normal-only soak with at least 24 measured hours (the current
default is 25 hours) that must not open a blind contract, run the candidate
lifecycle with `STOP_AFTER_NORMAL=true`. The lifecycle keeps the
cluster, storage, maintenance, detector-restart and zero-alert gates active,
then freezes normal evidence and exits before `normal_pass_blind_interlock_open`:

```bash
SSHPASS=... STOP_AFTER_NORMAL=true SUSPEND_CONTROL_COLLECTOR=true \
MODEL_SOURCE=/absolute/path/inside/the/worktree/to/frozen-model \
POLICY_SOURCE=$PWD/sentinel_pulse/protocol/decision-policy-temporal-b3.json \
NORMAL_RUN_ID=SENTINEL_PULSE_B3_SOAK_ID \
NORMAL_EVIDENCE_ROOT=/home/dat/sentinel-pulse-evidence/blind-b1/SENTINEL_PULSE_B3_SOAK_ID \
./sentinel_pulse/run_500ms_candidate_lifecycle.sh
```

`MODEL_SOURCE` and `POLICY_SOURCE` are mandatory identities. The lifecycle and
normal finalizer deliberately have no default decision policy, so an omitted
environment variable cannot silently bind a candidate to an older policy.
Each normal run also holds a non-blocking single-writer lock. On resume, the
supplied manifest and policy hashes must match `SOAK_START.json` before any
monitor or finalizer executes.

For the B4 group-specific confirmation candidate, use the frozen B4 worktree
and keep normal and blind phases separate. B4 retains the same model bundle;
it requires three consecutive `local_socket_beacon` windows, two consecutive
windows for other common groups, and immediate bypass only for
`identity_transition` and `namespace_probe`. The persistent supervisor stores
the explicit policy, stop-after-normal flag, collector isolation, duration and
preflight intervals in its root-only environment file:

```bash
sudo env SSHPASS=... LIFECYCLE_ID=b4-r1 \
  LOCAL_ROOT=/home/dat/eBPF-project-runtime-pulse-b4 \
  MODEL_SOURCE=/home/dat/eBPF-project-runtime-pulse-b4/.runtime-artifacts/sentinel-pulse-a2-b4-model \
  POLICY_SOURCE=/home/dat/eBPF-project-runtime-pulse-b4/sentinel_pulse/protocol/decision-policy-temporal-b4.json \
  STOP_AFTER_NORMAL=true SUSPEND_CONTROL_COLLECTOR=true \
  DURATION_SECONDS=90000 PREFLIGHT_STABILITY_SECONDS=300 \
  NORMAL_RUN_ID=SENTINEL_PULSE_B4_NORMAL_ID \
  NORMAL_EVIDENCE_ROOT=/home/dat/sentinel-pulse-evidence/blind-b4/SENTINEL_PULSE_B4_NORMAL_ID \
  BLIND_RUN_ID=SENTINEL_PULSE_B4_BLIND_ID \
  BLIND_EVIDENCE_ROOT=/home/dat/sentinel-pulse-evidence/blind-b4/SENTINEL_PULSE_B4_BLIND_ID \
  STATE_ROOT=/home/dat/sentinel-pulse-evidence/blind-b4 \
  /home/dat/eBPF-project/sentinel_pulse/install_candidate_lifecycle_service.sh
```

Do not use the lifecycle's generic blind phase for B4. After an independent
normal pass, invoke `open_b4_blind_after_normal.sh`; it verifies the normal
marker, model/policy hashes, clean tracked runtime and preregistered B4 blind
contract before any injection.

B4 was rejected by its normal canary because the one-second bounded join
paired a legitimate Kafka `identity_transition` burst with a model anomaly in
the following window. B5 therefore permits bounded cross-window evidence only
for `namespace_probe`; identity transition remains an immediate same-window
bypass. Replays used to freeze B5 are preserved under
`protocol/development-b5/`, and `open_b5_blind_after_normal.sh` is the only
supported B5 blind entry point.

The B5 non-formal live-normal canary completed with 63,531 decisions, zero
alerts, zero detector restarts and all 20 workload keys. Inference p99 was
29.50 ms and window-start-to-decision p99 was 0.851 s (max 0.998 s). This is a
15-minute engineering gate, not an FPR or recall claim; B5 still requires its
independent long normal soak before the blind opener can run.

The independent B5 normal run
`sentinel-pulse-formal-normal-b5-r1-20260904T082600Z` entered `normal_active`
on all three workers at 2026-09-04 08:33:22 UTC after passing its traffic and
300-second stability preflight. Its earliest eligible finalize time is
2026-09-05 08:32:14 UTC. `STOP_AFTER_NORMAL=true`; an active run is not a pass
and cannot open the blind matrix automatically.

That formal B5 run was rejected fail-closed at 2026-09-04 09:26:06 UTC after
one normal Kafka alert. The alert was a single-window identity-transition
burst coincident with periodic exec probes; B5's immediate identity bypass,
not its namespace-only bounded join, emitted it. Worker4 also had a 4.855 s
capture gap, so the run cannot estimate formal FPR. B5 remains rejected and
its blind matrix remains unopened. Development B6 replays remove the identity
bypass while retaining namespace bypass and project zero alerts over
1,159,324 scored normal windows; this is development evidence only.

B6 is frozen as policy SHA-256 `53f3346f...` on runtime commit `ab3535a`.
Its blind contract SHA-256 is `b2f5db8e...` and inherits the exact unopened
450-injection B5 matrix. `open_b6_blind_after_normal.sh` is the sole supported
entry point and remains unusable until an independent B6 normal run produces
a valid `NORMAL_PASS`.
The canonical B6 source passes 535 tests in the VM ML environment; the only
two messages are legacy Torch JIT deprecation warnings.

B6 canary `sentinel-pulse-b6-canary-r1-20260905T031108Z` completed with
63,464 decisions, 62,788 scored rows, zero alerts/restarts, all 20 workload
keys and minimum coverage 95.449%. Its inference p99 was 30.405 ms and
window-start-to-decision p99 was 0.854 s (max 1.079 s). This remains a
15-minute engineering gate, not an FPR or recall claim. Formal normal run
`sentinel-pulse-formal-normal-b6-r1-20260905T032856Z` was rejected by the
zero-alert normal gate at 2026-09-06 03:36:10 UTC after one MinIO alert. One
separate worker archive also failed full-stream continuity validation. B6 is
not stable, cannot provide a formal FPR estimate, and its blind root remains
unopened.

For a lifecycle process that was started from an older frozen runtime commit,
attach the read-only external guard from the control checkout. It does nothing
while the lifecycle PID is alive. If that PID exits without `NORMAL_PASS` or a
completed failure archive, the guard creates a fail-closed infrastructure
rejection and invokes the evidence freezer; it never opens blind evaluation:

```bash
SSHPASS=... ./sentinel_pulse/supervise_500ms_candidate_lifecycle.sh \
  /path/to/formal-normal-evidence LIFECYCLE_PID
```

If normal evaluation rejects a run after the formal finalizer has already
copied and verified all worker streams, the failure freezer reuses that
read-only archive. It records `FAILURE_SHA256SUMS` for the additional failure
metadata instead of copying/compressing the same multi-gigabyte streams again.
Monitor failures before the raw-archive checkpoint still use the remote
`raw.tar.gz` fallback. Neither path evaluates, trains, tunes, or promotes the
candidate.

When same-window model and semantic signals are phase-shifted, calibrate a
bounded event-time join strictly on checksum-bound normal decisions. Do not use
the attack pilot to select the horizon:

```bash
python -m sentinel_pulse.calibrate_temporal_join \
  --decisions /normal/nodes/k8s-worker1.local/decisions.jsonl \
  --decisions /normal/nodes/k8s-worker3.local/decisions.jsonl \
  --decisions /normal/nodes/k8s-worker4.local/decisions.jsonl \
  --horizon 0.5 --horizon 1.0 --horizon 1.5 --horizon 2.0 \
  --evidence-checksums /normal/FAILED_FINAL_SHA256SUMS \
  --expected-model-sha256 "$MODEL_MANIFEST_SHA256" \
  --expected-policy-sha256 "$BASE_POLICY_SHA256" \
  --eligible-semantic-group identity_transition \
  --eligible-semantic-group namespace_probe \
  --output TEMPORAL_CALIBRATION.json

python -m sentinel_pulse.build_temporal_policy \
  --base-policy decision-policy-semantic-a2.json \
  --calibration TEMPORAL_CALIBRATION.json \
  --maximum-evidence-age-seconds 1.0 \
  --eligible-semantic-group identity_transition \
  --eligible-semantic-group namespace_probe \
  --policy-name sentinel-pulse-risk-tiered-bounded-join-b2 \
  --output decision-policy-temporal-b2.json

SSHPASS=... MODEL_SOURCE=/evidence/model \
POLICY_SOURCE=/evidence/decision-policy-temporal-b3.json \
EVIDENCE_ROOT=/home/dat/sentinel-pulse-evidence/pilot-a2/CANARY_ID \
RUN_ID=CANARY_ID DURATION_SECONDS=900 \
./sentinel_pulse/run_bounded_live_canary.sh
```

The runner starts all worker finalizers, monitors alert and terminal state, and
automatically performs checksum-bound collection on success. The lower-level
collector remains available only for recovery of an older run that was started
without the supervisor:

```bash
SSHPASS=... ./sentinel_pulse/collect_bounded_live_canary.sh \
  /home/dat/sentinel-pulse-evidence/pilot-a2/CANARY_ID

# If a normal alert already violates the zero-alert gate, stop and preserve
# the failed run instead of waiting or deleting it.
SSHPASS=... ./sentinel_pulse/freeze_failed_bounded_live_canary.sh \
  /home/dat/sentinel-pulse-evidence/pilot-a2/CANARY_ID
```

Policy schema v3 requires model anomaly, score excess and semantic evidence,
but lets their event-time timestamps differ by at most the frozen horizon. The
state is source-scoped, expires on time, resets on telemetry gap/regime change,
and is consumed after alert. The horizon is hard-capped at two seconds. A v3
policy is rejected unless its selected horizon has zero projected alerts in
the bound normal calibration. A risk-tiered policy carries only the explicitly
listed rare/high-risk groups across windows; every other group still requires
same-window model and semantic corroboration. The B2 live-normal canary
`sentinel-pulse-risk-tiered-canary-b2-20260831T175000Z` completed on three
workers with 63,315 decisions across 20 workloads, zero observed normal alerts,
zero detector restarts, 29.28 ms inference p99, and 0.837 s
window-start-to-decision p99. Its aggregate SHA-256 is
`861090772045a495c10e07340f7a620e1d74061321690c5db5ea68ff57b207d5`.
This is still only a 0.25-hour non-formal candidate observation: it does not
establish FPR=0, recall, blind accuracy, or production readiness. A long normal
soak and the separately frozen C2 blind set remain required.

The intended 24-hour normal-only run
`sentinel-pulse-risk-tiered-soak-b2-20260831T175408Z` started at
`2026-08-31T17:54:14.278261Z` with the same model and policy identities, but
was stopped after about 13 minutes when two normal PostgreSQL alerts violated
the zero-alert gate. The frozen failure has 52,660 decisions, two alerts, zero
restarts, summary SHA-256
`194c1541e21df3120690d84a103dacaac138aba886b131d9cb8baa2fec887cae`, and
checksum-index SHA-256
`ff438b3c25deb681fafe366fd50c01b826edb794bf6085c7282709afaeeaaf5f`.
B2 is rejected. C2 remains unopened; consecutive-window confirmation is only
a normal-evidence development direction until implemented and independently
evaluated as a new candidate.

B3 implements that direction as a checksum-bound policy. Common-volume groups
must pass the model, score, and semantic gates in two consecutive 500 ms
windows with the same signal group and at most a 1.25 s gap. The
`identity_transition` and `namespace_probe` groups bypass the extra wait, and
all confirmation state resets on telemetry gaps or traffic-regime changes.
The bound B2-failure replay projected zero alerts over 51,869 scored normal
decisions; replay SHA-256 is
`83d049bad9955cee00ce9e946914e9276f62c3dc334b601b8b285a968424fb8e` and B3
policy SHA-256 is
`02e0f02aa846ae6a6548004b73e5e8274d5f53f098f6cccf4fc6301277583d10`.
This is development calibration, not a live-normal, recall, or latency result.

The B3 successor blind contract is frozen at
`protocol/blind-attack-contract-b3.json`. It binds model manifest
`2e37ffd1...`, B3 policy `02e0f02a...`, and the exact normal-soak runtime
commit `3c3be6c...`. Its 450-trial matrix (18 controllers, five scenarios,
five frozen seed/rate pairs) is reused only from unopened C2; it excludes the
A2 development scenarios and records that no predecessor attack outcome was
used. Freezing the file does not open the set. While the formal normal soak is
active, do not run the attack generator or either blind launcher.

After the exact normal evidence has a checksum-valid `NORMAL_PASS`, use the
guarded opener from the control checkout. It refuses an active/failed normal
run, a dirty runtime worktree, or a runtime commit different from the one that
was soaked:

```bash
SSHPASS=... \
NORMAL_EVIDENCE_ROOT=/home/dat/sentinel-pulse-evidence/blind-b1/FORMAL_B3_RUN \
./sentinel_pulse/open_b3_blind_after_normal.sh
```

Before a clean-source 24-hour formal soak exists, attack-path integration may
be checked only with the explicitly non-formal pilot lifecycle:

```bash
SSHPASS=... MODEL_SOURCE=/evidence/model \
POLICY_SOURCE=/evidence/decision-policy.json \
NORMAL_CANARY_AGGREGATE=/evidence/AGGREGATE.v2.json \
./sentinel_pulse/start_attack_latency_pilot.sh

python -m sentinel_pulse.run_500ms_blind_matrix \
  --evidence-root /evidence/pulse500-attack-latency-pilot-ID \
  --model-dir /evidence/pulse500-attack-latency-pilot-ID/model \
  --attack-contract /evidence/pulse500-attack-latency-pilot-ID/protocol/blind-attack-contract.json \
  --implementation-contract /evidence/pulse500-attack-latency-pilot-ID/protocol/attack-implementation-contract.json \
  --exec-provenance-policy /evidence/pulse500-attack-latency-pilot-ID/protocol/tetragon-exec-provenance.yaml \
  --pilot-plan /evidence/pulse500-attack-latency-pilot-ID/PILOT_PLAN.json

SSHPASS=... ./sentinel_pulse/finalize_attack_latency_pilot.sh \
  /evidence/pulse500-attack-latency-pilot-ID
```

The pilot defaults to 15 preselected trials: all five frozen scenarios on one
stateless, one database, and one streaming workload at one frozen mid-rate
trial. It cannot create `MATRIX_COMPLETE`, cannot call the candidate finalizer,
and records `formal_blind_evidence=false`. Its result is engineering evidence
for attribution and latency wiring only, not formal recall or paper accuracy.

Blind latency evaluation must use both `--injections` and `--kernel-events` in
the paper run. The immutable marker set defines the denominator and prevents an
unknown or duplicated ID from inflating recall. The kernel event file binds
each injection to an independently timestamped Tetragon event. The current
runner opens a live gRPC capture before the marker and requires exactly one
exact-path `sys_execve` event from the checksum-bound
`sentinel-pulse-exec-provenance` policy. This avoids treating a lossy stdout
exporter as the source of truth for short-lived container-exec tasks. The
evaluator recomputes kernel-to-alert latency from `alerted_at` and refuses
to treat the userspace pre-exec marker as kernel latency. The frozen Pulse contract requires the
complete 18-workload x 5-scenario x 5-trial matrix (450 injections); merely
producing 450 unrelated IDs does not pass.

The default `alpha=1e-4` requires at least 9,999 independent calibration
examples per workload candidate. Training fails closed when the temporal split
cannot provide that p-value resolution. A zero observed alert count is reported
with its Wilson 95% upper bound; it is never described as proof of zero future
false positives. The A2 compatibility pilot explicitly overrides alpha to
`1e-3`, which requires at least 999 calibration examples per workload; do not
describe that pilot as using the stricter default.

The finalizer never promotes a detector. Passing creates only an
`eligible_for_overhead_evaluation` decision; counterbalanced overhead,
independent reproduction and manual review remain mandatory.

Promotion requires the gates in `SENTINEL_PULSE_REPORT.md`; successful build or
short smoke testing alone is not a latency, recall, or false-positive claim.

## B6 rejection and B7 development update (2026-09-06)

B6 failed its independent zero-alert normal gate at 03:36:10 UTC after one
MinIO alert. The alert was a two-window `openat`-volume event on one replica;
another MinIO replica showed a synchronized burst. The legacy group name
`credential_open` is only an `openat` count proxy and carries no pathname
evidence. A different worker also failed full-stream continuity, so B6 is
rejected and cannot yield a formal FPR estimate. No B6 blind outcome was
opened.

Development B7 raises only `credential_open` to three consecutive windows,
retains `local_socket_beacon=3`, default confirmation=2 and namespace-only
immediate/bounded corroboration. Checksum-bound normal replays project zero
alerts over 7,350,925 scored rows, including 6,191,601 from B6. This is tuning
evidence, not FPR/recall/latency evidence. The next candidate also includes a
live feature-tail integrity check so cumulative collector loss terminates a
formal run during monitoring. Policy SHA-256 `711e66a9...` and runtime commit
`9cc382c...` are frozen; blind contract `ee1cb43d...` inherits the exact
unopened B6 matrix.

B7 canary `sentinel-pulse-b7-canary-r1-20260906T080908Z` completed valid:
63,534 decisions, 62,851 scored, zero alerts/restarts, 20/20 workload coverage,
minimum duration 901.991 seconds. Window-start-to-decision p99 was 0.852 s;
inference p99 was 29.574 ms. These are normal-decision measurements, not
attack kernel-to-alert or formal FPR/recall evidence. The archived aggregate
is in `validation-evidence/sentinel-pulse-canary/b7-r1-20260906/AGGREGATE.json`.

The B7 normal lifecycle was started at 2026-09-06 15:12:39 UTC with a
90,000-second capture and a 300-second stability preflight. Service:
`sentinel-pulse-b7-r1-lifecycle.service`; run:
`sentinel-pulse-formal-normal-b7-r1-20260906T151400Z`. Its initial phase is
`normal_preflight`. `SOAK_START.json` records 2026-09-06 15:18:35 UTC;
all three workers reached `normal_active` at 15:19:43 UTC. The first monitor
pass recorded 2,168 decisions, zero alerts/restarts, and valid feature tails.
The lifecycle may finalize after 24 hours plus a 300-second margin; 90,000
seconds is the collector's upper duration limit. Archive evaluation takes
additional time. `STOP_AFTER_NORMAL=true`; blind evaluation remains gated.

Update verified on 2026-09-07 03:28 UTC: B7 R1 is terminal, rejected for
`collector_integrity_violation` on `.239` at 2026-09-06 16:55:05 UTC.
The archive is complete; the lifecycle has been disabled and control
collectors restored. The worker had a 13.252-second maximum interval alongside
kernel iSCSI and containerd timeouts; the underlying stall cause is unresolved.
Last per-host monitor samples recorded 409,603 decisions and zero alerts,
which is not a valid formal accuracy result.

The canonical telemetry repair handles zero transition deltas without NaN,
rejects non-finite captured vectors, persists bounded-capture interval
violations across recovered windows, and retains failed tail-check output.
68 local regression tests pass. This repair is not deployed: SSH timed out
after the audit. Reconnect, validate in the VM ML environment and freeze a new
runtime identity for a diagnostic canary before another formal soak.

On 2026-09-07 SSH recovered. The R2 diagnostic launch failed before detector
decisions because the old collector installer started the new unit before
copying the new Python package. Commit `ba3b8e5` fixes installation ordering
and verifies capture CLI support; 261 Pulse tests pass in the VM ML venv.

The next diagnostic run is `sentinel-pulse-b7-telemetry-r3-20260907T083400Z`,
with a 7,200-second canary and a 7,800-second per-node sysstat recording.
Runtime: `/home/dat/eBPF-project-runtime-pulse-b7-telemetry-r3` at `ba3b8e5`.
Model/policy retain B7 bytes. The supervisor is
`sentinel-pulse-b7-telemetry-r3-canary.service`; evidence is under
`/home/dat/sentinel-pulse-evidence/canary-b7-telemetry/<run_id>/`.
`record_node_pressure.sh` records one-second CPU/run-queue/paging/swap/I/O
samples and final kernel logs with checksums, without changing workloads.
Node diagnostics are under `/var/lib/sentinel-pulse-diagnostics/<run_id>/`.
This does not open the old B7 blind contract or establish a formal normal pass.

As of 2026-10-02, the observer also records one-second NIC/TCP counters,
clock/PSI samples and final kubelet/containerd journals. Deploy
`record_node_pressure.sh` **together with** `node_clock_probe.py` in the same
directory. Clock flags identify observer delay or wall/monotonic offset change,
not their root cause; this diagnostic never changes the ML decision policy.
R10-C2 diagnosis and the six-hour background observer are documented in
`validation-evidence/longhorn-r10-c2-diagnosis-20261002/README.md`.

R3 completed valid at 2026-09-07 10:36 UTC. It recorded 517,956 decisions,
513,271 scored decisions, zero alerts/restarts and all 20 workload-container
keys over at least 7,201.959 seconds. Inference p99 was 30.197 ms;
window-start-to-decision p99 was 0.854 seconds (maximum 1.094 seconds). All
three finalizers were valid and all seven integrity counters were zero;
snapshot interval p99 was 0.507--0.509 seconds (maximum 0.634 seconds).

The one-second sysstat observer produced 7,800 samples per node. Average
iowait remained below 0.1%; a short 15.89% worker1 spike did not cause a
telemetry gap. The queried kernel-error classes had no matches. The aggregate
SHA-256 is `cebce2686c63c2774b680cbab5613bca49c3940d3d101194f1c58bd9c326e6bb`.
This two-hour normal-only canary is not a formal FPR, recall or attack-latency
result and does not permit promotion.

The successor formal normal-only run was
`sentinel-pulse-formal-normal-b7-telemetry-r4-20260907T113747Z`. The immutable
marker started at 2026-09-07 11:43:43 UTC and binds runtime `ba3b8e5`, model
`2e37ffd1...`, and policy `711e66a9...`; its SHA-256 is
`aefcf411016b6d063b6ad3b3007428930d633a2f42ed1c5649a2d861345268ff`.
Initial monitoring recorded 16,990 decisions, zero alerts/restarts, valid
feature tails and zero integrity counters. One-second node diagnostics run for
the intended 90,000-second collector bound.

R4 was stopped fail-closed at 11:55:28 UTC and archived at 11:56:03 UTC. On
worker3, one interval reached 4.832 seconds, the next 1.355 seconds, ingest lag
6.197 seconds and window-start-to-emit 6.808 seconds. Sysstat missed four
one-second samples in the same period, while containerd reported deadline and
ExecSync timeouts; worker1 simultaneously reached 14.67% iowait. The run is an
infrastructure rejection with `normal_gate_result=null`, not an FPR result.
Blind stayed closed and the candidate was not promoted.

Commit `d54c739` caches atomically replaced resolver metadata, writes and
flushes one batch per BPF snapshot, and counts interval violations per loader
snapshot rather than per emitted workload row. It does not relax the
0.35--0.80-second gate. All 262 Pulse tests pass on both the host and VM.

The isolated normal-only R5 canary
`sentinel-pulse-b7-telemetry-r5-20260907T122659Z` started at 12:27:05 UTC for
7,200 seconds without the sysstat pressure recorder. This is an observer
perturbation isolation test, not evidence that the observer caused R4. The
12:29 UTC checkpoint had 7,208 decisions, zero alerts/restarts, valid feature
tails and zero integrity counters.

R5 subsequently completed its 7,200-second bound but failed the original
zero-cadence-violation contract. The archive contains 517,116 decisions and
zero alerts; worker1/worker4 passed while worker3 had one 4.873938-second
loader interval. Worker3 interval p99 remained 0.507403 seconds,
window-start-to-emit p99 was 0.523591 seconds and ingest-lag p99 was 0.019569
seconds. Containerd/kubelet ExecSync probes timed out in the same node pause.
Because R5 had no sysstat recorder, it does not support the observer
perturbation hypothesis. It remains an immutable infrastructure rejection;
zero observed alerts are not an accuracy result.

The successor code separates zero-tolerance BPF/data integrity from bounded
telemetry availability. Availability budgets must be preregistered for a new
run and report delayed snapshots, estimated missing snapshots, availability,
and maximum gap. They never waive map insertion, snapshot consistency,
target-attribution, finite-vector, or checksum failures. Runtime history and
corroboration evidence are cleared after a gap beyond the model's contiguous
history contract, forcing warm-up instead of scoring across missing time.

Prospective canary R6-r2
`sentinel-pulse-availability-r6-r2-20260908T033340Z` binds commit `105e452`,
the unchanged B7 model/policy, a 500 ms nominal interval, minimum telemetry
availability 0.999 and maximum single gap 10 seconds. It runs for 7,200 seconds
on all three workers. The first checkpoint recorded 5,111 decisions, zero
alerts and active collectors/detectors/finalizers.

R6-r2 completed valid at 05:36:28 UTC with 517,459 decisions, 512,694 scored,
zero alerts/restarts and complete 20/20 workload coverage. Aggregate inference
p99 was 29.778 ms and window-start-to-decision p99 was 0.858 seconds; the latter
had a 3.356-second maximum and therefore does not establish a hard two-second
maximum. Worker1/worker3/worker4 telemetry availability was
1.0/0.999650/0.999720, with maximum loader gaps of 0.608/2.853/2.574 seconds.
All hard-integrity counters were zero and delayed sources were reset to
`warming_reason=temporal_gap` rather than scored across missing history.
Start/final checksum indexes verify. This is a nonformal normal-only canary,
not an FPR, recall, blind attack latency or production promotion result; it
permits preparation of a new 24-hour formal soak under the same preregistered
availability contract.

The availability lifecycle was subsequently promoted in source commit
`a0a8c5b`; 277/277 Sentinel Pulse tests pass in the canonical VM ML venv. A
300-second R7 smoke was correctly rejected because four scored workload spans
were only 281--282 seconds against a 300-second coverage gate. The bounded
minimum was therefore fixed prospectively at 360 seconds.

The replacement 600-second smoke
`sentinel-pulse-availability-r8-smoke-20260908T061606Z` completed valid with
42,031 decisions, 41,544 scored, zero alerts/restarts, complete 20/20 coverage,
and 100% measured telemetry availability on all three workers. Inference p99
was 29.787 ms and window-start-to-decision p99/max was 0.852/1.038 seconds.
This remains nonformal normal-only evidence.

Formal run
`sentinel-pulse-formal-normal-availability-r8-20260908T062950Z` is registered
under `/home/dat/sentinel-pulse-evidence/formal-availability-r8/`. It uses the
detached `a0a8c5b` runtime, unchanged B7 model/policy, a 500 ms nominal interval,
99.9% minimum availability, 10-second maximum gap, 90,000-second collector
bound and 300-second finalization margin. The persistent lifecycle and an
external fail-closed supervisor are active. `STOP_AFTER_NORMAL=true`; blind
evaluation and automatic promotion remain disabled.

The preflight passed. `SOAK_START.json` binds a `started_not_before` time of
2026-09-08 06:35:47 UTC and an eligible-finalize time exactly 24 hours later;
its SHA-256 is `5574c8fc2d9577a89d930cc13da62c77d19a72b09434a8ec17833ce920d4218a`.
All three workers reached `normal_active` at 06:36:56 UTC and the external
supervisor attached at 06:37:06 UTC.

At the 09:11 UTC checkpoint, the sequential monitor samples totalled 668,621
decisions with zero alerts/restarts. Worker3 had two cadence events of 1.430
and 9.853 seconds, estimating 21 missing snapshots. Its current availability
was 0.998864 and therefore explicitly `telemetry_degraded`; monitoring remains
valid because the preregistered full-run budget is 180 snapshots and the
single-gap bound is 10 seconds. Gap decisions were reset to
`warming_reason=temporal_gap` followed by `history_fill`, not scored across the
missing interval. This is an active checkpoint, not a terminal normal pass.
## Current recovery lifecycle

Recovery preregistration/supervision/finalization and scored exposure are now
wired through a three-worker coordinator. Fleet diagnostic C2 finished with
integrity gate=true; no24h/key formal PASS and no formal soak running.
Historical C2 smoke
terminal10:56:48 ICT:26,648 decisions,19 scored keys,
0 alerts, no recovery incident. All-run window-start→post-model p9912.551s;
after120s startup p991.907s. Neither is kernel-to-alert. Processing-age gate
is a separate opt-in under validation; no model/policy tuning or formal PASS.
See [status and raw evidence references](../PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md).
