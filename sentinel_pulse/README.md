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
