#!/usr/bin/env bash
# Pulse 5.22 (ML: protocol burden-reduction-v1 + amendment 1) and, separately, the rule tier on top of its
# results (RULE_INTEGRATION_STATUS, protocol rule-integration-v1), on .234 as dat:
#   1. wait for the retention compression (a file must not be read while it is being replaced);
#   2. window tables of the two development runs (one process each; features + decisions read once);
#   3. lever evaluation and the registered selection (refreshed calibration; Mondrian classes from the
#      calibration-span table built from the local copy of pulse-live-recalibrated): ML only, no rule;
#   4. rule tier: the ML choices re-scored unchanged, then the post-ML probe triage (RCA cases, declared probes).
#   SRC=/var/tmp/burden-levers/source-<sha> bash burden_levers.sh
set -euo pipefail
SRC=${SRC:?source}
B=/var/tmp/burden-levers
A=/mnt/sentinel-pulse-archive
PY=/home/dat/ml-venv/bin/python
REFRESHED=$A/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection/calibration-r6-1300-1900.npz
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
while [ "$(systemctl is-active after-stable-refreshed)" = active ]; do sleep 300; done
cfg() { python3 -c "import json;print(json.load(open('$A/$1/CONFIG.json'))['$2'])"; }
RUNS=(pulse-stable-candidate pulse-stable-refreshed)
pids=()
for r in "${RUNS[@]}"; do
  [ -f $B/table-$r.npz ] && continue
  roots=(); for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do roots+=(--worker-root $A/$r/workers/$n); done
  $PY -u -m sentinel_pulse.attack.window_table "${roots[@]}" --model-hash "$(cfg $r model_hash)" \
    --policy-hash "$(cfg $r policy_hash)" --since "$(cfg $r selection_start)" --output $B/table-$r.npz > $B/table-$r.log 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
until [ -f $B/cal-pulse-live-recalibrated.npz ]; do sleep 60; done   # calibration-span table (local copy)
args=(); for r in "${RUNS[@]}"; do
  args+=(--run "name=$r,table=$B/table-$r.npz,since=$(cfg $r selection_start),campaign=$A/$r/pulse-development-matrix")
done
$PY -u $SRC/scripts/analysis/burden_levers.py "${args[@]}" --calibration $REFRESHED \
  --calibration-table $B/cal-pulse-live-recalibrated.npz --output $B/BURDEN-LEVERS.json
cp $B/BURDEN-LEVERS.json $A/pulse-stable-refreshed/analysis/burden-levers.json
echo "ML evaluation done $(date -u +%FT%T)"
# rule tier, separate output: never changes the ML results above
rargs=(); for r in "${RUNS[@]}"; do
  rargs+=(--run "name=$r,table=$B/table-$r.npz,since=$(cfg $r selection_start),campaign=$A/$r/pulse-development-matrix,cases=/var/lib/sentinel-pulse-rca/rca-$r/cases")
done
$PY -u $SRC/scripts/analysis/rule_tier.py "${rargs[@]}" --calibration $REFRESHED \
  --calibration-table $B/cal-pulse-live-recalibrated.npz --ml-results $B/BURDEN-LEVERS.json \
  --probe-spec $SRC/validation-evidence/results-20261021/exec-probe-spec.json --output $B/RULE-TIER.json
cp $B/RULE-TIER.json $A/pulse-stable-refreshed/analysis/rule-tier.json
echo "done $(date -u +%FT%T)"
