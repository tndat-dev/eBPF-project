#!/usr/bin/env bash
# cbds-confirmation-v1 on .234 as dat, once the live run's analysis unit has finished (no heavy job during a live run):
# alias conversion of the CB-DS archive built on the host (sentinel_pulse/lidds/cbds.py), the frozen v2 evaluation,
# then the protocol's criteria and per-attack breakdown.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [WAIT_UNITS="after-recal-confirm"] bash cbds_after_live.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
D=/var/tmp/cb-ds
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
[ -f $D/archives/CB-DS.zip ] || { echo "missing $D/archives/CB-DS.zip"; exit 1; }
for unit in ${WAIT_UNITS:-after-recal-confirm}; do
  while [ "$(systemctl is-active "$unit")" = active ] || [ "$(systemctl is-active "$unit")" = activating ]; do sleep 300; done
  echo "wait unit $unit is $(systemctl is-active "$unit") $(date -u +%FT%T)"
done
cd /tmp
echo "conversion start $(date -u +%FT%T)"
$PY -m sentinel_pulse.lidds.convert $D/archives/CB-DS.zip --output $D/converted > $D/convert.log 2>&1 || { echo "conversion FAILED"; exit 1; }
echo "evaluation start $(date -u +%FT%T)"
OMP_NUM_THREADS=3 $PY -u $SRC/scripts/analysis/lidds_evaluate_v2.py --converted $D/converted --archives $D/archives \
  --exec-set $SRC/validation-evidence/results-20261021/pulse-stable-candidate/final/exec-set-E.json \
  --scenario CB-DS --output $D/lidds-evaluation-v2-cbds.json > $D/evaluate.log 2>&1 || { echo "evaluation FAILED"; exit 1; }
$PY $SRC/scripts/analysis/cbds_confirmation.py $D/lidds-evaluation-v2-cbds.json --output $D/cbds-confirmation.json \
  || echo "confirmation FAILED"
echo "cb-ds done $(date -u +%FT%T)"
