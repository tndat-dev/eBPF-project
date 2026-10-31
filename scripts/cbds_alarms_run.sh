#!/usr/bin/env bash
# lidds-evaluation-v4 on .234 as dat: rerun the v2 branches on CB-DS (existing conversion) keeping alarm times, and
# check every per-recording outcome against the cbds-confirmation-v1 receipt.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> bash cbds_alarms_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
D=/var/tmp/cb-ds
OUT=$D/v4
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
mkdir -p $OUT && cd /tmp
OMP_NUM_THREADS=3 $PY -u $SRC/scripts/analysis/lidds_evaluate_v2.py --converted $D/converted --archives $D/archives \
  --exec-set $SRC/validation-evidence/results-20261021/pulse-stable-candidate/final/exec-set-E.json \
  --scenario CB-DS --output $OUT/lidds-evaluation-v2-cbds-alarms.json > $OUT/evaluate.log 2>&1 || { echo "evaluation FAILED"; exit 1; }
$PY - <<PY
import gzip, json
new = json.load(open('$OUT/lidds-evaluation-v2-cbds-alarms.json'))['recordings']
old = json.load(gzip.open('$SRC/validation-evidence/results-20261029/cbds/lidds-evaluation-v2-cbds.json.gz', 'rt'))['recordings']
diff = [(s, a) for s in old for a in old[s] if sorted(map(tuple, old[s][a])) != sorted(map(tuple, new[s][a]))]
json.dump(dict(identical=not diff, differing=diff), open('$OUT/REPRODUCIBILITY.json', 'w'), indent=1)
print('reproducible' if not diff else f'NOT reproducible: {diff}')
PY
echo "cb-ds alarms done $(date -u +%FT%T)"
