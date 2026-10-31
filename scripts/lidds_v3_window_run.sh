#!/usr/bin/env bash
# lidds-evaluation-v3 amendment 1 on .234 as dat: rerun the v2 branches on LID-DS 2021 keeping alarm times (one
# process per scenario, largest first, JOBS at a time), merge, check every per-recording outcome against the v2
# receipt, then the time-horizon vote.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=5] bash lidds_v3_window_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
D=/var/tmp/lid-ds-2021
OUT=$D/v3-window
PY=/home/dat/ml-venv/bin/python
JOBS=${JOBS:-5}
export SRC D OUT PY PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
mkdir -p $OUT && cd /tmp
echo "evaluation start $(date -u +%FT%T)"
one() {
  [ -f $OUT/part-$1.json ] && return 0
  OMP_NUM_THREADS=2 $PY -u $SRC/scripts/analysis/lidds_evaluate_v2.py --converted $D/converted-v2 --archives $D \
    --exec-set $SRC/validation-evidence/results-20261021/pulse-stable-candidate/final/exec-set-E.json \
    --scenario $1 --output $OUT/part-$1.json > $OUT/evaluate-$1.log 2>&1 || echo "FAILED $1"
  echo "done $1 $(date -u +%FT%T)"
}
export -f one
ls -S $D/*.zip | xargs -n1 basename | sed 's/\.zip$//' | xargs -P $JOBS -I{} bash -c 'one {}'
$PY $SRC/scripts/analysis/lidds_evaluate_v2.py --merge $OUT/part-*.json --output $OUT/lidds-evaluation-v2-alarms.json || { echo "merge FAILED"; exit 1; }
$PY - <<PY
import gzip, json
new = json.load(open('$OUT/lidds-evaluation-v2-alarms.json'))['recordings']
old = json.load(gzip.open('$SRC/validation-evidence/results-20261031/lidds-v2/lidds-evaluation-v2.json.gz', 'rt'))['recordings']
diff = [(s, a) for s in old for a in old[s] if sorted(map(tuple, old[s][a])) != sorted(map(tuple, new[s][a]))]
json.dump(dict(identical=not diff, differing=diff), open('$OUT/REPRODUCIBILITY.json', 'w'), indent=1)
print('reproducible' if not diff else f'NOT reproducible: {diff}')
PY
$PY $SRC/scripts/analysis/lidds_v3_window.py --select $OUT/lidds-evaluation-v2-alarms.json --output $OUT/lidds-v3-window.json
echo "v3 window done $(date -u +%FT%T)"
