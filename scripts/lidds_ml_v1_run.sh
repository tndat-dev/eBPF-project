#!/usr/bin/env bash
# lidds-ml-v1 on .234 as dat (run under systemd-run with MemoryMax): the grouped ML over the 15 LID-DS 2021 scenarios
# and CB-DS (JOBS at a time, largest first), a recording-by-recording reproducibility check of the baseline
# configuration against the v2 receipts, then the selection and the single official scoring.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=3] bash lidds_ml_v1_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=/var/tmp/lid-ds-2021/ml-v1
PY=/home/dat/ml-venv/bin/python
export SRC OUT PY PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
mkdir -p $OUT && cd /tmp
one() {
  local conv=$1 arch=$2 s=$3
  [ -f $OUT/$s.json ] && return 0
  OMP_NUM_THREADS=2 $PY -u $SRC/scripts/analysis/lidds_ml_groups.py --converted $conv --archives $arch --scenario $s \
    --output $OUT/$s.json > $OUT/$s.log 2>&1 || echo "FAILED $s"
  echo "done $s $(date -u +%FT%T)"
}
export -f one
{ echo "/var/tmp/cb-ds/converted /var/tmp/cb-ds/archives CB-DS"
  ls -S /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed 's|^|/var/tmp/lid-ds-2021/converted-v2 /var/tmp/lid-ds-2021 |'
} | xargs -P ${JOBS:-3} -L 1 bash -c 'one $0 $1 $2'
$PY - <<PY
import gzip, json, glob, os
def receipt(p): return json.load(gzip.open(p, 'rt'))['recordings']
old = receipt('$SRC/validation-evidence/results-20261031/lidds-v2/lidds-evaluation-v2.json.gz')
old.update(receipt('$SRC/validation-evidence/results-20261029/cbds/lidds-evaluation-v2-cbds.json.gz'))
diff = []
for f in glob.glob('$OUT/*.json'):
    if os.path.basename(f) in ('REPRODUCIBILITY.json', 'lidds-ml-v1.json'): continue
    d = json.load(open(f)); s = d['scenario']
    new = sorted(tuple(o[:4]) + (o[5], o[6]) for o in d['outcomes']['g0|plain|bonferroni'])
    ref = sorted(tuple(o[:4]) + (o[5], o[6]) for o in old[s]['ml'])
    if new != ref: diff.append(s)
json.dump(dict(identical=not diff, differing=diff), open('$OUT/REPRODUCIBILITY.json', 'w'), indent=1)
print('reproducible' if not diff else f'NOT reproducible: {diff}')
PY
python3 -c "import json,sys; sys.exit(0 if json.load(open('$OUT/REPRODUCIBILITY.json'))['identical'] else 1)" || { echo "baseline not reproduced: no selection"; exit 1; }
$PY $SRC/scripts/analysis/lidds_ml_select.py --lidds2021 $(ls $OUT/*.json | grep -v -e CB-DS.json -e REPRODUCIBILITY -e lidds-ml-v1) \
  --cbds $OUT/CB-DS.json --output $OUT/lidds-ml-v1.json > $OUT/select.log 2>&1 || echo "selection FAILED"
echo "ml-v1 done $(date -u +%FT%T)"
