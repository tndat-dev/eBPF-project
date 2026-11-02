#!/usr/bin/env bash
# Raw branch scores for choosing the ML decision rule offline (lidds_ml_scores.py), on .234 as dat under systemd-run
# with MemoryMax: CB-DS and the 15 LID-DS 2021 scenarios, largest first, JOBS at a time; finished parts are kept.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=3] bash lidds_ml_scores_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=/var/tmp/lid-ds-2021/ml-scores
PY=/home/dat/ml-venv/bin/python
export SRC OUT PY PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
mkdir -p $OUT && cd /tmp
one() {
  [ -f $OUT/$3.json ] && return 0
  OMP_NUM_THREADS=2 $PY -u $SRC/scripts/analysis/lidds_ml_scores.py --converted $1 --archives $2 --scenario $3 \
    --output $OUT/$3.npz > $OUT/$3.log 2>&1 || echo "FAILED $3"
  echo "done $3 $(date -u +%FT%T)"
}
export -f one
{ echo "/var/tmp/cb-ds/converted /var/tmp/cb-ds/archives CB-DS"
  ls -S /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed 's|^|/var/tmp/lid-ds-2021/converted-v2 /var/tmp/lid-ds-2021 |'
} | xargs -P ${JOBS:-3} -L 1 bash -c 'one $0 $1 $2'
echo "scores done $(date -u +%FT%T)"
