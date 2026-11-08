#!/usr/bin/env bash
# Cross-fitted token branch (lidds_ml_token_crossfit.py), development test recordings only (CB-DS: all), on .234 as dat
# under systemd-run with MemoryMax, smallest scenario first; finished parts are kept.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=8 FOLDS=5 OUT=dir] bash lidds_ml_crossfit_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=${OUT:-/var/tmp/lid-ds-2021/ml-xfit-tokens}
PY=/home/dat/ml-venv/bin/python
ALARMS=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz
export SRC OUT PY ALARMS FOLDS=${FOLDS:-5} PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
mkdir -p $OUT && cd /tmp
one() {
  [ -f $OUT/$2.json ] && return 0
  local filter=(); [ "$2" = CB-DS ] || filter=(--alarms $ALARMS)
  $PY -u $SRC/scripts/analysis/lidds_ml_token_crossfit.py --archives $1 --scenario $2 "${filter[@]}" --folds $FOLDS --output $OUT/$2.npz > $OUT/$2.log 2>&1 || echo "FAILED $2"
  echo "done $2 $(date -u +%FT%T)"
}
export -f one
{ echo "/var/tmp/cb-ds/archives CB-DS"
  ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed 's|^|/var/tmp/lid-ds-2021 |'
} | xargs -P ${JOBS:-8} -L 1 bash -c 'one $0 $1'
echo "crossfit done $(date -u +%FT%T)"
