#!/usr/bin/env bash
# The token alphabets a cheap probe could collect (lidds_ml_token_alphabets.py), development recordings only, on .234 as
# dat under systemd-run with MemoryMax, smallest scenario first; finished parts are kept.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=6 ALPHABETS=full,select OUT=dir] bash lidds_ml_alphabets_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=${OUT:-/var/tmp/lid-ds-2021/ml-alphabets}
PY=/home/dat/ml-venv/bin/python
ALARMS=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz
export ALPHABETS=${ALPHABETS:-}
export SRC OUT PY ALARMS PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
mkdir -p $OUT && cd /tmp
one() {
  [ -f $OUT/$2.json ] && return 0
  local filter=(); [ "$2" = CB-DS ] || filter=(--alarms $ALARMS)
  $PY -u $SRC/scripts/analysis/lidds_ml_token_alphabets.py --archives $1 --scenario $2 "${filter[@]}" ${ALPHABETS:+--alphabets $ALPHABETS} --output $OUT/$2.npz > $OUT/$2.log 2>&1 || echo "FAILED $2"
  echo "done $2 $(date -u +%FT%T)"
}
export -f one
{ echo "/var/tmp/cb-ds/archives CB-DS"
  ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed 's|^|/var/tmp/lid-ds-2021 |'
} | xargs -P ${JOBS:-6} -L 1 bash -c 'one $0 $1'
echo "alphabets done $(date -u +%FT%T)"
