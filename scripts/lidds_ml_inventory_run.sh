#!/usr/bin/env bash
# Which syscalls the tokens need exit information for (lidds_ml_token_inventory.py), development recordings only, on .234 as
# dat under systemd-run with MemoryMax, smallest scenario first; finished parts are kept.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=6] bash lidds_ml_inventory_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=${OUT:-/var/tmp/lid-ds-2021/ml-inventory}
PY=/home/dat/ml-venv/bin/python
ALARMS=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz
export SRC OUT PY ALARMS PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
mkdir -p $OUT && cd /tmp
one() {
  [ -f $OUT/$2.json ] && return 0
  local filter=(--alarms $ALARMS)
  $PY -u $SRC/scripts/analysis/lidds_ml_token_inventory.py --archives $1 --scenario $2 "${filter[@]}" --output $OUT/$2.json > $OUT/$2.log 2>&1 || echo "FAILED $2"
  echo "done $2 $(date -u +%FT%T)"
}
export -f one
{ ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed 's|^|/var/tmp/lid-ds-2021 |'
} | xargs -P ${JOBS:-6} -L 1 bash -c 'one $0 $1'
echo "inventory done $(date -u +%FT%T)"
