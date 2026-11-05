#!/usr/bin/env bash
# The enriched token language model over CB-DS and the 15 LID-DS 2021 scenarios (lidds_ml_tokens.py), on .234 as dat
# under systemd-run with MemoryMax, largest first, JOBS at a time; finished parts are kept.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=3 WAIT_UNITS=unit] bash lidds_ml_tokens_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=${OUT:-/var/tmp/lid-ds-2021/ml-tokens}
PY=/home/dat/ml-venv/bin/python
export SRC OUT PY PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
for unit in ${WAIT_UNITS:-}; do
  while [ "$(systemctl is-active "$unit")" = active ] || [ "$(systemctl is-active "$unit")" = activating ]; do sleep 300; done
done
mkdir -p $OUT && cd /tmp
one() {
  [ -f $OUT/$2.json ] && return 0
  OMP_NUM_THREADS=1 $PY -u $SRC/scripts/analysis/lidds_ml_tokens.py --archives $1 --scenario $2 --output $OUT/$2.npz > $OUT/$2.log 2>&1 || echo "FAILED $2"
  echo "done $2 $(date -u +%FT%T)"
}
export -f one
{ echo "/var/tmp/cb-ds/archives CB-DS"
  ls -S /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed 's|^|/var/tmp/lid-ds-2021 |'
} | xargs -P ${JOBS:-3} -L 1 bash -c 'one $0 $1'
echo "tokens done $(date -u +%FT%T)"
