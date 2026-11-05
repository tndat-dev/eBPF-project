#!/usr/bin/env bash
# The LSTM reference over CB-DS and the 15 LID-DS 2021 scenarios (lidds_ml_teacher.py), on .234 as dat under systemd-run
# with MemoryMax, smallest first so that a time or memory limit costs the fewest scenarios; finished parts are kept.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=3 SECONDS_LIMIT=7200 WAIT_UNITS=unit] bash lidds_ml_teacher_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=${OUT:-/var/tmp/lid-ds-2021/ml-teacher}
PY=/home/dat/ml-venv/bin/python
SECONDS_LIMIT=${SECONDS_LIMIT:-7200}
export SRC OUT PY SECONDS_LIMIT PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
for unit in ${WAIT_UNITS:-}; do
  while [ "$(systemctl is-active "$unit")" = active ] || [ "$(systemctl is-active "$unit")" = activating ]; do sleep 300; done
done
mkdir -p $OUT && cd /tmp
one() {
  [ -f $OUT/$2.json ] && return 0
  CUDA_VISIBLE_DEVICES= $PY -u $SRC/scripts/analysis/lidds_ml_teacher.py --archives $1 --scenario $2 --seconds $SECONDS_LIMIT --threads 4 \
    --output $OUT/$2.npz > $OUT/$2.log 2>&1 || echo "FAILED $2"
  echo "done $2 $(date -u +%FT%T)"
}
export -f one
{ echo "/var/tmp/cb-ds/archives CB-DS"
  ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed 's|^|/var/tmp/lid-ds-2021 |'
} | xargs -P ${JOBS:-3} -L 1 bash -c 'one $0 $1'
echo "teacher done $(date -u +%FT%T)"
