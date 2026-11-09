#!/usr/bin/env bash
# Pool matrices of lidds-ml-v5 (lidds_ml_token_pool.py), every recording, on .234 as dat under systemd-run with MemoryMax,
# never during a live run. Finished parts are kept.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [JOBS=6 OUT=dir WORK=dir] bash lidds_ml_pool_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=${OUT:-/var/tmp/lid-ds-2021/ml-v5-pool}
WORK=${WORK:-/var/tmp/lid-ds-2021/ml-v5-counts}
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
args=(--scenario /var/tmp/cb-ds/archives CB-DS)
for z in $(ls -S -r /var/tmp/lid-ds-2021/*.zip); do args+=(--scenario /var/tmp/lid-ds-2021 "$(basename "$z" .zip)"); done
cd /tmp && /home/dat/ml-venv/bin/python -u $SRC/scripts/analysis/lidds_ml_token_pool.py "${args[@]}" --work "$WORK" --output "$OUT" --jobs "${JOBS:-6}"
