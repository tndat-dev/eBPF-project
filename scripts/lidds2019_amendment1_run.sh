#!/usr/bin/env bash
# lidds2019-development-v1 amendment 1 on .234: LID-DS 2021 official caches, official scoring (base must reproduce
# lidds-ml-v5 first), then the single 2019 holdout scoring. Chạy trong systemd-run có MemoryMax.
set -euo pipefail
SRC=${SRC:?source checkout}
OUT=${OUT:-/var/tmp/lid-ds-2019-v2/development}
OC=${OC:-/var/tmp/lid-ds-2021/official-cache}
PY=/home/dat/ml-venv/bin/python
ALARMS=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz
CB=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-cbds-alarms.json.gz
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 SRC OC PY ALARMS
cd /tmp
mkdir -p "$OC"
one() {
  [ -f "$OC/$1.json" ] && return 0
  $PY -u "$SRC/scripts/analysis/lidds_token_cache.py" --archives /var/tmp/lid-ds-2021 --scenario "$1" --alarms "$ALARMS" --part official \
      --n 4 --output "$OC/$1.npz" > "$OC/$1.log" 2>&1 || { echo "FAILED $1"; return 1; }
  echo "official cache $1 $(date -u +%FT%T)"
}
export -f one
ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | xargs -P "${JOBS:-4}" -I{} bash -c 'one {}'
echo "official $(date -u +%FT%T)"
$PY -u "$SRC/scripts/analysis/lidds2019_dev.py" official --caches "$OC" --out "$OUT" --lidds-alarms "$ALARMS" --cbds-alarms "$CB" --jobs "${JOBS:-4}"
echo "holdout $(date -u +%FT%T)"
$PY -u "$SRC/scripts/analysis/lidds2019_dev.py" holdout --archives /var/tmp/lid-ds-2019-v2/archives --split "$OUT/split.json" \
    --tokens /var/tmp/lid-ds-2019-v2/tokens --out "$OUT" --jobs "${JOBS:-4}"
echo "done $(date -u +%FT%T)"
