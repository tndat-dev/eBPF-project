#!/usr/bin/env bash
# LID-DS 2019 development study (protocol lidds2019-development-v1) on .234: split once, development caches, gate, study.
# Chạy trong systemd-run có MemoryMax; không đụng phần holdout.
set -euo pipefail
SRC=${SRC:?source checkout}
BASE=${BASE:-/var/tmp/lid-ds-2019-v2}
OUT=${OUT:-$BASE/development}
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
cd /tmp
mkdir -p "$OUT/caches"
[ -f "$OUT/split.json" ] || $PY -u "$SRC/scripts/analysis/lidds2019_dev.py" split --tokens "$BASE/tokens" --output "$OUT/split.json"
one() {
  [ -f "$OUT/caches/$1.npz" ] && return 0
  $PY -u "$SRC/scripts/analysis/lidds2019_dev.py" cache --archives "$BASE/archives" --scenario "$1" --split "$OUT/split.json" \
      --output "$OUT/caches/$1.npz" > "$OUT/caches/$1.log" 2>&1 || { echo "FAILED $1"; return 1; }
  echo "cache done $1 $(date -u +%FT%T)"
}
export -f one; export OUT SRC PY BASE
ls -S -r "$BASE"/archives/*.zip | xargs -n1 basename | sed 's/\.zip$//' | xargs -P "${JOBS:-3}" -I{} bash -c 'one {}'
echo "gate $(date -u +%FT%T)"
$PY -u "$SRC/scripts/analysis/lidds2019_dev.py" gate --caches "$OUT/caches" --tokens "$BASE/tokens" --out "$OUT" --jobs "${JOBS:-3}"
echo "study $(date -u +%FT%T)"
$PY -u "$SRC/scripts/analysis/lidds2019_dev.py" study --caches "$OUT/caches" --out "$OUT" --jobs "${JOBS:-3}" \
    --receipts "$SRC/validation-evidence/results-20261112/token-design-study"
echo "done $(date -u +%FT%T)"
