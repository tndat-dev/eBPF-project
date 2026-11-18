#!/usr/bin/env bash
# improvement-round-v1 D8 (path2, path2+connect) and D17 (exec) on .234: richer caches for LID-DS 2021 development,
# CB-DS and LID-DS 2019 development, scoring of four specs, evaluation. Chạy trong systemd-run có MemoryMax.
set -euo pipefail
SRC=${SRC:?source checkout}; W=${W:-/var/tmp/improve-rich}; PY=/home/dat/ml-venv/bin/python
ALARMS=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz
CB=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-cbds-alarms.json.gz
D19=/var/tmp/lid-ds-2019-v2
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 SRC W PY ALARMS D19
cd /tmp
mkdir -p "$W"/2021 "$W"/2019
[ -e "$W/2021/base" ] || ln -s /var/tmp/lid-ds-2021/token-study/cache "$W/2021/base"
[ -e "$W/2019/base" ] || ln -s "$D19/development/caches" "$W/2019/base"
one() {  # variant dataset scenario
  local out="$W/$2/$1/$3.npz"; [ -f "${out%.npz}.json" ] && return 0
  mkdir -p "$W/$2/$1"
  if [ "$2" = 2019 ]; then
    $PY -u "$SRC/scripts/analysis/rich_token_cache.py" --variant "$1" --archives "$D19/archives" --scenario "$3" \
        --split "$D19/development/split.json" --output "$out" > "${out%.npz}.log" 2>&1 || echo "FAILED $*"
  elif [ "$3" = CB-DS ]; then
    $PY -u "$SRC/scripts/analysis/rich_token_cache.py" --variant "$1" --archives /var/tmp/cb-ds/archives --scenario CB-DS \
        --output "$out" > "${out%.npz}.log" 2>&1 || echo "FAILED $*"
  else
    $PY -u "$SRC/scripts/analysis/rich_token_cache.py" --variant "$1" --archives /var/tmp/lid-ds-2021 --scenario "$3" \
        --alarms "$ALARMS" --part development --output "$out" > "${out%.npz}.log" 2>&1 || echo "FAILED $*"
  fi
  echo "cache $* $(date -u +%FT%T)"
}
export -f one
{ for v in path2 exec; do
    echo "$v 2021 CB-DS"
    ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed "s/^/$v 2021 /"
    ls -S -r "$D19"/archives/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed "s/^/$v 2019 /"
  done; } | xargs -P "${JOBS:-6}" -L 1 bash -c 'one $0 $1 $2'
echo "score $(date -u +%FT%T)"
$PY -u "$SRC/scripts/analysis/improvement_offline.py" score-rich --caches-root "$W/2021" --out "$W/2021-out" --jobs "${JOBS:-6}"
$PY -u "$SRC/scripts/analysis/improvement_offline.py" score-rich --caches-root "$W/2019" --out "$W/2019-out" --jobs "${JOBS:-6}"
echo "evaluate $(date -u +%FT%T)"
$PY -u "$SRC/scripts/analysis/improvement_offline.py" rich --scores2021 "$W/2021-out/scores" --scores2019 "$W/2019-out/scores" \
    --caches2019-root "$W/2019" --lidds-alarms "$ALARMS" --cbds-alarms "$CB" --output "$W/rich.json"
echo "done $(date -u +%FT%T)"
