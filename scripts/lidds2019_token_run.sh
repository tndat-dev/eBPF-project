#!/usr/bin/env bash
# lidds2019-confirmation-v2 on .234 as dat, once, after the live run (no heavy job during a live run). Run it inside a
# unit with a memory cap:
#   systemd-run --unit lidds2019-v2 -p MemoryMax=24G -p OOMPolicy=continue --uid=dat --gid=dat \
#     env SRC=/home/dat/eBPF-project bash /home/dat/eBPF-project/scripts/lidds2019_token_run.sh
# [VI] LID-DS 2019 với mô hình token cuối, đúng một lần: kiểm SHA-256 của bản phát hành → chuyển 10 kịch bản sang bố cục
# [VI] 2021 (sentinel_pulse/lidds/lidds2019.py) → ma trận cross-fit từng kịch bản (lidds_ml_token_crossfit.py, không đổi) →
# [VI] chấm một lần (lidds2019_token.py score, cần gate đã đạt; file kết quả không được tồn tại trước).
set -euo pipefail
SRC=${SRC:?source checkout}
BASE=${BASE:-/var/tmp/lid-ds-2019-v2}
RELEASE=${RELEASE:-/var/tmp/lid-ds-2019/LID-DS-2019.zip}
SHA=c87e881d5de9f237fe33b1474d68d9887257bd7ed2c9921c500e7ef9241656cf   # registered in lidds2019-confirmation-v1/v2
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
cd /tmp
[ -f "$BASE/gate.json" ] || { echo "no gate receipt in $BASE" >&2; exit 1; }
[ ! -e "$BASE/lidds2019.json" ] || { echo "$BASE/lidds2019.json exists: LID-DS 2019 is scored once" >&2; exit 1; }
echo "sha256 check $(date -u +%FT%T)"
echo "$SHA  $RELEASE" | sha256sum -c -
mkdir -p "$BASE/archives" "$BASE/tokens"
echo "convert $(date -u +%FT%T)"
[ -n "$(ls "$BASE"/archives/*.zip 2>/dev/null)" ] || $PY -u -m sentinel_pulse.lidds.lidds2019 "$RELEASE" --output "$BASE/archives"
one() {
  [ -f "$BASE/tokens/$1.json" ] && return 0
  $PY -u "$SRC/scripts/analysis/lidds_ml_token_crossfit.py" --archives "$BASE/archives" --scenario "$1" --folds 5 \
      --output "$BASE/tokens/$1.npz" > "$BASE/tokens/$1.log" 2>&1 || { echo "FAILED $1"; return 1; }
  echo "crossfit done $1 $(date -u +%FT%T)"
}
export -f one; export BASE SRC PY
ls -S -r "$BASE"/archives/*.zip | xargs -n1 basename | sed 's/\.zip$//' | xargs -P "${JOBS:-3}" -I{} bash -c 'one {}'
echo "score $(date -u +%FT%T)"
$PY -u "$SRC/scripts/analysis/lidds2019_token.py" score --tokens "$BASE/tokens" --archives "$BASE/archives" \
    --gate "$BASE/gate.json" --output "$BASE/lidds2019.json"
echo "lidds2019 done $(date -u +%FT%T)"
