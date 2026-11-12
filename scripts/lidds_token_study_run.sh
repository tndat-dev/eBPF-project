#!/usr/bin/env bash
# Token design study (protocol token-design-study-v1 + amendment 1) on .234 as dat. Run it inside a unit with a memory cap:
#   systemd-run --unit=token-study --uid=dat -p MemoryMax=30G -p OOMPolicy=continue -p Nice=10 \
#     env SRC=/var/tmp/lid-ds-2021/source-<sha> bash $SRC/scripts/lidds_token_study_run.sh
# [JOBS=12 OUT=/var/tmp/lid-ds-2021/token-study STEPS="cache gate q1 q2 q3 q4" ONLY="CVE-2014-0160 CVE-2017-7529"]
# cache: development test recordings only (official is not read); CB-DS: every recording. Finished parts are kept.
# PART=official OUT=.../token-study-official STEPS="cache official" SPEC_FROM=.../q1.json: the declared official scoring.
# GUARD=unit-name: do nothing while that systemd unit is active on a worker-facing run (no heavy job during a live run).
set -uo pipefail
SRC=${SRC:?source snapshot}
OUT=${OUT:-/var/tmp/lid-ds-2021/token-study}
JOBS=${JOBS:-12}
STEPS=${STEPS:-cache gate q1 q2 q3 q4}
PY=/home/dat/ml-venv/bin/python
ALARMS=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz
CB_ALARMS=$SRC/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-cbds-alarms.json.gz
export SRC OUT PY ALARMS PART=${PART:-development} PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
if [ -n "${GUARD:-}" ] && systemctl is-active -q "$GUARD"; then
  echo "guard: $GUARD is active, nothing started"; exit 0
fi
mkdir -p $OUT/cache && cd /tmp
one() {
  [ -f $OUT/cache/$2.json ] && return 0
  local filter=(); [ "$2" = CB-DS ] || filter=(--alarms $ALARMS --part ${PART:-development})
  $PY -u $SRC/scripts/analysis/lidds_token_cache.py --archives $1 --scenario $2 "${filter[@]}" --output $OUT/cache/$2.npz > $OUT/cache/$2.log 2>&1 || echo "FAILED $2"
  echo "cached $2 $(date -u +%FT%T)"
}
export -f one
for step in $STEPS; do
  echo "== $step $(date -u +%FT%T)"
  if [ "$step" = cache ]; then
    { echo "/var/tmp/cb-ds/archives CB-DS"
      ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//' | sed 's|^|/var/tmp/lid-ds-2021 |'
    } | { if [ -n "${ONLY:-}" ]; then grep -E " ($(echo $ONLY | tr ' ' '|'))\$"; else cat; fi; } | xargs -P $JOBS -L 1 bash -c 'one $0 $1'
  else
    ref=(); [ "$step" = gate ] && ref=(--reference ${REFERENCE:-/var/tmp/lid-ds-2021/ml-xfit-tokens})
    [ "$step" = official ] && ref=(--spec-from ${SPEC_FROM:?q1.json})
    $PY -u $SRC/scripts/analysis/lidds_token_study.py $step --caches $OUT/cache --out $OUT --lidds-alarms $ALARMS \
      --cbds-alarms $CB_ALARMS --jobs $JOBS "${ref[@]}" || { echo "FAILED $step"; exit 1; }
  fi
done
echo "token study done $(date -u +%FT%T)"
