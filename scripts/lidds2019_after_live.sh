#!/usr/bin/env bash
# lidds2019-confirmation-v1 on .234 as dat, once the live run's analysis unit has finished (no heavy job during a live
# run). The release must already be at $D/LID-DS-2019.zip (copied from 10.1.16.254 after the live run, sha256 checked).
# Builds the 10 LID-DS 2021-layout archives, converts them (6 in parallel), evaluates the frozen v2 arms in 4 parallel
# parts and merges.
#   SRC=/var/tmp/lid-ds-2019/source-<sha> [WAIT_UNITS="after-recal-confirm"] bash lidds2019_after_live.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
D=/var/tmp/lid-ds-2019
OUT=$D/eval
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
WANT=c87e881d5de9f237fe33b1474d68d9887257bd7ed2c9921c500e7ef9241656cf
for unit in ${WAIT_UNITS:-after-recal-confirm}; do
  while [ "$(systemctl is-active "$unit")" = active ] || [ "$(systemctl is-active "$unit")" = activating ]; do sleep 300; done
  echo "wait unit $unit is $(systemctl is-active "$unit") $(date -u +%FT%T)"
done
[ "$(sha256sum $D/LID-DS-2019.zip | cut -d' ' -f1)" = "$WANT" ] || { echo "release sha256 mismatch"; exit 1; }
mkdir -p $OUT $D/archives && cd /tmp
echo "build start $(date -u +%FT%T)"
$PY -m sentinel_pulse.lidds.lidds2019 $D/LID-DS-2019.zip --output $D/archives > $OUT/build.log 2>&1 || { echo "build FAILED"; exit 1; }
echo "conversion start $(date -u +%FT%T)"
ls $D/archives/*.zip | xargs -P 6 -I{} $PY -m sentinel_pulse.lidds.convert {} --output $D/converted >> $OUT/convert.log 2>&1
echo "conversion done $(date -u +%FT%T)"
names=($(ls $D/converted | sort))
pids=()
for k in 0 1 2 3; do
  args=(); for i in "${!names[@]}"; do [ $((i % 4)) = $k ] && args+=(--scenario "${names[$i]}"); done
  OMP_NUM_THREADS=3 $PY -u $SRC/scripts/analysis/lidds_evaluate_v2.py --converted $D/converted --archives $D/archives \
    --exec-set $SRC/validation-evidence/results-20261021/pulse-stable-candidate/final/exec-set-E.json \
    "${args[@]}" --output $OUT/part-$k.json > $OUT/evaluate-$k.log 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || echo "part $p FAILED"; done
$PY $SRC/scripts/analysis/lidds_evaluate_v2.py --merge $OUT/part-0.json $OUT/part-1.json $OUT/part-2.json $OUT/part-3.json \
  --output $OUT/lidds2019-evaluation-v2.json || echo "merge FAILED"
echo "lid-ds 2019 done $(date -u +%FT%T)"
