#!/usr/bin/env bash
# lidds-evaluation-v2 on .234 as dat, once the live run's analysis unit has finished (no heavy job during a live run):
# alias conversion of the 15 LID-DS 2021 archives (6 in parallel), then the v2 evaluation in 4 parallel parts merged.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [WAIT_UNITS="after-recal-confirm"] bash lidds_v2_after_live.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
D=/var/tmp/lid-ds-2021
OUT=$D/v2
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1
for unit in ${WAIT_UNITS:-after-recal-confirm}; do
  while [ "$(systemctl is-active "$unit")" = active ] || [ "$(systemctl is-active "$unit")" = activating ]; do sleep 300; done
  echo "wait unit $unit is $(systemctl is-active "$unit") $(date -u +%FT%T)"
done
mkdir -p "$OUT" && cd /tmp
echo "conversion start $(date -u +%FT%T)"
ls $D/*.zip | xargs -P 6 -I{} $PY -m sentinel_pulse.lidds.convert {} --output $D/converted-v2 >> $OUT/convert.log 2>&1
echo "conversion done $(date -u +%FT%T)"
names=($(ls $D/converted-v2 | sort))
pids=()
for k in 0 1 2 3; do
  args=(); for i in "${!names[@]}"; do [ $((i % 4)) = $k ] && args+=(--scenario "${names[$i]}"); done
  OMP_NUM_THREADS=3 $PY -u $SRC/scripts/analysis/lidds_evaluate_v2.py --converted $D/converted-v2 --archives $D \
    --exec-set $SRC/validation-evidence/results-20261021/pulse-stable-candidate/final/exec-set-E.json \
    "${args[@]}" --output $OUT/part-$k.json > $OUT/evaluate-$k.log 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || echo "part $p FAILED"; done
echo "evaluation parts done $(date -u +%FT%T)"
$PY $SRC/scripts/analysis/lidds_evaluate_v2.py --merge $OUT/part-0.json $OUT/part-1.json $OUT/part-2.json $OUT/part-3.json \
  --output $OUT/lidds-evaluation-v2.json || echo "merge FAILED"
echo "v2 done $(date -u +%FT%T)"
