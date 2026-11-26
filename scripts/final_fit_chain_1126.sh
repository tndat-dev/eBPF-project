#!/bin/bash
# Fit 3 ngày sau khi nén xong và B1 xong (chủ đồ án yêu cầu watcher, 26/11). Chạy bằng root (systemd-run cho từng bước).
set -u
D=/var/tmp/final-fit-1126; A=/mnt/sentinel-pulse-archive; OUT=$A/pulse-live-diurnal3-fit-1126
PY=/home/dat/.venvs/sentinel-pulse/bin/python; CODE=/home/dat/eBPF-project
log() { echo "$(date '+%F %T %z') $*" >> $D/chain.log; }
fail() { log "FAILED: $*"; echo "$*" > $D/FAILED; exit 1; }
log "waiting for compression (3 markers) and b1-1126"
deadline=$(( $(date +%s) + 6*3600 ))
while [ "$(ls $A/.compress-done-1126-* 2>/dev/null | wc -l)" -lt 3 ] || systemctl is-active -q b1-1126; do
  [ "$(date +%s)" -gt "$deadline" ] && fail "timeout waiting for compression or B1"
  sleep 120
done
for m in $A/.compress-done-1126-*; do
  grep -q '^Result=success' "$m" || fail "compression unit failed: $m"
  [ "$(grep -c '"mismatched": \[\]' "$m")" -eq 2 ] || fail "seal mismatch or missing total: $m"
done
plain=$(ls $A/pulse-token-capture-diurnal-1121/workers/*/segments/*/tokens.jsonl $A/pulse-token-capture-diurnal2-1124/workers/*/segments/*/tokens.jsonl 2>/dev/null | wc -l)
[ "$plain" -eq 0 ] || fail "$plain plain tokens.jsonl left"
log "compression ok; b1-1126 result: $(systemctl show -p Result b1-1126 | cut -d= -f2)"
install -d -o dat -g dat $OUT
run() {  # name memory args...
  local name=$1 mem=$2; shift 2
  log "start $name"
  systemd-run --wait --collect --quiet --unit "$name" --uid dat --gid dat -p MemoryMax="$mem" -p OOMPolicy=continue \
    -p WorkingDirectory=$CODE -p StandardOutput=file:$D/$name.log -p StandardError=file:$D/$name.err "$PY" "$@"
  local rc=$?; log "end $name rc=$rc"; return $rc
}
COMMON=(scripts/analysis/token_branch_fit.py --run-root $A/pulse-token-capture-diurnal2-1124
  --train 1795521400.1032605 1795659640.1032605 --validation 1795659640.1032605 1795694200.1032605
  --alpha 0.0003 --block 60 --folds 5 --fold-seconds 1800 --top 3 --trim 0.005
  --extra-run $A/pulse-token-capture-diurnal-1121 --extra-span 1795265817.0669737 1795352217.0669737
  --extra-run $A/pulse-live-final-1119 --extra-span 1795184498.5691864 1795218639.152689 --gzip-work)
( run fit3-token-1126 18G "${COMMON[@]}" --share 1 --output $OUT/token --dump-maxima $OUT/maxima --work $D/work-token --jobs 3 \
    || echo token > $D/step-failed ) &
( run fit3-session-1126 12G "${COMMON[@]}" --share 0.5 --part session --pool-key pool/session --output $OUT/session-pooled --work $D/work-session \
    && run fit3-prog-1126 12G "${COMMON[@]}" --share 0.5 --part session --pool-key pool/session --by-prog --minimum-blocks 200 \
         --output $OUT/session-prog --work $D/work-prog \
    || echo session > $D/step-failed ) &
wait
[ -e $D/step-failed ] && fail "fit step: $(cat $D/step-failed | tr '\n' ' ')"
run fit3-a6-1126 4G scripts/analysis/improvement_round2.py a6 --fit-dir $OUT --capture $A/pulse-token-capture-diurnal2-1124 \
  --output $OUT/a6.json || fail a6
sudo -u dat "$PY" -c "import json,sys; json.dump(json.load(open('$OUT/a6.json'))['scale'], open('$OUT/a6-scale.json','w'), indent=1, sort_keys=True)" || fail a6-scale
run fit3-session-config-1126 2G scripts/analysis/session_branch_config.py --fit $OUT/token/FIT.json \
  --pooled $OUT/session-pooled/MODELS.json --branch-alpha 0.0003 --alpha-scale $OUT/a6-scale.json \
  --output $OUT/SESSION-S1a-A6.json || fail session-config
rm -rf $D/work-token $D/work-session $D/work-prog
log "DONE"; date '+%F %T %z' > $D/DONE
