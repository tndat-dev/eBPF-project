#!/bin/bash
# burst-round-v1 (27/11): sau capture sale-day 8 h, fit lại 3 ngày + capture sale (cùng tham số), A6, chỉ số burst trên
# khối của capture 1124, cấu hình S1a + A6 và chấm tấn công trên khoảng của lượt 1119. Chạy bằng root (systemd-run).
set -u
D=/var/tmp/burst-fit-1128; A=/mnt/sentinel-pulse-archive; OUT=$A/pulse-live-burst-fit-1128
PY=/home/dat/.venvs/sentinel-pulse/bin/python; CODE=/home/dat/eBPF-project; CAP=$A/pulse-token-capture-sale-1127
mkdir -p $D
log() { echo "$(date '+%F %T %z') $*" >> $D/chain.log; }
fail() { log "FAILED: $*"; echo "$*" > $D/FAILED; exit 1; }
run() {  # name memory args...
  local name=$1 mem=$2; shift 2
  log "start $name"
  systemd-run --wait --collect --quiet --unit "$name" --uid dat --gid dat -p MemoryMax="$mem" -p OOMPolicy=continue \
    -p WorkingDirectory=$CODE -p StandardOutput=file:$D/$name.log -p StandardError=file:$D/$name.err "$PY" "$@"
  local rc=$?; log "end $name rc=$rc"; return $rc
}
log "waiting for the sale-day capture (3 worker TERMINAL.json)"
deadline=$(( $(date +%s) + 12*3600 ))
while [ "$(ls $CAP/workers/*/TERMINAL.json 2>/dev/null | wc -l)" -lt 3 ]; do
  [ "$(date +%s)" -gt "$deadline" ] && fail "timeout waiting for the capture"
  sleep 120
done
log "capture done"
install -d -o dat -g dat $OUT
COMMON=(scripts/analysis/token_branch_fit.py --run-root $A/pulse-token-capture-diurnal2-1124
  --train 1795521400.1032605 1795659640.1032605 --validation 1795659640.1032605 1795694200.1032605
  --alpha 0.0003 --block 60 --folds 5 --fold-seconds 1800 --top 3 --trim 0.005
  --extra-run $A/pulse-token-capture-diurnal-1121 --extra-span 1795265817.0669737 1795352217.0669737
  --extra-run $A/pulse-live-final-1119 --extra-span 1795184498.5691864 1795218639.152689
  --extra-run $CAP --extra-span 1795783458.1090028 1795812258.1090028 --gzip-work)
rm -f $D/step-failed
( run burst-token-1128 18G "${COMMON[@]}" --share 1 --output $OUT/token --dump-maxima $OUT/maxima --work $D/work-token --jobs 3 \
    || echo token >> $D/step-failed ) &
( run burst-session-1128 12G "${COMMON[@]}" --share 0.5 --part session --pool-key pool/session --output $OUT/session-pooled \
    --work $D/work-session || echo session >> $D/step-failed ) &
wait
[ -e $D/step-failed ] && fail "fit step: $(tr '\n' ' ' < $D/step-failed)"
rm -rf $D/work-token $D/work-session
run burst-a6-1128 4G scripts/analysis/improvement_round2.py a6 --fit-dir $OUT --capture $A/pulse-token-capture-diurnal2-1124 \
  --output $OUT/a6.json || fail a6
sudo -u dat "$PY" -c "import json; json.dump(json.load(open('$OUT/a6.json'))['scale'], open('$OUT/a6-scale.json','w'), indent=1, sort_keys=True)" || fail a6-scale
run burst-metric-1128 4G scripts/analysis/burst_round.py --fit-dir $OUT --capture $A/pulse-token-capture-diurnal2-1124 \
  --baseline $D/burst-baseline.json --output $OUT/burst-round.json || fail metric
run burst-session-config-1128 2G scripts/analysis/session_branch_config.py --fit $OUT/token/FIT.json \
  --pooled $OUT/session-pooled/MODELS.json --branch-alpha 0.0003 --alpha-scale $OUT/a6-scale.json \
  --output $OUT/SESSION-S1a-A6.json || fail session-config
run burst-attacks-1128 20G scripts/analysis/improvement_round2.py intervals --run-root $A/pulse-live-final-1119 \
  --session $OUT/session-pooled/MODELS.json --fit $OUT/token/FIT.json --alpha-scale $OUT/a6-scale.json \
  --system S1a_A6=$OUT/token/MODELS.json:a6 --output $OUT/attacks-1119.json --jobs 4 || fail attacks
log "DONE"; date '+%F %T %z' > $D/DONE
