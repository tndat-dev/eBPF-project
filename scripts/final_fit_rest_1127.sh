#!/bin/bash
# Phần còn lại của fit 3 ngày sau khi bước --by-prog của final_fit_chain_1126.sh lỗi (27/11): capture 1121 và lượt
# 1119 ghi bằng probe cũ, không có session_prog. exec-identity-v1 học mô hình theo chương trình từ capture có mã chương
# trình, nên bước này chỉ dùng capture 1124. Song song: A6 + SESSION-S1a-A6.json + kiểm t3 trên dataset; B1 chạy lại
# (thêm admin_without_b1 theo lệnh). Chạy bằng root.
set -u
D=/var/tmp/final-fit-1126; A=/mnt/sentinel-pulse-archive; OUT=$A/pulse-live-diurnal3-fit-1126
PY=/home/dat/.venvs/sentinel-pulse/bin/python; CODE=/home/dat/eBPF-project
E=$CODE/validation-evidence/results-20261101/lidds-v4; F23=$A/pulse-live-diurnal-fit-1123
log() { echo "$(date '+%F %T %z') $*" >> $D/chain.log; }
run() {  # name memory args...
  local name=$1 mem=$2; shift 2
  log "start $name"
  systemd-run --wait --collect --quiet --unit "$name" --uid dat --gid dat -p MemoryMax="$mem" -p OOMPolicy=continue \
    -p WorkingDirectory=$CODE -p StandardOutput=file:$D/$name.log -p StandardError=file:$D/$name.err "$PY" "$@"
  local rc=$?; log "end $name rc=$rc"; return $rc
}
rm -f $D/FAILED $D/step-failed; rm -rf $D/work-prog; install -d -o dat -g dat $D/b1
( run fit3-prog-1127 12G scripts/analysis/token_branch_fit.py --run-root $A/pulse-token-capture-diurnal2-1124 \
    --train 1795521400.1032605 1795659640.1032605 --validation 1795659640.1032605 1795694200.1032605 \
    --alpha 0.0003 --block 60 --folds 5 --fold-seconds 1800 --top 3 --trim 0.005 --gzip-work \
    --share 0.5 --part session --pool-key pool/session --by-prog --minimum-blocks 200 \
    --output $OUT/session-prog --work $D/work-prog || echo prog >> $D/step-failed ) &
( run fit3-a6-1127 4G scripts/analysis/improvement_round2.py a6 --fit-dir $OUT \
    --capture $A/pulse-token-capture-diurnal2-1124 --output $OUT/a6.json \
  && sudo -u dat "$PY" -c "import json; json.dump(json.load(open('$OUT/a6.json'))['scale'], open('$OUT/a6-scale.json','w'), indent=1, sort_keys=True)" \
  && run fit3-session-config-1127 2G scripts/analysis/session_branch_config.py --fit $OUT/token/FIT.json \
    --pooled $OUT/session-pooled/MODELS.json --branch-alpha 0.0003 --alpha-scale $OUT/a6-scale.json \
    --output $OUT/SESSION-S1a-A6.json \
  && run datasets-t3-1127 6G scripts/analysis/improvement_round2.py datasets --out /var/tmp/lid-ds-2019-v2/development \
    --caches21 /var/tmp/lid-ds-2021/token-study/cache --lidds-alarms $E/lidds-evaluation-v2-alarms.json.gz \
    --cbds-alarms $E/lidds-evaluation-v2-cbds-alarms.json.gz --output $D/datasets.json --jobs 4 \
  || echo a6-config-datasets >> $D/step-failed ) &
( run b1-1127 20G scripts/analysis/improvement_round2.py intervals --run-root $A/pulse-live-final-1119 \
    --session $F23/session-pooled/MODELS.json --fit $F23/token/FIT.json \
    --alpha-scale $CODE/validation-evidence/results-20261124/improvement-round-2/a6-scale.json \
    --system S1a_A6=$F23/token/MODELS.json:a6 --b1-runs $A/pulse-live-v6-1117 --output $D/b1/b1.json --jobs 4 \
  || echo b1 >> $D/step-failed ) &
wait
if [ -e $D/step-failed ]; then log "FAILED: $(tr '\n' ' ' < $D/step-failed)"; cp $D/step-failed $D/FAILED; exit 1; fi
rm -rf $D/work-token $D/work-session $D/work-prog
log "DONE"; date '+%F %T %z' > $D/DONE
