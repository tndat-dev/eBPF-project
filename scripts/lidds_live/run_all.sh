#!/usr/bin/env bash
# Orchestrate a single-node lidds-live run on .234 (protocol pulse-live-lidds-v1): bring victims up on the pinned
# worker, start the lineage probe there, run a capture phase (normal only) and a live phase (exploits), stop the probe,
# collect the probe output and schedules into RUN, and score. Self-contained; uses ssh to the pinned worker.
#   SCN=ZipSlip,CVE-2017-7529,CVE-2020-9484 NODE=k8s-worker1.local WORKER=10.1.16.237 \
#   CAP=300 LIVE=420 RUN=/mnt/sentinel-pulse-archive/pulse-live-lidds-<date> bash run_all.sh
set -uo pipefail
cd /home/dat/eBPF-project
SCN=${SCN:?comma scenarios}; NODE=${NODE:?pinned node name}; WORKER=${WORKER:?pinned worker ip}
CAP=${CAP:-300}; LIVE=${LIVE:-420}; RUN=${RUN:?run dir on NFS}
SRC=/home/dat/eBPF-project; BUILD=/home/dat/pulse-tokens-lineage; POUT=/var/tmp/lidds-cap
mkdir -p "$RUN"
export PULSE_LIDDS_NODE=$NODE
echo "[1] bring victims up (capture duration $CAP primes them)"
# a short warmup capture run that only creates victims and sends a little normal traffic; keeps victims up afterwards
timeout 90 python3 scripts/lidds_live/driver.py capture --scenarios-file scripts/lidds_live/scenarios.json \
    --run-dir "$RUN" --duration 1 --only "$SCN" --seed 1 >/dev/null 2>&1 || true
kubectl -n lidds-live get deploy -o wide 2>/dev/null | sed -n 1,20p
echo "[2] start the lineage probe on $WORKER"
ssh "$WORKER" "echo 1 | sudo -S -p '' rm -rf $POUT; echo 1 | sudo -S -p '' systemd-run --unit=lidds-probe --uid=root -p MemoryMax=4G -p OOMPolicy=continue /bin/bash $SRC/scripts/lidds_live/run_probe.sh $BUILD $POUT $SRC" 2>&1 | tail -1
sleep 20
ssh "$WORKER" "echo 1 | sudo -S -p '' tail -1 $POUT/loader.err 2>/dev/null; echo 1 | sudo -S -p '' systemctl is-active lidds-probe"
echo "[3] capture phase ($CAP s, normal only)"
timeout $((CAP+120)) python3 scripts/lidds_live/driver.py capture --scenarios-file scripts/lidds_live/scenarios.json \
    --run-dir "$RUN" --duration "$CAP" --only "$SCN" --seed 20261113
echo "[4] live phase ($LIVE s, exploit cycles w.p. 0.5)"
timeout $((LIVE+180)) python3 scripts/lidds_live/driver.py live --scenarios-file scripts/lidds_live/scenarios.json \
    --run-dir "$RUN" --duration "$LIVE" --only "$SCN" --seed 20261113
echo "[5] stop probe, collect"
ssh "$WORKER" "echo 1 | sudo -S -p '' systemctl stop lidds-probe 2>/dev/null; echo 1 | sudo -S -p '' chmod -R a+r $POUT" 2>&1 | tail -1
for f in tokens.jsonl meta.jsonl loader.err resolver.err; do
  ssh "$WORKER" "echo 1 | sudo -S -p '' cat $POUT/$f 2>/dev/null" > "$RUN/$f"
done
echo "[6] score"
/home/dat/ml-venv/bin/python scripts/analysis/lidds_live_score.py --run-dir "$RUN" --output "$RUN/lidds-live-score.json"
echo "done: $RUN"
