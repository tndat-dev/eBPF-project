#!/usr/bin/env bash
# Launch the R6 live run (shadow preview only) from k8s-master (.234) as user dat.
#
#   LAB_SSH_PASSWORD=... bash launch_r6.sh [plan|workers|rca|master|all]
#   LAB_SSH_PASSWORD=... COORDINATOR_SOURCE=/mnt/.../source bash launch_r6.sh [derive|rca|master]
#
# COORDINATOR_SOURCE (optional) moves the campaign and RCA onto a newer source
# snapshot through derive_matched_coordinator_run, keeping the worker capture.
# 19/10: used to bound in-container `tetra getevents` clients that leaked.
#
# R6 = recalibrated candidate ec72d9ea... + policy recalibrated-preview-policy-r6
# (k1of1, alpha x3), fixture runtime_attack_r6.c with benign-exec controls, 24 h
# capture without raw.jsonl, RCA subscriber with the flow policy and a frozen
# binary baseline. Every step refuses to overwrite an existing run/unit.
set -euo pipefail
: "${LAB_SSH_PASSWORD:?set LAB_SSH_PASSWORD}"
SNAP=/mnt/sentinel-pulse-archive/runtime-r6-4ba303a-20261018/source
ROOT=/mnt/sentinel-pulse-archive/matched-r6-20261018
RUN=r6-20261018
CREDENTIAL=/home/dat/.pulse-recovery-credential-20261005
RCA_NAME=runtime-events-20261018-r6
WORKERS=(10.1.16.237 10.1.16.238 10.1.16.239)
COORDINATOR_SOURCE=${COORDINATOR_SOURCE:-}
COORD=$ROOT/coordinator-$(basename "$(dirname "${COORDINATOR_SOURCE:-/none/x}")")
CAMPAIGN_CONFIG=$ROOT/CONFIG.json; RCA_SOURCE=$SNAP
if [ -n "$COORDINATOR_SOURCE" ]; then CAMPAIGN_CONFIG=$COORD/CONFIG.json; RCA_SOURCE=$COORDINATOR_SOURCE; fi
export SSHPASS=$LAB_SSH_PASSWORD

as_root() { printf '%s\n' "$LAB_SSH_PASSWORD" | sudo -S -p '' "$@"; }

plan() {
  cd /tmp
  PYTHONPATH=$SNAP /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.plan_matched_run \
    --source "$SNAP" --root "$ROOT" --run-id "$RUN" --profile r6 --frozen-source "$SNAP"
}

workers() {
  for host in "${WORKERS[@]}"; do
    sshpass -e ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/home/dat/.ssh/known_hosts "dat@$host" \
      "cd /tmp && sudo -S -p '' env PYTHONPATH=$SNAP /opt/sentinel-pulse/runtime-venv/bin/python \
       -m sentinel_pulse.pipeline.matched_services --config $ROOT/CONFIG.json --role worker" <<<"$LAB_SSH_PASSWORD"
  done
}

derive() {
  [ -n "$COORDINATOR_SOURCE" ] || { echo 'COORDINATOR_SOURCE required' >&2; return 1; }
  cd /tmp
  PYTHONPATH=$COORDINATOR_SOURCE /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.derive_matched_coordinator_run \
    --capture-config "$ROOT/CONFIG.json" --source "$COORDINATOR_SOURCE" --root "$COORD" --run-id "$RUN-coordinator"
}

wait_for_workers() {
  for _ in $(seq 60); do
    ready=0
    for node in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
      python3 -c "import json,sys;sys.exit(0 if json.load(open('$ROOT/workers/$node/STATUS.json')).get('current_segment') else 1)" \
        2>/dev/null && ready=$((ready+1))
    done
    [ "$ready" = 3 ] && return 0
    sleep 5
  done
  echo 'workers did not report a current segment' >&2; return 1
}

rca() {
  wait_for_workers
  kubectl apply -f "$RCA_SOURCE/sentinel_pulse/k8s/tetragon-rca-flow-policy.yaml"
  as_root mkdir -p "/opt/sentinel-pulse-rca/$RCA_NAME"
  # NFS ACLs cannot be preserved on local disk; plain mode/timestamps are enough.
  as_root test -d "/opt/sentinel-pulse-rca/$RCA_NAME/source/.git" ||
    as_root cp -r --preserve=mode,timestamps "$RCA_SOURCE" "/opt/sentinel-pulse-rca/$RCA_NAME/source"
  as_root git -C "/opt/sentinel-pulse-rca/$RCA_NAME/source" -c safe.directory='*' rev-parse HEAD
  python3 - "$CAMPAIGN_CONFIG" >"/tmp/$RCA_NAME.json" <<'PY'
import json, sys
run = json.load(open(sys.argv[1]))
print(json.dumps(dict(
    output='/var/lib/sentinel-pulse-rca/runtime-events-20261018-r6',
    previous_output='/var/lib/sentinel-pulse-rca/runtime-events-20261015-r2',
    registration_reason='R6 live run: recalibrated candidate + R6 policy; adds the sampled '
                        'tcp/udp_sendmsg flow policy and a binary baseline frozen before the first attack',
    kubeconfig='/home/dat/.kube/config', model_hash=run['model_hash'], policy_hash=run['policy_hash'],
    runtime_events=True, connect_policy='sentinel-rca-runtime-v1',
    runtime_policies=['sentinel-rca-runtime-v1', 'sentinel-rca-fork-v1', 'sentinel-rca-flow-v1'],
    workers=[dict(node_name=w['node_name'], output=w['output']) for w in run['workers'].values()],
    before_seconds=30, after_seconds=0, case_ready_grace_seconds=2, ring_seconds=180,
    max_ring_events=120000, max_cases=2000, case_cooldown_seconds=300,
    binary_baseline_frozen_at=run['attack_not_before'] - 120), indent=2))
PY
  as_root install -m 0640 -o root -g dat "/tmp/$RCA_NAME.json" "/etc/sentinel-pulse-rca/$RCA_NAME.json"
  rm -f "/tmp/$RCA_NAME.json"
  unit=/etc/systemd/system/pulse-rca-runtime-events-r6.service
  systemctl is-active --quiet pulse-rca-runtime-events-r6.service && { echo "$unit already running" >&2; return 1; }
  # Write via a temp file: as_root feeds the password on stdin, so it cannot also carry a heredoc.
  cat >/tmp/pulse-rca-r6.service <<UNIT
[Unit]
Description=Pulse RCA runtime-event subscriber ($RUN, read-only)
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/mnt/sentinel-pulse-archive

[Service]
Type=simple
User=root
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONPATH=/opt/sentinel-pulse-rca/$RCA_NAME/source
ExecStart=/usr/bin/python3 -u -m sentinel_pulse.rca.service --config /etc/sentinel-pulse-rca/$RCA_NAME.json
Restart=on-failure
RestartSec=30
MemoryMax=2G
Nice=10

[Install]
WantedBy=multi-user.target
UNIT
  as_root install -m 0644 -o root -g root /tmp/pulse-rca-r6.service "$unit"
  rm -f /tmp/pulse-rca-r6.service
  as_root systemctl daemon-reload
  as_root systemctl disable --now pulse-rca-runtime-events.service
  as_root systemctl enable --now pulse-rca-runtime-events-r6.service
}

master() {
  cd /tmp
  as_root env PYTHONPATH="$SNAP" /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.matched_services \
    --config "$ROOT/CONFIG.json" --role traffic
  as_root env PYTHONPATH="$SNAP" /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.matched_services \
    --config "$CAMPAIGN_CONFIG" --role campaign --credential "$CREDENTIAL"
}

case "${1:-all}" in
  plan) plan ;; workers) workers ;; derive) derive ;; rca) rca ;; master) master ;;
  all) plan; workers; rca; master ;;
  *) echo "unknown step $1" >&2; exit 2 ;;
esac
