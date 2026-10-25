#!/usr/bin/env bash
# Launch a matched live run (shadow preview only) from k8s-master (.234) as user dat.
# Generalises launch_pulse_live_recalibrated.sh; every pinned value comes from the environment:
#
#   LAB_SSH_PASSWORD=... RUN=pulse-stable-candidate SNAP=/mnt/.../source \
#   CANDIDATE=/mnt/.../model-bundle MODEL_HASH=... POLICY=sentinel_pulse/protocol/x.json POLICY_HASH=... \
#   [FIXTURE=testbed/attack/runtime_attack_with_benign_control.c] [SECONDS_TOTAL=86400] [FAST=1] \
#   [RCA_PREV_UNIT=rca-subscriber] [ATTACK_RATES=1,3,6] [BASELINE_SEED=/mnt/.../rca-baseline-seed.json] [FINAL=1] \
#   [FROZEN_SOURCE=/mnt/.../source whose pinned scorer bytes the workers must match; default SNAP] \
#   bash launch_run.sh [plan|workers|rca|bridge|master|all]
#
# Defaults: benign-exec controls on, no raw.jsonl, fast scoring on, RCA with follow-up cases.
# FINAL=1 (final system, owner 25/10): tripwire A1 in the workers (frozen exec set E), shared-storage writes off the
# scoring loop, decisions also on each worker's local disk (STREAM_ROOT) for the bridge, RCA and campaign, benign
# control from its own file name, RCA built from alerts Alertmanager delivered (bridge triggers), bridge before
# the campaign.
set -euo pipefail
: "${LAB_SSH_PASSWORD:?}" "${RUN:?}" "${SNAP:?}" "${CANDIDATE:?}" "${MODEL_HASH:?}" "${POLICY:?}" "${POLICY_HASH:?}"
FIXTURE=${FIXTURE:-testbed/attack/runtime_attack_with_benign_control.c}
SECONDS_TOTAL=${SECONDS_TOTAL:-86400}
FAST=${FAST:-1}
FINAL=${FINAL:-0}
STREAM_ROOT=${STREAM_ROOT:-/var/lib/sentinel-pulse-live}
EXEC_SET=validation-evidence/results-20261021/pulse-stable-candidate/final/exec-set-E.json
BRIDGE_OUT=/var/lib/sentinel-pulse-alert-bridge/$RUN
ROOT=/mnt/sentinel-pulse-archive/$RUN
CREDENTIAL=/home/dat/.pulse-recovery-credential-20261005
RCA_NAME=rca-$RUN                  # e.g. rca-pulse-stable-candidate
RCA_UNIT=$RCA_NAME
RCA_PREV_UNIT=${RCA_PREV_UNIT:-rca-subscriber}
WORKERS=(10.1.16.237 10.1.16.238 10.1.16.239)
export SSHPASS=$LAB_SSH_PASSWORD

as_root() { printf '%s\n' "$LAB_SSH_PASSWORD" | sudo -S -p '' "$@"; }

plan() {
  cd /tmp
  flags=(--benign-exec-control --no-raw-frames)
  [ "$FAST" = 1 ] && flags+=(--fast-scoring)
  [ -n "${ATTACK_RATES:-}" ] && flags+=(--attack-rates "$ATTACK_RATES")   # G4 slow attacker; default 6,12,24
  [ "$FINAL" = 1 ] && flags+=(--tripwire-exec-set "$SNAP/$EXEC_SET" --stream-root "$STREAM_ROOT")
  PYTHONPATH=$SNAP /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.plan_matched_run \
    --source "$SNAP" --root "$ROOT" --run-id "$RUN" --profile custom --frozen-source "${FROZEN_SOURCE:-$SNAP}" \
    --candidate "$CANDIDATE" --model-hash "$MODEL_HASH" --policy "$POLICY" --policy-hash "$POLICY_HASH" \
    --fixture "$FIXTURE" --seconds "$SECONDS_TOTAL" "${flags[@]}"
}

workers() {
  for host in "${WORKERS[@]}"; do
    # local decision copy: root writes (UMask 0027), group dat reads (bridge and RCA followers run as dat)
    [ "$FINAL" = 1 ] && sshpass -e ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/home/dat/.ssh/known_hosts \
      "dat@$host" "sudo -S -p '' install -d -o root -g dat -m 2750 $STREAM_ROOT/$RUN" <<<"$LAB_SSH_PASSWORD"
    sshpass -e ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/home/dat/.ssh/known_hosts "dat@$host" \
      "cd /tmp && sudo -S -p '' env PYTHONPATH=$SNAP /opt/sentinel-pulse/runtime-venv/bin/python \
       -m sentinel_pulse.pipeline.matched_services --config $ROOT/CONFIG.json --role worker" <<<"$LAB_SSH_PASSWORD"
  done
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
  as_root mkdir -p "/opt/sentinel-pulse-rca/$RCA_NAME"
  as_root test -d "/opt/sentinel-pulse-rca/$RCA_NAME/source/.git" ||
    as_root cp -r "$SNAP" "/opt/sentinel-pulse-rca/$RCA_NAME/source"
  RUN=$RUN FINAL=$FINAL BRIDGE_OUT=$BRIDGE_OUT python3 - "$ROOT/CONFIG.json" >"/tmp/$RCA_NAME.json" <<'PY'
import json, os, sys
run = json.load(open(sys.argv[1]))
print(json.dumps(dict(
    output='/var/lib/sentinel-pulse-rca/rca-' + os.environ['RUN'],
    registration_reason='live run ' + os.environ['RUN'] + ': runtime + fork + flow policies, follow-up cases on '
                        'novel execs (15-min exec log), 20000-case retention, binary baseline frozen before attacks',
    kubeconfig='/home/dat/.kube/config', model_hash=run['model_hash'], policy_hash=run['policy_hash'],
    runtime_events=True, connect_policy='sentinel-rca-runtime-v1',
    runtime_policies=['sentinel-rca-runtime-v1', 'sentinel-rca-fork-v1', 'sentinel-rca-flow-v1'],
    workers=[dict(node_name=w['node_name'], output=w.get('stream_root', w['output']), host=host) for host, w in run['workers'].items()],
    # read decisions on each worker over SSH: NFS write-back made them visible ~5 s late on .234
    decision_stream=dict(user='dat', credential='/home/dat/.pulse-recovery-credential-20261005', rotate_seconds=3600),
    before_seconds=30, after_seconds=0, case_ready_grace_seconds=2, ring_seconds=180,
    max_ring_events=120000, max_cases=20000, case_cooldown_seconds=300, stream_rotate_seconds=900,
    follow_up_on_new_exec=True, follow_up_min_seconds=10, follow_up_max_per_cooldown=5,
    follow_up_novelty_seconds=300, binary_baseline_frozen_at=run['attack_not_before'] - 120,
    **({'binary_baseline_seed': os.environ['BASELINE_SEED']} if os.environ.get('BASELINE_SEED') else {}),
    # final system: a case per alert that Alertmanager delivered (bridge triggers.jsonl), ML or tripwire
    **({'alert_trigger_file': os.environ['BRIDGE_OUT'] + '/triggers.jsonl'} if os.environ.get('FINAL') == '1' else {})), indent=2))
PY
  as_root install -m 0640 -o root -g dat "/tmp/$RCA_NAME.json" "/etc/sentinel-pulse-rca/$RCA_NAME.json"
  rm -f "/tmp/$RCA_NAME.json"
  # As launch_rca_subscriber.sh: write via a temp file, as_root owns stdin for the password.
  cat >"/tmp/$RCA_UNIT.service" <<UNIT
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
  as_root install -m 0644 -o root -g root "/tmp/$RCA_UNIT.service" "/etc/systemd/system/$RCA_UNIT.service"
  rm -f "/tmp/$RCA_UNIT.service"
  as_root systemctl daemon-reload
  as_root systemctl disable --now "$RCA_PREV_UNIT.service" || true
  as_root systemctl enable --now "$RCA_UNIT.service"
}

bridge() {
  as_root bash "$SNAP/scripts/alert_bridge.sh" "$RUN"
}

master() {
  cd /tmp
  as_root env PYTHONPATH="$SNAP" /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.matched_services \
    --config "$ROOT/CONFIG.json" --role traffic
  as_root env PYTHONPATH="$SNAP" /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.matched_services \
    --config "$ROOT/CONFIG.json" --role campaign --credential "$CREDENTIAL"
}

case "${1:-all}" in
  plan) plan ;; workers) workers ;; rca) rca ;; bridge) bridge ;; master) master ;;
  all) plan; workers; rca; [ "$FINAL" = 1 ] && bridge; master ;;
  *) echo "unknown step $1" >&2; exit 2 ;;
esac
