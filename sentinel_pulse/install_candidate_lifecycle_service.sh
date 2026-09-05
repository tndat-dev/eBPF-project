#!/usr/bin/env bash
# Install a reboot-resumable control-plane supervisor for one frozen candidate.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "install_candidate_lifecycle_service.sh must run as root" >&2
  exit 2
fi

LIFECYCLE_ID=${LIFECYCLE_ID:?for example a3}
LOCAL_ROOT=${LOCAL_ROOT:?absolute detached source worktree}
MODEL_SOURCE=${MODEL_SOURCE:?absolute frozen model directory}
POLICY_SOURCE=${POLICY_SOURCE:?absolute frozen decision policy}
NORMAL_RUN_ID=${NORMAL_RUN_ID:?registered normal run ID}
NORMAL_EVIDENCE_ROOT=${NORMAL_EVIDENCE_ROOT:?absolute normal evidence path}
BLIND_RUN_ID=${BLIND_RUN_ID:?registered blind run ID}
BLIND_EVIDENCE_ROOT=${BLIND_EVIDENCE_ROOT:?absolute blind evidence path}
STATE_ROOT=${STATE_ROOT:?absolute evidence state root}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
STOP_AFTER_NORMAL=${STOP_AFTER_NORMAL:-true}
FINALIZE_MARGIN_SECONDS=${FINALIZE_MARGIN_SECONDS:-300}
SUSPEND_CONTROL_COLLECTOR=${SUSPEND_CONTROL_COLLECTOR:-true}
DURATION_SECONDS=${DURATION_SECONDS:-90000}
PREFLIGHT_STABILITY_SECONDS=${PREFLIGHT_STABILITY_SECONDS:-300}
PREFLIGHT_TIMEOUT_SECONDS=${PREFLIGHT_TIMEOUT_SECONDS:-1800}
: "${SSHPASS:?SSH/sudo credential is required at runtime}"

[[ $LIFECYCLE_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $NORMAL_RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $BLIND_RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $STOP_AFTER_NORMAL == true || $STOP_AFTER_NORMAL == false ]]
[[ $SUSPEND_CONTROL_COLLECTOR == true || $SUSPEND_CONTROL_COLLECTOR == false ]]
[[ $FINALIZE_MARGIN_SECONDS =~ ^[0-9]+$ ]]
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]]
[[ $PREFLIGHT_STABILITY_SECONDS =~ ^[0-9]+$ ]]
[[ $PREFLIGHT_TIMEOUT_SECONDS =~ ^[0-9]+$ ]]
for path in "$LOCAL_ROOT" "$MODEL_SOURCE" "$POLICY_SOURCE" "$NORMAL_EVIDENCE_ROOT" \
  "$BLIND_EVIDENCE_ROOT" "$STATE_ROOT" "$PYTHON"; do
  [[ $path == /* ]] || { echo "lifecycle paths must be absolute: $path" >&2; exit 2; }
done
test -x "$LOCAL_ROOT/sentinel_pulse/run_500ms_candidate_lifecycle.sh"
test -f "$MODEL_SOURCE/manifest.json"
test -f "$POLICY_SOURCE"
test -x "$PYTHON"

# systemd opens the redirected lifecycle log before ExecStart runs.  Therefore
# run_500ms_candidate_lifecycle.sh cannot create STATE_ROOT itself on a fresh
# deployment: the shell redirection would fail first.  Create the directory
# here and make it writable by the service account.
install -d -o dat -g dat -m 0750 "$STATE_ROOT"

SERVICE="sentinel-pulse-$LIFECYCLE_ID-lifecycle.service"
ENV_DIR=/etc/sentinel-pulse/lifecycle
ENV_FILE="$ENV_DIR/$LIFECYCLE_ID.env"
UNIT_FILE="/etc/systemd/system/$SERVICE"
LOG_FILE="$STATE_ROOT/$NORMAL_RUN_ID-lifecycle.out"
install -d -m 0700 "$ENV_DIR"

env_stage=$(mktemp "$ENV_DIR/.$LIFECYCLE_ID.XXXXXX")
unit_stage=$(mktemp "/etc/systemd/system/.$SERVICE.XXXXXX")
cleanup() { rm -f "$env_stage" "$unit_stage"; }
trap cleanup EXIT
{
  printf 'SSHPASS=%s\n' "$SSHPASS"
  printf 'LOCAL_ROOT=%s\n' "$LOCAL_ROOT"
  printf 'PYTHON=%s\n' "$PYTHON"
  printf 'MODEL_SOURCE=%s\n' "$MODEL_SOURCE"
  printf 'POLICY_SOURCE=%s\n' "$POLICY_SOURCE"
  printf 'STOP_AFTER_NORMAL=%s\n' "$STOP_AFTER_NORMAL"
  printf 'FINALIZE_MARGIN_SECONDS=%s\n' "$FINALIZE_MARGIN_SECONDS"
  printf 'SUSPEND_CONTROL_COLLECTOR=%s\n' "$SUSPEND_CONTROL_COLLECTOR"
  printf 'DURATION_SECONDS=%s\n' "$DURATION_SECONDS"
  printf 'PREFLIGHT_STABILITY_SECONDS=%s\n' "$PREFLIGHT_STABILITY_SECONDS"
  printf 'PREFLIGHT_TIMEOUT_SECONDS=%s\n' "$PREFLIGHT_TIMEOUT_SECONDS"
  printf 'NORMAL_RUN_ID=%s\n' "$NORMAL_RUN_ID"
  printf 'NORMAL_EVIDENCE_ROOT=%s\n' "$NORMAL_EVIDENCE_ROOT"
  printf 'BLIND_RUN_ID=%s\n' "$BLIND_RUN_ID"
  printf 'BLIND_EVIDENCE_ROOT=%s\n' "$BLIND_EVIDENCE_ROOT"
  printf 'STATE_ROOT=%s\n' "$STATE_ROOT"
} >"$env_stage"
chmod 0600 "$env_stage"
cat >"$unit_stage" <<EOF
[Unit]
Description=Sentinel Pulse $LIFECYCLE_ID fail-closed candidate lifecycle
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=dat
WorkingDirectory=$LOCAL_ROOT
EnvironmentFile=$ENV_FILE
ExecStart=/bin/bash -c 'exec "$LOCAL_ROOT/sentinel_pulse/run_500ms_candidate_lifecycle.sh" >>"$LOG_FILE" 2>&1'
Restart=no
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$unit_stage"

# This may replace a same-name transient systemd-run supervisor. Its remote
# collectors/detectors are separate services and continue without interruption.
systemctl stop "$SERVICE" 2>/dev/null || true
install -m 0600 "$env_stage" "$ENV_FILE"
install -m 0644 "$unit_stage" "$UNIT_FILE"
systemctl daemon-reload
systemctl enable --now "$SERVICE"
systemctl is-active --quiet "$SERVICE"
trap - EXIT
cleanup
printf 'persistent lifecycle active: %s\n' "$SERVICE"
