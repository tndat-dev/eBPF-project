#!/usr/bin/env bash
# One preregistered worker leg. No model promotion, blind evaluation or PASS.
# The fleet coordinator must stage START.json BEFORE invoking this launcher.
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
SOURCE_ROOT=${SOURCE_ROOT:?clean frozen source root required}
MODEL_SOURCE=${MODEL_SOURCE:?frozen complete bundle required}
DECISION_POLICY_SOURCE=${DECISION_POLICY_SOURCE:?frozen policy required}
PROJECTED_CANARY_RUN_DIR=${PROJECTED_CANARY_RUN_DIR:?verified safety run required}
RUN_ID=${RUN_ID:?new registered run required}
WORKER_IP=${WORKER_IP:?registered worker IP required}
PYTHON=${PYTHON:-/opt/sentinel-pulse/runtime-venv/bin/python}
[[ $SOURCE_ROOT =~ ^/home/dat/[A-Za-z0-9._-]+$ ]]
[[ $RUN_ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
case "$WORKER_IP" in 10.1.16.237|10.1.16.238|10.1.16.239) ;; *) exit 2 ;; esac
PREREG=/var/lib/sentinel-pulse-recovery-formal/$RUN_ID
MARKER=$PREREG/START.json
RUN_DIR=/var/lib/sentinel-pulse-500ms/runs/$RUN_ID
test -f "$MARKER"
test ! -e "$RUN_DIR"
test ! -e "$PREREG/WORKER_ATTESTATION.json"
test ! -e "$PREREG/WORKER_TERMINAL.json"
systemctl is-active --quiet sentinel-pulse-collector.service sentinel-pulse-resolver.service
! systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service
! systemctl is-active --quiet sentinel-pulse-detector-candidate.service
export PYTHONPATH="$SOURCE_ROOT"

# Validate every identity before installing or starting a service. Do not
# derive a formal marker by modifying an old diagnostic START receipt.
config=$(
  "$PYTHON" - "$MARKER" "$WORKER_IP" "$RUN_ID" <<'PY'
import json, socket, sys
from sentinel_pulse.recovery_formal import validate_marker
m = validate_marker(json.load(open(sys.argv[1])))
if m['run_id'] != sys.argv[3] or m['workers'][sys.argv[2]]['node_name'] != socket.gethostname():
    raise ValueError('formal marker run/node mismatch')
print(json.dumps(m))
PY
)
DURATION_SECONDS=$(jq -er '.collector_duration_seconds' <<<"$config")
EXPECTED_MODEL_SHA256=$(jq -er '.model_manifest_sha256' <<<"$config")
EXPECTED_POLICY_SHA256=$(jq -er '.decision_policy_sha256' <<<"$config")
TELEMETRY_RECOVERY_PROFILE_SOURCE=$SOURCE_ROOT/sentinel_pulse/protocol/telemetry-recovery-v1.json
"$PYTHON" - "$MARKER" "$TELEMETRY_RECOVERY_PROFILE_SOURCE" <<'PY'
import json, pathlib, sys
from sentinel_pulse.recovery_deployment import contract
m = json.load(open(sys.argv[1]))
if contract(pathlib.Path(sys.argv[2]), .5, .999, 30) != m['telemetry_recovery_contract']:
    raise ValueError('source recovery profile differs from formal registration')
PY

export SOURCE_ROOT MODEL_SOURCE DECISION_POLICY_SOURCE RUN_ID DURATION_SECONDS
export TELEMETRY_RECOVERY_PROFILE_SOURCE PROJECTED_CANARY_RUN_DIR
export COLLECTOR_VARIANT=projected DETECTOR_LIVE_FRESHNESS=true
export TELEMETRY_NOMINAL_INTERVAL_SECONDS=0.5 TELEMETRY_MINIMUM_AVAILABILITY=0.999
export TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS=30
if [[ $(jq -r '.observational_segment // false' <<<"$config") == true ]]; then
  export PULSE_OBSERVATIONAL_SCOPE=true
fi

finish() {
  rc=$?
  trap - EXIT INT TERM
  set +e
  # A failed or interrupted install must never stop a different operator's
  # run just because it uses the same shared experiment service name.
  if [[ -f /etc/sentinel-pulse-detector-candidate.env ]] &&
     grep -qx "PULSE_RUN_ID=$RUN_ID" /etc/sentinel-pulse-detector-candidate.env &&
     grep -qx "PULSE_FEATURES=$RUN_DIR/features.jsonl" /etc/sentinel-pulse-detector-candidate.env; then
    systemctl show sentinel-pulse-detector-candidate.service -p ActiveState -p Result -p NRestarts -p ExecMainStatus >"$RUN_DIR/detector-before-stop.systemd"
    source /etc/sentinel-pulse-detector-candidate.env
    systemctl stop sentinel-pulse-detector-candidate.service || rc=2
    systemctl disable sentinel-pulse-detector-candidate.service >/dev/null 2>&1 || rc=2
    install -m 0640 "$PULSE_DECISIONS" "$RUN_DIR/decisions.jsonl" || rc=2
    if [[ -f $PULSE_ALERTS ]]; then
      install -m 0640 "$PULSE_ALERTS" "$RUN_DIR/alerts.jsonl" || rc=2
    else
      install -m 0640 /dev/null "$RUN_DIR/alerts.jsonl" || rc=2
    fi
  else
    rc=2
  fi
  if [[ -f /etc/sentinel-pulse/500ms-experiment.env ]] &&
     grep -qx "PULSE_500MS_RUN_ID=$RUN_ID" /etc/sentinel-pulse/500ms-experiment.env; then
    systemctl show sentinel-pulse-collector-500ms-experiment.service -p ActiveState -p Result -p ExecMainStatus >"$RUN_DIR/collector-before-stop.systemd"
    systemctl stop sentinel-pulse-collector-500ms-experiment.service || rc=2
  else
    rc=2
  fi
  # No evaluation or automatic deletion here. The coordinator supplies the
  # final dependency journal, then streams evaluate-node and aggregates 3 legs.
  if [[ -d $RUN_DIR ]]; then
    (cd "$RUN_DIR" && find . -maxdepth 1 -type f ! -name FORMAL_WORKER_SHA256SUMS -print0 | sort -z | xargs -0 sha256sum) >"$RUN_DIR/FORMAL_WORKER_SHA256SUMS" || rc=2
    find "$RUN_DIR" -maxdepth 1 -type f -exec chmod 0444 {} + || rc=2
  fi
  "$PYTHON" - "$PREREG" "$MARKER" "$WORKER_IP" "$rc" <<'PY'
import json, pathlib, sys, time
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.recovery_formal import write_new
p = pathlib.Path(sys.argv[1])
write_new(p/'WORKER_TERMINAL.json', {
    'schema': 'sentinel-pulse-recovery-formal-worker-terminal-v1',
    'run_id': p.name, 'worker_ip': sys.argv[3],
    'marker_sha256': sha256_file(pathlib.Path(sys.argv[2])),
    'finished_at_unix': time.time(), 'exit_code': int(sys.argv[4]),
    'formal_recovery_pass': False, 'automatic_blind_evaluation': False,
    'automatic_promotion': False,
})
PY
  terminal_rc=$?
  if ((terminal_rc != 0)); then rc=2; fi
  exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT TERM

"$PYTHON" -m sentinel_pulse.recovery_formal attest-worker --marker "$MARKER" \
  --worker-ip "$WORKER_IP" --source-root "$SOURCE_ROOT" --model-dir "$MODEL_SOURCE" \
  --policy "$DECISION_POLICY_SOURCE" --output "$PREREG/WORKER_ATTESTATION.json"
MODEL_MANIFEST_SOURCE="$MODEL_SOURCE/manifest.json" /bin/bash "$SOURCE_ROOT/sentinel_pulse/install_500ms_experiment.sh"
install -m 0444 "$PREREG/WORKER_ATTESTATION.json" "$RUN_DIR/FORMAL_WORKER_START.json"
"$PYTHON" - "$RUN_DIR" "$MARKER" "$WORKER_IP" <<'PY'
import pathlib, sys
from sentinel_pulse.recovery_formal import record_collector_timing
record_collector_timing(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3])
PY
FEATURE_SOURCE="$RUN_DIR/features.jsonl" DEPLOYMENT_ID="$RUN_ID" ENABLE_INJECTION_TRACKING=false \
  /bin/bash "$SOURCE_ROOT/sentinel_pulse/install_detector_candidate.sh"
deadline=$("$PYTHON" -c 'import json,sys; m=json.load(open(sys.argv[1])); print(int(m["started_at_unix"])+m["collector_duration_seconds"]+120)' "$MARKER")
while systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service; do
  (( $(date +%s) < deadline ))
  systemctl is-active --quiet sentinel-pulse-detector-candidate.service
  [[ $(systemctl show sentinel-pulse-detector-candidate.service -p NRestarts --value) == 0 ]]
  "$PYTHON" -m sentinel_pulse.inspect_recovery_tail --capture "$RUN_DIR/features.jsonl" \
    --recovery-profile "$RUN_DIR/telemetry-recovery-profile.json"
  # Bounded telemetry recovery can continue; hard corruption cannot. Alerts
  # are retained for the preregistered rate budget, not waived or tuned away.
  sleep 5
done
[[ $(systemctl show sentinel-pulse-collector-500ms-experiment.service -p Result --value) == success ]]
[[ $(systemctl show sentinel-pulse-collector-500ms-experiment.service -p ExecMainStatus --value) == 0 ]]
sleep 2
