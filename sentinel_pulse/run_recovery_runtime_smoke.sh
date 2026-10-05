#!/usr/bin/env bash
# One finite worker diagnostic. Never formal NORMAL_PASS or promotion.
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
SOURCE_ROOT=${SOURCE_ROOT:?frozen clean source root required}
MODEL_SOURCE=${MODEL_SOURCE:?complete frozen model required}
DECISION_POLICY_SOURCE=${DECISION_POLICY_SOURCE:?frozen policy required}
PROJECTED_CANARY_RUN_DIR=${PROJECTED_CANARY_RUN_DIR:?verified projected safety run required}
RUN_ID=${RUN_ID:?new diagnostic run ID required}
EXPECTED_MODEL_SHA256=${EXPECTED_MODEL_SHA256:?frozen model identity required}
EXPECTED_POLICY_SHA256=${EXPECTED_POLICY_SHA256:?frozen policy identity required}
DURATION_SECONDS=${DURATION_SECONDS:-600}
CONTROLLED_LOADER_PAUSE_MS=${CONTROLLED_LOADER_PAUSE_MS:-0}
[[ $CONTROLLED_LOADER_PAUSE_MS == 0 || $CONTROLLED_LOADER_PAUSE_MS == 1200 ]]
if [[ $CONTROLLED_LOADER_PAUSE_MS == 1200 ]]; then
  [[ $DURATION_SECONDS == 1800 ]] || { echo 'controlled fault needs NEW registered 1800s diagnostic' >&2; exit 2; }
fi
[[ $SOURCE_ROOT =~ ^/home/dat/[A-Za-z0-9._-]+$ ]]
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $EXPECTED_MODEL_SHA256 =~ ^[0-9a-f]{64}$ && $EXPECTED_POLICY_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 180 && DURATION_SECONDS <= 1800))
# Root installs from a dat-owned checkout. Trust ONLY this validated leaf for
# this invocation; never set safe.directory=* or change global Git config.
# Separate assignment makes Git failure fatal, not an empty "clean" result.
source_status=$(git -c safe.directory="$SOURCE_ROOT" -C "$SOURCE_ROOT" status --porcelain --untracked-files=all)
[[ -z $source_status ]]
[[ $(awk '$2=="manifest.json" {print $1}' "$MODEL_SOURCE/manifest.sha256") == "$EXPECTED_MODEL_SHA256" ]]
[[ $(sha256sum "$DECISION_POLICY_SOURCE" | awk '{print $1}') == "$EXPECTED_POLICY_SHA256" ]]
systemctl is-active --quiet sentinel-pulse-resolver.service sentinel-pulse-collector.service
! systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service
! systemctl is-active --quiet sentinel-pulse-detector-candidate.service
RUN_DIR=/var/lib/sentinel-pulse-500ms/runs/$RUN_ID
PREREG=/var/lib/sentinel-pulse-recovery-smoke/$RUN_ID
test ! -e "$RUN_DIR"
test ! -e "$PREREG"
TELEMETRY_RECOVERY_PROFILE_SOURCE="$SOURCE_ROOT/sentinel_pulse/protocol/telemetry-recovery-v1.json"
export SOURCE_ROOT MODEL_SOURCE DECISION_POLICY_SOURCE RUN_ID DURATION_SECONDS TELEMETRY_RECOVERY_PROFILE_SOURCE
export EXPECTED_MODEL_SHA256 EXPECTED_POLICY_SHA256
export CONTROLLED_LOADER_PAUSE_MS
export COLLECTOR_VARIANT=projected PROJECTED_CANARY_RUN_DIR
export DETECTOR_LIVE_FRESHNESS=true
export TELEMETRY_NOMINAL_INTERVAL_SECONDS=0.5 TELEMETRY_MINIMUM_AVAILABILITY=0.999 TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS=30
install -d -m 0750 /var/lib/sentinel-pulse-recovery-smoke
mkdir -m 0750 "$PREREG"
preregistration_failure() {
  rc=$?
  trap - EXIT
  printf 'finished_at=%s\nexit_code=%s\nphase=preregistration\n' "$(date -u +%FT%TZ)" "$rc" >"$PREREG/TERMINAL.txt"
  chmod 0444 "$PREREG"/*
  exit "$rc"
}
trap preregistration_failure EXIT
PYTHONPATH="$SOURCE_ROOT" python3 - "$PREREG/START.json" "$TELEMETRY_RECOVERY_PROFILE_SOURCE" <<'PY'
import json, os, pathlib, subprocess, sys, time
from sentinel_pulse.recovery_deployment import contract
from sentinel_pulse.detector_freshness import CONTRACT, CONTRACT_SHA256
from sentinel_pulse.controlled_collector_pause import FAULT
p = {"schema": "sentinel-pulse-recovery-runtime-smoke-start-v1",
     "run_id": os.environ["RUN_ID"], "started_at": time.time(),
     "duration_seconds": int(os.environ["DURATION_SECONDS"]),
     "model_manifest_sha256": os.environ["EXPECTED_MODEL_SHA256"],
     "decision_policy_sha256": os.environ["EXPECTED_POLICY_SHA256"],
     "source_commit": subprocess.check_output(["git", "-c", "safe.directory=" + os.environ["SOURCE_ROOT"], "-C", os.environ["SOURCE_ROOT"], "rev-parse", "HEAD"], text=True).strip(),
     "telemetry_recovery_contract": contract(pathlib.Path(sys.argv[2]), .5, .999, 30),
     "detector_freshness_contract": CONTRACT,
     "detector_freshness_contract_sha256": CONTRACT_SHA256,
     "formal_lifecycle_enabled": False, "accuracy_claim_allowed": False,
     "automatic_promotion": False, "automatic_blind_evaluation": False}
if os.environ["CONTROLLED_LOADER_PAUSE_MS"] == "1200":
    p["controlled_fault"] = FAULT
with pathlib.Path(sys.argv[1]).open("x") as f: f.write(json.dumps(p, indent=2, sort_keys=True) + "\n")
PY
(cd "$SOURCE_ROOT" && find sentinel_pulse -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 | sort -z | xargs -0 sha256sum) >"$PREREG/SOURCE_SHA256SUMS"
chmod 0444 "$PREREG/START.json" "$PREREG/SOURCE_SHA256SUMS"
started=false
finish() {
  rc=$?
  trap - EXIT
  set +e
  if [[ $started == true ]]; then
    systemctl show sentinel-pulse-collector-500ms-experiment.service -p ActiveState -p Result -p ExecMainStatus >"$RUN_DIR/collector-before-stop.systemd"
    systemctl show sentinel-pulse-detector-candidate.service -p ActiveState -p Result -p NRestarts -p ExecMainStatus >"$RUN_DIR/detector-before-stop.systemd"
    systemctl stop sentinel-pulse-detector-candidate.service
    systemctl disable sentinel-pulse-detector-candidate.service >/dev/null 2>&1
    systemctl stop sentinel-pulse-collector-500ms-experiment.service
    # Installer owns and validates this environment, never print it.
    source /etc/sentinel-pulse-detector-candidate.env
    if [[ $PULSE_RUN_ID == "$RUN_ID" && $PULSE_FEATURES == "$RUN_DIR/features.jsonl" ]]; then
      install -m 0640 "$PULSE_DECISIONS" "$RUN_DIR/decisions.jsonl"
      if [[ -f $PULSE_ALERTS ]]; then install -m 0640 "$PULSE_ALERTS" "$RUN_DIR/alerts.jsonl"; else install -m 0640 /dev/null "$RUN_DIR/alerts.jsonl"; fi
      PYTHONPATH="$SOURCE_ROOT" /opt/sentinel-pulse/runtime-venv/bin/python -m sentinel_pulse.evaluate_recovery_smoke \
        --run-dir "$RUN_DIR" --recovery-profile "$RUN_DIR/telemetry-recovery-profile.json" \
        --expected-model "$EXPECTED_MODEL_SHA256" --expected-policy "$EXPECTED_POLICY_SHA256" \
        --expected-live-freshness \
        --output "$RUN_DIR/RECOVERY_SMOKE_REPORT.json"
      report_rc=$?
      if ((rc == 0 && report_rc != 0)); then rc=$report_rc; fi
      (cd "$RUN_DIR" && find . -maxdepth 1 -type f ! -name RECOVERY_SMOKE_SHA256SUMS -print0 | sort -z | xargs -0 sha256sum) >"$RUN_DIR/RECOVERY_SMOKE_SHA256SUMS"
      chmod 0444 "$RUN_DIR"/*
    else
      rc=2
    fi
  else
    # Includes partial installer failure: stop only if its root-owned env
    # identifies OUR new run, never another operator's experiment.
    if [[ -f /etc/sentinel-pulse/500ms-experiment.env ]] && grep -qx "PULSE_500MS_RUN_ID=$RUN_ID" /etc/sentinel-pulse/500ms-experiment.env; then
      systemctl stop sentinel-pulse-detector-candidate.service sentinel-pulse-collector-500ms-experiment.service
      systemctl disable sentinel-pulse-detector-candidate.service >/dev/null 2>&1
    fi
  fi
  printf 'finished_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" >"$PREREG/TERMINAL.txt"
  (cd "$PREREG" && sha256sum START.json SOURCE_SHA256SUMS TERMINAL.txt) >"$PREREG/SHA256SUMS"
  chmod 0444 "$PREREG"/*
  exit "$rc"
}
trap finish EXIT
MODEL_MANIFEST_SOURCE="$MODEL_SOURCE/manifest.json" /bin/bash "$SOURCE_ROOT/sentinel_pulse/install_500ms_experiment.sh"
FEATURE_SOURCE="$RUN_DIR/features.jsonl" DEPLOYMENT_ID="$RUN_ID" ENABLE_INJECTION_TRACKING=false \
  /bin/bash "$SOURCE_ROOT/sentinel_pulse/install_detector_candidate.sh"
started=true
deadline=$(( $(date +%s) + DURATION_SECONDS + 60 ))
fault_injected=false
fault_after=$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["started_at"]) + 120)' "$PREREG/START.json")
while systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service; do
  (( $(date +%s) < deadline ))
  systemctl is-active --quiet sentinel-pulse-detector-candidate.service
  [[ $(systemctl show sentinel-pulse-detector-candidate.service -p NRestarts --value) == 0 ]]
  source /etc/sentinel-pulse-detector-candidate.env
  if [[ -s $PULSE_ALERTS ]]; then echo 'normal alert observed; stopping diagnostic, preserving evidence' >&2; exit 1; fi
  PYTHONPATH="$SOURCE_ROOT" /opt/sentinel-pulse/runtime-venv/bin/python -m sentinel_pulse.inspect_recovery_tail \
    --capture "$RUN_DIR/features.jsonl" --recovery-profile "$TELEMETRY_RECOVERY_PROFILE_SOURCE"
  if [[ $CONTROLLED_LOADER_PAUSE_MS == 1200 && $fault_injected == false ]] && (( $(date +%s) >= fault_after )); then
    PYTHONPATH="$SOURCE_ROOT" /opt/sentinel-pulse/runtime-venv/bin/python -m sentinel_pulse.controlled_collector_pause --run-dir "$RUN_DIR"
    fault_injected=true
  fi
  sleep 5
done
[[ $(systemctl show sentinel-pulse-collector-500ms-experiment.service -p Result --value) == success ]]
# Allow bounded backlog drain; never claim unconsumed windows as scored.
sleep 2
