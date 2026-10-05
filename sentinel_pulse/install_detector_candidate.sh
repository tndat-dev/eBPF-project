#!/usr/bin/env bash
# Install a verified Sentinel Pulse model as an audit-only detector candidate.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "install_detector_candidate.sh must run as root" >&2
  exit 2
fi

SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
MODEL_SOURCE=${MODEL_SOURCE:?MODEL_SOURCE must point to a complete candidate bundle}
DECISION_POLICY_SOURCE=${DECISION_POLICY_SOURCE:-$SOURCE_ROOT/sentinel_pulse/protocol/decision-policy-semantic-v4.json}
FEATURE_SOURCE=${FEATURE_SOURCE:-/var/lib/sentinel-pulse/features.jsonl}
INSTALL_ROOT=${INSTALL_ROOT:-/opt/sentinel-pulse}
SERVICE=sentinel-pulse-detector-candidate.service
RUNTIME_USER=sentinel-pulse-detector
ENV_FILE=/etc/sentinel-pulse-detector-candidate.env
DEPLOYMENT_ID=${DEPLOYMENT_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
ENABLE_INJECTION_TRACKING=${ENABLE_INJECTION_TRACKING:-false}
REQUIRE_CONTROL_COLLECTOR=${REQUIRE_CONTROL_COLLECTOR:-true}
TELEMETRY_RECOVERY_PROFILE_SOURCE=${TELEMETRY_RECOVERY_PROFILE_SOURCE:-}
DETECTOR_LIVE_FRESHNESS=${DETECTOR_LIVE_FRESHNESS:-false}
case "$DETECTOR_LIVE_FRESHNESS" in
  true|false) ;;
  *) echo 'DETECTOR_LIVE_FRESHNESS must be true or false' >&2; exit 2 ;;
esac
if [[ $DETECTOR_LIVE_FRESHNESS == true && -z $TELEMETRY_RECOVERY_PROFILE_SOURCE ]]; then
  echo 'live freshness requires explicit recovery runtime' >&2
  exit 2
fi
if [[ ! $DEPLOYMENT_ID =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "DEPLOYMENT_ID contains unsafe characters" >&2
  exit 2
fi
case "$ENABLE_INJECTION_TRACKING" in
  true|false) ;;
  *) echo "ENABLE_INJECTION_TRACKING must be true or false" >&2; exit 2 ;;
esac
case "$REQUIRE_CONTROL_COLLECTOR" in
  true|false) ;;
  *) echo "REQUIRE_CONTROL_COLLECTOR must be true or false" >&2; exit 2 ;;
esac

test -f "$SOURCE_ROOT/sentinel_pulse/requirements-lock.txt"
test -f "$SOURCE_ROOT/sentinel_pulse/systemd/$SERVICE"
test -f "$MODEL_SOURCE/manifest.json"
test -f "$MODEL_SOURCE/manifest.sha256"
test -f "$DECISION_POLICY_SOURCE"
if [[ $REQUIRE_CONTROL_COLLECTOR == true ]]; then
  systemctl is-active --quiet sentinel-pulse-collector.service
else
  ! systemctl is-active --quiet sentinel-pulse-collector.service
fi
if [[ $FEATURE_SOURCE != /* ]] || [[ $FEATURE_SOURCE == *$'\n'* ]]; then
  echo "FEATURE_SOURCE must be an absolute single-line path" >&2
  exit 2
fi
FEATURE_SOURCE=$(realpath -e -- "$FEATURE_SOURCE")
case "$FEATURE_SOURCE" in
  /var/lib/sentinel-pulse/features.jsonl|/var/lib/sentinel-pulse-500ms/runs/*/features.jsonl) ;;
  *) echo "FEATURE_SOURCE is outside an approved telemetry root" >&2; exit 2 ;;
esac
test -s "$FEATURE_SOURCE"

# Refuse both a legacy reader of recovery features and an unregistered recovery
# reader of legacy features. This check precedes user/venv/unit mutation.
recovery_binding=$(PYTHONPATH="$SOURCE_ROOT" python3 - "$FEATURE_SOURCE" \
  "$TELEMETRY_RECOVERY_PROFILE_SOURCE" <<'PY'
import json
from pathlib import Path
import sys
from sentinel_pulse.recovery_deployment import bind_detector
binding = bind_detector(Path(sys.argv[1]), Path(sys.argv[2]) if sys.argv[2] else None)
print(json.dumps(binding))
PY
)
if [[ -n $TELEMETRY_RECOVERY_PROFILE_SOURCE ]]; then
  [[ $INSTALL_ROOT == /opt/sentinel-pulse ]] || {
    echo 'recovery runtime requires the registered /opt/sentinel-pulse root' >&2
    exit 2
  }
fi

if [[ $DETECTOR_LIVE_FRESHNESS == true ]]; then
  PYTHONPATH="$SOURCE_ROOT" python3 - "$FEATURE_SOURCE" <<'PY'
import json
from pathlib import Path
import sys
from sentinel_pulse.recovery_deployment import bind_freshness_preregistration
contract = bind_freshness_preregistration(Path(sys.argv[1]))
path = Path(sys.argv[1]).parent / "DETECTOR_FRESHNESS_CONTRACT.json"
with path.open("x") as stream:
    stream.write(json.dumps(contract, indent=2, sort_keys=True) + "\n")
path.chmod(0o444)
PY
fi

if ! id "$RUNTIME_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin "$RUNTIME_USER"
fi

install -d -m 0755 "$INSTALL_ROOT" "$INSTALL_ROOT/models" "$INSTALL_ROOT/policies"
if [[ ! -x "$INSTALL_ROOT/runtime-venv/bin/python" ]]; then
  python3 -m venv "$INSTALL_ROOT/runtime-venv"
fi

# Finite 500 ms canaries use a private reader group. Preserve the experiment's
# non-world-readable telemetry while allowing only the unprivileged detector to
# traverse and read the selected immutable run path.
if [[ $FEATURE_SOURCE == /var/lib/sentinel-pulse-500ms/runs/*/features.jsonl ]]; then
  READER_GROUP=sentinel-pulse-readers
  getent group "$READER_GROUP" >/dev/null || groupadd --system "$READER_GROUP"
  usermod -a -G "$READER_GROUP" "$RUNTIME_USER"
  run_dir=$(dirname "$FEATURE_SOURCE")
  chgrp "$READER_GROUP" /var/lib/sentinel-pulse-500ms \
    /var/lib/sentinel-pulse-500ms/runs "$run_dir" "$FEATURE_SOURCE"
  chmod 0750 /var/lib/sentinel-pulse-500ms \
    /var/lib/sentinel-pulse-500ms/runs "$run_dir"
  chmod 0640 "$FEATURE_SOURCE"
fi
"$INSTALL_ROOT/runtime-venv/bin/pip" install --disable-pip-version-check \
  -r "$SOURCE_ROOT/sentinel_pulse/requirements-lock.txt"

# Keep the runtime package synchronized without touching the running collector
# executable, BPF object, allow-list, or production V8 files.
install -d -m 0755 "$INSTALL_ROOT/sentinel_pulse"
cp -a "$SOURCE_ROOT/sentinel_pulse/." "$INSTALL_ROOT/sentinel_pulse/"

verify_bundle() {
  local model_dir=$1
  (
    cd "$INSTALL_ROOT"
    "$INSTALL_ROOT/runtime-venv/bin/python" - "$model_dir" <<'PY'
from pathlib import Path
import sys
from sentinel_pulse.detect import PulseRuntime
from sentinel_pulse.finalize_candidate import verify_model_bundle

root = Path(sys.argv[1])
manifest, candidates, collect_only = verify_model_bundle(root)
runtime = PulseRuntime(root)
if collect_only or len(candidates) != len(runtime.models):
    raise SystemExit("candidate bundle does not provide every manifest model")
print(runtime.model_manifest_sha256)
PY
  )
}

manifest_sha=$(verify_bundle "$MODEL_SOURCE" | tail -n 1)
if [[ ! $manifest_sha =~ ^[0-9a-f]{64}$ ]]; then
  echo "bundle verifier returned an invalid manifest identity" >&2
  exit 3
fi
policy_sha=$(
  cd "$INSTALL_ROOT"
  "$INSTALL_ROOT/runtime-venv/bin/python" - "$DECISION_POLICY_SOURCE" <<'PY'
from pathlib import Path
import sys
from sentinel_pulse.decision_policy import load_decision_policy
print(load_decision_policy(Path(sys.argv[1]))[1])
PY
)
if [[ ! $policy_sha =~ ^[0-9a-f]{64}$ ]]; then
  echo "decision policy verifier returned an invalid identity" >&2
  exit 3
fi
policy_path="$INSTALL_ROOT/policies/$policy_sha.json"
if [[ ! -f "$policy_path" ]]; then
  install -m 0444 "$DECISION_POLICY_SOURCE" "$policy_path"
fi
recovery_path=
if [[ -n $TELEMETRY_RECOVERY_PROFILE_SOURCE ]]; then
  recovery_sha=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["profile_sha256"])' <<<"$recovery_binding")
  [[ $recovery_sha =~ ^[0-9a-f]{64}$ ]]
  recovery_path="$INSTALL_ROOT/policies/recovery-$recovery_sha.json"
  if [[ ! -e $recovery_path ]]; then
    install -m 0444 "$TELEMETRY_RECOVERY_PROFILE_SOURCE" "$recovery_path"
  fi
  cmp -s "$TELEMETRY_RECOVERY_PROFILE_SOURCE" "$recovery_path" || {
    echo 'immutable recovery runtime profile differs from registered bytes' >&2
    exit 3
  }
fi
run_id="$manifest_sha-$policy_sha-$DEPLOYMENT_ID"
run_dir="/var/lib/sentinel-pulse-detector/runs/$run_id"
install -d -o "$RUNTIME_USER" -g "$RUNTIME_USER" -m 0750 \
  /var/lib/sentinel-pulse-detector \
  /var/lib/sentinel-pulse-detector/runs \
  "$run_dir"
decision_path="$run_dir/decisions.jsonl"
alert_path="$run_dir/alerts.jsonl"
injection_path=/dev/null
if [[ $ENABLE_INJECTION_TRACKING == true ]]; then
  injection_path="$run_dir/injections.jsonl"
  install -o root -g "$RUNTIME_USER" -m 0640 /dev/null "$injection_path"
fi
candidate_dir="$INSTALL_ROOT/models/$manifest_sha"
if [[ ! -d "$candidate_dir" ]]; then
  stage=$(mktemp -d "$INSTALL_ROOT/models/.candidate-${manifest_sha}.XXXXXX")
  cleanup_stage() { rm -rf -- "$stage"; }
  trap cleanup_stage EXIT
  while IFS= read -r -d '' source; do
    install -m 0444 "$source" "$stage/$(basename "$source")"
  done < <(find "$MODEL_SOURCE" -maxdepth 1 -type f -print0)
  verify_bundle "$stage" >/dev/null
  chmod 0555 "$stage"
  mv "$stage" "$candidate_dir"
  trap - EXIT
else
  verify_bundle "$candidate_dir" >/dev/null
fi

previous_target=""
previous_policy_target=""
if [[ -L "$INSTALL_ROOT/models/current" ]]; then
  previous_target=$(readlink "$INSTALL_ROOT/models/current")
elif [[ -e "$INSTALL_ROOT/models/current" ]]; then
  echo "$INSTALL_ROOT/models/current exists but is not a symlink" >&2
  exit 4
fi
if [[ -L "$INSTALL_ROOT/policies/current.json" ]]; then
  previous_policy_target=$(readlink "$INSTALL_ROOT/policies/current.json")
elif [[ -e "$INSTALL_ROOT/policies/current.json" ]]; then
  echo "$INSTALL_ROOT/policies/current.json exists but is not a symlink" >&2
  exit 4
fi
had_previous_env=false
previous_env_content=""
if [[ -f "$ENV_FILE" ]]; then
  had_previous_env=true
  previous_env_content=$(<"$ENV_FILE")
fi
service_was_enabled=false
if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then
  service_was_enabled=true
fi
rollback_candidate() {
  systemctl stop "$SERVICE" 2>/dev/null || true
  if [[ -n "$previous_target" ]]; then
    local rollback="$INSTALL_ROOT/models/.rollback-$manifest_sha"
    ln -sfn "$previous_target" "$rollback"
    mv -Tf "$rollback" "$INSTALL_ROOT/models/current"
    systemctl restart "$SERVICE" || true
  else
    rm -f -- "$INSTALL_ROOT/models/current"
  fi
  if [[ -n "$previous_policy_target" ]]; then
    local policy_rollback="$INSTALL_ROOT/policies/.rollback-$policy_sha"
    ln -sfn "$previous_policy_target" "$policy_rollback"
    mv -Tf "$policy_rollback" "$INSTALL_ROOT/policies/current.json"
  else
    rm -f -- "$INSTALL_ROOT/policies/current.json"
  fi
  if [[ "$had_previous_env" == true ]]; then
    printf '%s\n' "$previous_env_content" >"$ENV_FILE"
    chmod 0644 "$ENV_FILE"
  else
    rm -f -- "$ENV_FILE"
  fi
  if [[ "$service_was_enabled" != true ]]; then
    systemctl disable "$SERVICE" 2>/dev/null || true
  fi
}
next_link="$INSTALL_ROOT/models/.current-$manifest_sha"
ln -sfn "$candidate_dir" "$next_link"
mv -Tf "$next_link" "$INSTALL_ROOT/models/current"
next_policy_link="$INSTALL_ROOT/policies/.current-$policy_sha"
ln -sfn "$policy_path" "$next_policy_link"
mv -Tf "$next_policy_link" "$INSTALL_ROOT/policies/current.json"
env_stage=$(mktemp /etc/.sentinel-pulse-detector-candidate.XXXXXX)
{
  printf 'PULSE_MODEL_DIR=%s\n' "$INSTALL_ROOT/models/current"
  printf 'PULSE_DECISION_POLICY=%s\n' "$INSTALL_ROOT/policies/current.json"
  printf 'PULSE_FEATURES=%s\n' "$FEATURE_SOURCE"
  printf 'PULSE_DECISIONS=%s\n' "$decision_path"
  printf 'PULSE_ALERTS=%s\n' "$alert_path"
  printf 'PULSE_INJECTIONS=%s\n' "$injection_path"
  printf 'PULSE_RUN_ID=%s\n' "$DEPLOYMENT_ID"
  printf 'PULSE_TELEMETRY_RECOVERY_PROFILE=%s\n' "$recovery_path"
  printf 'PULSE_DETECTOR_LIVE_FRESHNESS=%s\n' "$DETECTOR_LIVE_FRESHNESS"
} >"$env_stage"
chmod 0644 "$env_stage"
mv -f "$env_stage" "$ENV_FILE"

unit_source="$SOURCE_ROOT/sentinel_pulse/systemd/$SERVICE"
unit_stage=$(mktemp "/etc/systemd/system/.${SERVICE}.XXXXXX")
cleanup_unit_stage() { rm -f -- "$unit_stage"; }
trap cleanup_unit_stage EXIT
if [[ $REQUIRE_CONTROL_COLLECTOR == true ]]; then
  cp "$unit_source" "$unit_stage"
else
  # The formal 500 ms experiment owns its telemetry source. The base candidate
  # unit is also used by bounded canaries that require the one-second control
  # collector, so render an isolated variant instead of letting Wants= restart
  # that collector behind the formal monitor's back.
  sed \
    -e '/^After=sentinel-pulse-collector\.service$/d' \
    -e '/^Wants=sentinel-pulse-collector\.service$/d' \
    "$unit_source" >"$unit_stage"
  ! grep -Eq '^(After|Wants)=sentinel-pulse-collector\.service$' "$unit_stage"
fi
if [[ -n $recovery_path ]]; then
  PYTHONPATH="$SOURCE_ROOT" python3 - "$unit_stage" "$recovery_path" "$DETECTOR_LIVE_FRESHNESS" <<'PY'
from pathlib import Path
import sys
from sentinel_pulse.recovery_deployment import render_unit
path = Path(sys.argv[1])
path.write_text(render_unit(path.read_text(), "detector", sys.argv[2], live_freshness=sys.argv[3] == "true"))
PY
fi
install -m 0644 "$unit_stage" "/etc/systemd/system/$SERVICE"
rm -f -- "$unit_stage"
trap - EXIT
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl reset-failed "$SERVICE" 2>/dev/null || true
if ! systemctl restart "$SERVICE"; then
  rollback_candidate
  exit 5
fi

for _attempt in $(seq 1 60); do
  if systemctl is-active --quiet "$SERVICE" && \
     test -s "$decision_path"; then
    break
  fi
  sleep 1
done
if ! systemctl is-active --quiet "$SERVICE" || \
   ! test -s "$decision_path"; then
  journalctl -u "$SERVICE" -n 80 --no-pager >&2 || true
  rollback_candidate
  exit 5
fi
observed_sha=$(sed -n 's/.*"model_manifest_sha256":"\([0-9a-f]\{64\}\)".*/\1/p' \
  "$decision_path" | tail -n 1)
if [[ "$observed_sha" != "$manifest_sha" ]]; then
  echo "live decision model identity mismatch" >&2
  rollback_candidate
  exit 6
fi
observed_policy_sha=$(sed -n 's/.*"decision_policy_sha256":"\([0-9a-f]\{64\}\)".*/\1/p' \
  "$decision_path" | tail -n 1)
if [[ "$observed_policy_sha" != "$policy_sha" ]]; then
  echo "live decision policy identity mismatch" >&2
  rollback_candidate
  exit 6
fi
if [[ -n $recovery_path ]]; then
  # Do not report ready merely because the service started. Verify actual
  # recovery decisions, profile identity, and an entirely replayed prefix.
  if ! PYTHONPATH="$SOURCE_ROOT" python3 - "$decision_path" "$recovery_sha" "$DETECTOR_LIVE_FRESHNESS" <<'PY'
import json, sys
from sentinel_pulse.detector_freshness import CONTRACT_SHA256
with open(sys.argv[1]) as source:
    rows = [json.loads(line) for line in source if line.endswith("\n")]
if not rows or any(row.get("telemetry_recovery", {}).get("profile_sha256") != sys.argv[2] for row in rows):
    raise SystemExit("live recovery decision profile identity mismatch")
if sys.argv[3] == "true" and any(
        row.get("detector_freshness", {}).get("contract_sha256") != CONTRACT_SHA256 for row in rows):
    raise SystemExit("live detector freshness contract identity mismatch")
PY
  then
    rollback_candidate
    exit 6
  fi
fi
printf 'candidate detector active: manifest=%s policy=%s run=%s decisions=%s alerts=%s injections=%s\n' \
  "$manifest_sha" "$policy_sha" "$DEPLOYMENT_ID" \
  "$(wc -l <"$decision_path")" \
  "$(wc -l <"$alert_path" 2>/dev/null || printf 0)" "$injection_path"
