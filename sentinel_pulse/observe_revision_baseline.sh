#!/usr/bin/env bash
# Observe one immutable production rollout generation before baseline assembly.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PYTHON=${PYTHON:-python3}
EVIDENCE_ROOT=${EVIDENCE_ROOT:?EVIDENCE_ROOT is required}
DURATION_SECONDS=${DURATION_SECONDS:-86400}
POLL_SECONDS=${POLL_SECONDS:-60}
PREFLIGHT_STABILITY_SECONDS=${PREFLIGHT_STABILITY_SECONDS:-300}
PREFLIGHT_TIMEOUT_SECONDS=${PREFLIGHT_TIMEOUT_SECONDS:-1800}
NAMESPACE=${NAMESPACE:-production}
KUBECONFIG_PATH=${KUBECONFIG_PATH:-/home/dat/.kube/config}

[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 3600)) || {
  echo "revision observation must last at least one hour" >&2
  exit 2
}
[[ $POLL_SECONDS =~ ^[0-9]+$ ]] && ((POLL_SECONDS >= 15 && POLL_SECONDS <= 300)) || {
  echo "poll interval must be 15..300 seconds" >&2
  exit 2
}
[[ $PREFLIGHT_STABILITY_SECONDS =~ ^[0-9]+$ ]] &&
  ((PREFLIGHT_STABILITY_SECONDS >= 60)) || {
  echo "preflight stability must be at least 60 seconds" >&2
  exit 2
}
[[ $PREFLIGHT_TIMEOUT_SECONDS =~ ^[0-9]+$ ]] &&
  ((PREFLIGHT_TIMEOUT_SECONDS >= PREFLIGHT_STABILITY_SECONDS)) || {
  echo "preflight timeout must cover stability interval" >&2
  exit 2
}
test ! -e "$EVIDENCE_ROOT"
test -r "$KUBECONFIG_PATH"
export KUBECONFIG="$KUBECONFIG_PATH"
mkdir -p "$EVIDENCE_ROOT"
RUNTIME_ROOT="$EVIDENCE_ROOT/runtime"
install -d -m 0755 "$RUNTIME_ROOT/sentinel_pulse"
install -m 0644 "$LOCAL_ROOT/sentinel_pulse/__init__.py" \
  "$LOCAL_ROOT/sentinel_pulse/cgroup_resolver.py" \
  "$LOCAL_ROOT/sentinel_pulse/workload_fingerprint.py" \
  "$RUNTIME_ROOT/sentinel_pulse/"
install -m 0555 "${BASH_SOURCE[0]}" \
  "$RUNTIME_ROOT/observe_revision_baseline.sh"
sha256sum "$RUNTIME_ROOT/observe_revision_baseline.sh" \
  "$RUNTIME_ROOT/sentinel_pulse/__init__.py" \
  "$RUNTIME_ROOT/sentinel_pulse/cgroup_resolver.py" \
  "$RUNTIME_ROOT/sentinel_pulse/workload_fingerprint.py" \
  >"$EVIDENCE_ROOT/SOURCE_SHA256SUMS"

snapshot() {
  local prefix=$1
  kubectl -n "$NAMESPACE" get pods -o json \
    >"$EVIDENCE_ROOT/$prefix-pods.json" || return 1
  PYTHONPATH="$RUNTIME_ROOT" "$PYTHON" -m sentinel_pulse.workload_fingerprint \
    --input "$EVIDENCE_ROOT/$prefix-pods.json" \
    --output "$EVIDENCE_ROOT/$prefix-fingerprint.json" || return 1
}

rollouts_healthy() {
  kubectl -n "$NAMESPACE" get rollouts.argoproj.io -o json \
    >"$EVIDENCE_ROOT/current-rollouts.json" || return 1
  jq -e 'all(.items[]; (.status.phase // "") == "Healthy")' \
    "$EVIDENCE_ROOT/current-rollouts.json" >/dev/null
}

fail() {
  local reason=$1
  printf 'failed_at=%s\nreason=%s\n' "$(date -u +%FT%TZ)" "$reason" \
    >"$EVIDENCE_ROOT/FAILED"
  rm -f "$EVIDENCE_ROOT/ACTIVE"
  exit 3
}

# Do not start the 24-hour clock while a rollout is still converging.  Require
# the exact same fingerprint and all Argo Rollouts Healthy for a continuous
# stability interval.  Changes during preflight reset the clock, not the model.
touch "$EVIDENCE_ROOT/PREFLIGHT"
preflight_deadline=$(( $(date +%s) + PREFLIGHT_TIMEOUT_SECONDS ))
stable_since=0
snapshot preflight-candidate || fail initial_fingerprint_unavailable
while :; do
  snapshot preflight-current || fail preflight_fingerprint_unavailable
  now=$(date +%s)
  if rollouts_healthy && cmp -s \
      "$EVIDENCE_ROOT/preflight-candidate-fingerprint.json" \
      "$EVIDENCE_ROOT/preflight-current-fingerprint.json"; then
    ((stable_since > 0)) || stable_since=$now
    if ((now - stable_since >= PREFLIGHT_STABILITY_SECONDS)); then
      break
    fi
  else
    cp "$EVIDENCE_ROOT/preflight-current-fingerprint.json" \
      "$EVIDENCE_ROOT/preflight-candidate-fingerprint.json"
    stable_since=0
  fi
  printf '%s stable_seconds=%s target_seconds=%s\n' "$(date -u +%FT%TZ)" \
    "$((stable_since > 0 ? now - stable_since : 0))" \
    "$PREFLIGHT_STABILITY_SECONDS" >>"$EVIDENCE_ROOT/PREFLIGHT.log"
  ((now < preflight_deadline)) || fail preflight_not_stable
  sleep "$POLL_SECONDS"
done

started_epoch=$(date +%s)
eligible_epoch=$((started_epoch + DURATION_SECONDS))
printf 'started_at=%s\neligible_at_epoch=%s\nduration_seconds=%s\nnamespace=%s\npreflight_stability_seconds=%s\n' \
  "$(date -u +%FT%TZ)" "$eligible_epoch" "$DURATION_SECONDS" "$NAMESPACE" \
  "$PREFLIGHT_STABILITY_SECONDS" >"$EVIDENCE_ROOT/START"
cp "$EVIDENCE_ROOT/preflight-current-fingerprint.json" \
  "$EVIDENCE_ROOT/APPROVED_FINGERPRINT.json"
sha256sum "$EVIDENCE_ROOT/START" "$EVIDENCE_ROOT/APPROVED_FINGERPRINT.json" \
  "$EVIDENCE_ROOT/SOURCE_SHA256SUMS" \
  >"$EVIDENCE_ROOT/START_SHA256SUMS"
touch "$EVIDENCE_ROOT/ACTIVE"
rm -f "$EVIDENCE_ROOT/PREFLIGHT"

while (( $(date +%s) < eligible_epoch )); do
  snapshot current || fail current_fingerprint_unavailable
  if ! cmp -s "$EVIDENCE_ROOT/APPROVED_FINGERPRINT.json" \
      "$EVIDENCE_ROOT/current-fingerprint.json"; then
    mv "$EVIDENCE_ROOT/current-fingerprint.json" \
      "$EVIDENCE_ROOT/DRIFT_FINGERPRINT.json"
    fail workload_revision_changed
  fi
  printf '%s sha256=%s\n' "$(date -u +%FT%TZ)" \
    "$(sha256sum "$EVIDENCE_ROOT/current-fingerprint.json" | awk '{print $1}')" \
    >>"$EVIDENCE_ROOT/OBSERVATIONS.log"
  sleep "$POLL_SECONDS"
done

snapshot final || fail final_fingerprint_unavailable
cmp -s "$EVIDENCE_ROOT/APPROVED_FINGERPRINT.json" \
  "$EVIDENCE_ROOT/final-fingerprint.json" || fail workload_revision_changed
sha256sum "$EVIDENCE_ROOT"/APPROVED_FINGERPRINT.json \
  "$EVIDENCE_ROOT"/final-fingerprint.json "$EVIDENCE_ROOT"/OBSERVATIONS.log \
  >"$EVIDENCE_ROOT/FINAL_SHA256SUMS"
printf 'completed_at=%s\n' "$(date -u +%FT%TZ)" >"$EVIDENCE_ROOT/COMPLETE"
rm -f "$EVIDENCE_ROOT/ACTIVE"
