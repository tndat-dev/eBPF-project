#!/usr/bin/env bash
# Validate, but never promote, a low-latency candidate.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -z ${KUBECONFIG:-} && -r /home/dat/.kube/sentinel-ha.conf ]]; then
  export KUBECONFIG=/home/dat/.kube/sentinel-ha.conf
fi
CANDIDATE=${1:?usage: $0 <candidate-model-directory>}
if [[ -z ${PYTHON_BIN:-} ]]; then
  if [[ -x /home/dat/ml-venv/bin/python ]]; then
    PYTHON_BIN=/home/dat/ml-venv/bin/python
  else
    PYTHON_BIN=python3
  fi
fi
WINDOW_SECONDS=${LOW_LATENCY_WINDOW_SECONDS:-10}
PHASE_SECONDS=${LOW_LATENCY_PHASE_SECONDS:-180}
MIN_WINDOWS=${LOW_LATENCY_MIN_WINDOWS_PER_PHASE:-12}
ATTACK_SECONDS=${LOW_LATENCY_ATTACK_SECONDS:-35}
POST_ATTACK_WAIT=${LOW_LATENCY_POST_ATTACK_WAIT:-35}
MODEL_VERSION=${LOW_LATENCY_MODEL_VERSION:-7}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
: "${SENTINEL_CONFIRMATION_FLOOR_RATIO:=0.94}"
: "${SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR:=0.45}"
: "${SENTINEL_FAST_PATH_CONFIRMATION_FLOOR:=0.20}"
: "${SENTINEL_POD_STARTUP_GRACE_SECONDS:=60}"
: "${SENTINEL_EXTREME_VOLUME_FACTOR:=2.0}"
export SENTINEL_CONFIRMATION_FLOOR_RATIO SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR
export SENTINEL_FAST_PATH_CONFIRMATION_FLOOR SENTINEL_POD_STARTUP_GRACE_SECONDS
export SENTINEL_EXTREME_VOLUME_FACTOR

cd "$ROOT_DIR"
candidate=$(realpath "$CANDIDATE")
[[ -r "$candidate/training_report.json" ]] || {
  printf 'candidate report missing: %s\n' "$candidate" >&2; exit 2;
}
"$PYTHON_BIN" - "$candidate/training_report.json" <<'PY'
import json, sys
if not json.load(open(sys.argv[1])).get("accepted_offline"):
    raise SystemExit("offline candidate gate failed")
PY

CANDIDATE_WINDOW_SECONDS="$WINDOW_SECONDS" \
CANDIDATE_PHASE_SECONDS="$PHASE_SECONDS" \
CANDIDATE_MIN_WINDOWS_PER_PHASE="$MIN_WINDOWS" \
STAMP="$STAMP" PYTHON_BIN="$PYTHON_BIN" \
  ./run_candidate_normal_matrix_windowed.sh "$candidate"

normal_report="$ROOT_DIR/candidate-window${WINDOW_SECONDS}-normal-report-${STAMP}.json"
calibration=$("$PYTHON_BIN" - "$normal_report" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
if not payload.get("passed"):
    raise SystemExit("normal matrix failed")
print(payload["calibration"])
PY
)

"$PYTHON_BIN" run_kernel_matrix.py \
  --model-dir "$candidate" --normal-calibration "$calibration" \
  --runtime-binary "$ROOT_DIR/runtime_attack" --window "$WINDOW_SECONDS" \
  --attack-seconds "$ATTACK_SECONDS" --post-attack-wait "$POST_ATTACK_WAIT" \
  --output-root "kernel-regression-window${WINDOW_SECONDS}-${STAMP}"

attack_report=$(find "kernel-regression-window${WINDOW_SECONDS}-${STAMP}" \
  -mindepth 2 -maxdepth 2 -name report.json -type f | sort | tail -n 1)
[[ -n "$attack_report" ]] || { printf 'kernel matrix report missing\n' >&2; exit 7; }

# Reuse the exact promotion gates as a dry run.  This turns window, model,
# vocabulary and runtime provenance checks into a recorded validation result
# while deliberately leaving the active production release untouched.
"$PYTHON_BIN" promote_candidate.py \
  --candidate "$candidate" --normal-report "$normal_report" \
  --attack-report "$attack_report" --calibration "$calibration" \
  --expected-version "$MODEL_VERSION" --expected-window "$WINDOW_SECONDS"

printf 'validated candidate=%s window=%ss; not promoted\n' "$candidate" "$WINDOW_SECONDS"
