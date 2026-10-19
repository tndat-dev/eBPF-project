#!/usr/bin/env bash
# After pulse-stable-candidate-selection (SELECTION.json): build the pulse-stable-candidate candidate and policy file.
# Run on .234 as dat:  SRC=/mnt/.../source bash prepare_pulse_stable_candidate.sh
# Prints the candidate path/hash and the policy file path/hash for scripts/launch_run.sh.
# The policy file must then be committed to sentinel_pulse/protocol/ and a new snapshot made.
set -euo pipefail
SRC=${SRC:?source snapshot}
SEL=/mnt/sentinel-pulse-archive/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection
BASE=/mnt/sentinel-pulse-archive/runtime-recal-c1-20261018/model-bundle
BASE_HASH=ec72d9ea22af7d84ac2e8567e19205f121498ad11e48a9b2ef673697f5843cd4
OUT=/mnt/sentinel-pulse-archive/pulse-stable-candidate-model
NAME=pulse-candidate-1020-recalibrated-on-pulse-live-recalibrated
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
CAL=$(python3 -c "import json;print(json.load(open('$SEL/SELECTION.json'))['calibration'])")
if [ "$CAL" = refreshed ]; then
  if [ -f "$OUT/model-bundle/CANDIDATE_MANIFEST.json" ]; then
    HASH=$(sha256sum "$OUT/model-bundle/CANDIDATE_MANIFEST.json" | cut -d' ' -f1)
  else
    mkdir -p "$OUT"
    HASH=$(/home/dat/ml-venv/bin/python -m sentinel_pulse.detector.recalibrate_bundle --candidate "$BASE" \
      --candidate-hash $BASE_HASH --calibration "$SEL/calibration-r6-1300-1900.npz" \
      --output "$OUT/model-bundle" --name $NAME | tail -1)
  fi
  CANDIDATE=$OUT/model-bundle
else
  CANDIDATE=$BASE; HASH=$BASE_HASH; NAME=sentinel-pulse-idle-aware-recalibrated-c1-20261018
fi
POLICY=/home/dat/pulse-stable-candidate-policy.json
PHASH=$(/home/dat/ml-venv/bin/python -m sentinel_pulse.attack.select_policy --from-selection "$SEL/SELECTION.json" \
  --template "$SRC/sentinel_pulse/protocol/recalibrated-preview-policy-r6.json" \
  --candidate-hash "$HASH" --candidate-name "$NAME" --output "$POLICY" | tail -1)
# The policy must load against the candidate under the normal checks before it is registered.
/home/dat/ml-venv/bin/python - "$CANDIDATE" "$HASH" "$POLICY" <<'PY'
import sys
from pathlib import Path
from sentinel_pulse.detector.idle_candidate import IdleCandidateScorer
from sentinel_pulse.detector.candidate_policy import load_preview_policy
scorer = IdleCandidateScorer(Path(sys.argv[1]), sys.argv[2])
policy = load_preview_policy(Path(sys.argv[3]), scorer)
print('policy loads; models', len(scorer.models), 'sha256', policy.sha256)
PY
echo "CANDIDATE=$CANDIDATE"; echo "MODEL_HASH=$HASH"; echo "POLICY_FILE=$POLICY"; echo "POLICY_HASH=$PHASH"
