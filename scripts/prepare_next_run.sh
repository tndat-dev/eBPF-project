#!/usr/bin/env bash
# Build the candidate and policy file for the next live run from a rule-v2 selection (select_policy --rule v2).
# Run on .234 as dat:  SRC=/mnt/.../source SELECTION=/mnt/.../SELECTION-v2.json NAME=<policy-file-stem> bash prepare_next_run.sh
# Prints CANDIDATE / MODEL_HASH / POLICY_FILE / POLICY_HASH for scripts/launch_run.sh. The policy file must then be
# committed to sentinel_pulse/protocol/ and a new snapshot made (same as pulse-stable-candidate).
set -euo pipefail
SRC=${SRC:?source snapshot}
SELECTION=${SELECTION:?rule-v2 SELECTION json}
NAME=${NAME:?policy file stem, e.g. policy-2of3-a10-refreshed}
BASE=/mnt/sentinel-pulse-archive/runtime-recal-c1-20261018/model-bundle
BASE_HASH=ec72d9ea22af7d84ac2e8567e19205f121498ad11e48a9b2ef673697f5843cd4
# the refreshed calibration that rule v2 / Pulse 5.7b evaluated (pulse-live-recalibrated normal 19/10 13:00-18:25)
REFRESHED=/mnt/sentinel-pulse-archive/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection/calibration-r6-1300-1900.npz
OUT=/mnt/sentinel-pulse-archive/pulse-next-run-model
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
CAL=$(python3 -c "import json;print(json.load(open('$SELECTION'))['calibration'])")
if [ "$CAL" = refreshed ]; then
  CANDIDATE_NAME=pulse-candidate-recalibrated-on-pulse-live-recalibrated
  if [ -f "$OUT/model-bundle/CANDIDATE_MANIFEST.json" ]; then
    HASH=$(sha256sum "$OUT/model-bundle/CANDIDATE_MANIFEST.json" | cut -d' ' -f1)
  else
    mkdir -p "$OUT"
    HASH=$($PY -m sentinel_pulse.detector.recalibrate_bundle --candidate "$BASE" --candidate-hash $BASE_HASH \
      --calibration "$REFRESHED" --output "$OUT/model-bundle" --name $CANDIDATE_NAME | tail -1)
  fi
  CANDIDATE=$OUT/model-bundle
else
  CANDIDATE=$BASE; HASH=$BASE_HASH; CANDIDATE_NAME=sentinel-pulse-idle-aware-recalibrated-c1-20261018
fi
POLICY=/home/dat/$NAME.json
PHASH=$($PY -m sentinel_pulse.attack.select_policy --from-selection "$SELECTION" \
  --template "$SRC/sentinel_pulse/protocol/policy-2of2-a10.json" \
  --candidate-hash "$HASH" --candidate-name "$CANDIDATE_NAME" --output "$POLICY" | tail -1)
# the policy must load against the candidate through the real loader before it is registered
$PY - "$CANDIDATE" "$HASH" "$POLICY" <<'PYCODE'
import sys
from pathlib import Path
from sentinel_pulse.detector.idle_candidate import IdleCandidateScorer
from sentinel_pulse.detector.candidate_policy import load_preview_policy
scorer = IdleCandidateScorer(Path(sys.argv[1]), sys.argv[2])
policy = load_preview_policy(Path(sys.argv[3]), scorer)
print('policy loads; models', len(scorer.models), 'sha256', policy.sha256)
PYCODE
echo "CANDIDATE=$CANDIDATE"; echo "MODEL_HASH=$HASH"; echo "POLICY_FILE=$POLICY"; echo "POLICY_HASH=$PHASH"
