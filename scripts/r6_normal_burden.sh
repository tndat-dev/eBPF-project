#!/usr/bin/env bash
# Normal alert burden of every k-of-n / alpha policy on the R6 capture (run on .234 as dat
# after all three R6 workers wrote TERMINAL.json). Excludes the Tetragon-contention start
# (02:04-02:13 UTC+7) and the attack campaign (+-60 s). Output feeds the R7 policy choice.
set -euo pipefail
SRC=${SRC:?source snapshot with confirmation_study --model-hash}
ROOT=/mnt/sentinel-pulse-archive/matched-r6-20261018
OUT=$ROOT/analysis-20261019/normal-burden
CAMPAIGN=$ROOT/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
for node in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f "$ROOT/workers/$node/TERMINAL.json" ]; do sleep 60; done
done
mkdir -p "$OUT"
read -r CAMP_START CAMP_END < <(python3 - "$CAMPAIGN" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
starts = [float(json.loads(l)['start_at']) for l in (root/'INTERVALS.jsonl').read_text().splitlines()]
end = json.loads((root/'TERMINAL.json').read_text())['finished_at_unix']
print(min(starts) - 60, end + 60)
PY
)
cd /tmp
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
for node in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  for grid in default looser; do
    /home/dat/ml-venv/bin/python -m sentinel_pulse.attack.confirmation_study normal \
      --worker-root "$ROOT/workers/$node" --since 1792350800 \
      --exclude "$CAMP_START:$CAMP_END" --grid "$grid" \
      --model-hash ec72d9ea22af7d84ac2e8567e19205f121498ad11e48a9b2ef673697f5843cd4 \
      --policy-hash f61073512035dad4177b0fcce518f6a4b452322250b28b8a563605c2f0a8c9cb \
      --output "$OUT/normal-$grid-$node.json"
  done
done
