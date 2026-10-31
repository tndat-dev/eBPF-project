#!/usr/bin/env bash
# lidds-evaluation-v4 selection on .234 as dat, after the LID-DS 2021 and CB-DS reruns with alarm times: runs only if
# both reruns reproduced their receipts recording by recording; scores LID-DS 2021 official once for the selection.
#   SRC=/var/tmp/lid-ds-2021/source-<sha> [WAIT_UNITS="lidds-v3-window cbds-alarms"] bash lidds_v4_run.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
PY=/home/dat/ml-venv/bin/python
OUT=/var/tmp/lid-ds-2021/v4
for unit in ${WAIT_UNITS:-lidds-v3-window cbds-alarms}; do
  while [ "$(systemctl is-active "$unit")" = active ] || [ "$(systemctl is-active "$unit")" = activating ]; do sleep 300; done
done
A=/var/tmp/lid-ds-2021/v3-window; C=/var/tmp/cb-ds/v4
for f in $A/REPRODUCIBILITY.json $C/REPRODUCIBILITY.json; do
  python3 -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))['identical'] else 1)" $f || { echo "not reproducible: $f"; exit 1; }
done
mkdir -p $OUT && cd /tmp
$PY $SRC/scripts/analysis/lidds_v4_select.py --lidds2021 $A/lidds-evaluation-v2-alarms.json \
  --cbds $C/lidds-evaluation-v2-cbds-alarms.json --workers 8 --output $OUT/lidds-v4.json > $OUT/select.log 2>&1 \
  || { echo "selection FAILED"; exit 1; }
echo "v4 done $(date -u +%FT%T)"
