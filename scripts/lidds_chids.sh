#!/usr/bin/env bash
# lidds-dl-baseline-v1, arm CHIDS, on .234 as dat: lidds_chids.py over the 15 LID-DS 2021 scenarios, smallest first,
# one scenario at a time (each uses WORKERS processes), in the Python 3.9 environment pinned to ContainerHIDS'
# requirements; parts already written are kept. Starts after the units in WAIT_UNITS.
#   R=/home/dat/eBPF-project [WORKERS=6 WAIT_UNITS="lidds-v3-window"] bash lidds_chids.sh
set -uo pipefail
R=${R:-/home/dat/eBPF-project}
D=/var/tmp/dl-baseline
WORKERS=${WORKERS:-6}
for unit in ${WAIT_UNITS:-}; do
  while [ "$(systemctl is-active "$unit")" = active ] || [ "$(systemctl is-active "$unit")" = activating ]; do sleep 300; done
done
mkdir -p $D/chids-out && cd /tmp
export PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=4
for s in $(ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//'); do
  [ -f $D/chids-out/$s-chids.json ] && continue
  echo "start $s $(date -u +%FT%T)"
  timeout 24h $D/chids-venv39/bin/python -u $R/scripts/analysis/lidds_chids.py --chids $D/ContainerHIDS \
    --archive /var/tmp/lid-ds-2021/$s.zip --v2 $R/validation-evidence/results-20261031/lidds-v2/lidds-evaluation-v2.json.gz \
    --workers $WORKERS --output $D/chids-out/$s-ARM.json > $D/chids-out/$s.log 2>&1 || echo "FAILED $s"
  echo "done $s $(date -u +%FT%T)"
done
echo "chids all done $(date -u +%FT%T)"
