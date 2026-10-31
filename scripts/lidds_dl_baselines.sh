#!/usr/bin/env bash
# lidds-dl-baseline-v1 on .234 as dat: the LID-DS library's MLP and LSTM over the 15 LID-DS 2021 scenarios, smallest
# first, JOBS (scenario, arm) parts at a time; each scenario is extracted once from /var/tmp/lid-ds-2021 (outer zip ->
# training/validation/test directories of recording zips, the layout the library reads). Parts already written are
# kept; then everything is merged.
#   R=/home/dat/eBPF-project [JOBS=4 THREADS=4] bash lidds_dl_baselines.sh
set -uo pipefail
R=${R:-/home/dat/eBPF-project}
D=/var/tmp/dl-baseline
JOBS=${JOBS:-4}
THREADS=${THREADS:-4}
export R D THREADS PYTHONDONTWRITEBYTECODE=1 MPLBACKEND=Agg
mkdir -p $D/data/LID-DS-2021 $D/out $D/models
part() {
  local s=$1 arm=$2
  [ -f $D/out/$s-$arm.json ] && return 0
  if [ ! -f $D/data/LID-DS-2021/$s/.extracted ]; then
    ( flock 9
      [ -f $D/data/LID-DS-2021/$s/.extracted ] || python3 -c "
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1]); z.extractall(sys.argv[2], [m for m in z.namelist() if not m.startswith('__MACOSX')])
" /var/tmp/lid-ds-2021/$s.zip $D/data/LID-DS-2021 && touch $D/data/LID-DS-2021/$s/.extracted
    ) 9> $D/data/.lock-$s
  fi
  echo "start $s $arm $(date -u +%FT%T)"
  OMP_NUM_THREADS=$THREADS timeout 24h $D/venv/bin/python -u $R/scripts/analysis/lidds_dl_baselines.py --lib $D/LID-DS \
    --scenario-dir $D/data/LID-DS-2021/$s --arm $arm --v2 $R/validation-evidence/results-20261031/lidds-v2/lidds-evaluation-v2.json.gz \
    --models $D/models/$s-$arm --workers $THREADS --output $D/out/$s-$arm.json > $D/out/$s-$arm.log 2>&1 \
    || echo "FAILED $s $arm (exit $?)"
  echo "done $s $arm $(date -u +%FT%T)"
}
export -f part
for s in $(ls -S -r /var/tmp/lid-ds-2021/*.zip | xargs -n1 basename | sed 's/\.zip$//'); do
  for arm in mlp lstm; do echo "$s $arm"; done
done | xargs -P $JOBS -L 1 bash -c 'part $0 $1'
$D/venv/bin/python $R/scripts/analysis/lidds_dl_baselines.py --merge $D/out/*-mlp.json $D/out/*-lstm.json --output $D/lidds-dl-baselines.json
echo "all done $(date -u +%FT%T)"
