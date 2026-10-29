#!/usr/bin/env bash
# LID-DS 2019 (one 13.01 GB archive on Proton Drive) onto .234 local disk as dat, once the live run (capture and its
# analysis unit) has finished: no multi-GB download on any VM during a live run (owner, 30/10). Zip check at the end; nothing is extracted or read otherwise.
#   SRC=/var/tmp/cb-ds/source-<sha> [WAIT_UNITS=after-recal-confirm] bash lidds2019_fetch_after_live.sh
set -u
SRC=${SRC:?source snapshot}
D=/var/tmp/lid-ds-2019
PY=/home/dat/.venvs/playwright/bin/python   # reinstall after the live run: uv venv + playwright + chromium (removed 29/10)
URL='https://drive.proton.me/urls/4DCRHJC9XC#pn6TukLN0Wq5'
F=LID-DS-2019.zip
for unit in ${WAIT_UNITS:-after-recal-confirm}; do
  while [ "$(systemctl is-active "$unit")" = active ] || [ "$(systemctl is-active "$unit")" = activating ]; do sleep 300; done
  echo "wait unit $unit is $(systemctl is-active "$unit") $(date -u +%FT%T)"
done
mkdir -p $D && cd $D
for attempt in 1 2 3; do
  [ -s "$F" ] && break
  echo "attempt $attempt $(date -u +%FT%T)"
  nice -n 10 timeout 14400 $PY $SRC/scripts/lidds_fetch.py "$URL" get "$F" || { echo "attempt $attempt failed"; rm -f "$F"; sleep 60; }
done
[ -s "$F" ] || { echo "download FAILED"; exit 1; }
sha256sum "$F" > "$F.sha256"
python3 -I -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); bad=z.testzip(); print(sys.argv[1], len(z.namelist()), 'entries, testzip', bad)" "$F"
echo "fetch done $(date -u +%FT%T)"
