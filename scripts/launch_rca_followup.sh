#!/usr/bin/env bash
# RCA follow-up on the running R6 capture (run on .234 as dat):
#   LAB_SSH_PASSWORD=... SRC=/mnt/.../source bash launch_rca_followup.sh [derive|rca|campaign|all]
#
# - derive: a 7-workload coordinator (105 pairs, benign controls) on the R6 capture;
# - rca: replace subscriber r6 with r6b: follow-up cases on new execs, 20000-case
#   retention, binary baseline seeded from r6 (same freeze time);
# - campaign: install the coordinator campaign service.
set -euo pipefail
: "${LAB_SSH_PASSWORD:?}" "${SRC:?}"
ROOT=/mnt/sentinel-pulse-archive/matched-r6-20261018
COORD=$ROOT/coordinator-rca-followup-20261019
CREDENTIAL=/home/dat/.pulse-recovery-credential-20261005
# r6b (10:36) used a ring-limited novelty check that let periodic probes open follow-ups;
# r6c (19/10 ~10:55) uses a 15-min exec log. Override with OLD/NAME/OLD_UNIT/UNIT.
OLD=${OLD:-/var/lib/sentinel-pulse-rca/runtime-events-20261019-r6b}
NAME=${NAME:-runtime-events-20261019-r6c}
OLD_UNIT=${OLD_UNIT:-pulse-rca-runtime-events-r6b}
UNIT=${UNIT:-pulse-rca-runtime-events-r6c}
WORKLOADS=(production/api-gateway:app production/payment-service:app production/notification-service:app
           production/aims-redis:aims-redis production/aims-rabbitmq-server:rabbitmq
           production/aims-postgres-cnpg:postgres production/aims-kafka-dual-role:kafka)

as_root() { printf '%s\n' "$LAB_SSH_PASSWORD" | sudo -S -p '' "$@"; }

derive() {
  cd /tmp
  args=(); for w in "${WORKLOADS[@]}"; do args+=(--campaign-workload "$w"); done
  PYTHONPATH=$SRC /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.derive_matched_coordinator_run \
    --capture-config "$ROOT/CONFIG.json" --source "$SRC" --root "$COORD" --run-id r6-rca-followup-20261019 \
    --selection-delay 60 --selection-seconds 600 --attack-delay 60 "${args[@]}"
}

rca() {
  as_root mkdir -p "/opt/sentinel-pulse-rca/$NAME" "/var/lib/sentinel-pulse-rca/$NAME"
  as_root test -d "/opt/sentinel-pulse-rca/$NAME/source/.git" ||
    as_root cp -r "$SRC" "/opt/sentinel-pulse-rca/$NAME/source"
  NAME=$NAME OLD=$OLD python3 - >"/tmp/$NAME.json" <<'PY'
import json, sys
old = json.load(open('/etc/sentinel-pulse-rca/runtime-events-20261018-r6.json'))
import os
old.update(output='/var/lib/sentinel-pulse-rca/' + os.environ['NAME'],
           previous_output=os.environ['OLD'],
           registration_reason='R6 RCA follow-up: bounded follow-up cases on new execs inside the cooldown, '
                               '20000-case retention, binary baseline seeded from r6 with the same freeze time',
           follow_up_on_new_exec=True, follow_up_min_seconds=10, follow_up_max_per_cooldown=5,
           follow_up_novelty_seconds=300,
           max_cases=20000, stream_rotate_seconds=900)
print(json.dumps(old, indent=2))
PY
  as_root install -m 0640 -o root -g dat "/tmp/$NAME.json" "/etc/sentinel-pulse-rca/$NAME.json"
  rm -f "/tmp/$NAME.json"
  # Seed the never-expiring first-seen table so the freeze time keeps its meaning. The script
  # goes through a temp file: as_root feeds the password on stdin, so `python3 -` with a
  # heredoc ran an empty program and r6b/r6c started unseeded (found 19/10 16:30).
  cat >/tmp/seed-binaries.py <<'PY'
import sqlite3, sys
from sentinel_pulse.rca.service import database
src = sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True)
dst = database(sys.argv[2])
rows = src.execute('select workload, binary, first_seen from binaries').fetchall()
dst.executemany('insert into binaries values(?,?,?) on conflict(workload, binary) do update set '
                'first_seen=min(first_seen, excluded.first_seen)', rows); dst.commit()
if not rows:
    sys.exit('no baseline rows to seed')
print('seeded binaries', len(rows))
PY
  as_root env PYTHONPATH="$SRC" python3 /tmp/seed-binaries.py "$OLD/context.sqlite3" "/var/lib/sentinel-pulse-rca/$NAME/context.sqlite3"
  rm -f /tmp/seed-binaries.py
  cat >/tmp/$UNIT.service <<UNIT
[Unit]
Description=Pulse RCA runtime-event subscriber ($NAME, follow-up cases, read-only)
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/mnt/sentinel-pulse-archive

[Service]
Type=simple
User=root
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONPATH=/opt/sentinel-pulse-rca/$NAME/source
ExecStart=/usr/bin/python3 -u -m sentinel_pulse.rca.service --config /etc/sentinel-pulse-rca/$NAME.json
Restart=on-failure
RestartSec=30
MemoryMax=2G
Nice=10

[Install]
WantedBy=multi-user.target
UNIT
  as_root install -m 0644 -o root -g root /tmp/$UNIT.service /etc/systemd/system/$UNIT.service
  rm -f /tmp/$UNIT.service
  as_root systemctl daemon-reload
  as_root systemctl disable --now "$OLD_UNIT.service"
  as_root systemctl enable --now "$UNIT.service"
}

campaign() {
  cd /tmp
  as_root env PYTHONPATH="$SRC" /home/dat/ml-venv/bin/python -m sentinel_pulse.pipeline.matched_services \
    --config "$COORD/CONFIG.json" --role campaign --credential "$CREDENTIAL"
}

case "${1:-all}" in
  derive) derive ;; rca) rca ;; campaign) campaign ;;
  all) derive; rca; campaign ;;
  *) echo "unknown step $1" >&2; exit 2 ;;
esac
