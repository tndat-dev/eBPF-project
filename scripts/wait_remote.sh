#!/usr/bin/env bash
# Block until a condition on .234 holds, then print a line (used as a local background waiter).
#   LAB_SSH_PASSWORD=... bash scripts/wait_remote.sh 'test -f /path/x' [poll-seconds]
#   LAB_SSH_PASSWORD=... bash scripts/wait_remote.sh unit:<systemd-unit>   (until the unit is no longer active)
cd "$(dirname "$0")/.."
cond=$1; poll=${2:-300}
if [[ $cond == unit:* ]]; then u=${cond#unit:}; cond="[ \"\$(systemctl is-active $u)\" != active ] && [ \"\$(systemctl is-active $u)\" != activating ]"; fi
until timeout 60 python3 scripts/ssh_lab.py --host 10.1.16.234 bash -c "$cond" >/dev/null 2>&1; do sleep "$poll"; done
echo "condition met $(date +%H:%M): $1"
[[ $1 == unit:* ]] && timeout 60 python3 scripts/ssh_lab.py --host 10.1.16.234 bash -c "systemctl show -p Result --value ${1#unit:}; echo $LAB_SSH_PASSWORD | sudo -S -p '' journalctl -u ${1#unit:} --no-pager -o cat | tail -6 | cut -c1-200"
exit 0
