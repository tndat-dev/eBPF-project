#!/usr/bin/env bash
# Fast-forward the working checkout /home/dat/eBPF-project on the cluster VMs to origin/main,
# so GitHub main, the host checkout and the VMs hold the same code (run after every push).
# Refuses to touch a checkout with local edits. Run snapshots under /mnt/.../runtime-<commit>-<date>
# are frozen run inputs and are not touched.
#   LAB_SSH_PASSWORD=... bash scripts/sync_cluster_checkouts.sh
set -euo pipefail
cd "$(dirname "$0")/.."
want=$(git rev-parse --short origin/main)
[ "$(git rev-parse --short HEAD)" = "$want" ] || echo "warning: host HEAD $(git rev-parse --short HEAD) != origin/main $want" >&2
for host in 10.1.16.234 10.1.16.237 10.1.16.238 10.1.16.239; do
  python3 scripts/ssh_lab.py --host "$host" bash -c '
    cd /home/dat/eBPF-project || exit 1
    if [ -n "$(git status --porcelain)" ]; then echo "$(hostname): LOCAL EDITS, not synced"; exit 1; fi
    git fetch -q origin && git merge -q --ff-only origin/main && echo "$(hostname): $(git log -1 --format=%h)"' \
    || echo "$host: sync failed" >&2
done
echo "origin/main = $want"
