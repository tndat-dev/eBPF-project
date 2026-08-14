#!/usr/bin/env bash
# Install the isolated Pulse collector on one Kubernetes worker node.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "install_node.sh must run as root" >&2
  exit 2
fi

SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PULSE_SOURCE="$SOURCE_ROOT/sentinel_pulse"
INSTALL_ROOT=${INSTALL_ROOT:-/opt/sentinel-pulse}

test -f "$PULSE_SOURCE/ebpf/pulse_counter.bpf.c"
test -f "$PULSE_SOURCE/requirements-collector.txt"

make -C "$PULSE_SOURCE/ebpf" clean all
install -d -m 0755 "$INSTALL_ROOT/bin" "$INSTALL_ROOT/sentinel_pulse"
cp -a "$PULSE_SOURCE/." "$INSTALL_ROOT/sentinel_pulse/"
install -m 0755 "$PULSE_SOURCE/ebpf/pulse_counter_loader" "$INSTALL_ROOT/bin/"
install -m 0644 "$PULSE_SOURCE/ebpf/pulse_counter.bpf.o" "$INSTALL_ROOT/bin/"

if [[ ! -x "$INSTALL_ROOT/venv/bin/python" ]]; then
  python3 -m venv "$INSTALL_ROOT/venv"
fi
"$INSTALL_ROOT/venv/bin/pip" install --disable-pip-version-check \
  -r "$PULSE_SOURCE/requirements-collector.txt"

install -m 0644 "$PULSE_SOURCE/systemd/sentinel-pulse-resolver.service" \
  /etc/systemd/system/sentinel-pulse-resolver.service
install -m 0644 "$PULSE_SOURCE/systemd/sentinel-pulse-collector.service" \
  /etc/systemd/system/sentinel-pulse-collector.service
systemctl daemon-reload
systemctl enable sentinel-pulse-resolver.service sentinel-pulse-collector.service
# Deploy is an explicit generation boundary.  Stop the old collector before
# replacing its allow-list, force a fresh CRI/cgroup resolution, then start the
# newly installed binary.  `enable --now` alone would leave an already-running
# process on the previous executable.
systemctl stop sentinel-pulse-collector.service 2>/dev/null || true
install -d -m 0755 /run/sentinel-pulse
: > /run/sentinel-pulse/allowed-cgroups
systemctl restart sentinel-pulse-resolver.service

for _attempt in $(seq 1 30); do
  if [[ -s /run/sentinel-pulse/allowed-cgroups ]]; then
    break
  fi
  sleep 1
done
test -s /run/sentinel-pulse/allowed-cgroups
systemctl restart sentinel-pulse-collector.service
# A successful systemctl start only proves that the pipeline forked.  Require
# an actual feature row so verifier errors and a short allow-list refresh race
# cannot be reported as a successful installation.
for _attempt in $(seq 1 20); do
  if systemctl is-active --quiet sentinel-pulse-resolver.service && \
     systemctl is-active --quiet sentinel-pulse-collector.service && \
     test -s /var/lib/sentinel-pulse/features.jsonl; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet sentinel-pulse-resolver.service
systemctl is-active --quiet sentinel-pulse-collector.service
test -s /var/lib/sentinel-pulse/features.jsonl
systemctl --no-pager --full status sentinel-pulse-resolver.service \
  sentinel-pulse-collector.service
