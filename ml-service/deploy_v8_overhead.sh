#!/usr/bin/env bash
# Verify and atomically install the post-terminal V8 overhead automation.
set -Eeuo pipefail

STAGING_ROOT=${V8_OVERHEAD_STAGING_ROOT:-/home/dat/v8-overhead-staging/v8-paired-replay-20260811}
RUNTIME_ROOT=${V8_RUNTIME_ROOT:-/home/dat/ml-service}
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}

[[ $(id -u) == 0 ]] || { printf 'deploy_v8_overhead.sh must run as root\n' >&2; exit 4; }
[[ -r "$STAGING_ROOT/STAGING_SHA256SUMS" ]] || {
  printf 'missing V8 overhead staging manifest\n' >&2
  exit 4
}
(cd "$STAGING_ROOT" && sha256sum -c STAGING_SHA256SUMS)

cd "$STAGING_ROOT"
PYTHONPATH="$STAGING_ROOT/ml-service" "$PYTHON_BIN" -m pytest -q \
  tests/test_v8_overhead_prerequisites.py \
  tests/test_v8_overhead_systemd.py \
  tests/test_counterbalanced_overhead.py \
  tests/test_benchmarks.py

install_atomic() {
  local source=$1 target=$2 mode=$3
  local temporary=${target}.v8-overhead-staging
  mkdir -p "$(dirname "$target")"
  cp "$source" "$temporary"
  chmod "$mode" "$temporary"
  mv "$temporary" "$target"
}

install_atomic "$STAGING_ROOT/ml-service/validate_v8_overhead_prerequisites.py" \
  "$RUNTIME_ROOT/validate_v8_overhead_prerequisites.py" 0644
for name in aggregate_counterbalanced_overhead.py capture_environment.sh \
  compare_overhead.py measure_phase.py run_aims_overhead_counterbalanced.sh \
  run_aims_overhead_matrix.sh run_v8_overhead_counterbalanced.sh; do
  mode=0644
  [[ $name == *.sh ]] && mode=0755
  install_atomic "$STAGING_ROOT/sentinel/benchmarks/$name" \
    "$RUNTIME_ROOT/sentinel/benchmarks/$name" "$mode"
done
install_atomic "$STAGING_ROOT/sentinel/systemd/aims-v8-overhead.env" \
  "$RUNTIME_ROOT/sentinel/systemd/aims-v8-overhead.env" 0644
for name in aims-v8-overhead.service aims-v8-overhead.timer \
  aims-v8-overhead.path; do
  install_atomic "$STAGING_ROOT/sentinel/systemd/$name" \
    "/etc/systemd/system/$name" 0644
done

systemctl daemon-reload
systemctl enable --now aims-v8-overhead.timer aims-v8-overhead.path
systemctl is-active --quiet aims-v8-overhead.timer
systemctl is-active --quiet aims-v8-overhead.path
printf 'ARMED: V8 overhead path trigger and retry timer wait for NORMAL_ABLATION_REPLAY_COMPLETE\n'
