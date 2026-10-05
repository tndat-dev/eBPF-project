import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from sentinel_pulse.features import TRACKED_SYSCALLS
from sentinel_pulse.features import PulseFeatureBuilder, PulseSnapshot
from sentinel_pulse.inspect_feature_tail import inspect
from sentinel_pulse.inspect_feature_tail import HARD_INTEGRITY_COUNTERS as TAIL_COUNTERS
from sentinel_pulse.validate_capture import HARD_INTEGRITY_COUNTERS as CAPTURE_COUNTERS
from sentinel_pulse.validate_capture import validate

ROOT = Path(__file__).resolve().parents[1]
EBPF = ROOT / "sentinel_pulse" / "ebpf"


def test_projection_preserves_all_syscall_histograms_and_rejects_overflow(tmp_path):
    cc = shutil.which("cc")
    assert cc, "C compiler required to validate the collector projection"
    binary = tmp_path / "projection-test"
    subprocess.run([
        cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I", str(EBPF), str(ROOT / "tests/c/pulse_counter_projection.c"),
        "-o", str(binary),
    ], check=True, capture_output=True, text=True, timeout=30)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=5)
    assert "1024 IDs x 4 CPUs" in result.stdout
    assert "PASS" in result.stdout


def test_projection_tracked_order_matches_249_feature_schema():
    rows = re.findall(r"X\((\d+), (\d+)\)", (EBPF / "pulse_counter_ids.h").read_text())
    assert [(int(i), int(s)) for i, s in rows] == [
        (identifier, slot) for slot, identifier in enumerate(TRACKED_SYSCALLS)
    ]


def test_projection_is_opt_in_and_map_abi_is_verified_before_attach():
    makefile = (EBPF / "Makefile").read_text()
    assert "all: check-deps pulse_counter.bpf.o pulse_counter_loader" in makefile
    assert "-DPULSE_PROJECTED_COUNTERS" in makefile
    loader = (EBPF / "pulse_counter_loader.c").read_text()
    assert loader.index("counter map layout does not match loader") < loader.index(
        'bpf_program__attach_raw_tracepoint(program, "sys_enter")'
    )


def test_projection_kernel_tracked_writes_expand_constant_cases():
    kernel = (EBPF / "pulse_counter.bpf.c").read_text()
    assert "case number: counters->tracked[slot]++; return 1;" in kernel
    assert "PULSE_TRACKED_ROWS(PULSE_CASE)" in kernel
    assert "if (!increment_projected_tracked(counters, syscall_id))" in kernel


def test_projection_failure_is_hard_integrity_not_budgeted():
    assert "snapshot_projection_fail" in CAPTURE_COUNTERS
    assert "snapshot_projection_fail" in TAIL_COUNTERS


def test_projection_loss_rejects_both_live_tail_and_complete_capture(tmp_path):
    builder = PulseFeatureBuilder()
    builder.ingest(PulseSnapshot(7, 10.0, {0: 2}, {}), "production/test:app")
    feature = builder.ingest(PulseSnapshot(7, 10.5, {0: 4}, {}), "production/test:app")
    record = feature.as_record()
    record.update(emitted_at=10.6, collector_stats={"snapshot_projection_fail": 1})
    path = tmp_path / "features.jsonl"
    path.write_text(json.dumps(record) + "\n")
    reports = [
        inspect(path, observed_at=10.7),
        validate(path, minimum_rows_per_workload=1, interval_min_seconds=0.35,
                 interval_max_seconds=0.8, nominal_interval_seconds=0.5),
    ]
    for report in reports:
        assert report["valid"] is False
        assert "collector loss: snapshot_projection_fail=1" in report["errors"]


def test_projection_canary_refuses_to_start_over_an_existing_candidate():
    script = (ROOT / "sentinel_pulse/run_projected_counter_canary.sh").read_text()
    assert "sentinel-pulse-detector-candidate.service" in script
    assert "must not overlap a candidate run" in script
    assert "--interval-ms 500" in script
    assert "--minimum-telemetry-availability 1.0" in script
    assert "is-active --quiet sentinel-pulse-collector.service" in script
