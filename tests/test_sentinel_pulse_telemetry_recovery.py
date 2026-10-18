import io
import json
from pathlib import Path

import pytest

from sentinel_pulse.capture import run
from sentinel_pulse.model import PulseDecision
from sentinel_pulse.telemetry_recovery import HARD_COUNTERS, RecoveryTracker, load_profile, validate_profile

PROFILE = Path(__file__).resolve().parents[1] / "sentinel_pulse/protocol/telemetry-recovery-v1.json"
ZERO_STATS = {name: 0 for name in HARD_COUNTERS}


@pytest.fixture
def profile():
    return load_profile(PROFILE)


def make_capture(tmp_path, monkeypatch, profile, times, counters=None, lag_at=None):
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({"cgroups": {"7": {
        "namespace": "production", "workload_name": "test", "container_name": "app",
        "pod_uid": "pod", "pod_name": "test-a", "node_name": "node",
        "workload_revision": "revision-a",
    }}}))
    clock = [times[0]]
    monkeypatch.setattr("sentinel_pulse.capture.time.time", lambda: clock[0])

    def source():
        for index, end in enumerate(times):
            clock[0] = max(clock[0], end + (lag_at or {}).get(index, 0.001))
            count = counters[index] if counters else (index + 1) * 10
            yield json.dumps({"type": "cgroup_snapshot", "cgroup_id": 7, "total": count,
                              "counts": {"0": count}, "syscall_bins": [count] + [0] * 63,
                              "transition_bins": [0] * 64}) + "\n"
            for name, value in ZERO_STATS.items():
                yield json.dumps({"type": "stat", "name": name, "cumulative": value}) + "\n"
            yield json.dumps({"type": "snapshot_end", "observed_at": end,
                              "targets": 1, "snapshots": 1, "snapshot_read_seconds": 0.001}) + "\n"

    destination = io.StringIO()
    run(source(), destination, metadata, rolling_windows=10, interval_min_seconds=.35,
        interval_max_seconds=.8, nominal_interval_seconds=.5, recovery_profile=profile)
    path = tmp_path / "capture.jsonl"
    path.write_text(destination.getvalue())
    return path, [json.loads(line) for line in destination.getvalue().splitlines()]


@pytest.mark.parametrize("counter", HARD_COUNTERS)
def test_hard_errors_never_recover(profile, counter):
    tracker = RecoveryTracker(profile)
    tracker.step(100, 100.001, ZERO_STATS)
    bad = tracker.step(100.5, 100.501, {**ZERO_STATS, counter: 1})
    assert bad["status"] == "fatal"
    later = tracker.step(101, 101.001, ZERO_STATS)
    assert later["status"] == "fatal"


def test_missing_counter_rejected(profile):
    state = RecoveryTracker(profile).step(100, 100.001, {})
    assert state["status"] == "fatal"


@pytest.mark.parametrize("field,value", [
    ("maximum_recoverable_gap_seconds", 31), ("maximum_excluded_seconds", 901),
    ("minimum_telemetry_availability", .9), ("rolling_windows", 3),
    ("automatic_promotion", True), ("maximum_incidents", True),
    ("maximum_wall_seconds", float("nan")),
])
def test_profile_cannot_relax_safety_bounds(profile, field, value):
    profile[field] = value
    with pytest.raises(ValueError):
        validate_profile(profile)


def test_availability_not_reset_on_recovery(profile):
    tracker = RecoveryTracker(profile)
    for i in range(40000):
        end = 100 + i * .5
        tracker.step(end, end + .001, ZERO_STATS)
    last = end
    bad = tracker.step(last + 14, last + 14.001, ZERO_STATS)
    assert bad["estimated_missing_snapshots"] == 27
    for i in range(1, 12):
        ready = tracker.step(last + 14 + i * .5, last + 14.001 + i * .5, ZERO_STATS)
    assert ready["status"] == "ready"
    assert ready["estimated_missing_snapshots"] == 27
    assert .999 < ready["availability"] < 1


def test_recovery_timeout_and_oversized_gap_stay_fatal(profile):
    tracker = RecoveryTracker(profile)
    tracker.step(100, 100.001, ZERO_STATS)
    assert tracker.step(131, 131.001, ZERO_STATS)["status"] == "fatal"
    tracker = RecoveryTracker(profile)
    for i in range(123):
        end = 100 + i * .5
        state = tracker.step(end, end + 2, ZERO_STATS)
    assert state["status"] == "fatal"
    assert "incident recovery timeout" in state["reasons"]


class SpyModel:
    def __init__(self):
        self.calls = 0

    def predict(self, history, row):
        self.calls += 1
        assert len(history) == 3
        return PulseDecision(score=0, conformal_p=1, anomalous=False, inference_ms=.1)


def test_late_backlog_is_quarantined(tmp_path, monkeypatch, profile):
    _path, rows = make_capture(tmp_path, monkeypatch, profile,
                               [100 + i * .5 for i in range(40)], lag_at={20: 2, 21: 1.5})
    features = [r for r in rows if r["schema"] == "sentinel-pulse-feature-v1"]
    bad = [r for r in features if r["window_end"] in {110, 110.5}]
    assert all(not r["telemetry_recovery"]["eligible"] for r in bad)
    assert all(r["telemetry_recovery"]["reason"] == "feature_ingest_lag" for r in bad)


def test_capture_profile_mismatch_fails_before_reading(tmp_path, profile):
    with pytest.raises(ValueError, match="configuration differs"):
        run(io.StringIO(""), io.StringIO(), tmp_path / "metadata", recovery_profile=profile)


def test_receive_clock_and_snapshot_clock_steps_fail_closed(profile):
    tracker = RecoveryTracker(profile)
    tracker.step(100, 100.001, ZERO_STATS)
    with pytest.raises(ValueError, match="non-monotonic"):
        tracker.step(100, 100.501, ZERO_STATS)
    tracker = RecoveryTracker(profile)
    tracker.step(100, 100.001, ZERO_STATS)
    with pytest.raises(ValueError, match="clock moved backwards"):
        tracker.step(100.5, 99.0, ZERO_STATS)
