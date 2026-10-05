import io
import json
from pathlib import Path

import numpy as np
import pytest

from sentinel_pulse.capture import run
from sentinel_pulse.detect import PulseRuntime
from sentinel_pulse.encoding import decode_vector, schema_digest
from sentinel_pulse.features import PulseFeatureBuilder
from sentinel_pulse.inspect_recovery_tail import inspect
from sentinel_pulse.model import PulseDecision
from sentinel_pulse.telemetry_recovery import (
    HARD_COUNTERS, RecoveryTracker, SNAPSHOT_SCHEMA, digest, load_profile, validate_profile,
)
from sentinel_pulse.validate_capture import validate as validate_legacy
from sentinel_pulse.validate_recovery_capture import validate
from sentinel_pulse.recovery_deployment import contract
from sentinel_pulse.evaluate_recovery_smoke import evaluate as evaluate_smoke
from sentinel_pulse.train import load_sequences, load_workload_revisions

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


def test_gap_quarantined_then_clean_rolling_replay(tmp_path, monkeypatch, profile):
    times = [100 + i * .5 for i in range(20)]
    times += [times[-1] + 14 + i * .5 for i in range(20)]
    # The gap contains a very large count delta. It MUST NOT pollute the next
    # clean rolling mean/std, or be fed into the model.
    counts = [(i + 1) * 10 for i in range(20)] + [250000 + i * 10 for i in range(20)]
    path, rows = make_capture(tmp_path, monkeypatch, profile, times, counts)
    features = [r for r in rows if r["schema"] == "sentinel-pulse-feature-v1"]
    gap = next(r for r in features if r["window_end"] == times[20])
    assert not gap["telemetry_recovery"]["eligible"]
    assert gap["exact_counts"]["read"] == 249800  # diagnostic data retained
    following = [r for r in features if r["window_end"] > times[20]]
    assert [r["telemetry_recovery"]["eligible"] for r in following[:11]] == [False] * 10 + [True]
    first_ready = following[10]
    columns = PulseFeatureBuilder(rolling_windows=10).columns
    vector = decode_vector(first_ready)
    assert vector[columns.index("rolling_mean:read")] == pytest.approx(np.log1p(20))
    assert vector[columns.index("rolling_std:read")] == 0
    report = validate(path, profile)
    assert report["integrity_valid"], report["errors"]
    assert not report["availability_valid"]  # short test cannot hide missing time
    assert report["incidents"] == 1
    assert report["maximum_gap_seconds"] == 14
    assert report["excluded_seconds"] == 19.5
    assert report["eligible_feature_rows"]["production/test:app"] > 0
    assert not report["legacy_normal_pass"] and not report["operational_soak_pass"]
    assert not validate_legacy(path, 1, .35, .8, .5, .999, 10)["valid"]


def test_clean_capture_valid_but_never_formal_pass(tmp_path, monkeypatch, profile):
    path, _ = make_capture(tmp_path, monkeypatch, profile, [100 + i * .5 for i in range(30)])
    report = validate(path, profile)
    assert report["valid"], report["errors"]
    assert report["availability"] == 1
    assert report["eligible_feature_rows"]["production/test:app"] == 19
    assert not report["operational_soak_pass"]


@pytest.mark.parametrize("mutation", ["eligibility", "journal", "rolling", "delete_gap", "hard_counter"])
def test_validator_rejects_tampered_evidence(tmp_path, monkeypatch, profile, mutation):
    times = [100 + i * .5 for i in range(20)] + [123 + i * .5 for i in range(20)]
    path, rows = make_capture(tmp_path, monkeypatch, profile, times)
    feature = next(r for r in rows if r["schema"] == "sentinel-pulse-feature-v1")
    if mutation == "eligibility":
        feature["telemetry_recovery"]["eligible"] = True
    elif mutation == "journal":
        next(r for r in rows if r["schema"] == SNAPSHOT_SCHEMA)["recovery"]["excluded_seconds"] = 100
    elif mutation == "rolling":
        feature["vector"] = decode_vector(feature).tolist()
        feature["vector"][191] += 1
    elif mutation == "delete_gap":
        rows = [r for r in rows if not (r["schema"] == SNAPSHOT_SCHEMA and r["observed_at"] == 123)]
    else:
        feature["collector_stats"] = {**feature["collector_stats"], "snapshot_projection_fail": 1}
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    report = validate(path, profile)
    assert not report["integrity_valid"], report


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


def fake_runtime(profile=None):
    runtime = PulseRuntime.__new__(PulseRuntime)
    runtime.history_size = 3
    runtime.max_contiguous_gap_seconds = 1.25
    runtime.model_manifest_sha256 = "a" * 64
    runtime.feature_schema_sha256 = schema_digest(PulseFeatureBuilder().columns)
    runtime.models = {"production/test:app": SpyModel()}
    runtime.approved_workload_revisions = {"production/test:app": {"revision-a"}}
    runtime.histories, runtime.history_metadata = {}, {}
    runtime.temporal_evidence, runtime.confirmation_evidence = {}, {}
    runtime.decision_policy, runtime.decision_policy_sha256 = None, None
    runtime.recovery_tracker = RecoveryTracker(profile) if profile is not None else None
    runtime.recovery_state, runtime.recovery_last_features = None, {}
    return runtime


def test_runtime_does_not_score_gap_or_reuse_history(tmp_path, monkeypatch, profile):
    times = [100 + i * .5 for i in range(20)] + [123 + i * .5 for i in range(20)]
    _path, rows = make_capture(tmp_path, monkeypatch, profile, times)
    runtime = fake_runtime(profile)
    decisions = []
    for row in rows:
        if row["schema"] == SNAPSHOT_SCHEMA:
            runtime.observe_recovery_snapshot(row)
            if row["observed_at"] == 123:
                assert not runtime.histories
                assert not runtime.confirmation_evidence
                assert not runtime.temporal_evidence
        elif row["schema"] == "sentinel-pulse-feature-v1":
            decisions.append(runtime.score(row))
    after = [r for r in decisions if r["window_end"] >= 123]
    assert after[0]["status"] == "telemetry-degraded"
    assert [r["status"] for r in after[1:14]] == ["warming"] * 13
    assert after[14]["status"] == "normal"
    assert runtime.models["production/test:app"].calls == 12


def test_legacy_runtime_refuses_recovery_rows(tmp_path, monkeypatch, profile):
    _path, rows = make_capture(tmp_path, monkeypatch, profile, [100, 100.5])
    runtime = fake_runtime()
    feature = next(r for r in rows if r["schema"] == "sentinel-pulse-feature-v1")
    with pytest.raises(ValueError, match="legacy runtime"):
        runtime.score(feature)
    with pytest.raises(ValueError, match="explicit recovery runtime"):
        runtime.observe_recovery_snapshot(rows[0])


def test_cold_runtime_cannot_skip_journal(tmp_path, monkeypatch, profile):
    _path, rows = make_capture(tmp_path, monkeypatch, profile, [100, 100.5])
    runtime = fake_runtime(profile)
    feature = next(r for r in rows if r["schema"] == "sentinel-pulse-feature-v1")
    with pytest.raises(ValueError, match="no replayed snapshot"):
        runtime.score(feature)


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


def test_live_guard_allows_bounded_wait_but_never_terminal_pass(tmp_path, monkeypatch, profile):
    path, _ = make_capture(tmp_path, monkeypatch, profile, [100 + i * .5 for i in range(30)])
    pending = inspect(path, profile, now=114.5 + 14)
    assert pending["valid"]
    assert pending["status"] == "telemetry-degraded"
    assert not pending["terminal_pass"]
    assert not pending["availability_floor_evaluated"]
    expired = inspect(path, profile, now=114.5 + 31)
    assert not expired["valid"]
    assert "stream stalled" in expired["errors"][0]


def test_live_guard_rejects_hard_counter_even_when_journal_says_ready(tmp_path, monkeypatch, profile):
    path, rows = make_capture(tmp_path, monkeypatch, profile, [100 + i * .5 for i in range(30)])
    journal = [r for r in rows if r["schema"] == SNAPSHOT_SCHEMA][-1]
    journal["collector_stats"]["snapshot_projection_fail"] = 1
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    result = inspect(path, profile, now=114.501)
    assert not result["valid"]


def test_gap_cannot_be_accepted_under_another_profile(tmp_path, monkeypatch, profile):
    path, _ = make_capture(tmp_path, monkeypatch, profile, [100 + i * .5 for i in range(30)])
    alternative = {**profile, "maximum_incidents": 11}
    assert not inspect(path, alternative, now=114.501)["valid"]
    assert not validate(path, alternative)["integrity_valid"]


def test_receive_clock_and_snapshot_clock_steps_fail_closed(profile):
    tracker = RecoveryTracker(profile)
    tracker.step(100, 100.001, ZERO_STATS)
    with pytest.raises(ValueError, match="non-monotonic"):
        tracker.step(100, 100.501, ZERO_STATS)
    tracker = RecoveryTracker(profile)
    tracker.step(100, 100.001, ZERO_STATS)
    with pytest.raises(ValueError, match="clock moved backwards"):
        tracker.step(100.5, 99.0, ZERO_STATS)


@pytest.mark.parametrize("reader", [load_sequences, load_workload_revisions])
def test_training_refuses_even_recovery_features_stripped_of_journal(tmp_path, monkeypatch, profile, reader):
    path, rows = make_capture(tmp_path, monkeypatch, profile, [100 + i * .5 for i in range(30)])
    rows = [row for row in rows if row["schema"] != SNAPSHOT_SCHEMA]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(ValueError, match="not admitted for training"):
        reader(path)


def test_observer_launcher_checks_samples_and_invokes_interpreter():
    source = (PROFILE.parent.parent / "start_node_pressure_diagnostic.sh").read_text()
    assert '/bin/bash "$script"' in source
    assert '-s $run_dir/clock.jsonl' in source
    assert '-s $run_dir/sar.bin' in source
    assert 'sha256sum -c "$run_dir/SOURCE_SHA256SUMS"' in source
    assert 'test ! -e "$run_dir"' in source


def test_c2_incident_timing_quarantines_backlog_and_confirmation_windows(tmp_path, monkeypatch, profile):
    # Observed timestamps from the rejected C2 incident, NOT its dataset or
    # model scores. Counts here are synthetic test inputs, never training.
    last = 1791046876.3029811
    gap_end = 1791046889.5119402
    times = [last - (19 - i) * .5 for i in range(20)]
    times += [gap_end, 1791046890.0896232, 1791046890.6024785,
              1791046891.111563, 1791046891.6241994]
    times += [times[-1] + i * .5 for i in range(1, 20)]
    path, rows = make_capture(tmp_path, monkeypatch, profile, times, lag_at={19: 13.393888})
    runtime = fake_runtime(profile)
    actual_alert_window_ends = {1791046891.111563, 1791046891.6241994}
    quarantined = []
    for row in rows:
        if row["schema"] == SNAPSHOT_SCHEMA:
            runtime.observe_recovery_snapshot(row)
        elif row["schema"] == "sentinel-pulse-feature-v1":
            decision = runtime.score(row)
            if row["window_end"] in actual_alert_window_ends:
                quarantined.append(decision)
    assert len(quarantined) == 2
    assert all(row["status"] == "warming" and "inference_ms" not in row for row in quarantined)
    result = validate(path, profile)
    assert result["integrity_valid"], result["errors"]
    assert result["incidents"] == 1
    assert result["estimated_missing_snapshots"] == 25
    assert not result["availability_valid"]


@pytest.mark.parametrize("live_freshness", [False, True])
@pytest.mark.parametrize("mutation", [None, "omit_alert", "identity", "quarantine_score", "duplicate", "collector_active", "missing_decision"])
def test_recovery_smoke_preserves_alerts_and_never_emits_formal_pass(tmp_path, monkeypatch, profile, mutation, live_freshness):
    path, rows = make_capture(tmp_path, monkeypatch, profile, [100 + i * .5 for i in range(40)])
    path.rename(tmp_path / "features.jsonl")
    installed = tmp_path / "telemetry-recovery-profile.json"
    installed.write_bytes(PROFILE.read_bytes())
    (tmp_path / "START.json").write_text(json.dumps({
        "telemetry_recovery_contract": contract(installed, .5, .999, 30),
        "telemetry_availability_contract": {"nominal_interval_seconds": .5,
            "minimum_availability": .999, "maximum_single_gap_seconds": 30},
    }))
    runtime = fake_runtime(profile)
    if live_freshness:
        from sentinel_pulse.detector_freshness import CONTRACT
        (tmp_path / "DETECTOR_FRESHNESS_CONTRACT.json").write_text(json.dumps(CONTRACT))
        runtime.live_freshness = True
        runtime.last_processing_check = None
        clock = [100]
        monkeypatch.setattr("sentinel_pulse.detect.time.time", lambda: clock[0])
    decisions = []
    for row in rows:
        if row["schema"] == SNAPSHOT_SCHEMA:
            runtime.observe_recovery_snapshot(row)
        elif row["schema"] == "sentinel-pulse-feature-v1":
            if live_freshness:
                clock[0] = row["window_end"] + .03
            result = runtime.score(row)
            result.update(run_id=tmp_path.name, decision_policy_sha256="b" * 64)
            result["telemetry_recovery"] = row["telemetry_recovery"]
            decisions.append(result)
    if mutation == "omit_alert":
        decisions[-1]["status"] = "alert"
    elif mutation == "identity":
        decisions[-1]["model_manifest_sha256"] = "c" * 64
    elif mutation == "quarantine_score":
        decisions[0].update(status="normal", score=0, conformal_p=1, inference_ms=1, post_window_processing_seconds=.01)
    elif mutation == "duplicate":
        decisions.append(dict(decisions[-1]))
    elif mutation == "missing_decision":
        decisions.pop()
    (tmp_path / "decisions.jsonl").write_text("".join(json.dumps(row) + "\n" for row in decisions))
    (tmp_path / "alerts.jsonl").touch()
    (tmp_path / "detector-before-stop.systemd").write_text("ActiveState=active\nResult=success\nExecMainStatus=0\nNRestarts=0\n")
    state = "active" if mutation == "collector_active" else "inactive"
    (tmp_path / "collector-before-stop.systemd").write_text(f"ActiveState={state}\nResult=success\nExecMainStatus=0\n")
    report = evaluate_smoke(tmp_path, installed, "a" * 64, "b" * 64,
                            expected_live_freshness=live_freshness)
    assert report["runtime_smoke_valid"] == (mutation is None), report["errors"]
    assert not report["operational_soak_pass"] and not report["legacy_normal_pass"]
    assert not report["automatic_blind_evaluation"] and not report["automatic_promotion"]
    if mutation == "omit_alert":
        assert report["alerts"] == 1
        assert any("ALL decision alerts" in e for e in report["errors"])


def test_detector_queue_stale_resets_context_without_calling_model(tmp_path, monkeypatch, profile):
    _path, rows = make_capture(tmp_path, monkeypatch, profile, [100 + i * .5 for i in range(45)])
    runtime = fake_runtime(profile)
    runtime.live_freshness, runtime.last_processing_check = True, None
    clock = [100]
    monkeypatch.setattr("sentinel_pulse.detect.time.time", lambda: clock[0])
    after = []
    for row in rows:
        if row["schema"] == SNAPSHOT_SCHEMA:
            runtime.observe_recovery_snapshot(row)
        elif row["schema"] == "sentinel-pulse-feature-v1":
            # Simulate a 2s detector pause while capture itself remains clean.
            clock[0] = max(clock[0], row["window_end"] + (.01 if row["window_end"] != 110 else 2))
            before = runtime.models["production/test:app"].calls
            result = runtime.score(row)
            if row["window_end"] == 110:
                assert result["status"] == "telemetry-degraded"
                assert result["telemetry_reason"] == "detector_queue_stale"
                assert runtime.models["production/test:app"].calls == before
                assert not runtime.histories and not runtime.history_metadata
                assert not runtime.confirmation_evidence and not runtime.temporal_evidence
                assert "score" not in result and "inference_ms" not in result
            if row["window_end"] >= 111:
                after.append(result)
    assert [r["status"] for r in after[:4]] == ["warming"] * 3 + ["normal"]
    assert all(r["detector_freshness"]["eligible"] for r in after)


@pytest.mark.parametrize("mutation", ["missing_contract", "eligibility", "stale_inference"])
def test_terminal_replays_processing_freshness_instead_of_trusting_decision(tmp_path, monkeypatch, profile, mutation):
    test_recovery_smoke_preserves_alerts_and_never_emits_formal_pass(
        tmp_path, monkeypatch, profile, None, True)
    if mutation == "missing_contract":
        (tmp_path / "DETECTOR_FRESHNESS_CONTRACT.json").unlink()
    else:
        rows = [json.loads(line) for line in (tmp_path / "decisions.jsonl").read_text().splitlines()]
        meta = rows[-1]["detector_freshness"]
        if mutation == "eligibility":
            meta["eligible"] = False
        else:
            from sentinel_pulse.detector_freshness import check, complete
            end = rows[-1]["window_end"]
            rows[-1]["detector_freshness"] = complete(check(
                {"window_end": end, "emitted_at": end + .001}, end + 2), end, end + 2.01)
        (tmp_path / "decisions.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    report = evaluate_smoke(tmp_path, tmp_path / "telemetry-recovery-profile.json",
                            "a" * 64, "b" * 64, expected_live_freshness=True)
    assert not report["runtime_smoke_valid"]
