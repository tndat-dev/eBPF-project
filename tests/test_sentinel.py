import json
import time
from pathlib import Path
pytest = __import__("pytest")
np = pytest.importorskip("numpy")

from adaptive_threshold import (POTThreshold, StreamingThreshold,
                                load_calibrators, save_calibrators)
from graph_signals import (behavior_signals, evaluate_behavior,
                           fit_behavior_limits)
from anomaly_detector2 import AnomalyDetector
from feature_engineering import PodWindowBuffer, parse_event_time
from tetragon_consumer import TetragonKubectlReader
from sentinel.telemetry import inject, detection_latency


@pytest.fixture(autouse=True)
def isolate_test_telemetry(tmp_path, monkeypatch):
    """Never let unit-test inference rows enter the production JSONL file."""
    monkeypatch.setenv("SENTINEL_METRICS", str(tmp_path / "metrics.jsonl"))

def test_threshold_has_floor_and_ignores_small_sample():
    assert POTThreshold(minimum=.8).fit([.1, .2]) == .8
    assert .8 <= POTThreshold(minimum=.8).fit(np.linspace(.1, .3, 100)) <= .995

def test_evt_threshold_fits_a_non_degenerate_tail_when_scipy_is_available():
    estimator = POTThreshold(minimum=.2, min_samples=80, min_exceedances=8)
    rng = np.random.default_rng(42)
    estimator.fit(rng.beta(2, 8, 200))
    assert estimator.fit_method in {"evt-gpd", "empirical"}
    assert estimator.diagnostics["samples"] == 200

def test_behavior_signals_marks_privileged_syscalls():
    rows = behavior_signals({"execve": 5, "read": 5}, 10)
    assert next(x for x in rows if x["name"] == "execve")["signal"] == "suspicious"


def test_workload_conditioned_gate_accepts_common_behavior_and_rejects_burst():
    vocab = {"connect": 0, "clone": 1}
    baseline = np.asarray([
        [.15, .10], [.16, .09], [.14, .11], [.15, .10], [.16, .10],
    ])
    limits = fit_behavior_limits(baseline, vocab)
    normal = evaluate_behavior({"connect": 15, "clone": 10}, 100, limits)
    attack = evaluate_behavior({"connect": 80, "clone": 10}, 100, limits)
    assert normal["method"] == "workload-conditioned"
    assert not normal["gate"]
    assert attack["gate"] and attack["syscall"] == "connect"

def test_injection_clock_is_monotonic(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_METRICS", str(tmp_path / "metrics.jsonl"))
    inject("ns/pod", "test")
    value = detection_latency("ns/pod")
    assert value is not None and value >= 0
    assert json.loads((tmp_path / "metrics.jsonl").read_text())["kind"] == "injection"


def test_detection_latency_reads_external_injection_clock(tmp_path, monkeypatch):
    path = tmp_path / "external-metrics.jsonl"
    monkeypatch.setenv("SENTINEL_METRICS", str(path))
    started = time.time() - 0.01
    path.write_text(json.dumps({
        "kind": "injection", "ts": started, "pod_key": "ns/external-pod",
    }) + "\n")
    latency = detection_latency("ns/external-pod")
    assert latency is not None and latency >= 0.01

def test_streaming_threshold_requires_warmup():
    threshold = StreamingThreshold(minimum=.8, warmup=3)
    threshold.observe(.2); threshold.observe(.3)
    assert not threshold.ready
    threshold.observe(.25)
    assert threshold.ready and threshold.current >= .8

def test_calibration_round_trip(tmp_path):
    threshold = StreamingThreshold(minimum=.8, warmup=2)
    threshold.observe(.2, 1000); threshold.observe(.3, 1200)
    path = tmp_path / "calibration.json"
    save_calibrators(path, {"production/nginx": threshold})
    loaded = load_calibrators(path, minimum=.8, warmup=2)
    assert loaded["production/nginx"].ready
    assert list(loaded["production/nginx"].scores) == [.2, .3]
    assert list(loaded["production/nginx"].event_counts) == [1000, 1200]
    assert loaded["production/nginx"].minimum_event_count == 510


def test_concurrent_calibration_snapshots_remain_atomic(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "calibration.json"

    def write_snapshot(index):
        threshold = StreamingThreshold(minimum=.8, warmup=1)
        threshold.observe(index / 1000.0, 100 + index)
        save_calibrators(path, {"production/nginx": threshold})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write_snapshot, range(64)))

    payload = json.loads(path.read_text())
    assert payload["schema_version"] == 2
    state = payload["workloads"]["production/nginx"]
    assert len(state["scores"]) == len(state["event_counts"]) == 1
    assert not list(tmp_path.glob(".calibration.json.*.tmp"))


def test_event_guard_uses_lower_tail_not_high_load_median():
    threshold = StreamingThreshold(minimum=.8, warmup=10)
    for count in [120] * 9 + [10_000]:
        threshold.observe(.2, count)
    assert threshold.minimum_event_count == 60


def test_legacy_calibration_format_is_backward_compatible(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text('{"production/nginx": [0.2, 0.3]}')
    loaded = load_calibrators(path, minimum=.8, warmup=2)
    assert list(loaded["production/nginx"].scores) == [.2, .3]
    assert list(loaded["production/nginx"].event_counts) == []


def test_score_outlier_cannot_poison_online_calibration(tmp_path, monkeypatch):
    class Manager:
        def __init__(self):
            self.result = {
                "ensemble_score": .95, "lstm_score": .95, "if_score": .2,
            }

        def list_models(self):
            return ["production/nginx"]

        def score(self, _key, _vector):
            return self.result

    class Vector:
        pod_key = "production/nginx-56fcf95486-abcde"
        pod_name = "nginx-56fcf95486-abcde"
        pod_namespace = "production"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"read": 100}
        window_start = 0.0
        window_end = 30.0

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    monkeypatch.setenv("SENTINEL_WARMUP_WINDOWS", "3")
    detector = AnomalyDetector(Manager())
    detector.handle_feature_vector(Vector())
    calibrator = detector.calibrators["production/nginx"]
    assert list(calibrator.scores) == []

    detector.model_manager.result["ensemble_score"] = .2
    detector.model_manager.result["lstm_score"] = .2
    detector.handle_feature_vector(Vector())
    assert list(calibrator.scores) == [.2]


def test_conditioned_normal_connect_mass_can_calibrate(tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .2,
                "lstm_score": .2,
                "if_score": .2,
                "behavior_limits": {"connect": .30, "clone": .30},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"connect": 20, "clone": 5, "read": 75}
        window_start = 0.0
        window_end = 30.0

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    monkeypatch.setenv("SENTINEL_WARMUP_WINDOWS", "3")
    detector = AnomalyDetector(Manager())
    detector.handle_feature_vector(Vector())
    assert list(detector.calibrators["default/postgres"].scores) == [.2]


def test_rfc3339_event_timestamp_parser():
    parsed = parse_event_time("2026-07-22T03:30:00.123456789Z")
    assert parsed == pytest.approx(1784691000.123456, abs=1e-6)


def test_windows_use_event_time_instead_of_processing_time():
    completed = []
    buffer = PodWindowBuffer(
        "nginx-hash-pod", "production", "worker", window_seconds=30,
        vocab={"read": 0}, on_window_complete=completed.append,
    )
    buffer.add_event("read", event_time=1000.0)
    buffer.add_event("read", event_time=1029.9)
    buffer.add_event("read", event_time=1030.0)
    assert len(completed) == 1
    assert completed[0].window_start == 1000.0
    assert completed[0].window_end == 1030.0
    assert completed[0].total_events() == 2


def test_tetragon_queue_capacity_and_health_are_observable(monkeypatch):
    monkeypatch.setenv("SENTINEL_QUEUE_SIZE", "12345")
    reader = TetragonKubectlReader()
    assert reader.health() == {
        "queue_size": 0,
        "queue_capacity": 12345,
        "backpressure_events": 0,
    }
