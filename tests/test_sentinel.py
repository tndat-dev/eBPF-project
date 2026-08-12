import json
import os
import time
from pathlib import Path
pytest = __import__("pytest")
np = pytest.importorskip("numpy")

import anomaly_detector2
from adaptive_threshold import (POTThreshold, StreamingThreshold,
                                load_calibrators, save_calibrators)
from graph_signals import (behavior_signals, evaluate_behavior,
                           fit_behavior_limits)
from anomaly_detector2 import (
    AnomalyDetector,
    feature_window_evidence,
    get_deployment_key,
)
from feature_engineering import PodWindowBuffer, parse_event_time
from tetragon_consumer import (PodInfo, ProcessInfo, SyscallEvent,
                               TetragonConsumer, TetragonKubectlReader)
from sentinel.telemetry import inject, detection_latency
from sentinel.fast_path import FastPathDetector


@pytest.fixture(autouse=True)
def isolate_test_telemetry(tmp_path, monkeypatch):
    """Never let unit-test inference rows enter the production JSONL file."""
    monkeypatch.setenv("SENTINEL_METRICS", str(tmp_path / "metrics.jsonl"))

def test_threshold_has_floor_and_ignores_small_sample():
    assert POTThreshold(minimum=.8).fit([.1, .2]) == .8
    assert .8 <= POTThreshold(minimum=.8).fit(np.linspace(.1, .3, 100)) <= .995


def test_feature_window_evidence_is_sparse_replayable_and_privacy_minimised():
    class Vector:
        pod_key = "production/service-pod"
        node_name = "worker-1"
        window_start = 10.0
        window_end = 20.0
        vector = np.array([0.0, 0.25, 0.0, 0.75], dtype=np.float32)
        syscall_counts = {"connect": 1, "execve": 3}
        raw_syscalls = ["execve", "execve", "connect", "execve"]

        def total_events(self):
            return len(self.raw_syscalls)

    aggregate = feature_window_evidence(Vector(), "aggregate")
    assert aggregate["schema"] == "sentinel-feature-window/v2"
    assert aggregate["sparse_vector"] == [[1, 0.25], [3, 0.75]]
    assert aggregate["syscall_counts"] == {"connect": 1, "execve": 3}
    assert aggregate["contains_arguments_or_payloads"] is False
    assert "syscall_sequence" not in aggregate

    sequence = feature_window_evidence(Vector(), "sequence")
    assert sequence["syscall_sequence"] == Vector.raw_syscalls
    with pytest.raises(ValueError, match="invalid feature capture mode"):
        feature_window_evidence(Vector(), "off")


def test_statefulset_workload_key_resolves_stable_ordinal():
    assert get_deployment_key("production/aims-postgres-0") == "production/aims-postgres"


@pytest.mark.parametrize("replicaset_hash", ["56956b54", "7b596c5bff"])
def test_deployment_key_accepts_observed_replicaset_hash_lengths(replicaset_hash):
    pod = f"production/aims-frontend-{replicaset_hash}-abcde"
    assert get_deployment_key(pod) == "production/aims-frontend"


def test_deployment_key_does_not_strip_ambiguous_short_suffix():
    pod = "production/audit-worker-short-abcde"
    assert get_deployment_key(pod) == pod


def test_consumer_filter_runs_before_window_callback(monkeypatch):
    event = SyscallEvent(
        event_type="process_exec", syscall_name="execve",
        pod=PodInfo(name="unmodelled-0000000000-abcde", namespace="production"),
        process=ProcessInfo(1, 0, "/bin/sh", "", "", ""),
        timestamp="2026-01-01T00:00:00Z", node_name="worker",
    )

    class Reader:
        def stream(self):
            yield "event"

    consumer = TetragonConsumer(mode="file", event_filter=lambda _: False)
    consumer.reader = Reader()
    monkeypatch.setattr(consumer.parser, "parse_line", lambda _: event)
    received = []
    consumer.run(received.append)
    assert received == []


def test_fast_path_requires_ordered_high_specificity_sequence():
    from types import SimpleNamespace

    warnings = []
    detector = FastPathDetector(
        lambda key: "production/nginx" if key.startswith("production/nginx") else None,
        sequence_seconds=2, cooldown_seconds=60, on_warning=warnings.append,
    )
    def event(syscall, timestamp):
        return SimpleNamespace(
            syscall_name=syscall, timestamp=timestamp,
            pod=SimpleNamespace(namespace="production", name="nginx-1234567890-abcde"),
        )

    assert detector.handle_event(event("connect", "2026-01-01T00:00:00Z")) is None
    assert detector.handle_event(event("execve", "2026-01-01T00:00:01Z")) is None
    warning = detector.handle_event(event("unshare", "2026-01-01T00:00:02Z"))
    assert warning is not None
    assert warning.rule == "exec_to_privilege_transition"
    assert warning.sequence_seconds == pytest.approx(1.0)
    assert len(warnings) == 1
    assert detector.recent_warning(warning.pod_key, now=warning.detected_ts + 1)
    row = json.loads(Path(os.environ["SENTINEL_METRICS"]).read_text())
    assert row["kind"] == "early_warning"
    assert row["processing_ms"] >= 0
    assert row["event_to_warning_seconds"] >= 0


def test_fast_path_restricts_exec_to_network_to_shell_or_network_binary():
    from types import SimpleNamespace

    detector = FastPathDetector(lambda _: "production/nginx")
    def event(syscall, binary):
        return SimpleNamespace(
            syscall_name=syscall, timestamp="2026-01-01T00:00:00Z",
            pod=SimpleNamespace(namespace="production", name="nginx-1234567890-abcde"),
            process=SimpleNamespace(binary=binary),
        )

    assert detector.handle_event(event("execve", "/usr/sbin/nginx")) is None
    assert detector.handle_event(event("connect", "/usr/sbin/nginx")) is None
    assert detector.handle_event(event("execve", "/bin/sh")) is None
    assert detector.handle_event(event("connect", "/bin/sh")) is not None


def test_fast_path_expires_sequence_and_suppresses_duplicate_rule():
    from types import SimpleNamespace

    detector = FastPathDetector(lambda _: "production/redis", sequence_seconds=1,
                                cooldown_seconds=60)
    def event(syscall, second):
        return SimpleNamespace(
            syscall_name=syscall, timestamp=f"2026-01-01T00:00:{second:02d}Z",
            pod=SimpleNamespace(namespace="production", name="redis-1234567890-abcde"),
        )

    assert detector.handle_event(event("execve", 0)) is None
    assert detector.handle_event(event("connect", 3)) is None
    assert detector.handle_event(event("execve", 4)) is None
    assert detector.handle_event(event("unshare", 5)) is not None
    assert detector.handle_event(event("unshare", 5)) is None


def test_fast_path_consumes_benign_daemon_group_drop_before_setuid():
    """Nginx-style exec -> setgid -> setuid startup must not warn."""
    from types import SimpleNamespace

    detector = FastPathDetector(lambda _: "production/nginx", sequence_seconds=2)

    def event(syscall, second):
        return SimpleNamespace(
            syscall_name=syscall,
            timestamp=f"2026-01-01T00:00:{second:02d}Z",
            pod=SimpleNamespace(namespace="production", name="nginx-1234567890-abcde"),
        )

    assert detector.handle_event(event("execve", 0)) is None
    assert detector.handle_event(event("setgid", 1)) is None
    assert detector.handle_event(event("setuid", 2)) is None
    assert detector.handle_event(event("execve", 3)) is None
    assert detector.handle_event(event("setuid", 4)) is not None

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
    assert normal["method"] == "workload-conditioned-wilson"
    assert not normal["gate"]
    assert attack["gate"] and attack["syscall"] == "connect"


def test_behavior_gate_accounts_for_low_event_sampling_uncertainty():
    low_count = evaluate_behavior({"connect": 2, "read": 12}, 14, {"connect": .12})
    sustained = evaluate_behavior({"connect": 20, "read": 80}, 100, {"connect": .12})
    assert low_count["frequency"] > low_count["limit"]
    assert low_count["confidence_lower"] < low_count["limit"]
    assert low_count["gate"] is False
    assert sustained["confidence_lower"] > sustained["limit"]
    assert sustained["gate"] is True

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


def test_calibration_restore_matches_incremental_final_threshold(tmp_path):
    threshold = StreamingThreshold(minimum=.8, warmup=10)
    for score in [0.10 + index / 1000 for index in range(120)]:
        threshold.observe(score, 100 + int(score * 10))
    expected = threshold.current
    path = tmp_path / "calibration.json"
    save_calibrators(path, {"production/nginx": threshold})
    loaded = load_calibrators(path, minimum=.8, warmup=10)
    assert loaded["production/nginx"].current == pytest.approx(expected)


def test_replay_can_update_calibration_without_persisting_each_window(
        tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["production/nginx"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .2, "lstm_score": .2, "if_score": .2,
                "behavior_limits": {},
            }

    class Vector:
        pod_key = "production/nginx-56956b54-abcde"
        pod_name = "nginx-56956b54-abcde"
        pod_namespace = "production"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"read": 100}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 100

    calibration = tmp_path / "calibration.json"
    monkeypatch.setenv("SENTINEL_CALIBRATION", str(calibration))
    writes = []
    monkeypatch.setattr(
        anomaly_detector2, "save_calibrators",
        lambda *_args, **_kwargs: writes.append(True),
    )
    detector = AnomalyDetector(
        Manager(), persist_calibration=False,
        pod_started_at_lookup=lambda _pod: None,
    )
    detector.handle_feature_vector(Vector())

    assert list(detector.calibrators["production/nginx"].scores) == [.2]
    assert writes == []
    assert not calibration.exists()


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


def test_event_guard_has_conservative_clean_upper_volume_bound():
    threshold = StreamingThreshold(minimum=.8, warmup=10)
    for count in [100] * 9 + [150]:
        threshold.observe(.2, count)
    assert 290 <= threshold.maximum_event_count <= 300


def test_extreme_volume_ml_requires_two_persistent_high_score_windows(
        tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .95,
                "lstm_score": .95,
                "if_score": 1.0,
                # Cryptomining preserves this learned syscall proportion.
                "behavior_limits": {"clone": .188},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"clone": 160, "read": 840}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return sum(self.syscall_counts.values())

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    monkeypatch.setenv("SENTINEL_WARMUP_WINDOWS", "10")
    monkeypatch.setenv("SENTINEL_EXTREME_VOLUME_FACTOR", "2.0")
    alerts = []
    detector = AnomalyDetector(Manager(), on_alert=alerts.append, threshold=.8)
    calibrator = detector.calibrators["default/postgres"]
    for count in range(100, 150, 5):
        calibrator.observe(.2, count)

    detector.handle_feature_vector(Vector())
    assert alerts == []
    detector.handle_feature_vector(Vector())
    assert len(alerts) == 1
    rows = [
        json.loads(line) for line in
        Path(os.environ["SENTINEL_METRICS"]).read_text().splitlines()
    ]
    detection = next(row for row in rows if row["kind"] == "detection")
    assert detection["confirmation_path"] == "extreme_volume_ml"
    assert detection["behavior_gate"] is False
    assert detection["extreme_volume"] is True
    assert detection["event_count"] == 1000
    assert detection["learned_maximum_events"] < 1000


def test_high_ml_score_without_extreme_volume_remains_behavior_gated(
        tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .95, "lstm_score": .95, "if_score": 1.0,
                "behavior_limits": {"clone": .188},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"clone": 32, "read": 168}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 200

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    detector = AnomalyDetector(Manager(), on_alert=lambda alert: pytest.fail(
        f"unexpected alert: {alert}"
    ))
    calibrator = detector.calibrators["default/postgres"]
    for count in range(100, 150, 5):
        calibrator.observe(.2, count)
    detector.handle_feature_vector(Vector())
    detector.handle_feature_vector(Vector())
    assert detector._volume_consecutive[Vector.pod_key] == 0


def test_research_ablation_can_remove_behavior_requirement_without_changing_default(
        tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .95, "lstm_score": .95, "if_score": .4,
                "behavior_limits": {},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"read": 100}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    alerts = []
    detector = AnomalyDetector(
        Manager(), on_alert=alerts.append, threshold=.8,
        require_behavior_gate=False,
    )
    detector.handle_feature_vector(Vector())
    assert alerts == []
    detector.handle_feature_vector(Vector())
    assert len(alerts) == 1
    rows = [
        json.loads(line) for line in
        Path(os.environ["SENTINEL_METRICS"]).read_text().splitlines()
    ]
    inference = next(row for row in rows if row["kind"] == "inference")
    assert inference["observed_behavior_gate"] is False
    assert inference["behavior_gate_required"] is False


def test_research_ablation_can_disable_extreme_volume_route(
        tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .95, "lstm_score": .95, "if_score": .4,
                "behavior_limits": {},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"read": 1000}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 1000

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    alerts = []
    detector = AnomalyDetector(
        Manager(), on_alert=alerts.append, threshold=.8,
        enable_extreme_volume_gate=False,
    )
    calibrator = detector.calibrators["default/postgres"]
    for count in range(100, 150, 5):
        calibrator.observe(.2, count)
    detector.handle_feature_vector(Vector())
    detector.handle_feature_vector(Vector())
    assert alerts == []


def test_research_ablation_can_use_one_window_confirmation(
        tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .95, "lstm_score": .95, "if_score": .4,
                "behavior_limits": {"unshare": .1},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"unshare": 90, "read": 10}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    alerts = []
    detector = AnomalyDetector(
        Manager(), on_alert=alerts.append, threshold=.8,
        confirmation_windows=1,
    )
    detector.handle_feature_vector(Vector())
    assert len(alerts) == 1

    with pytest.raises(ValueError, match="confirmation_windows"):
        AnomalyDetector(Manager(), confirmation_windows=3)


def test_fixed_threshold_baseline_does_not_learn_online_calibration(
        tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .2, "lstm_score": .2, "if_score": .2,
                "behavior_limits": {},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"read": 100}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    detector = AnomalyDetector(
        Manager(), enable_adaptive_threshold=False,
        persist_calibration=False,
    )
    detector.handle_feature_vector(Vector())
    calibrator = detector.calibrators["default/postgres"]
    assert list(calibrator.scores) == []
    assert not (tmp_path / "calibration.json").exists()


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


def test_behavior_corroborated_confirmation_floor_keeps_initial_threshold(tmp_path, monkeypatch):
    class Manager:
        def __init__(self):
            self.scores = iter([.801, .759])

        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            score = next(self.scores)
            return {
                "ensemble_score": score,
                "lstm_score": score,
                "if_score": 1.0,
                "behavior_limits": {"connect": .10},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"connect": 90, "read": 10}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    alerts = []
    detector = AnomalyDetector(
        Manager(), on_alert=alerts.append, threshold=.8,
        confirmation_floor_ratio=.94,
    )
    detector.handle_feature_vector(Vector())
    detector.handle_feature_vector(Vector())
    assert len(alerts) == 1
    rows = [json.loads(line) for line in Path(os.environ["SENTINEL_METRICS"]).read_text().splitlines()]
    detection = next(row for row in rows if row["kind"] == "detection")
    assert detection["confirmation_floor"] == pytest.approx(.752)
    assert detection["confirmation_path"] == "hysteresis_ml"


def test_confirmation_floor_cannot_start_an_alert(tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .759,
                "lstm_score": .759,
                "if_score": 1.0,
                "behavior_limits": {"connect": .10},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"connect": 90, "read": 10}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    alerts = []
    detector = AnomalyDetector(
        Manager(), on_alert=alerts.append, threshold=.8,
        confirmation_floor_ratio=.94,
    )
    detector.handle_feature_vector(Vector())
    detector.handle_feature_vector(Vector())
    assert alerts == []


def test_fast_path_behavior_ml_floor_is_candidate_opt_in(tmp_path, monkeypatch):
    class Manager:
        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .25,
                "lstm_score": .25,
                "if_score": 1.0,
                "behavior_limits": {"unshare": .10},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"unshare": 90, "read": 10}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    alerts = []
    detector = AnomalyDetector(
        Manager(), on_alert=alerts.append, threshold=.8,
        early_warning_lookup=lambda _: {"rule": "exec_to_privilege_transition"},
    )
    detector.handle_feature_vector(Vector())
    assert alerts == []  # Default floor is threshold: V1 behavior is unchanged.

    monkeypatch.setenv("SENTINEL_FAST_PATH_CONFIRMATION_FLOOR", ".20")
    detector = AnomalyDetector(
        Manager(), on_alert=alerts.append, threshold=.8,
        early_warning_lookup=lambda _: {"rule": "exec_to_privilege_transition"},
        confirmation_floor_ratio=.94,
    )
    detector.handle_feature_vector(Vector())
    assert len(alerts) == 1
    rows = [json.loads(line) for line in Path(os.environ["SENTINEL_METRICS"]).read_text().splitlines()]
    assert next(row for row in rows if row["kind"] == "detection")["confirmation_path"] == "fast_path_behavior_ml_floor"


def test_pod_startup_grace_suppresses_only_lifecycle_confirmation(tmp_path, monkeypatch):
    """A new pod's entrypoint burst cannot trigger candidate fusion."""
    class Manager:
        def list_models(self):
            return ["production/nginx"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": 1.0,
                "lstm_score": 1.0,
                "if_score": 1.0,
                "behavior_limits": {"unshare": .10},
            }

    class Vector:
        pod_key = "production/nginx-56fcf95486-abcde"
        pod_name = "nginx-56fcf95486-abcde"
        pod_namespace = "production"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"unshare": 90, "read": 10}
        window_start = time.time()
        window_end = window_start + 10

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    monkeypatch.setenv("SENTINEL_POD_STARTUP_GRACE_SECONDS", "60")
    monkeypatch.setenv("SENTINEL_FAST_PATH_CONFIRMATION_FLOOR", ".20")
    alerts = []
    vector = Vector()
    detector = AnomalyDetector(
        Manager(), on_alert=alerts.append, threshold=.8,
        early_warning_lookup=lambda _: {"rule": "exec_to_privilege_transition"},
        pod_started_at_lookup=lambda _: vector.window_start,
    )
    detector.handle_feature_vector(vector)
    assert alerts == []
    rows = [json.loads(line) for line in Path(os.environ["SENTINEL_METRICS"]).read_text().splitlines()]
    assert rows[-1]["decision"] == "pod_startup_grace"

    vector.window_start += 61
    vector.window_end += 61
    detector.handle_feature_vector(vector)
    assert len(alerts) == 1


def test_behavior_persistence_ml_floor_requires_two_windows(tmp_path, monkeypatch):
    class Manager:
        def __init__(self):
            self.scores = iter([.475, .496])

        def list_models(self):
            return ["default/postgres"]

        def score(self, _key, _vector):
            score = next(self.scores)
            return {
                "ensemble_score": score,
                "lstm_score": score,
                "if_score": 1.0,
                "behavior_limits": {"connect": .10},
            }

    class Vector:
        pod_key = "default/postgres-5cd4775869-abcde"
        pod_name = "postgres-5cd4775869-abcde"
        pod_namespace = "default"
        node_name = "worker"
        vector = np.zeros(1)
        syscall_counts = {"connect": 90, "read": 10}
        window_start = 0.0
        window_end = time.time()

        def total_events(self):
            return 100

    monkeypatch.setenv("SENTINEL_CALIBRATION", str(tmp_path / "calibration.json"))
    monkeypatch.setenv("SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR", ".45")
    alerts = []
    detector = AnomalyDetector(Manager(), on_alert=alerts.append, threshold=.8)
    detector.handle_feature_vector(Vector())
    assert alerts == []
    detector.handle_feature_vector(Vector())
    assert len(alerts) == 1
    rows = [json.loads(line) for line in Path(os.environ["SENTINEL_METRICS"]).read_text().splitlines()]
    assert next(row for row in rows if row["kind"] == "detection")["confirmation_path"] == "behavior_persistence_ml_floor"


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
        "membership_refreshes": 0,
        "membership_failures": 0,
        "coverage_failures": 0,
        "stream_failures": 0,
        "stream_failure_details": [],
        "stale_streams_removed": 0,
        "active_tetragon_pods": [],
        "ready_tetragon_pods": [],
        "expected_tetragon_pods": None,
        "require_full_coverage": False,
        "coverage_healthy": True,
    }


def test_tetragon_stream_failure_details_are_bounded_and_attributed():
    reader = TetragonKubectlReader()
    for index in range(105):
        reader._record_stream_failure(
            "tetragon-a", "kubectl_exec_exit", returncode=index,
        )
    health = reader.health()
    assert health["stream_failures"] == 105
    assert len(health["stream_failure_details"]) == 100
    assert health["stream_failure_details"][0]["returncode"] == 5
    assert health["stream_failure_details"][-1]["pod"] == "tetragon-a"
