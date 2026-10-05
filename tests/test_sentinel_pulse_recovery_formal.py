import copy
import json
from pathlib import Path
import subprocess

import pytest

from sentinel_pulse.detector_freshness import CONTRACT, CONTRACT_SHA256
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.recovery_deployment import contract
from sentinel_pulse.recovery_formal import (
    SCHEMA, NODE_SCHEMA, add_interval, aggregate, check_resume, evaluate_node,
    health_exclusions, register, validate_marker, write_new,
    supervision_step, COLLECTOR_TIMING, validate_collector_timing,
)
from sentinel_pulse.telemetry_recovery import HARD_COUNTERS, SNAPSHOT_SCHEMA, digest, load_profile
from sentinel_pulse.operational_soak import observe
from test_sentinel_pulse_operational_soak import binding
from test_sentinel_pulse_telemetry_recovery import PROFILE, make_capture, fake_runtime


def marker_fixture():
    b = binding()
    b["expected_workloads"] = ["production/test:app"]
    b["minimum_ready_pods"] = {"production/test": 1}
    b["ready_pods_at_registration"] = {"production/test": 1}
    b["worker_nodes"] = ["w1", "node", "w3"]
    files = {"sentinel_pulse/test.py": "d" * 64}
    return {"schema": SCHEMA, "run_id": "new", "source_commit": "c" * 40,
            "collector_timing_contract": dict(COLLECTOR_TIMING),
            "source_files": files, "source_files_sha256": digest(files),
            "model_manifest_sha256": "a" * 64, "decision_policy_sha256": "b" * 64,
            "started_at_unix": 99, "collector_duration_seconds": 89880, "diagnostic_only": False,
            "telemetry_recovery_contract": contract(PROFILE, .5, .999, 30),
            "detector_freshness_contract": CONTRACT, "detector_freshness_contract_sha256": CONTRACT_SHA256,
            "operational_evaluation_contract": b,
            "workers": {ip: {"node_name": name, "expected_workloads": ["production/test:app"],
                              "loader_sha256": "e" * 64, "bpf_object_sha256": "f" * 64}
                        for ip, name in zip(["10.1.16.237", "10.1.16.238", "10.1.16.239"], b["worker_nodes"])},
            "automatic_promotion": False, "automatic_blind_evaluation": False}


@pytest.mark.parametrize("mutation", ["legacy", "blind", "short", "long", "bool_duration", "availability", "source", "worker", "freshness"])
def test_formal_registration_fail_closed(mutation):
    m = copy.deepcopy(marker_fixture())
    if mutation == "legacy":
        m["schema"] = "sentinel-pulse-semantic-soak-start-v1"
    elif mutation == "blind":
        m["automatic_blind_evaluation"] = True
    elif mutation in {"short", "long", "bool_duration"}:
        m["collector_duration_seconds"] = {"short": 600, "long": 90001, "bool_duration": True}[mutation]
    elif mutation == "availability":
        m["telemetry_recovery_contract"]["profile"]["minimum_telemetry_availability"] = .99
    elif mutation == "source":
        m["source_files"]["sentinel_pulse/test.py"] = "0" * 64
    elif mutation == "worker":
        m["workers"]["10.1.16.238"]["node_name"] = "w1"
    else:
        m["detector_freshness_contract_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        validate_marker(m)


@pytest.mark.parametrize("name", ["source_commit", "model_manifest_sha256", "decision_policy_sha256", "diagnostic_only"])
def test_resume_cannot_change_bound_identity_or_protocol(name):
    m = marker_fixture()
    changed = copy.deepcopy(m)
    changed[name] = ("0" * len(m[name])) if isinstance(m[name], str) else True
    with pytest.raises(ValueError):
        check_resume(m, changed)
    check_resume(m, {**m, "started_at_unix": 100})
    with pytest.raises(ValueError, match="terminal"):
        check_resume(m, m, terminal=True)


def test_registration_refuses_dirty_source_and_writes_exclusive_marker(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "sentinel_pulse").mkdir(parents=True)
    (source / "sentinel_pulse/test.py").write_text("# unit test source\n")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "sentinel_pulse/test.py"], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "test"], check=True)
    model = tmp_path / "model"
    model.mkdir()
    (model / "manifest.json").write_text("{}")
    policy = tmp_path / "policy.json"
    policy.write_text("{}")
    monkeypatch.setattr("sentinel_pulse.finalize_candidate.verify_model_bundle", lambda _: ({}, ["production/test:app"], []))
    monkeypatch.setattr("sentinel_pulse.decision_policy.load_decision_policy", lambda _: ({}, "b" * 64))
    m = marker_fixture()
    result = register("new", source, model, policy, PROFILE, m["operational_evaluation_contract"], m["workers"], 89880, now=99)
    assert result["source_files"]["sentinel_pulse/test.py"] == sha256_file(source / "sentinel_pulse/test.py")
    output = tmp_path / "marker.json"
    write_new(output, result)
    with pytest.raises(FileExistsError):
        write_new(output, result)
    (source / "sentinel_pulse/test.py").write_text("# changed\n")
    with pytest.raises(ValueError, match="clean Git"):
        register("new", source, model, policy, PROFILE, m["operational_evaluation_contract"], m["workers"], 89880)


def test_interval_union_handles_replica_overlap_out_of_order_without_row_storage():
    intervals = []
    for start, end in [(10, 11), (11, 12), (10.5, 11.5), (8, 9), (8.5, 10.5), (20, 21)]:
        add_interval(intervals, start, end)
    assert intervals == [[8, 12], [20, 21]]
    for i in range(10000):
        add_interval(intervals, 100 + i * .5, 100.5 + i * .5)
    assert len(intervals) == 3


def make_node_fixture(tmp_path, monkeypatch, snapshots=40, duration=600):
    root = tmp_path / "new"
    root.mkdir()
    profile = load_profile(PROFILE)
    path, rows = make_capture(root, monkeypatch, profile, [100 + i * .5 for i in range(snapshots)])
    path.rename(root / "features.jsonl")
    (root / "telemetry-recovery-profile.json").write_bytes(PROFILE.read_bytes())
    (root / "DETECTOR_FRESHNESS_CONTRACT.json").write_text(json.dumps(CONTRACT))
    m = marker_fixture()
    m["diagnostic_only"], m["collector_duration_seconds"] = True, duration
    manifest = {"workloads": {"production/test:app": {"alpha": .001}}, "history_windows": 3,
                "max_contiguous_gap_seconds": 1.25, "approved_workload_revisions": {"production/test:app": ["revision-a"]}}
    model = tmp_path / "manifest.json"
    model.write_text(json.dumps(manifest))
    m["model_manifest_sha256"] = sha256_file(model)
    marker_path = tmp_path / "START.json"
    marker_path.write_text(json.dumps(m))
    (root / "FORMAL_WORKER_START.json").write_text(json.dumps({
        "schema": "sentinel-pulse-recovery-formal-worker-start-v1", "worker_ip": "10.1.16.238",
        "marker_sha256": sha256_file(marker_path), "source_commit": m["source_commit"],
        "source_files_sha256": m["source_files_sha256"], "attested_at_unix": 99.5}))
    (root / "START.json").write_text(json.dumps({"started_at_unix": 99.9, "collector_variant": "projected",
        "sha256": {"loader": "e" * 64, "bpf_object": "f" * 64},
        "telemetry_recovery_contract": m["telemetry_recovery_contract"],
        "telemetry_availability_contract": {"nominal_interval_seconds": .5, "minimum_availability": .999, "maximum_single_gap_seconds": 30}}))
    (root / "COLLECTOR_RUNTIME_START.json").write_text(json.dumps(timing_fixture(root, marker_path)))
    runtime = fake_runtime(profile)
    runtime.model_manifest_sha256, runtime.decision_policy_sha256 = m["model_manifest_sha256"], m["decision_policy_sha256"]
    runtime.live_freshness, runtime.last_processing_check = True, None
    clock = [100]
    monkeypatch.setattr("sentinel_pulse.detect.time.time", lambda: clock[0])
    decisions = []
    for row in rows:
        if row["schema"] == SNAPSHOT_SCHEMA:
            runtime.observe_recovery_snapshot(row)
        elif row["schema"] == "sentinel-pulse-feature-v1":
            clock[0] = row["window_end"] + .02
            result = runtime.score(row)
            result.update(run_id="new", telemetry_recovery=row["telemetry_recovery"])
            decisions.append(result)
    (root / "decisions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in decisions))
    (root / "alerts.jsonl").touch()
    (root / "collector-before-stop.systemd").write_text("ActiveState=inactive\nResult=success\nExecMainStatus=0\n")
    (root / "detector-before-stop.systemd").write_text("ActiveState=active\nResult=success\nExecMainStatus=0\nNRestarts=0\n")
    health_path = tmp_path / "health.jsonl"
    h = observe(m["operational_evaluation_contract"], [], {"fatal": [], "transient": [], "warnings": []}, 120, 99)
    health_path.write_text(json.dumps(h) + "\n")
    return root, marker_path, model, health_path


def timing_fixture(root, marker_path, actual=99.9):
    return {"schema": "sentinel-pulse-collector-runtime-start-v1", "run_id": "new",
            "worker_ip": "10.1.16.238", "unit": "sentinel-pulse-collector-500ms-experiment.service",
            "marker_sha256": sha256_file(marker_path), "collector_registration_sha256": sha256_file(root / "START.json"),
            "invocation_id": "1" * 32, "main_pid": 42, "active_state_at_observation": "active",
            "exec_start_monotonic_usec": 40000000,
            "clock_pair": {"monotonic_before": 50., "monotonic_after": 50., "realtime": actual + 10},
            "exec_started_at_unix": actual}


@pytest.mark.parametrize("mutation", [None, "missing", "marker", "registration", "replayed_time", "late", "pair", "bool_clock", "inactive", "bool_pid"])
def test_actual_collector_timing_is_checksum_bound_and_replayed(tmp_path, monkeypatch, mutation):
    root, marker, _model, _health = make_node_fixture(tmp_path, monkeypatch)
    path = root / "COLLECTOR_RUNTIME_START.json"
    receipt = json.loads(path.read_text())
    if mutation == "missing":
        path.unlink()
    elif mutation == "marker":
        receipt["marker_sha256"] = "0" * 64
    elif mutation == "registration":
        receipt["collector_registration_sha256"] = "0" * 64
    elif mutation == "replayed_time":
        receipt["exec_started_at_unix"] += 3
    elif mutation == "late":
        receipt = timing_fixture(root, marker, actual=220)
    elif mutation == "pair":
        receipt["clock_pair"]["monotonic_after"] += .1
    elif mutation == "bool_clock":
        receipt["exec_start_monotonic_usec"] = True
    elif mutation == "inactive":
        receipt["active_state_at_observation"] = "inactive"
    elif mutation == "bool_pid":
        receipt["main_pid"] = True
    if mutation != "missing":
        path.write_text(json.dumps(receipt))
    if mutation is None:
        assert validate_collector_timing(root, marker, "10.1.16.238") == pytest.approx(99.9)
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            validate_collector_timing(root, marker, "10.1.16.238")


def test_setup_receipt_cannot_shorten_actual_registered_capture_duration(tmp_path, monkeypatch):
    root, marker, model, health = make_node_fixture(tmp_path, monkeypatch, snapshots=361, duration=180)
    registration = json.loads(marker.read_text())
    registration["started_at_unix"] = 95
    marker.write_text(json.dumps(registration))
    setup = json.loads((root / "START.json").read_text())
    setup["started_at_unix"] = 96
    (root / "START.json").write_text(json.dumps(setup))
    attestation = json.loads((root / "FORMAL_WORKER_START.json").read_text())
    attestation.update(marker_sha256=sha256_file(marker), attested_at_unix=95.5)
    (root / "FORMAL_WORKER_START.json").write_text(json.dumps(attestation))
    (root / "COLLECTOR_RUNTIME_START.json").write_text(json.dumps(timing_fixture(root, marker)))
    # 3.9s of pre-execution setup is not part of the timeout's180s. The old
    # setup-anchored upper bound277s would reject this complete280s endpoint.
    result = evaluate_node(root, marker, "10.1.16.238", model, health)
    assert result["valid"] and not result["formal_recovery_pass"]


def test_actual_runtime_anchor_does_not_allow_preexecution_feature_rows(tmp_path, monkeypatch):
    root, marker, model, health = make_node_fixture(tmp_path, monkeypatch)
    (root / "COLLECTOR_RUNTIME_START.json").write_text(json.dumps(timing_fixture(root, marker, actual=104)))
    with pytest.raises(ValueError, match="outside registered capture interval"):
        evaluate_node(root, marker, "10.1.16.238", model, health)


def test_streaming_node_excludes_warming_and_refuses_legacy_pass(tmp_path, monkeypatch):
    root, marker, model, health = make_node_fixture(tmp_path, monkeypatch)
    report = evaluate_node(root, marker, "10.1.16.238", model, health)
    # This synthetic 20s trace MUST NOT pass its registered 600s duration,
    # even though the fake service receipt says it exited cleanly.
    assert not report["valid"]
    assert report["errors"] == ["capture did not complete registered duration"]
    assert report["statuses"]["warming"] > 0
    assert report["valid_scored_intervals"]["production/test:app"] == [[106.5, 119.5]]
    assert not report["formal_recovery_pass"] and not report["legacy_normal_pass"]


@pytest.mark.parametrize("mutation", [None, "missing_attestation", "marker_hash", "unknown_worker",
                                     "late_attestation", "boolean_attestation", "loader_hash",
                                     "profile_bytes", "run_identity", "ambiguous"])
def test_formal_freshness_installer_requires_attested_capture(tmp_path, monkeypatch, mutation):
    from sentinel_pulse.recovery_deployment import bind_freshness_preregistration
    root, marker_path, _model, _health = make_node_fixture(tmp_path, monkeypatch)
    formal = tmp_path / "formal" / "new"
    formal.mkdir(parents=True)
    formal_marker = formal / "START.json"
    formal_marker.write_bytes(marker_path.read_bytes())
    smoke = tmp_path / "smoke"
    attestation_path = root / "FORMAL_WORKER_START.json"
    attestation = json.loads(attestation_path.read_text())
    if mutation == "missing_attestation":
        attestation_path.unlink()
    elif mutation == "marker_hash":
        attestation["marker_sha256"] = "0" * 64
    elif mutation == "unknown_worker":
        attestation["worker_ip"] = "10.1.16.234"
    elif mutation == "late_attestation":
        attestation["attested_at_unix"] = 100
    elif mutation == "boolean_attestation":
        attestation["attested_at_unix"] = True
    elif mutation == "loader_hash":
        start = json.loads((root / "START.json").read_text())
        start["sha256"]["loader"] = "0" * 64
        (root / "START.json").write_text(json.dumps(start))
    elif mutation == "profile_bytes":
        profile = root / "telemetry-recovery-profile.json"
        profile.write_text(profile.read_text() + " ")
    elif mutation == "run_identity":
        marker = json.loads(formal_marker.read_text())
        marker["run_id"] = "another-run"
        formal_marker.write_text(json.dumps(marker))
    elif mutation == "ambiguous":
        (smoke / "new").mkdir(parents=True)
        (smoke / "new" / "START.json").write_bytes(formal_marker.read_bytes())
    if mutation not in {None, "missing_attestation"}:
        attestation_path.write_text(json.dumps(attestation))
    feature = root / "features.jsonl"
    if mutation is None:
        assert bind_freshness_preregistration(feature, smoke, formal.parent) == CONTRACT
    else:
        with pytest.raises((ValueError, KeyError, FileNotFoundError)):
            bind_freshness_preregistration(feature, smoke, formal.parent)


@pytest.mark.parametrize("mutation", ["missing_attestation", "late_attestation", "missing_decision", "extra_decision", "revision", "stale_score", "warming_score"])
def test_node_terminal_integrity_failures(tmp_path, monkeypatch, mutation):
    root, marker, model, health = make_node_fixture(tmp_path, monkeypatch)
    if mutation == "missing_attestation":
        (root / "FORMAL_WORKER_START.json").write_text("{}")
    elif mutation == "late_attestation":
        r = json.loads((root / "FORMAL_WORKER_START.json").read_text())
        r["attested_at_unix"] = 110
        (root / "FORMAL_WORKER_START.json").write_text(json.dumps(r))
    else:
        rows = [json.loads(l) for l in (root / "decisions.jsonl").read_text().splitlines()]
        if mutation == "missing_decision":
            rows.pop()
        elif mutation == "extra_decision":
            rows.append(rows[-1])
        elif mutation == "revision":
            rows[-1]["workload_revision"] = "new-version"
        elif mutation == "stale_score":
            last = rows[-1]
            feature = {"window_end": last["window_end"], "emitted_at": last["window_end"] + .001}
            from sentinel_pulse.detector_freshness import check, complete
            last["detector_freshness"] = complete(check(feature, last["window_end"] + 2), last["window_end"], last["window_end"] + 2)
        else:
            rows[-1]["status"] = "warming"
        (root / "decisions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises((ValueError, KeyError)):
        evaluate_node(root, marker, "10.1.16.238", model, health)


def test_every_alert_retained_even_when_health_degraded(tmp_path, monkeypatch):
    root, marker_path, model, health = make_node_fixture(tmp_path, monkeypatch)
    marker = json.loads(marker_path.read_text())
    b = marker["operational_evaluation_contract"]
    bad = observe(b, [], {"fatal": [], "transient": [{"reason": "unit-test"}], "warnings": []}, 108, 99)
    recovered = observe(b, [bad], {"fatal": [], "transient": [], "warnings": []}, 120, 99)
    health.write_text(json.dumps(bad) + "\n" + json.dumps(recovered) + "\n")
    rows = [json.loads(l) for l in (root / "decisions.jsonl").read_text().splitlines()]
    rows[-1]["status"] = "alert"
    (root / "decisions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (root / "alerts.jsonl").write_text(json.dumps(rows[-1]) + "\n")
    report = evaluate_node(root, marker_path, "10.1.16.238", model, health)
    assert report["all_alerts"] == {"production/test:app": 1}
    assert report["alerts_during_health_degraded"] == {"production/test:app": 1}
    assert not report["valid_scored_intervals"]


def make_reports(tmp_path, diagnostic=False, hours=24):
    marker = marker_fixture()
    keys = ["production/test:" + name for name in ("app", "sidecar", "aux", "consumer", "proxy")]
    marker["operational_evaluation_contract"]["expected_workloads"] = keys
    for worker in marker["workers"].values():
        worker["expected_workloads"] = keys
    marker["diagnostic_only"] = diagnostic
    if diagnostic:
        marker["collector_duration_seconds"] = 600
    path = tmp_path / "marker.json"
    path.write_text(json.dumps(marker))
    paths = []
    for ip in sorted(marker["workers"]):
        report = {"schema": NODE_SCHEMA, "run_id": "new", "worker_ip": ip,
            "marker_sha256": sha256_file(path), "source_files_sha256": marker["source_files_sha256"],
            "model_manifest_sha256": marker["model_manifest_sha256"], "decision_policy_sha256": marker["decision_policy_sha256"],
            "telemetry_profile_sha256": marker["telemetry_recovery_contract"]["profile_sha256"],
            "detector_freshness_contract_sha256": CONTRACT_SHA256, "health_log_sha256": "9" * 64,
            "valid": True, "errors": [], "capture": {"valid": True, "availability": 1,
                "profile_sha256": marker["telemetry_recovery_contract"]["profile_sha256"],
                "hard_integrity_counters": {k: 0 for k in HARD_COUNTERS}}, "all_alerts": {},
            "valid_scored_intervals": {k: [[110, 110 + hours * 3600]] for k in keys}}
        p = tmp_path / (ip + ".json")
        p.write_text(json.dumps(report))
        paths.append(p)
    return path, paths


def test_fleet_union_is_24_not_72_hours_per_key(tmp_path):
    marker, paths = make_reports(tmp_path)
    report = aggregate(marker, paths)
    assert report["formal_recovery_pass"]
    assert all(w["valid_scored_hours"] == 24 for w in report["workloads"].values())
    assert report["total_valid_workload_hours"] == 120
    assert not report["legacy_normal_pass"] and not report["automatic_blind_evaluation"]


@pytest.mark.parametrize("mutation", ["duplicate", "profile", "health", "telemetry", "short", "too_many_alerts"])
def test_fleet_refuses_invalid_evidence_or_exposure(tmp_path, mutation):
    marker, paths = make_reports(tmp_path, hours=23.9 if mutation == "short" else 24)
    if mutation == "duplicate":
        with pytest.raises(ValueError):
            aggregate(marker, [paths[0], paths[0], paths[2]])
        return
    r = json.loads(paths[0].read_text())
    if mutation == "profile":
        r["telemetry_profile_sha256"] = "0" * 64
    elif mutation == "health":
        r["health_log_sha256"] = "0" * 64
    elif mutation == "telemetry":
        r["capture"]["availability"] = .99
    elif mutation == "too_many_alerts":
        r["all_alerts"] = {"production/test:app": 2}
    paths[0].write_text(json.dumps(r))
    if mutation in {"profile", "health"}:
        with pytest.raises(ValueError):
            aggregate(marker, paths)
    else:
        assert not aggregate(marker, paths)["formal_recovery_pass"]


def test_bounded_diagnostic_can_never_be_formal_pass(tmp_path):
    marker, paths = make_reports(tmp_path, diagnostic=True, hours=.1)
    report = aggregate(marker, paths)
    assert report["diagnostic_integrity_gate"]
    assert not report["formal_recovery_pass"]


@pytest.mark.parametrize("mutation", ["missing", "empty", "omitted_counter", "extra_counter",
                                     "boolean_counter", "boolean_availability", "excess_availability",
                                     "infinite_availability", "missing_availability"])
def test_incomplete_or_invalid_capture_metrics_cannot_pass(tmp_path, mutation):
    marker, paths = make_reports(tmp_path)
    report = json.loads(paths[0].read_text())
    capture = report["capture"]
    if mutation == "missing":
        del capture["hard_integrity_counters"]
    elif mutation == "empty":
        capture["hard_integrity_counters"] = {}
    elif mutation == "omitted_counter":
        del capture["hard_integrity_counters"][HARD_COUNTERS[0]]
    elif mutation == "extra_counter":
        capture["hard_integrity_counters"]["unsupported"] = 0
    elif mutation == "boolean_counter":
        capture["hard_integrity_counters"][HARD_COUNTERS[0]] = False
    elif mutation == "missing_availability":
        del capture["availability"]
    else:
        capture["availability"] = {"boolean_availability": True, "excess_availability": 1.1,
                                   "infinite_availability": float("inf")}[mutation]
    paths[0].write_text(json.dumps(report))
    result = aggregate(marker, paths)
    assert not result["formal_recovery_pass"]
    assert not result["diagnostic_integrity_gate"]


def test_rate_budget_not_zero_alert_requirement(tmp_path):
    marker, paths = make_reports(tmp_path)
    r = json.loads(paths[0].read_text())
    r["all_alerts"] = {"production/test:app": 1}
    paths[0].write_text(json.dumps(r))
    report = aggregate(marker, paths)
    assert report["all_alerts"] == 1
    assert report["formal_recovery_pass"]  # 1/24 per key and 1/120 fleet under unchanged budgets


def live_nodes(marker):
    return {host: {"status": "active", "run_id": marker["run_id"], "marker_sha256": "8" * 64,
                   "detector_active": True, "detector_restarts": 0,
                   "capture_tail": {"valid": True, "status": "ready",
                                    "profile_sha256": marker["telemetry_recovery_contract"]["profile_sha256"]}}
            for host in marker["workers"]}


def test_supervisor_allows_bounded_recovery_but_never_mints_pass():
    m = marker_fixture()
    nodes = live_nodes(m)
    first = supervision_step(m, "8" * 64, None, nodes, 230)
    nodes["10.1.16.238"]["capture_tail"]["status"] = "quarantined"
    degraded = supervision_step(m, "8" * 64, first, nodes, 240)
    assert degraded["phase"] == "recovering"
    nodes["10.1.16.238"]["capture_tail"]["status"] = "ready"
    ready = supervision_step(m, "8" * 64, degraded, nodes, 250)
    assert ready["phase"] == "monitoring"
    assert not ready["formal_recovery_pass"]


def test_supervisor_unreachable_timeout_cannot_become_normal():
    m = marker_fixture()
    nodes = live_nodes(m)
    nodes["10.1.16.238"] = {"status": "unavailable"}
    state = supervision_step(m, "8" * 64, None, nodes, 230)
    assert state["phase"] == "recovering"
    for now in (245, 260, 261):
        state = supervision_step(m, "8" * 64, state, nodes, now)
    assert state["phase"] == "rejected"
    with pytest.raises(ValueError, match="terminal"):
        supervision_step(m, "8" * 64, state, live_nodes(m), 270)


@pytest.mark.parametrize("mutation", ["hard_integrity", "profile", "restart", "identity"])
def test_supervisor_fails_closed_on_live_runtime_drift(mutation):
    m = marker_fixture()
    nodes = live_nodes(m)
    node = nodes["10.1.16.238"]
    if mutation == "hard_integrity":
        node["capture_tail"]["valid"] = False
    elif mutation == "profile":
        node["capture_tail"]["profile_sha256"] = "0" * 64
    elif mutation == "restart":
        node["detector_restarts"] = 1
    else:
        node["marker_sha256"] = "0" * 64
    assert supervision_step(m, "8" * 64, None, nodes, 230)["phase"] == "rejected"


def test_supervisor_finalization_is_not_pass_and_audit_gap_fails():
    m = marker_fixture()
    nodes = live_nodes(m)
    previous = supervision_step(m, "8" * 64, None, nodes, 230)
    with pytest.raises(ValueError, match="observation gap"):
        supervision_step(m, "8" * 64, previous, nodes, 261)
    for node in nodes.values():
        node.update(status="finished", collector_exit_status=0)
    result = supervision_step(m, "8" * 64, previous, nodes, 240)
    assert result["phase"] == "ready_to_finalize"
    assert not result["formal_recovery_pass"]
