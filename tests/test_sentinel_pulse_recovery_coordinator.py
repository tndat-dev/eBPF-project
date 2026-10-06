import copy
import json
import os
from pathlib import Path
import subprocess

import pytest

from sentinel_pulse import recovery_coordinator as coordinator
from sentinel_pulse import recovery_worker_probe as worker
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.telemetry_recovery import digest
from test_sentinel_pulse_recovery_formal import marker_fixture


def config_fixture():
    paths = {"source": "/home/dat/recovery-test", "model": "/opt/sentinel-pulse/models/frozen",
             "policy": "/opt/sentinel-pulse/policies/frozen.json"}
    return {"schema": "sentinel-pulse-recovery-coordinator-config-v1", **paths,
            "workers": {ip: {**paths, "safety": "/var/lib/sentinel-pulse-projection-canary/safe"}
                        for ip in coordinator.WORKERS}}


@pytest.mark.parametrize("mutation", ["secret", "missing", "shell", "relative", "traversal", "root_source", "safety"])
def test_reject_unsafe_or_credential_bearing_config(mutation):
    cfg = config_fixture()
    host = sorted(coordinator.WORKERS)[0]
    if mutation == "secret":
        cfg["password"] = "do-not-log"
    elif mutation == "missing":
        del cfg["workers"][host]
    elif mutation == "shell":
        cfg["workers"][host]["policy"] = "/tmp/a; touch /tmp/b"
    elif mutation == "relative":
        cfg["model"] = "../models"
    elif mutation == "traversal":
        cfg["workers"][host]["source"] = "/home/dat/../data"
    elif mutation == "root_source":
        cfg["source"] = "/home/dat"
    else:
        cfg["workers"][host]["safety"] = "/var/lib/other"
    with pytest.raises(ValueError):
        coordinator.validate_config(cfg)


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, "symlink", "multiline"])
def test_secret_private_file_only(tmp_path, mode):
    path = tmp_path / "private"
    path.write_text("example\n" if mode != "multiline" else "first\nsecond\n")
    path.chmod(mode if isinstance(mode, int) else 0o600)
    if mode == "symlink":
        link = tmp_path / "link"
        link.symlink_to(path)
        path = link
    if mode == 0o600:
        assert coordinator.secret(path) == "example"
    else:
        with pytest.raises(ValueError):
            coordinator.secret(path)


def test_parallel_probe_failures_do_not_fabricate_healthy_api():
    def fail():
        raise subprocess.TimeoutExpired("kubectl", 10)
    results, failures = coordinator.parallel_calls({"nodes": fail, "pods": lambda: {"items": []}})
    assert results == {"pods": {"items": []}}
    health = coordinator.dependency_health({}, results, failures)
    assert health["transient"][0]["reason"] == "dependency_api_unavailable"
    assert "nodes" in health["transient"][0]["resources"]
    assert not health["fatal"]


def test_ssh_password_not_in_args_config_or_error(tmp_path, monkeypatch):
    secret = tmp_path / "credential"
    secret.write_text("test-secret-value\n")
    secret.chmod(0o600)
    remote = coordinator.Remote(config_fixture(), secret)
    captured = []
    def execute(args, **kwargs):
        captured.append((args, kwargs))
        return subprocess.CompletedProcess(args, 1, "test-secret-value", "test-secret-value")
    monkeypatch.setattr(coordinator.subprocess, "run", execute)
    with pytest.raises(RuntimeError) as error:
        remote.call("10.1.16.238", "probe", {"marker": {}})
    assert "test-secret-value" not in str(error.value)
    assert "test-secret-value" not in json.dumps(captured[0][0])
    assert captured[0][1]["timeout"] == 12
    assert captured[0][1]["input"].startswith("test-secret-value\n")
    assert "StrictHostKeyChecking=yes" in captured[0][0]


def node(marker, marker_sha, status="finished"):
    return {"run_id": marker["run_id"], "marker_sha256": marker_sha, "status": status,
            "collector_exit_status": 0, "detector_restarts": 0,
            "detector_active": True, "capture_tail": {"valid": True, "status": "ready",
                "profile_sha256": marker["telemetry_recovery_contract"]["profile_sha256"]}}


class FakeRemote:
    def __init__(self, marker, path, failure=None):
        self.marker, self.path, self.failure = marker, path, failure
        self.calls = []

    def call(self, host, command, payload=None, timeout=12):
        self.calls.append((host, command))
        if command == self.failure and host == "10.1.16.238":
            raise RuntimeError("injected adapter failure")
        if command == "probe":
            value = node(self.marker, sha256_file(self.path))
            if self.failure == "integrity" and host == "10.1.16.238":
                value["status"] = "invalid"
            return value
        if command == "finalize":
            return {"worker_ip": host}
        return {"ok": True}


def setup_fake_run(tmp_path, monkeypatch, failure=None):
    root = tmp_path / "new"
    cfg, marker = config_fixture(), marker_fixture()
    marker["diagnostic_only"], marker["collector_duration_seconds"] = True, 180
    marker["coordinator_config_sha256"] = digest(cfg)
    def fake_start(*args):
        root.mkdir()
        coordinator.write_new(root / "START.json", marker)
        coordinator.write_new(root / "CONFIG.json", cfg)
        return marker
    monkeypatch.setattr(coordinator, "start", fake_start)
    monkeypatch.setattr(coordinator.time, "time", lambda: 110)
    monkeypatch.setattr(coordinator, "api_snapshot", lambda _: {"items": []})
    monkeypatch.setattr(coordinator, "dependency_health", lambda *_: {"fatal": [], "transient": [], "warnings": []})
    monkeypatch.setattr(coordinator, "aggregate", lambda *_: {
        "formal_recovery_pass": False, "diagnostic_integrity_gate": True})
    return root, cfg, marker, FakeRemote(marker, root / "START.json", failure)


def test_mocked_coordinator_finalizes_three_legs_never_promotes(tmp_path, monkeypatch):
    root, cfg, marker, remote = setup_fake_run(tmp_path, monkeypatch)
    result = coordinator.run(root, cfg, remote, "new", 180, True)
    assert result["reason"] is None and result["diagnostic_integrity_gate"]
    assert not result["formal_recovery_pass"] and not result["automatic_promotion"]
    assert not result["kernel_to_alert_claim_allowed"]
    assert sum(cmd == "stage" for _, cmd in remote.calls) == 3
    assert sum(cmd == "finalize" for _, cmd in remote.calls) == 3
    assert sum(cmd == "stop" for _, cmd in remote.calls) == 0
    seals = json.loads((root / "SHA256.json").read_text())
    assert all(sha256_file(root / name) == sha for name, sha in seals.items())
    with pytest.raises(ValueError, match="terminal"):
        coordinator.load_resume(root, cfg)


@pytest.mark.parametrize("failure", ["stage", "finalize", "integrity"])
def test_failure_stops_only_owned_parents_and_retains_rejection(tmp_path, monkeypatch, failure):
    root, cfg, marker, remote = setup_fake_run(tmp_path, monkeypatch, failure)
    result = coordinator.run(root, cfg, remote, "new", 180, True)
    assert result["reason"] and not result["diagnostic_integrity_gate"] and not result["formal_recovery_pass"]
    assert sum(cmd == "stop" for _, cmd in remote.calls) == 3
    assert (root / "TERMINAL.json").exists()
    if failure == "integrity":
        row = json.loads((root / "SUPERVISION.jsonl").read_text())
        assert row["state"]["phase"] == "rejected"


@pytest.mark.parametrize("mutation", ["config", "state", "clock", "fatal"])
def test_resume_replays_evidence_and_rejects_drift(tmp_path, monkeypatch, mutation):
    root, cfg, marker, remote = setup_fake_run(tmp_path, monkeypatch)
    coordinator.start(root, cfg, remote, "new", 180, True)
    nodes = {host: node(marker, sha256_file(root / "START.json"), "active") for host in coordinator.WORKERS}
    state = coordinator.supervision_step(marker, sha256_file(root / "START.json"), None, nodes, 110)
    health = coordinator.observe(marker["operational_evaluation_contract"], [],
        {"fatal": [{"reason": "test"}] if mutation == "fatal" else [], "transient": [], "warnings": []}, 110, 99)
    if mutation == "config":
        cfg["workers"]["10.1.16.238"]["policy"] = "/opt/other.json"
    elif mutation == "state":
        state["degraded_workers"] = ["10.1.16.238"]
    elif mutation == "clock":
        state["checked_at_unix"] = 98
    coordinator.append(root / "SUPERVISION.jsonl", {"nodes": nodes, "state": state})
    coordinator.append(root / "dependency-health.jsonl", health)
    with pytest.raises(ValueError):
        coordinator.load_resume(root, cfg)


def test_single_writer_lock_released_without_replacing_inode(tmp_path):
    root = tmp_path / "new"
    with coordinator.coordinator_lock(root):
        inode = (tmp_path / ".coordinator-locks/new.lock").stat().st_ino
        with pytest.raises(ValueError, match="another coordinator"):
            with coordinator.coordinator_lock(root):
                pytest.fail("second writer acquired lock")
    with coordinator.coordinator_lock(root):
        assert (tmp_path / ".coordinator-locks/new.lock").stat().st_ino == inode
        assert not root.exists()  # lock does not create or mutate sealed run


@pytest.mark.parametrize("mutation", ["directory_symlink", "public_directory", "lock_symlink", "public_lock"])
def test_lock_refuses_unsafe_paths(tmp_path, mutation):
    directory = tmp_path / ".coordinator-locks"
    if mutation == "directory_symlink":
        target = tmp_path / "other"
        target.mkdir(mode=0o700)
        directory.symlink_to(target, target_is_directory=True)
    else:
        directory.mkdir(mode=0o755 if mutation == "public_directory" else 0o700)
        if mutation == "lock_symlink":
            target = tmp_path / "other"
            target.write_text("do not overwrite")
            (directory / "new.lock").symlink_to(target)
        elif mutation == "public_lock":
            path = directory / "new.lock"
            path.touch(mode=0o644)
    with pytest.raises((ValueError, OSError)):
        with coordinator.coordinator_lock(tmp_path / "new"):
            pytest.fail("unsafe lock acquired")


def test_lock_released_when_owner_process_is_killed(tmp_path):
    # A real subprocess, but entirely synthetic local paths; no cluster signals.
    child = subprocess.Popen([os.sys.executable, "-c",
        "from pathlib import Path; import sys,time; "
        "from sentinel_pulse.recovery_coordinator import coordinator_lock; "
        "guard=coordinator_lock(Path(sys.argv[1])); guard.__enter__(); "
        "print('locked',flush=True); time.sleep(20)", str(tmp_path / "new")],
        stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(ValueError, match="another coordinator"):
            with coordinator.coordinator_lock(tmp_path / "new"):
                pytest.fail("second writer acquired lock")
        child.kill()
        child.wait(timeout=5)
        with coordinator.coordinator_lock(tmp_path / "new"):
            pass
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()


@pytest.mark.parametrize("observation", [False, True])
@pytest.mark.parametrize("mutation", [None, "executable", "commit", "files", "manifest", "policy", "profile", "scope", "collect_only"])
def test_resume_verifies_local_executable_source_and_entire_bundle(tmp_path, monkeypatch, mutation, observation):
    cfg, marker = config_fixture(), marker_fixture()
    if observation:marker['observational_segment']=True
    source, model = tmp_path / "source", tmp_path / "model"
    (source / "sentinel_pulse/protocol").mkdir(parents=True)
    model.mkdir()
    policy = tmp_path / "policy.json"
    policy.write_text("{}")
    (model / "manifest.json").write_text("{}")
    profile = source / "sentinel_pulse/protocol/telemetry-recovery-v1.json"
    profile.write_text("profile bytes")
    cfg.update(source=str(source), model=str(model), policy=str(policy))
    marker["model_manifest_sha256"] = sha256_file(model / "manifest.json")
    marker["decision_policy_sha256"] = sha256_file(policy)
    marker["telemetry_recovery_contract"]["profile_file_sha256"] = sha256_file(profile)
    monkeypatch.setattr(coordinator, "__file__", str(source / "sentinel_pulse/recovery_coordinator.py"))
    commit, files = marker["source_commit"], dict(marker["source_files"])
    candidates, collect_only = ["production/test:app"], []
    if mutation == "executable":
        monkeypatch.setattr(coordinator, "__file__", str(tmp_path / "foreign.py"))
    elif mutation == "commit":
        commit = "0" * 40
    elif mutation == "files":
        files["sentinel_pulse/test.py"] = "0" * 64
    elif mutation in {"manifest", "policy", "profile"}:
        {"manifest": model / "manifest.json", "policy": policy, "profile": profile}[mutation].write_text("drift")
    elif mutation == "scope":
        candidates = []
    elif mutation == "collect_only":
        collect_only = ["production/test:app"]
    monkeypatch.setattr(worker, "clean_source", lambda _: (commit, files))
    monkeypatch.setattr("sentinel_pulse.finalize_candidate.verify_model_bundle", lambda _: ({}, candidates, collect_only))
    if mutation is None or (observation and mutation=='executable'):
        coordinator.validate_resume_runtime(marker, cfg)
    else:
        with pytest.raises(ValueError, match="resume"):
            coordinator.validate_resume_runtime(marker, cfg)


def resumable_fake_run(tmp_path, monkeypatch):
    root, cfg, marker, remote = setup_fake_run(tmp_path, monkeypatch)
    coordinator.start(root, cfg, remote, "new", 180, True)
    nodes = {host: node(marker, sha256_file(root / "START.json"), "active") for host in coordinator.WORKERS}
    state = coordinator.supervision_step(marker, sha256_file(root / "START.json"), None, nodes, 105)
    health = coordinator.observe(marker["operational_evaluation_contract"], [],
        {"fatal": [], "transient": [], "warnings": []}, 105, marker["started_at_unix"])
    coordinator.append(root / "SUPERVISION.jsonl", {"nodes": nodes, "state": state})
    coordinator.append(root / "dependency-health.jsonl", health)
    monkeypatch.setattr(coordinator, "validate_resume_runtime", lambda *_: None)
    return root, cfg, marker, remote


def test_successful_resume_does_not_relaunch_or_replace_registration(tmp_path, monkeypatch):
    root, cfg, marker, remote = resumable_fake_run(tmp_path, monkeypatch)
    before = sha256_file(root / "START.json")
    result = coordinator.run(root, cfg, remote, "new", 180, True, resume=True)
    assert result["diagnostic_integrity_gate"] and result["reason"] is None
    assert sha256_file(root / "START.json") == before
    assert not any(cmd == "stage" for _, cmd in remote.calls)
    event = json.loads((root / "RESUME.jsonl").read_text())
    assert event["marker_sha256"] == before
    assert not event["worker_relaunch"] and not event["registration_replaced"]
    seals = json.loads((root / "SHA256.json").read_text())
    assert seals["RESUME.jsonl"] == sha256_file(root / "RESUME.jsonl")


@pytest.mark.parametrize("mutation", ["run_id", "duration", "diagnostic", "source"])
def test_resume_rejects_arguments_or_runtime_before_worker_contact(tmp_path, monkeypatch, mutation):
    root, cfg, marker, remote = resumable_fake_run(tmp_path, monkeypatch)
    def fail(*_):
        raise ValueError("resume runtime drift")
    if mutation == "source":
        monkeypatch.setattr(coordinator, "validate_resume_runtime", fail)
    with pytest.raises(ValueError, match="resume"):
        coordinator.run(root, cfg, remote, "other" if mutation == "run_id" else "new",
            181 if mutation == "duration" else 180, mutation != "diagnostic", resume=True)
    assert not remote.calls
    assert not (root / "RESUME.jsonl").exists()
    assert not (root / "TERMINAL.json").exists()


def test_worker_stop_refuses_differently_registered_parent(tmp_path, monkeypatch):
    marker = marker_fixture()
    prereg = tmp_path / "new"
    prereg.mkdir()
    wrong = copy.deepcopy(marker)
    wrong["started_at_unix"] += 1
    (prereg / "START.json").write_text(json.dumps(wrong))
    monkeypatch.setattr(worker, "PREREG", tmp_path)
    monkeypatch.setattr(worker.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("must not stop any unit"))
    with pytest.raises(ValueError, match="refusing"):
        worker.stop_owned(marker, "10.1.16.238")


def test_worker_environment_is_parsed_not_executed(tmp_path):
    path = tmp_path / "env"
    path.write_text("# ignored\nPULSE_RUN_ID=example\nPAYLOAD=$(touch /tmp/not-executed)\n")
    assert worker.environment(path)["PAYLOAD"] == "$(touch /tmp/not-executed)"


@pytest.mark.parametrize("mutation", [None, "early", "failed_collector", "failed_detector", "restarted", "active_collector"])
def test_verified_worker_sealing_is_bounded_unknown_not_false_startup_failure(tmp_path, monkeypatch, mutation):
    marker = marker_fixture()
    root = tmp_path / "captures" / "new"
    prereg = tmp_path / "prereg" / "new"
    root.mkdir(parents=True)
    prereg.mkdir(parents=True)
    (prereg / "START.json").write_text(json.dumps(marker))
    (root / "FORMAL_WORKER_START.json").write_text("{}")
    (root / "COLLECTOR_RUNTIME_START.json").write_text("{}")
    (root / "START.json").write_text(json.dumps({"started_at_unix": 100}))
    monkeypatch.setattr(worker, "CAPTURES", root.parent)
    monkeypatch.setattr(worker, "PREREG", prereg.parent)
    now = 300 if mutation == "early" else 100 + marker["collector_duration_seconds"] + 1
    monkeypatch.setattr(worker.time, "time", lambda: now)
    verified = []
    monkeypatch.setattr(worker, "validate_worker_start", lambda *_: verified.append("marker"))
    monkeypatch.setattr(worker, "validate_collector_timing", lambda *_: 100)
    monkeypatch.setattr(worker, "check_runtime", lambda *_: verified.append("runtime"))
    def state(name):
        result = {"ActiveState": "active" if name.startswith("sentinel-pulse-recovery-worker-") else "inactive",
                  "Result": "success", "ExecMainStatus": "0", "NRestarts": "0"}
        if mutation == "failed_collector" and name == worker.COLLECTOR:
            result["Result"] = "exit-code"
        if mutation == "failed_detector" and name == worker.DETECTOR:
            result["Result"] = "exit-code"
        if mutation == "restarted" and name == worker.DETECTOR:
            result["NRestarts"] = "1"
        if mutation == "active_collector" and name == worker.COLLECTOR:
            result["ActiveState"] = "active"
        return result
    monkeypatch.setattr(worker, "service", state)
    if mutation is None:
        result = worker.probe(tmp_path, "10.1.16.238", marker)
        assert result["status"] == "unavailable" and result["reason"] == "worker_sealing"
        assert verified == ["marker", "runtime"]
    else:
        with pytest.raises(ValueError, match="detector stopped during runtime"):
            worker.probe(tmp_path, "10.1.16.238", marker)
        assert not verified


def test_finalization_interrupt_cannot_mint_success(tmp_path, monkeypatch):
    root, cfg, marker, remote = setup_fake_run(tmp_path, monkeypatch)
    handlers = {}
    def install_handler(sig, fn):
        previous = handlers.get(sig)
        handlers[sig] = fn
        return previous
    monkeypatch.setattr(coordinator.signal, "signal", install_handler)
    original = remote.call
    def call(host, command, payload=None, timeout=12):
        if command == "finalize":
            handlers[coordinator.signal.SIGTERM](coordinator.signal.SIGTERM, None)
        return original(host, command, payload, timeout)
    remote.call = call
    result = coordinator.run(root, cfg, remote, "new", 180, True)
    assert result["reason"] == "coordinator interrupted during finalization"
    assert not result["formal_recovery_pass"] and not result["diagnostic_integrity_gate"]
    assert not (root / "REPORT.json").exists()
