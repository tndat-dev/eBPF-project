import json
from pathlib import Path
import subprocess

import pytest

from sentinel_pulse import recovery_capacity_guard as guard
from test_sentinel_pulse_recovery_coordinator import config_fixture


def sample(used=50, available=40):
    return {p: {"device": 1, "used_bytes": used, "available_bytes": available,
                "size_bytes": 100, "checked_at_unix": 1.0} for p in guard.PATHS}


@pytest.mark.parametrize("used,available,safe", [(50, 40, True), (81, 9, False),
                                                 (80, 10, True), (90, 0, False)])
def test_reserved_blocks_and_exact_threshold(used, available, safe):
    assert all(row["safe"] is safe for row in guard.capacity(sample(used, available)).values())


@pytest.mark.parametrize("mutation", ["missing", "negative", "bool", "overflow", "nan", "zero"])
def test_malformed_probe_fails_closed(mutation):
    value = sample()
    path = sorted(guard.PATHS)[0]
    if mutation == "missing":
        del value[path]
    elif mutation == "negative":
        value[path]["available_bytes"] = -1
    elif mutation == "bool":
        value[path]["used_bytes"] = True
    elif mutation == "overflow":
        value[path]["used_bytes"] = 90
    elif mutation == "nan":
        value[path]["checked_at_unix"] = float("nan")
    else:
        value[path]["size_bytes"] = 0
    with pytest.raises(ValueError):
        guard.capacity(value)


def test_transport_bounded_and_does_not_expose_remote_stderr(monkeypatch):
    calls = []
    def execute(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 1, "secret", "secret")
    monkeypatch.setattr(guard.subprocess, "run", execute)
    with pytest.raises(RuntimeError) as error:
        guard.probe("10.1.16.237", Path("/private/file"))
    assert "secret" not in str(error.value)
    assert calls[0][1]["timeout"] == 12
    assert "StrictHostKeyChecking=yes" in calls[0][0]
    assert "sudo" not in " ".join(calls[0][0])


class Child:
    pid = 77
    returncode = None
    calls = []

    def poll(self):
        return self.returncode

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")

    def wait(self, timeout):
        self.calls.append(("wait", timeout))
        if timeout == 55:
            raise subprocess.TimeoutExpired("owned-child", timeout)
        self.returncode = -9


def test_cleanup_only_owned_popen_child():
    child = Child()
    child.calls = []
    guard.stop_child(child)
    assert child.calls == ["terminate", ("wait", 55), "kill", ("wait", 5)]
    guard.stop_child(child)
    assert len(child.calls) == 4


def setup(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "sentinel_pulse").mkdir(parents=True)
    (source / "sentinel_pulse/recovery_coordinator.py").write_text("frozen")
    config = config_fixture()
    config["source"] = str(source)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    credential = tmp_path / "credential"
    credential.write_text("test-private-value\n")
    credential.chmod(0o600)
    monkeypatch.setattr(guard, "validate_config", lambda value: value)
    return config_path, credential, tmp_path / "output", tmp_path / "guard"


@pytest.mark.parametrize("failure", ["capacity", "ssh", "existing"])
def test_preflight_never_starts_child_on_failure(tmp_path, monkeypatch, failure):
    args = setup(tmp_path, monkeypatch)
    results = {"10.1.16.237": guard.capacity(sample(81 if failure == "capacity" else 50,
                                                            9 if failure == "capacity" else 40))}
    monkeypatch.setattr(guard, "observations", lambda *_: (results, {"worker": "error"} if failure == "ssh" else {}))
    monkeypatch.setattr(guard.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("child launched"))
    if failure == "existing":
        (args[2] / "new").mkdir(parents=True)
    with pytest.raises(ValueError):
        guard.supervise(*args, "new", 180, True)


def test_live_capacity_violation_retained_and_terminates_only_child(tmp_path, monkeypatch):
    args = setup(tmp_path, monkeypatch)
    count = [0]
    def observe(*_):
        count[0] += 1
        value = sample() if count[0] == 1 else sample(81, 9)
        return {"10.1.16.237": guard.capacity(value)}, {}
    monkeypatch.setattr(guard, "observations", observe)
    child = Child()
    child.calls = []
    captured = []
    def launch(command, **kwargs):
        captured.append((command, kwargs))
        return child
    monkeypatch.setattr(guard.subprocess, "Popen", launch)
    assert guard.supervise(*args, "new", 180, True) == 1
    root = args[3] / "new"
    start = json.loads((root / "START.json").read_text())
    terminal = json.loads((root / "TERMINAL.json").read_text())
    assert start["contract"] == guard.CONTRACT
    assert terminal["reason"] == "registered capacity budget exceeded"
    assert terminal["formal_recovery_pass"] is False
    assert "test-private-value" not in "".join(p.read_text() for p in root.iterdir())
    assert child.returncode == -9
    assert captured[0][1]["env"]["PYTHONPATH"] == str(tmp_path / "source")
    assert all(guard.sha256_file(root / name) == sha for name, sha in
               json.loads((root / "SHA256.json").read_text()).items())


@pytest.mark.parametrize("duration,diagnostic", [(180, False), (89881, False), (1801, True), (True, True)])
def test_duration_rejected_before_launch(tmp_path, monkeypatch, duration, diagnostic):
    args = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(guard, "observations", lambda *_: pytest.fail("preflight launched"))
    with pytest.raises(ValueError):
        guard.supervise(*args, "new", duration, diagnostic)


def test_unknown_storage_timeout_not_reported_as_healthy(tmp_path, monkeypatch):
    args = setup(tmp_path, monkeypatch)
    calls = [0]
    def observe(*_):
        calls[0] += 1
        if calls[0] == 1:
            return {host: guard.capacity(sample()) for host in config_fixture()["workers"]}, {}
        return {}, {host: "TimeoutExpired" for host in config_fixture()["workers"]}
    monkeypatch.setattr(guard, "observations", observe)
    monkeypatch.setitem(guard.CONTRACT, "maximum_unknown_seconds", 0)
    child = Child()
    child.calls = []
    monkeypatch.setattr(guard.subprocess, "Popen", lambda *_args, **_kwargs: child)
    assert guard.supervise(*args, "new", 180, True) == 1
    terminal = json.loads((args[3] / "new/TERMINAL.json").read_text())
    assert terminal["reason"] == "capacity observation unavailable beyond budget"
    assert child.returncode == -9
