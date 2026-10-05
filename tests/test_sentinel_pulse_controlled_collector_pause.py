import json
import os
from pathlib import Path
import signal

import pytest

from sentinel_pulse.controlled_collector_pause import FAULT, find_loader, pause_pidfd, validate_event
from sentinel_pulse.integrity import sha256_file


def test_only_one_exact_private_loader_can_be_selected(tmp_path):
    group = "/system.slice/sentinel-pulse-collector-500ms-experiment.service"
    cgroup = tmp_path / "cgroup" / group.lstrip("/")
    cgroup.mkdir(parents=True)
    cgroup.joinpath("cgroup.procs").write_text("10\n11\n")
    proc = tmp_path / "proc"
    for pid, exe in [(10, "/opt/sentinel-pulse/experiments/new/pulse_counter_projected_loader"),
                     (11, "/usr/bin/python3")]:
        path = proc / str(pid)
        path.mkdir(parents=True)
        path.joinpath("exe").symlink_to(exe)
        path.joinpath("cmdline").write_bytes(exe.encode() + b"\0--interval-ms\0" + b"500\0")
    assert find_loader("new", group, proc, tmp_path / "cgroup") == 10
    with pytest.raises(ValueError, match="cgroup"):
        find_loader("new", "/system.slice/sentinel-pulse-collector.service", proc, tmp_path / "cgroup")
    proc.joinpath("10/exe").unlink()
    proc.joinpath("10/exe").symlink_to("/opt/sentinel-pulse/bin/pulse_counter_loader")
    with pytest.raises(ValueError, match="exactly ONE"):
        find_loader("new", group, proc, tmp_path / "cgroup")


@pytest.mark.parametrize("fail_sleep", [False, True])
def test_pidfd_always_resumes_on_exception(monkeypatch, fail_sleep):
    events = []
    monkeypatch.setattr(os, "pidfd_open", lambda pid, flags: 44)
    monkeypatch.setattr(os, "readlink", lambda _: "/private/loader")
    monkeypatch.setattr(os, "close", lambda fd: events.append(("close", fd)))
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda fd, sig: events.append((fd, sig)))
    def sleep(seconds):
        assert seconds == 1.2
        if fail_sleep:
            raise RuntimeError("interrupted")
    monkeypatch.setattr("sentinel_pulse.controlled_collector_pause.time.sleep", sleep)
    if fail_sleep:
        with pytest.raises(RuntimeError):
            pause_pidfd(10, "/private/loader")
    else:
        assert pause_pidfd(10, "/private/loader")["resume_sent"]
    assert events == [(44, signal.SIGSTOP), (44, signal.SIGCONT), ("close", 44)]


def test_pid_reuse_identity_mismatch_is_never_signalled(monkeypatch):
    events = []
    monkeypatch.setattr(os, "pidfd_open", lambda pid, flags: 44)
    monkeypatch.setattr(os, "readlink", lambda _: "/someone/else")
    monkeypatch.setattr(os, "close", lambda fd: events.append("close"))
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda *args: events.append("signal"))
    with pytest.raises(ValueError, match="identity changed"):
        pause_pidfd(10, "/private/loader")
    assert events == ["close"]


def test_sigterm_during_pause_resumes_and_restores_handler(monkeypatch):
    events = []
    handlers = {signal.SIGTERM: "original-handler"}
    monkeypatch.setattr(os, "pidfd_open", lambda pid, flags: 44)
    monkeypatch.setattr(os, "readlink", lambda _: "/private/loader")
    monkeypatch.setattr(os, "close", lambda fd: events.append(("close", fd)))
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda fd, sig: events.append((fd, sig)))

    def install_handler(sig, handler):
        old = handlers[sig]
        handlers[sig] = handler
        return old

    monkeypatch.setattr(signal, "signal", install_handler)
    monkeypatch.setattr("sentinel_pulse.controlled_collector_pause.time.sleep",
                        lambda _: handlers[signal.SIGTERM](signal.SIGTERM, None))
    with pytest.raises(InterruptedError, match="resuming private loader"):
        pause_pidfd(10, "/private/loader")
    assert events == [(44, signal.SIGSTOP), (44, signal.SIGCONT), ("close", 44)]
    assert handlers[signal.SIGTERM] == "original-handler"


@pytest.mark.parametrize("mutation", [None, "missing_recovery", "wrong_loader", "too_long", "no_quarantine"])
def test_event_requires_real_bound_quarantine_then_recovery(tmp_path, mutation):
    root = tmp_path / "new"
    root.mkdir()
    prereg = tmp_path / "preregister.json"
    registered = {"controlled_fault": FAULT, "duration_seconds": 1800, "started_at": 0}
    prereg.write_text(json.dumps(registered))
    start = {"collector_loader": "/private/loader", "sha256": {"loader": "a" * 64}}
    (root / "START.json").write_text(json.dumps(start))
    event = {"run_id": "new", "fault": FAULT, "preregistration_sha256": sha256_file(prereg),
             "resume_sent": True, "loader": "/private/loader", "loader_sha256": "a" * 64,
             "started_at_unix": 120.1, "resumed_at_unix": 121.3, "elapsed_monotonic_seconds": 1.2}
    if mutation == "wrong_loader":
        event["loader"] = "/control/loader"
    elif mutation == "too_long":
        event["elapsed_monotonic_seconds"] = 31
    (root / "CONTROLLED_FAULT_EVENT.json").write_text(json.dumps(event))
    rows = [{"schema": "sentinel-pulse-recovery-snapshot-v1", "observed_at": end,
             "recovery": {"sequence": seq, "status": status, "can_score": status == "ready"}}
            for seq, (end, status) in enumerate([(120, "ready"), (121.5, "quarantined"), (128, "ready")], 1)]
    if mutation == "missing_recovery":
        rows.pop()
    elif mutation == "no_quarantine":
        rows[1]["recovery"].update(status="ready", can_score=True)
    (root / "features.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    if mutation is None:
        assert validate_event(root, registered, prereg)["clean_recovery_observed"]
    else:
        with pytest.raises(ValueError):
            validate_event(root, registered, prereg)
