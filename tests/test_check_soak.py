import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "check_a5_soak.py"
SPEC = importlib.util.spec_from_file_location("check_soak", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def make_run(root: Path, name: str, *, active: bool = True) -> Path:
    run = root / name
    run.mkdir()
    (run / "SOAK_START.json").write_text(json.dumps({
        "started_not_before": "2026-08-29T00:00:00+00:00",
        "eligible_finalize_after": "2026-08-30T00:00:00+00:00",
    }))
    if active:
        (run / "ACTIVE").touch()
    rows = []
    for host in MODULE.EXPECTED_WORKERS:
        rows.append(json.dumps({
            "host": host, "checked_at_unix": 1787961590.0,
            "collector": "active", "detector": "active",
            "nrestarts": 0, "decisions": 10, "alerts": 0,
        }))
    (run / "MONITOR.jsonl").write_text("\n".join(rows) + "\n")
    return run


def test_auto_detects_only_active_nonterminal_run(tmp_path):
    active = make_run(tmp_path, "pulse500-normal-soak-a7-20260829T000000Z")
    failed = make_run(tmp_path, "pulse500-normal-soak-a6-20260828T000000Z")
    (failed / "FAILED").touch()
    assert MODULE.resolve_run(tmp_path, None) == active


def test_refuses_ambiguous_active_runs(tmp_path):
    make_run(tmp_path, "pulse500-normal-soak-a7-20260829T000000Z")
    make_run(tmp_path, "pulse500-normal-soak-a8-20260830T000000Z")
    try:
        MODULE.resolve_run(tmp_path, None)
    except RuntimeError as exc:
        assert "exactly one" in str(exc)
    else:
        raise AssertionError("ambiguous active campaigns must be rejected")


def test_status_is_read_only_and_does_not_claim_accuracy(tmp_path, monkeypatch):
    run = make_run(tmp_path, "pulse500-normal-soak-a7-20260829T000000Z")
    before = {path: path.read_bytes() for path in run.iterdir() if path.is_file()}
    monkeypatch.setattr(MODULE, "kubernetes_summary", lambda: {
        "available": True, "running_unready": 0, "phases": {"Running": 1},
    })
    status, healthy = MODULE.build_status(run, now=1787961600.0)
    after = {path: path.read_bytes() for path in run.iterdir() if path.is_file()}
    assert healthy
    assert status["worker_decisions_total"] == 30
    assert status["worker_alerts_total"] == 0
    assert status["accuracy_claim_allowed"] is False
    assert before == after


def test_terminal_marker_makes_snapshot_unhealthy(tmp_path, monkeypatch):
    run = make_run(tmp_path, "pulse500-normal-soak-a7-20260829T000000Z")
    (run / "ARCHIVE_COMPLETE").touch()
    monkeypatch.setattr(MODULE, "kubernetes_summary", lambda: {
        "available": True, "running_unready": 0, "phases": {"Running": 1},
    })
    status, healthy = MODULE.build_status(run, now=1787961600.0)
    assert not healthy
    assert not status["active"]
    assert status["terminal_markers"] == ["ARCHIVE_COMPLETE"]


def test_stale_monitor_rows_are_not_healthy(tmp_path, monkeypatch):
    run = make_run(tmp_path, "pulse500-normal-soak-a7-20260829T000000Z")
    monkeypatch.setattr(MODULE, "kubernetes_summary", lambda: {
        "available": True, "running_unready": 0, "phases": {"Running": 1},
    })
    _status, healthy = MODULE.build_status(run, now=1787962000.0)
    assert not healthy
