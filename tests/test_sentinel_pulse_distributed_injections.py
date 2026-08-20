import json
from pathlib import Path

from sentinel_pulse.verify_distributed_injections import verify


def write(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(item) + "\n" for item in records))


def marker(injection_id: str) -> dict:
    return {
        "schema": "sentinel-pulse-injection-v1",
        "injection_id": injection_id,
        "workload_key": "production/catalog:app",
    }


def test_distributed_marker_union_must_exactly_equal_controller(tmp_path):
    controller = tmp_path / "controller.jsonl"
    left, right = tmp_path / "left.jsonl", tmp_path / "right.jsonl"
    write(controller, [marker("one"), marker("two")])
    write(left, [marker("one")])
    write(right, [marker("two")])
    report = verify(controller, [left, right])
    assert report["valid"] is True
    assert report["distributed_rows"] == 2


def test_duplicate_or_changed_remote_marker_fails(tmp_path):
    controller = tmp_path / "controller.jsonl"
    left, right = tmp_path / "left.jsonl", tmp_path / "right.jsonl"
    write(controller, [marker("one"), marker("two")])
    changed = marker("two")
    changed["workload_key"] = "production/order:app"
    write(left, [marker("one"), changed])
    write(right, [marker("one")])
    report = verify(controller, [left, right])
    assert report["valid"] is False
    assert report["duplicate_injection_ids"] == ["one"]
    assert report["changed_injection_ids"] == ["two"]
