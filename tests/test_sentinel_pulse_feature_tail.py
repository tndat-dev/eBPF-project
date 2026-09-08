import json
from pathlib import Path

import pytest

from sentinel_pulse.inspect_feature_tail import inspect


def write_capture(path: Path, *, stats: dict | None = None, interval: float = 0.5) -> None:
    rows = [
        {"schema": "sentinel-pulse-feature-schema-v1", "columns": ["x"]},
        {
            "schema": "sentinel-pulse-feature-v1",
            "workload_key": "production/database:app",
            "window_start": 99.0,
            "window_end": 99.0 + interval,
            "emitted_at": 99.6,
            "collector_stats": stats or {},
        },
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_tail_accepts_fresh_lossless_feature(tmp_path: Path) -> None:
    capture = tmp_path / "features.jsonl"
    write_capture(capture)

    result = inspect(capture, observed_at=100.0)

    assert result["valid"] is True
    assert result["interval_seconds"] == 0.5
    assert result["feature_age_seconds"] == pytest.approx(0.4)


def test_tail_rejects_cumulative_collector_loss(tmp_path: Path) -> None:
    capture = tmp_path / "features.jsonl"
    write_capture(capture, stats={"target_snapshot_gap": 1})

    result = inspect(capture, observed_at=100.0)

    assert result["valid"] is False
    assert "collector loss: target_snapshot_gap=1" in result["errors"]


def test_tail_rejects_stale_or_invalid_interval(tmp_path: Path) -> None:
    capture = tmp_path / "features.jsonl"
    write_capture(capture, interval=1.0)

    result = inspect(capture, observed_at=110.0)

    assert result["valid"] is False
    assert any("invalid latest interval" in item for item in result["errors"])
    assert any("latest feature age" in item for item in result["errors"])


def test_tail_accepts_preregistered_bounded_cadence_degradation(tmp_path: Path) -> None:
    capture = tmp_path / "features.jsonl"
    write_capture(
        capture,
        stats={"capture_interval_violation": 1},
        interval=4.8,
    )

    result = inspect(
        capture,
        observed_at=104.0,
        maximum_age_seconds=5.0,
        maximum_single_gap_seconds=10.0,
        maximum_capture_interval_violations=1,
    )

    assert result["valid"] is True
    assert result["telemetry_degraded"] is True


def test_tail_never_budgets_hard_integrity_failure(tmp_path: Path) -> None:
    capture = tmp_path / "features.jsonl"
    write_capture(
        capture,
        stats={"capture_interval_violation": 1, "count_insert_fail": 1},
    )
    result = inspect(
        capture,
        observed_at=100.0,
        maximum_single_gap_seconds=10.0,
        maximum_capture_interval_violations=1,
    )
    assert result["valid"] is False
    assert "collector loss: count_insert_fail=1" in result["errors"]


def test_tail_rejects_malformed_newest_row(tmp_path: Path) -> None:
    capture = tmp_path / "features.jsonl"
    write_capture(capture)
    with capture.open("a", encoding="utf-8") as destination:
        destination.write("{broken\n")

    result = inspect(capture, observed_at=100.0)

    assert result["valid"] is False
    assert any("invalid newest JSON row" in item for item in result["errors"])


def test_tail_ignores_an_in_progress_unterminated_append(tmp_path: Path) -> None:
    capture = tmp_path / "features.jsonl"
    write_capture(capture)
    with capture.open("a", encoding="utf-8") as destination:
        destination.write('{"schema":"sentinel-pulse-feature-v1"')

    result = inspect(capture, observed_at=100.0)

    assert result["valid"] is True
