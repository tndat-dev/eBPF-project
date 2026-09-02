"""Classify a failed formal-normal finalizer without changing its evidence."""

from __future__ import annotations

import json
from pathlib import Path


def classify(evidence_root: Path) -> str:
    report_path = evidence_root / "NORMAL_REPORT.json"
    if not report_path.is_file():
        return "normal_finalize_failed"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema") != "sentinel-pulse-normal-soak-report-v1":
        return "normal_finalize_failed"
    if int(report.get("alerts", 0)) > int(report.get("maximum_alerts", 0)):
        return "normal_alert_gate_failed"
    if report.get("coverage_gate") is False:
        return "normal_coverage_gate_failed"
    if report.get("duration_gate") is False:
        return "normal_duration_gate_failed"
    if report.get("expected_workload_gate") is False:
        return "normal_workload_gate_failed"
    if any(
        report.get(field) is False
        for field in (
            "model_identity_gate",
            "model_manifest_gate",
            "decision_policy_identity_gate",
            "run_identity_gate",
        )
    ):
        return "normal_identity_gate_failed"
    if report.get("soak_marker_gate") is False:
        return "normal_soak_marker_gate_failed"
    if int(report.get("scored_windows", 0)) < int(
        report.get("minimum_scored_windows", 0)
    ):
        return "normal_scored_window_gate_failed"
    return "normal_finalize_failed"


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_root", type=Path)
    args = parser.parse_args()
    print(classify(args.evidence_root))


if __name__ == "__main__":
    main()
