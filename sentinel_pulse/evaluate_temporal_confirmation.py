"""Replay a temporal-confirmation ablation on frozen normal decisions.

This evaluator consumes only development-normal evidence.  It does not mutate
the frozen candidate, estimate attack recall, or authorize blind evaluation.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import json
import math
from pathlib import Path

from .integrity import sha256_file


DEFAULT_BYPASS_GROUPS = frozenset({"namespace_probe"})


def triggered_groups(record: dict) -> frozenset[str]:
    groups = record.get("semantic_signal_groups", {})
    if not isinstance(groups, dict):
        raise ValueError("decision has invalid semantic signal groups")
    return frozenset(
        str(name)
        for name, details in groups.items()
        if isinstance(details, dict) and details.get("triggered") is True
    )


def evaluate(
    paths: list[Path],
    required_consecutive_windows: int = 2,
    maximum_gap_seconds: float = 1.75,
    bypass_groups: frozenset[str] = DEFAULT_BYPASS_GROUPS,
    soak_marker_path: Path | None = None,
) -> dict:
    if not paths:
        raise ValueError("at least one decision source is required")
    if required_consecutive_windows < 2:
        raise ValueError("temporal confirmation requires at least two windows")
    if not math.isfinite(maximum_gap_seconds) or maximum_gap_seconds <= 0.0:
        raise ValueError("maximum temporal confirmation gap must be positive")
    if not bypass_groups:
        raise ValueError("at least one immediate bypass group is required")

    marker = None
    if soak_marker_path is not None:
        marker = json.loads(soak_marker_path.read_text(encoding="utf-8"))
        if (
            not str(marker.get("schema", "")).startswith(
                "sentinel-pulse-semantic-soak-start-"
            )
            or marker.get("blind_evaluation_started") is not False
        ):
            raise ValueError("invalid normal-only soak marker")
        try:
            marker_started_at = datetime.fromisoformat(
                str(marker["started_not_before"])
            ).timestamp()
        except (KeyError, ValueError) as error:
            raise ValueError("invalid normal-only soak marker time") from error
    else:
        marker_started_at = None

    status_counts: Counter[str] = Counter()
    projected_status_counts: Counter[str] = Counter()
    projected_alerts_by_workload: Counter[str] = Counter()
    original_alerts = 0
    projected_alerts = 0
    original_alerts_suppressed = 0
    scored_rows = 0
    excluded_before_marker = 0
    sources = []

    for path in paths:
        pending: dict[tuple[str, str], dict] = {}
        rows = 0
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"{path}:{line_number}: invalid JSON") from error
                rows += 1
                status = str(record.get("status", "unknown"))
                if record.get("schema") != "sentinel-pulse-decision-v1":
                    status_counts[status] += 1
                    projected_status_counts[status] += 1
                    continue
                if status not in {"normal", "suppressed", "alert"}:
                    status_counts[status] += 1
                    projected_status_counts[status] += 1
                    continue
                try:
                    window_end = float(record["window_end"])
                except (KeyError, TypeError, ValueError) as error:
                    raise ValueError(
                        f"{path}:{line_number}: invalid window_end"
                    ) from error
                if not math.isfinite(window_end):
                    raise ValueError(f"{path}:{line_number}: invalid window_end")
                if marker_started_at is not None and window_end < marker_started_at:
                    excluded_before_marker += 1
                    continue
                if marker is not None and (
                    record.get("run_id") != marker.get("run_id")
                    or record.get("model_manifest_sha256")
                    != marker.get("model_manifest_sha256")
                    or record.get("decision_policy_sha256")
                    != marker.get("decision_policy_sha256")
                ):
                    raise ValueError(
                        f"{path}:{line_number}: decision identity differs from soak marker"
                    )
                status_counts[status] += 1
                scored_rows += 1
                workload = str(record.get("workload_key", "unknown"))
                source_key = (workload, str(record.get("cgroup_id", "unknown")))

                instant_candidate = bool(
                    record.get("raw_model_anomalous") is True
                    and record.get("semantic_corroborated") is True
                    and record.get("score_corroborated") is True
                )
                groups = triggered_groups(record)
                projected_alert = False
                if instant_candidate and groups & bypass_groups:
                    projected_alert = True
                    pending.pop(source_key, None)
                elif instant_candidate and groups:
                    previous = pending.get(source_key)
                    if (
                        previous is not None
                        and 0.0 < window_end - previous["window_end"]
                        <= maximum_gap_seconds
                        and groups & previous["groups"]
                    ):
                        count = previous["count"] + 1
                    else:
                        count = 1
                    pending[source_key] = {
                        "window_end": window_end,
                        "groups": groups,
                        "count": count,
                    }
                    projected_alert = count >= required_consecutive_windows
                else:
                    pending.pop(source_key, None)

                if status == "alert":
                    original_alerts += 1
                    if not projected_alert:
                        original_alerts_suppressed += 1
                if projected_alert:
                    projected_alerts += 1
                    projected_alerts_by_workload[workload] += 1
                    projected_status_counts["alert"] += 1
                elif record.get("raw_model_anomalous") is True:
                    projected_status_counts["suppressed"] += 1
                else:
                    projected_status_counts["normal"] += 1
        sources.append(
            {
                "path": str(path),
                "sha256": sha256_file(path),
                "rows": rows,
            }
        )

    return {
        "schema": "sentinel-pulse-temporal-confirmation-development-replay-v1",
        "normal_only_development_evidence": True,
        "attack_outcomes_used": False,
        "soak_marker_sha256": (
            sha256_file(soak_marker_path) if soak_marker_path is not None else None
        ),
        "soak_marker_identity_gate": marker is not None,
        "excluded_scored_windows_before_marker": excluded_before_marker,
        "sources": sources,
        "required_consecutive_windows": required_consecutive_windows,
        "maximum_gap_seconds": maximum_gap_seconds,
        "bypass_groups": sorted(bypass_groups),
        "scored_rows": scored_rows,
        "status_counts": dict(sorted(status_counts.items())),
        "projected_status_counts": dict(sorted(projected_status_counts.items())),
        "original_alerts": original_alerts,
        "projected_alerts": projected_alerts,
        "original_alerts_suppressed": original_alerts_suppressed,
        "projected_alerts_by_workload": dict(
            sorted(projected_alerts_by_workload.items())
        ),
        "latency_cost_contract": {
            "additional_windows_for_non_bypass_groups": (
                required_consecutive_windows - 1
            ),
            "attack_latency_not_estimated_from_normal_evidence": True,
            "blind_live_latency_gate_still_required": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--required-consecutive-windows", type=int, default=2)
    parser.add_argument("--maximum-gap-seconds", type=float, default=1.75)
    parser.add_argument("--soak-marker", type=Path)
    parser.add_argument(
        "--bypass-group", action="append", default=["namespace_probe"]
    )
    args = parser.parse_args()
    report = evaluate(
        args.decisions,
        args.required_consecutive_windows,
        args.maximum_gap_seconds,
        frozenset(args.bypass_group),
        args.soak_marker,
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
