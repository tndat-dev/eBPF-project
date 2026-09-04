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
    evidence_checksums_path: Path | None = None,
    expected_model_sha256: str | None = None,
    expected_policy_sha256: str | None = None,
    required_consecutive_windows_by_group: dict[str, int] | None = None,
    bounded_join_groups: frozenset[str] | None = None,
    maximum_evidence_age_seconds: float = 1.0,
) -> dict:
    if not paths:
        raise ValueError("at least one decision source is required")
    if required_consecutive_windows < 2:
        raise ValueError("temporal confirmation requires at least two windows")
    if not math.isfinite(maximum_gap_seconds) or maximum_gap_seconds <= 0.0:
        raise ValueError("maximum temporal confirmation gap must be positive")
    if not bypass_groups:
        raise ValueError("at least one immediate bypass group is required")
    per_group_windows = required_consecutive_windows_by_group or {}
    if any(
        not isinstance(group, str)
        or not group
        or isinstance(value, bool)
        or not isinstance(value, int)
        or value < 2
        or value > 4
        for group, value in per_group_windows.items()
    ):
        raise ValueError("per-group temporal confirmation requirements are invalid")
    if set(per_group_windows) & set(bypass_groups):
        raise ValueError("a bypass group cannot also require temporal confirmation")
    if bounded_join_groups is not None and (
        not bounded_join_groups
        or not math.isfinite(maximum_evidence_age_seconds)
        or maximum_evidence_age_seconds <= 0.0
        or maximum_evidence_age_seconds > 2.0
    ):
        raise ValueError("bounded join evidence age must be in (0, 2]")
    if (expected_model_sha256 is None) != (expected_policy_sha256 is None):
        raise ValueError("expected model and policy identities must be supplied together")

    evidence_checksums_sha256 = None
    if evidence_checksums_path is not None:
        evidence_root = evidence_checksums_path.parent.resolve()
        expected_files = {}
        for line in evidence_checksums_path.read_text(encoding="ascii").splitlines():
            digest, separator, relative = line.partition("  ")
            relative = relative.removeprefix("./")
            if (
                not separator
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                or not relative
                or relative in expected_files
            ):
                raise ValueError("normal evidence checksum index is malformed")
            expected_files[relative] = digest
        for path in paths:
            try:
                relative = path.resolve().relative_to(evidence_root).as_posix()
            except ValueError as error:
                raise ValueError("normal decision is outside evidence bundle") from error
            if expected_files.get(relative) != sha256_file(path):
                raise ValueError("normal decision checksum is missing or mismatched")
        evidence_checksums_sha256 = sha256_file(evidence_checksums_path)

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
    model_ids: set[str] = set()
    policy_ids: set[str] = set()
    run_ids: set[str] = set()

    for path in paths:
        pending: dict[tuple[str, ...], dict] = {}
        bounded_pending: dict[tuple[str, ...], dict] = {}
        rows = 0
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"{path}:{line_number}: invalid JSON") from error
                rows += 1
                status = str(record.get("status", "unknown"))
                if any(
                    key in record
                    for key in ("injection_id", "attack_injected_at", "scenario_id")
                ):
                    raise ValueError("attack-attributed decision in normal evidence")
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
                model_ids.add(str(record.get("model_manifest_sha256", "")))
                policy_ids.add(str(record.get("decision_policy_sha256", "")))
                run_ids.add(str(record.get("run_id", "")))
                if expected_model_sha256 is not None:
                    identity_fields = (
                        workload,
                        str(record.get("node_name", "")),
                        str(record.get("pod_uid", "")),
                        str(record.get("container_name", "")),
                        str(record.get("cgroup_id", "")),
                    )
                    if any(not value for value in identity_fields):
                        raise ValueError("normal decision is missing source identity")
                    source_key = identity_fields
                else:
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
                    contiguous = (
                        previous is not None
                        and 0.0 < window_end - previous["window_end"]
                        <= maximum_gap_seconds
                    )
                    previous_counts = (
                        previous.get("group_counts", {}) if contiguous else {}
                    )
                    group_counts = {
                        group: int(previous_counts.get(group, 0)) + 1
                        for group in groups
                    }
                    pending[source_key] = {
                        "window_end": window_end,
                        "groups": groups,
                        "count": max(group_counts.values()),
                        "group_counts": group_counts,
                    }
                    projected_alert = any(
                        group_counts[group]
                        >= per_group_windows.get(group, required_consecutive_windows)
                        for group in groups
                    )
                    if projected_alert:
                        pending.pop(source_key, None)
                else:
                    pending.pop(source_key, None)

                bounded_alert = False
                if bounded_join_groups is not None:
                    evidence = bounded_pending.setdefault(source_key, {})
                    for name in ("model", "semantic"):
                        item = evidence.get(name)
                        if (
                            item is not None
                            and window_end - float(item["window_end"])
                            > maximum_evidence_age_seconds
                        ):
                            evidence.pop(name, None)
                    if (
                        record.get("raw_model_anomalous") is True
                        and record.get("score_corroborated") is True
                    ):
                        evidence["model"] = {"window_end": window_end}
                    if (
                        record.get("semantic_corroborated") is True
                        and groups & bounded_join_groups
                    ):
                        evidence["semantic"] = {"window_end": window_end}
                    model_evidence = evidence.get("model")
                    semantic_evidence = evidence.get("semantic")
                    bounded_alert = bool(
                        model_evidence is not None
                        and semantic_evidence is not None
                        and abs(
                            float(model_evidence["window_end"])
                            - float(semantic_evidence["window_end"])
                        )
                        <= maximum_evidence_age_seconds
                    )
                    if projected_alert or bounded_alert:
                        bounded_pending.pop(source_key, None)
                projected_alert = projected_alert or bounded_alert

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

    model_sha256 = policy_sha256 = run_id = None
    if expected_model_sha256 is not None:
        if len(model_ids) != 1 or "" in model_ids:
            raise ValueError("normal confirmation model identity is ambiguous")
        if len(policy_ids) != 1 or "" in policy_ids:
            raise ValueError("normal confirmation policy identity is ambiguous")
        if len(run_ids) != 1 or "" in run_ids:
            raise ValueError("normal confirmation run identity is ambiguous")
        model_sha256 = next(iter(model_ids))
        policy_sha256 = next(iter(policy_ids))
        run_id = next(iter(run_ids))
        if model_sha256 != expected_model_sha256:
            raise ValueError("normal confirmation model identity differs from expected")
        if policy_sha256 != expected_policy_sha256:
            raise ValueError("normal confirmation policy identity differs from expected")

    return {
        "schema": "sentinel-pulse-temporal-confirmation-development-replay-v1",
        "normal_only_development_evidence": True,
        "attack_outcomes_used": False,
        "automatic_promotion": False,
        "evidence_checksums_sha256": evidence_checksums_sha256,
        "model_manifest_sha256": model_sha256,
        "decision_policy_sha256": policy_sha256,
        "run_id": run_id,
        "soak_marker_sha256": (
            sha256_file(soak_marker_path) if soak_marker_path is not None else None
        ),
        "soak_marker_identity_gate": marker is not None,
        "excluded_scored_windows_before_marker": excluded_before_marker,
        "sources": sources,
        "required_consecutive_windows": required_consecutive_windows,
        "required_consecutive_windows_by_group": dict(sorted(per_group_windows.items())),
        "maximum_gap_seconds": maximum_gap_seconds,
        "bypass_groups": sorted(bypass_groups),
        "bounded_event_time_groups": (
            sorted(bounded_join_groups) if bounded_join_groups is not None else None
        ),
        "maximum_evidence_age_seconds": (
            maximum_evidence_age_seconds if bounded_join_groups is not None else None
        ),
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
            "maximum_additional_windows_for_overridden_groups": max(
                (value - 1 for value in per_group_windows.values()), default=0
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
    parser.add_argument("--evidence-checksums", type=Path)
    parser.add_argument("--expected-model-sha256")
    parser.add_argument("--expected-policy-sha256")
    parser.add_argument(
        "--group-required-windows",
        action="append",
        default=[],
        metavar="GROUP=WINDOWS",
    )
    parser.add_argument(
        "--bypass-group", action="append", default=["namespace_probe"]
    )
    parser.add_argument("--bounded-join-group", action="append")
    parser.add_argument("--maximum-evidence-age-seconds", type=float, default=1.0)
    args = parser.parse_args()
    group_requirements = {}
    for item in args.group_required_windows:
        group, separator, value = item.partition("=")
        if not separator or group in group_requirements:
            parser.error("--group-required-windows must be unique GROUP=WINDOWS values")
        try:
            group_requirements[group] = int(value)
        except ValueError:
            parser.error("--group-required-windows WINDOWS must be an integer")
    report = evaluate(
        args.decisions,
        args.required_consecutive_windows,
        args.maximum_gap_seconds,
        frozenset(args.bypass_group),
        args.soak_marker,
        args.evidence_checksums,
        args.expected_model_sha256,
        args.expected_policy_sha256,
        group_requirements,
        (
            frozenset(args.bounded_join_group)
            if args.bounded_join_group is not None
            else None
        ),
        args.maximum_evidence_age_seconds,
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
