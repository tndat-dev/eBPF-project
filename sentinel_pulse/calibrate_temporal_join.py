"""Replay normal-only decisions to calibrate bounded event-time joins.

This utility never consumes attack labels.  It projects how often a recent
model anomaly (already past the score gate) and semantic evidence would join
within each predeclared horizon, while preserving source identity, temporal
gaps, and consume-on-alert behavior used by the live runtime.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path

from .integrity import sha256_file


SCHEMA = "sentinel-pulse-temporal-calibration-v1"


def _identity(record: dict) -> tuple[str, ...]:
    fields = ("workload_key", "node_name", "pod_uid", "container_name", "cgroup_id")
    values = tuple(str(record.get(field, "")) for field in fields)
    if any(not value for value in values):
        raise ValueError("normal decision is missing source identity")
    return values


def calibrate(
    paths: list[Path],
    horizons: list[float],
    *,
    maximum_contiguous_gap_seconds: float,
    expected_model_sha256: str | None = None,
    expected_policy_sha256: str | None = None,
    eligible_semantic_signal_groups: list[str] | None = None,
    evidence_checksums_path: Path | None = None,
) -> dict:
    if not paths:
        raise ValueError("at least one normal decision stream is required")
    normalized_horizons = sorted(set(float(value) for value in horizons))
    if (
        not normalized_horizons
        or any(not math.isfinite(value) or value <= 0.0 or value > 2.0 for value in normalized_horizons)
        or not math.isfinite(maximum_contiguous_gap_seconds)
        or maximum_contiguous_gap_seconds <= 0.0
    ):
        raise ValueError("temporal calibration horizon/gap contract is invalid")
    eligible_groups = (
        sorted(set(eligible_semantic_signal_groups))
        if eligible_semantic_signal_groups is not None
        else None
    )
    if eligible_groups is not None and (
        not eligible_groups
        or len(eligible_groups) != len(eligible_semantic_signal_groups)
    ):
        raise ValueError("eligible temporal semantic groups must be non-empty and unique")
    evidence_checksums_sha256 = None
    if evidence_checksums_path is not None:
        evidence_root = evidence_checksums_path.parent.resolve()
        expected = {}
        for line in evidence_checksums_path.read_text(encoding="ascii").splitlines():
            digest, separator, relative = line.partition("  ")
            relative = relative.removeprefix("./")
            if (
                not separator
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                or not relative
                or relative in expected
            ):
                raise ValueError("normal evidence checksum index is malformed")
            expected[relative] = digest
        for path in paths:
            try:
                relative = path.resolve().relative_to(evidence_root).as_posix()
            except ValueError as error:
                raise ValueError("normal decision is outside evidence bundle") from error
            if expected.get(relative) != sha256_file(path):
                raise ValueError("normal decision checksum is missing or mismatched")
        evidence_checksums_sha256 = sha256_file(evidence_checksums_path)

    state = {horizon: {} for horizon in normalized_horizons}
    projected = {horizon: [] for horizon in normalized_horizons}
    previous_end: dict[tuple[str, ...], float] = {}
    model_ids: set[str] = set()
    policy_ids: set[str] = set()
    run_ids: set[str] = set()
    records = scored = warming = baseline_alerts = 0

    for path in paths:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                record = json.loads(line)
                if record.get("schema") != "sentinel-pulse-decision-v1":
                    continue
                records += 1
                if record.get("injection_id") is not None:
                    raise ValueError(
                        f"attack-attributed decision in normal evidence: {path}:{line_number}"
                    )
                model_ids.add(str(record.get("model_manifest_sha256", "")))
                policy_ids.add(str(record.get("decision_policy_sha256", "")))
                run_ids.add(str(record.get("run_id", "")))
                status = record.get("status")
                if status == "collect-only":
                    raise ValueError("normal calibration contains collect-only decisions")
                # The frozen A2 canary predates full provenance on warming
                # records.  Warming rows are never scored and cannot carry
                # model/semantic evidence.  Skip them before source identity
                # validation; the next scored row still clears stale evidence
                # through the measured contiguous-gap contract.  Scored rows
                # remain fail-closed on every identity field.
                if status == "warming":
                    warming += 1
                    continue
                identity = _identity(record)
                window_end = float(record["window_end"])
                if not math.isfinite(window_end):
                    raise ValueError("normal decision has invalid window timestamp")
                previous = previous_end.get(identity)
                if previous is not None and window_end <= previous:
                    raise ValueError("normal decision stream is non-monotonic per source")
                reset = (
                    status == "warming"
                    or previous is None
                    or window_end - previous > maximum_contiguous_gap_seconds
                )
                previous_end[identity] = window_end
                if reset:
                    for horizon in normalized_horizons:
                        state[horizon].pop(identity, None)
                if status not in {"normal", "suppressed", "alert"}:
                    raise ValueError(f"unsupported normal decision status: {status}")
                scored += 1
                baseline_alerts += int(status == "alert")
                model_signal = bool(
                    record.get("raw_model_anomalous")
                    and record.get("score_corroborated")
                )
                semantic_signal = bool(record.get("semantic_corroborated"))
                triggered_groups = {
                    name for name, details in record.get(
                        "semantic_signal_groups", {}
                    ).items() if details.get("triggered") is True
                }
                temporal_semantic_signal = bool(
                    semantic_signal
                    and (
                        eligible_groups is None
                        or triggered_groups & set(eligible_groups)
                    )
                )
                for horizon in normalized_horizons:
                    evidence = state[horizon].setdefault(identity, {})
                    for name in ("model", "semantic"):
                        observed = evidence.get(name)
                        if observed is not None and window_end - observed > horizon:
                            evidence.pop(name, None)
                    if model_signal:
                        evidence["model"] = window_end
                    if temporal_semantic_signal:
                        evidence["semantic"] = window_end
                    same_window_signal = model_signal and semantic_signal
                    if same_window_signal or (
                        "model" in evidence and "semantic" in evidence
                    ):
                        model_window = (
                            window_end if same_window_signal else evidence["model"]
                        )
                        semantic_window = (
                            window_end if same_window_signal else evidence["semantic"]
                        )
                        span = abs(model_window - semantic_window)
                        if span <= horizon:
                            projected[horizon].append({
                                "workload_key": identity[0],
                                "node_name": identity[1],
                                "pod_uid": identity[2],
                                "container_name": identity[3],
                                "cgroup_id": identity[4],
                                "decision_window_end": window_end,
                                "model_evidence_window_end": model_window,
                                "semantic_evidence_window_end": semantic_window,
                                "evidence_span_seconds": span,
                            })
                            state[horizon].pop(identity, None)

    if records == 0 or scored == 0:
        raise ValueError("normal calibration has no scored decisions")
    if len(model_ids) != 1 or "" in model_ids:
        raise ValueError("normal calibration model identity is ambiguous")
    if len(policy_ids) != 1 or "" in policy_ids:
        raise ValueError("normal calibration policy identity is ambiguous")
    if len(run_ids) != 1 or "" in run_ids:
        raise ValueError("normal calibration run identity is ambiguous")
    model_sha256 = next(iter(model_ids))
    policy_sha256 = next(iter(policy_ids))
    if expected_model_sha256 is not None and model_sha256 != expected_model_sha256:
        raise ValueError("normal calibration model identity differs from expected")
    if expected_policy_sha256 is not None and policy_sha256 != expected_policy_sha256:
        raise ValueError("normal calibration policy identity differs from expected")

    return {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evidence_class": "normal_only_temporal_join_calibration",
        "normal_only": True,
        "blind_outcome_used": False,
        "automatic_promotion": False,
        "decision_sources": [
            {"path": str(path), "sha256": sha256_file(path)} for path in paths
        ],
        "model_manifest_sha256": model_sha256,
        "decision_policy_sha256": policy_sha256,
        "run_id": next(iter(run_ids)),
        "maximum_contiguous_gap_seconds": maximum_contiguous_gap_seconds,
        "eligible_semantic_signal_groups": eligible_groups,
        "evidence_checksums_sha256": evidence_checksums_sha256,
        "decision_records": records,
        "scored_decisions": scored,
        "warming_decisions": warming,
        "baseline_alerts": baseline_alerts,
        "horizons": [
            {
                "maximum_evidence_age_seconds": horizon,
                "projected_alerts": len(projected[horizon]),
                "projected_alert_records": projected[horizon],
            }
            for horizon in normalized_horizons
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, action="append", required=True)
    parser.add_argument("--horizon", type=float, action="append", required=True)
    parser.add_argument("--maximum-contiguous-gap-seconds", type=float, default=1.5)
    parser.add_argument("--expected-model-sha256")
    parser.add_argument("--expected-policy-sha256")
    parser.add_argument("--eligible-semantic-group", action="append")
    parser.add_argument("--evidence-checksums", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = calibrate(
        args.decisions,
        args.horizon,
        maximum_contiguous_gap_seconds=args.maximum_contiguous_gap_seconds,
        expected_model_sha256=args.expected_model_sha256,
        expected_policy_sha256=args.expected_policy_sha256,
        eligible_semantic_signal_groups=args.eligible_semantic_group,
        evidence_checksums_path=args.evidence_checksums,
    )
    if args.output.exists():
        raise ValueError(f"refusing to overwrite temporal calibration: {args.output}")
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
