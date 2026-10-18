"""Aggregate sealed exact-ID captures without ranking or promoting features."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path

from .common import atomic_json
from .syscall_histogram_analysis import summarize


def aggregate(capture_dirs: list[Path]) -> dict:
    if not capture_dirs:
        raise ValueError("provide at least one capture directory")
    reports = []
    errors = []
    seen_paths = set()
    for capture_dir in capture_dirs:
        path = capture_dir.resolve()
        if path in seen_paths:
            errors.append({"capture_dir": str(path), "reason": "duplicate_input_path"})
            continue
        seen_paths.add(path)
        try:
            report = summarize(path)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            errors.append({"capture_dir": str(path), "reason": str(exc)})
            continue
        reports.append((path, report))

    by_run: dict[str, list[int]] = defaultdict(list)
    for index, (_path, report) in enumerate(reports):
        by_run[str(report.get("run_id"))].append(index)
    duplicate_run_indices = set()
    for run_id, indices in by_run.items():
        if len(indices) > 1:
            duplicate_run_indices.update(indices)
            errors.append({"run_id": run_id, "reason": "duplicate_run_id"})

    overlapping = set()
    for left in range(len(reports)):
        left_report = reports[left][1]
        left_start, left_end = left_report.get("probe_started_at_unix"), left_report.get("probe_ended_at_unix")
        if not all(isinstance(value, (int, float)) and math.isfinite(value)
                   for value in (left_start, left_end)):
            continue
        for right in range(left + 1, len(reports)):
            right_report = reports[right][1]
            if left_report.get("node_name") != right_report.get("node_name"):
                continue
            right_start, right_end = right_report.get("probe_started_at_unix"), right_report.get("probe_ended_at_unix")
            if not all(isinstance(value, (int, float)) and math.isfinite(value)
                       for value in (right_start, right_end)):
                continue
            if left_start < right_end and right_start < left_end:
                overlapping.update((left, right))
                errors.append({"run_ids": [left_report.get("run_id"), right_report.get("run_id")],
                               "node_name": left_report.get("node_name"),
                               "reason": "overlapping_probe_runs_on_same_node"})

    excluded = []
    accepted = []
    for index, (path, report) in enumerate(reports):
        reason = None
        if index in overlapping:
            reason = "overlapping_probe_runs_on_same_node"
        elif index in duplicate_run_indices:
            reason = "duplicate_run_id"
        elif not report.get("capture_valid_for_feature_selection"):
            reason = "capture_not_eligible_for_feature_selection"
        if reason:
            excluded.append({"capture_dir": str(path), "run_id": report.get("run_id"),
                             "reason": reason, "integrity": report.get("integrity")})
        else:
            accepted.append((path, report))

    grouped = defaultdict(lambda: {
        "syscall_counts": Counter(), "observed_container_seconds": 0.0,
        "interval_records": 0, "captures": set(), "nodes": set(), "pod_uids": set(),
        "per_capture_rates": [],
    })
    for path, report in accepted:
        for workload in report.get("workloads", {}).values():
            identity = workload["identity"]
            static = (identity.get("namespace"), identity.get("workload_name"),
                      identity.get("container_name"), identity.get("workload_revision"),
                      report.get("architecture"), report.get("process_abi_scope"), report.get("kernel"))
            for regime, details in workload.get("by_regime", {}).items():
                key = static + (regime,)
                target = grouped[key]
                target["observed_container_seconds"] += details["observed_container_seconds"]
                target["interval_records"] += details["interval_records"]
                target["captures"].add(report.get("run_id"))
                target["nodes"].add(identity.get("node_name"))
                target["pod_uids"].add(identity.get("pod_uid"))
                target["syscall_counts"].update({item["id"]: item["count"]
                                                 for item in details["syscall_ids"]})
                seconds = details["observed_container_seconds"]
                total = details["syscall_total"]
                target["per_capture_rates"].append({
                    "run_id": report.get("run_id"),
                    "syscalls_per_container_second": total / seconds if seconds else None,
                })

    summaries = []
    for key, value in sorted(grouped.items(), key=lambda item: tuple(str(v) for v in item[0])):
        (namespace, workload_name, container_name, revision,
         architecture, abi_scope, kernel, regime) = key
        total = sum(value["syscall_counts"].values())
        seconds = value["observed_container_seconds"]
        summaries.append({
            "namespace": namespace, "workload_name": workload_name,
            "container_name": container_name, "workload_revision": revision,
            "architecture": architecture, "process_abi_scope": abi_scope,
            "kernel": kernel, "traffic_regime": regime,
            "syscall_total": total,
            "observed_container_seconds": seconds,
            "interval_records": value["interval_records"],
            "capture_count": len(value["captures"]),
            "node_count": len(value["nodes"]), "nodes": sorted(value["nodes"]),
            "pod_replica_count": len(value["pod_uids"]),
            "syscall_ids": [
                {"id": syscall_id, "count": count,
                 "share": count / total if total else 0.0,
                 "per_container_second": count / seconds if seconds else None}
                for syscall_id, count in value["syscall_counts"].most_common()
            ],
            "per_capture_rates": value["per_capture_rates"],
        })

    return {
        "schema": "sentinel-pulse-syscall-histogram-cohort-v1",
        "evidence_class": "descriptive_normal_frequency_only",
        "input_capture_count": len(capture_dirs),
        "verified_capture_count": len(reports),
        "eligible_capture_count": len(accepted),
        "excluded_capture_count": len(excluded),
        "selection_rank_allowed": False,
        "automatic_feature_selection": False,
        "captures": [{"capture_dir": str(path), "run_id": report.get("run_id"),
                      "capture_sha256": report.get("capture_sha256"),
                      "valid_for_selection": report.get("capture_valid_for_feature_selection")}
                     for path, report in reports],
        "excluded_captures": excluded,
        "input_errors": errors,
        "workload_revision_regime_summaries": summaries,
        "interpretation": [
            "Counts are syscall-entry observations, not successful syscall outcomes.",
            "Rates are weighted by observed container-seconds; per-capture rates are exposed to show heterogeneity.",
            "This descriptive frequency summary does not establish feature importance, attack recall, precision, or causality.",
            "Do not rank/select syscall features from blind, test, or attack data.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", action="append", required=True, type=Path,
                        help="sealed capture directory; repeat for independent runs")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    atomic_json(args.output, aggregate(args.capture_dir))


if __name__ == "__main__":
    main()
