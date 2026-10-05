"""Exposure-based operational evaluation, distinct from the legacy zero-alert gate."""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime
import json
import math
from pathlib import Path

from .evaluate_normal import evaluate, SCORED_STATUSES
from .integrity import sha256_file
from .operational_soak import digest, load_binding, merge_intervals, observe


def poisson_rate_interval(count: int, hours: float) -> list[float] | None:
    # Descriptive equal-tail 95% interval, CONDITIONAL on Poisson assumptions.
    # Correlated alert bursts need block-bootstrap analysis; not a gate here.
    if hours <= 0:
        return None
    from scipy.stats import chi2
    return [float(chi2.ppf(0.025, 2 * count) / (2 * hours)) if count else 0.0,
            float(chi2.ppf(0.975, 2 * (count + 1)) / (2 * hours))]


def evaluate_operational(marker_path: Path, health_path: Path, decision_paths: list[Path],
                         manifest_path: Path, telemetry_path: Path) -> dict:
    marker, binding = load_binding(marker_path)
    profile = binding["profile"]
    if len({p.resolve() for p in decision_paths}) != len(decision_paths):
        raise ValueError("duplicate decision path")
    strict = evaluate(decision_paths, maximum_alerts=0, soak_marker_path=marker_path,
                      model_manifest_path=manifest_path)
    if strict["expected_workloads"] != binding["expected_workloads"]:
        raise ValueError("dependency scope differs from model manifest")
    health = [json.loads(line) for line in health_path.read_text().splitlines()]
    if not health:
        raise ValueError("missing operational health observations")
    started = datetime.fromisoformat(marker["started_not_before"]).timestamp()
    previous = started
    replay = []
    for row in health:
        checked = float(row["checked_at_unix"])
        if (row.get("binding_sha256") != digest(binding) or not math.isfinite(checked)
                or not 0 < checked - previous <= profile["maximum_health_observation_gap_seconds"]):
            raise ValueError("health identity/order/observation gap mismatch")
        expected = observe(binding, replay, {k: row[k] for k in ("fatal", "transient", "warnings")}, checked, started)
        if any(row.get(k) != expected[k] for k in ("degraded", "outage_started_at", "excluded_interval", "excluded_seconds")):
            raise ValueError("degraded interval log does not match preregistered policy")
        replay.append(row)
        previous = checked
    excluded = merge_intervals([r["excluded_interval"] for r in health if r.get("excluded_interval")])
    exclusion_ends = [end for _, end in excluded]
    intervals = defaultdict(list)
    alerts, degraded_alerts, statuses = Counter(), Counter(), Counter()
    rejected_cadence = Counter()
    total_end = started
    for path in decision_paths:
        last_end = {}
        with path.open() as stream:
            for line in stream:
                row = json.loads(line)
                if row.get("schema") != "sentinel-pulse-decision-v1":
                    continue
                status = row.get("status")
                if status not in SCORED_STATUSES | {"warming"}:
                    raise ValueError("unsupported operational decision status")
                end = float(row["window_end"])
                if end < started:
                    continue
                key = row["workload_key"]
                if (key not in binding["expected_workloads"]
                        or row.get("model_manifest_sha256") != marker["model_manifest_sha256"]
                        or row.get("decision_policy_sha256") != marker["decision_policy_sha256"]
                        or row.get("run_id") != marker["run_id"]
                        or row.get("node_name") not in binding["worker_nodes"]):
                    raise ValueError("operational decision identity mismatch")
                begin = float(row["window_start"])
                if not all(math.isfinite(v) for v in (begin, end)) or begin >= end:
                    raise ValueError("invalid operational decision window")
                source = (key, row.get("pod_uid"), row.get("cgroup_id"))
                if source in last_end and end <= last_end[source]:
                    raise ValueError("duplicate/non-monotonic decision window")
                last_end[source] = end
                total_end = max(total_end, end)
                if end > started + marker["registered_collector_duration_seconds"] + 10:
                    raise ValueError("decision outside registered capture duration")
                statuses[status] += 1
                # Exclude any overlapping interval, including recovery padding.
                index = bisect_right(exclusion_ends, begin)
                degraded = (index < len(excluded) and excluded[index][0] < end)
                if status == "alert":
                    alerts[key] += 1  # Never discard an alert to improve the gate.
                    if degraded:
                        degraded_alerts[key] += 1
                if end - begin > 0.8:
                    rejected_cadence[key] += 1
                    continue
                if status in SCORED_STATUSES and not degraded and begin >= started:
                    intervals[key].append([begin, end])
    telemetry = json.loads(telemetry_path.read_text())
    telemetry_gate = (telemetry.get("valid") is True and telemetry.get("run_id") == marker["run_id"]
                      and telemetry.get("contract") == marker["telemetry_availability_contract"]
                      and len(telemetry.get("nodes", {})) == 3
                      and all(n.get("valid") is True for n in telemetry["nodes"].values()))
    health_gate = (not any(r.get("fatal") for r in health) and not health[-1]["degraded"]
                   and abs(total_end - health[-1]["checked_at_unix"]) <= profile["maximum_health_observation_gap_seconds"]
                   and sum(b - a for a, b in excluded) <= profile["maximum_excluded_seconds"])
    workloads = {}
    for key in binding["expected_workloads"]:
        merged = merge_intervals(intervals[key])
        hours = sum(end - begin for begin, end in merged) / 3600
        rate = alerts[key] / hours if hours else None
        workloads[key] = {"valid_scored_exposure_hours": hours, "all_alerts": alerts[key],
                          "alerts_during_degraded": degraded_alerts[key],
                          "outside_cadence_windows": rejected_cadence[key],
                          "all_alerts_per_valid_workload_hour": rate,
                          "poisson_rate_interval_95_assumption_dependent": poisson_rate_interval(alerts[key], hours),
                          "exposure_gate": hours >= marker["minimum_duration_hours_per_workload"],
                          "rate_gate": rate is not None and rate <= profile["maximum_alerts_per_hour_per_workload"]}
    hours = sum(w["valid_scored_exposure_hours"] for w in workloads.values())
    count = sum(alerts.values())
    rate = count / hours if hours else None
    identity_gate = all(strict.get(k) is True for k in (
        "model_identity_gate", "model_manifest_gate", "expected_workload_gate",
        "decision_policy_identity_gate", "run_identity_gate", "soak_marker_gate"))
    gate = (identity_gate and telemetry_gate and health_gate
            and all(w["exposure_gate"] and w["rate_gate"] for w in workloads.values())
            and rate is not None and rate <= profile["maximum_alerts_per_workload_hour"])
    return {"schema": "sentinel-pulse-operational-soak-report-v1", "run_id": marker["run_id"],
            "soak_marker_sha256": sha256_file(marker_path), "health_log_sha256": sha256_file(health_path),
            "telemetry_report_sha256": sha256_file(telemetry_path),
            "operational_contract_sha256": digest(binding), "decision_files": strict["decision_files"],
            "legacy_zero_alert_normal_gate": strict["normal_gate"],
            "operational_normal_gate": gate, "identity_gate": identity_gate,
            "telemetry_gate": telemetry_gate, "health_gate": health_gate,
            "total_valid_workload_hours": hours, "all_alerts": count,
            "all_alerts_per_valid_workload_hour": rate,
            "poisson_rate_interval_95_assumption_dependent": poisson_rate_interval(count, hours),
            "excluded_intervals": excluded, "workloads": workloads, "statuses": dict(statuses),
            "profile": profile, "automatic_promotion": False, "automatic_blind_evaluation": False,
            "false_positive_ground_truth_adjudicated": False,
            "confidence_interval_is_acceptance_gate": False,
            "kernel_to_alert_claim_allowed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--health-log", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, action="append", required=True)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--telemetry-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("refusing to overwrite operational report")
    result = evaluate_operational(args.marker, args.health_log, args.decisions, args.model_manifest, args.telemetry_report)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n")
    raise SystemExit(0 if result["operational_normal_gate"] else 1)


if __name__ == "__main__":
    main()
