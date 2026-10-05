"""Evaluate runtime plumbing only; never a formal soak/accuracy verdict."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path

from .integrity import sha256_file
from .recovery_deployment import bind_detector
from .telemetry_recovery import digest, load_profile
from .detector_freshness import CONTRACT, check as check_freshness, complete as complete_freshness
from .audit_recovery_smoke_latency import quantiles
from .validate_recovery_capture import validate


def source_key(row: dict) -> tuple:
    return (row["node_name"], row["pod_uid"], row["container_name"],
            str(row["cgroup_id"]), row["window_start"], row["window_end"])


def evaluate(root: Path, profile_path: Path, model: str, policy: str,
             expected_live_freshness: bool = False) -> dict:
    profile = load_profile(profile_path)
    binding = bind_detector(root / "features.jsonl", profile_path)
    if binding is None:
        raise ValueError("smoke requires registered recovery capture")
    capture = validate(root / "features.jsonl", profile)
    errors = list(capture["errors"])
    prereg_path = Path("/var/lib/sentinel-pulse-recovery-smoke") / root.name / "START.json"
    registered = json.loads(prereg_path.read_text()) if prereg_path.exists() else {}
    fault = registered.get("controlled_fault")
    fault_review = None
    if fault is not None:
        from .controlled_collector_pause import validate_event
        try:
            fault_review = validate_event(root, registered, prereg_path)
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append("controlled fault validation: " + str(error))
    freshness_path = root / "DETECTOR_FRESHNESS_CONTRACT.json"
    freshness_enabled = freshness_path.exists()
    if expected_live_freshness and not freshness_enabled:
        errors.append("missing preregistered detector freshness contract")
    if freshness_enabled and json.loads(freshness_path.read_text()) != CONTRACT:
        errors.append("detector freshness contract differs from frozen implementation")
    features = {}
    with (root / "features.jsonl").open() as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("schema") == "sentinel-pulse-feature-v1":
                key = source_key(row)
                if key in features:
                    errors.append("duplicate source feature")
                features[key] = (row["workload_key"], row["telemetry_recovery"], row["emitted_at"])
    counts, scored, alert_rows = Counter(), Counter(), Counter()
    seen, previous = set(), {}
    freshness_counts, completed_lags = Counter(), []
    previous_checked_at = None
    with (root / "decisions.jsonl").open() as stream:
        for line in stream:
            row = json.loads(line)
            try:
                if (row.get("schema") != "sentinel-pulse-decision-v1"
                        or row.get("run_id") != root.name
                        or row.get("model_manifest_sha256") != model
                        or row.get("decision_policy_sha256") != policy):
                    raise ValueError("decision run/model/policy identity mismatch")
                key = source_key(row)
                feature = features.get(key)
                if feature is None or feature[:2] != (row["workload_key"], row.get("telemetry_recovery")) or key in seen:
                    raise ValueError("decision/feature recovery binding mismatch or duplicate")
                seen.add(key)
                identity = key[:4]
                if key[-1] <= previous.get(identity, -math.inf):
                    raise ValueError("non-monotonic decision timestamp")
                previous[identity] = key[-1]
                status = row["status"]
                if freshness_enabled:
                    meta = row["detector_freshness"]
                    replay = check_freshness({"window_end": row["window_end"], "emitted_at": feature[2]},
                                             meta["checked_at"], previous_checked_at)
                    replay = complete_freshness(replay, row["window_end"], meta["decision_completed_at"])
                    if replay != meta:
                        raise ValueError("detector freshness audit differs from independent replay")
                    previous_checked_at = meta["checked_at"]
                    if not meta["eligible"]:
                        if status not in {"telemetry-degraded", "collect-only", "rebaseline-required"} or "inference_ms" in row:
                            raise ValueError("stale detector queue item entered inference/history")
                    freshness_counts[meta["reason"]] += 1
                elif "detector_freshness" in row:
                    raise ValueError("unbound detector freshness decision")
                if status not in {"normal", "alert", "suppressed", "warming", "telemetry-degraded"}:
                    raise ValueError("unsupported recovery smoke decision status")
                if status in {"normal", "alert", "suppressed"}:
                    if not feature[1]["eligible"]:
                        raise ValueError("inference on quarantined feature")
                    for field in ("score", "conformal_p", "inference_ms", "post_window_processing_seconds"):
                        value = row[field]
                        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                            raise ValueError("invalid scored decision metric")
                    if not 0 <= row["conformal_p"] <= 1 or row["inference_ms"] < 0 or row["post_window_processing_seconds"] < 0:
                        raise ValueError("invalid scored decision metric range")
                    scored[row["workload_key"]] += 1
                    if freshness_enabled:
                        completed_lags.append(row["detector_freshness"]["window_end_to_decision_completed_seconds"])
                counts[status] += 1
                if status == "alert":
                    alert_rows[digest(row)] += 1
            except (ValueError, KeyError, TypeError) as error:
                errors.append(str(error))
    recorded_alerts = Counter()
    with (root / "alerts.jsonl").open() as stream:
        for line in stream:
            recorded_alerts[digest(json.loads(line))] += 1
    if recorded_alerts != alert_rows:
        errors.append("alert stream differs from ALL decision alerts")
    if alert_rows:
        errors.append("normal alert observed; retained, never infrastructure-excused")
    if not scored:
        errors.append("no frozen model inference observed")
    if len(features) != len(seen):
        errors.append("unconsumed feature rows: detector did not process every capture feature")
    service = {}
    for line in (root / "detector-before-stop.systemd").read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            service[key] = value
    if (service.get("ActiveState") != "active" or service.get("Result") != "success"
            or service.get("ExecMainStatus") != "0" or service.get("NRestarts") != "0"):
        errors.append("detector service failure/restart")
    collector = dict(line.split("=", 1) for line in
                     (root / "collector-before-stop.systemd").read_text().splitlines() if "=" in line)
    if (collector.get("ActiveState") != "inactive" or collector.get("Result") != "success"
            or collector.get("ExecMainStatus") != "0"):
        errors.append("collector did not complete its registered duration successfully")
    return {"schema": "sentinel-pulse-recovery-runtime-smoke-v1", "run_id": root.name,
            "runtime_smoke_valid": not errors, "errors": errors[:200],
            "model_manifest_sha256": model, "decision_policy_sha256": policy,
            "profile_sha256": digest(profile), "capture": capture,
            "decision_statuses": dict(counts), "scored_rows_by_workload": dict(scored),
            "alerts": sum(alert_rows.values()), "recorded_alerts": sum(recorded_alerts.values()),
            "unconsumed_feature_rows": len(features) - len(seen),
            "detector_live_freshness_enabled": freshness_enabled,
            "detector_freshness_counts": dict(freshness_counts),
            "controlled_fault_registered": fault is not None,
            "controlled_fault_review": fault_review,
            "window_end_to_decision_completed_seconds": quantiles(completed_lags),
            "latency_scope": "decision completed after policy, before serialization/output flush; not kernel-to-alert",
            "decisions_sha256": sha256_file(root / "decisions.jsonl"),
            "alerts_sha256": sha256_file(root / "alerts.jsonl"),
            "legacy_normal_pass": False, "operational_soak_pass": False,
            "accuracy_claim_allowed": False, "kernel_to_alert_claim_allowed": False,
            "automatic_promotion": False, "automatic_blind_evaluation": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--recovery-profile", required=True, type=Path)
    parser.add_argument("--expected-model", required=True)
    parser.add_argument("--expected-policy", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-live-freshness", action="store_true")
    args = parser.parse_args()
    report = evaluate(args.run_dir, args.recovery_profile, args.expected_model, args.expected_policy,
                      expected_live_freshness=args.expected_live_freshness)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "capture"}, sort_keys=True))
    raise SystemExit(0 if report["runtime_smoke_valid"] else 1)


if __name__ == "__main__":
    main()
