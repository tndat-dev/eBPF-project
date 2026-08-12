#!/usr/bin/env python3
"""Post-hoc construct-validity audit for the frozen V8 attack campaign.

The primary blind outcome is never changed by this audit.  It only reports
whether at least one scenario-specific syscall family was visible in target-pod
feature windows overlapping each injection interval.  This separates model
misses from attacks whose intended syscall was blocked before the Tetragon
observation point, while preserving both outcomes for the paper.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "sentinel-attack-observability-audit/v1"
# Every tuple is a required semantic family; one syscall in each family must be
# visible.  The rules deliberately use names only and never persist arguments.
SCENARIO_FAMILIES: dict[str, tuple[tuple[str, ...], ...]] = {
    "local_socket_beacon": (("connect",),),
    "namespace_probe": (("unshare", "mount", "ptrace"),),
    "process_fanout": (("clone", "clone3", "fork", "vfork"),),
    "identity_transition_probe": (
        ("setuid", "setgid", "setresuid", "setresgid", "capset"),
    ),
    "credential_read_burst": (
        ("open", "openat", "openat2"),
        ("read", "readv", "pread64", "preadv", "preadv2"),
    ),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def contained(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"evidence path escapes attack root: {path}") from error
    if not resolved.is_file():
        raise ValueError(f"evidence file is missing: {resolved}")
    return resolved


def capture_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"capture row {line_number} is not an object")
        rows.append(row)
    return rows


def summarize_capture(path: Path, scenario: str) -> dict[str, Any]:
    rows = capture_rows(path)
    starts = [row for row in rows if row.get("kind") == "injection"]
    ends = [row for row in rows if row.get("kind") == "injection_end"]
    if len(starts) != 1 or len(ends) != 1:
        raise ValueError(f"{path}: exactly one injection interval is required")
    start, end = starts[0], ends[0]
    if start.get("attack_type") != scenario or end.get("attack_type") != scenario:
        raise ValueError(f"{path}: scenario/boundary mismatch")
    if start.get("injection_id") != end.get("injection_id"):
        raise ValueError(f"{path}: injection identity mismatch")
    if int(end.get("attack_exit_code", -1)) != 0:
        raise ValueError(f"{path}: attack process did not exit successfully")
    pod_key = str(start.get("pod_key", ""))
    started, finished = float(start["ts"]), float(end["ts"])
    if not pod_key or finished < started:
        raise ValueError(f"{path}: invalid injection boundary")

    counts: Counter[str] = Counter()
    windows = 0
    event_count = 0
    for row in rows:
        if row.get("kind") != "feature_window" or row.get("pod_key") != pod_key:
            continue
        if float(row.get("window_end", 0.0)) < started:
            continue
        if float(row.get("window_start", 0.0)) > finished:
            continue
        windows += 1
        event_count += int(row.get("event_count", 0))
        for name, value in dict(row.get("syscall_counts", {})).items():
            counts[str(name).lower()] += int(value)

    families = SCENARIO_FAMILIES.get(scenario)
    if families is None:
        raise ValueError(f"unsupported scenario: {scenario}")
    family_evidence = []
    for alternatives in families:
        observed = {name: counts[name] for name in alternatives if counts[name] > 0}
        family_evidence.append({
            "alternatives": list(alternatives),
            "observed_counts": observed,
            "observed": bool(observed),
        })
    return {
        "injection_id": start["injection_id"],
        "pod_key": pod_key,
        "start": started,
        "end": finished,
        "overlapping_target_windows": windows,
        "overlapping_target_events": event_count,
        "semantic_families": family_evidence,
        "semantic_signal_observed": bool(windows) and all(
            item["observed"] for item in family_evidence
        ),
        "arguments_or_payloads_persisted": False,
    }


def breakdown(rows: list[dict[str, Any]], field: str) -> dict[str, dict[str, int]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row[field])].append(row)
    return {
        key: {
            "trials": len(items),
            "observable": sum(bool(item["semantic_signal_observed"]) for item in items),
            "primary_detected": sum(bool(item["primary_detected"]) for item in items),
            "primary_misses": sum(not bool(item["primary_detected"]) for item in items),
            "observable_primary_misses": sum(
                item["semantic_signal_observed"] and not item["primary_detected"]
                for item in items
            ),
        }
        for key, items in sorted(groups.items())
    }


def build_audit(attack_root: Path, expected_trials: int) -> dict[str, Any]:
    root = attack_root.resolve()
    top_path = contained(root / "report.json", root)
    top = read_json(top_path)
    trials = list(top.get("trials", []))
    if int(top.get("completed_trials", -1)) != len(trials):
        raise ValueError("top-level blind report is not terminal")
    if int(top.get("expected_scenario_trials", -1)) != expected_trials:
        raise ValueError("top-level expected scenario count mismatch")
    if int(top.get("total", -1)) != expected_trials:
        raise ValueError("top-level blind report has incomplete primary outcomes")

    outcomes = []
    seen = set()
    for trial in trials:
        report_path = contained(Path(str(trial["report_path"])), root)
        if sha256(report_path) != trial.get("report_sha256"):
            raise ValueError(f"child report digest mismatch: {report_path}")
        report = read_json(report_path)
        workload = str(trial["target"])
        scenario_results = report.get("scenarios")
        if not isinstance(scenario_results, dict):
            raise ValueError(f"child report lacks scenarios: {report_path}")
        for scenario, primary in scenario_results.items():
            if scenario not in SCENARIO_FAMILIES or not isinstance(primary, dict):
                raise ValueError(f"invalid scenario result in {report_path}")
            feature = primary.get("feature_capture")
            if not isinstance(feature, dict):
                raise ValueError(f"scenario lacks feature capture: {report_path}")
            capture = contained(Path(str(feature["path"])), root)
            if sha256(capture) != feature.get("sha256"):
                raise ValueError(f"feature capture digest mismatch: {capture}")
            validation = feature.get("validation", {})
            if validation.get("valid") is not True:
                raise ValueError(f"feature capture is invalid: {capture}")
            privacy = validation.get("privacy_contract", {})
            if any(bool(privacy.get(name)) for name in (
                "arguments", "file_contents", "network_contents", "payloads"
            )):
                raise ValueError(f"privacy contract violated: {capture}")
            observed = summarize_capture(capture, scenario)
            identity = observed["injection_id"]
            if identity in seen:
                raise ValueError(f"duplicate injection identity: {identity}")
            seen.add(identity)
            outcomes.append({
                "injection_id": identity,
                "workload": workload,
                "trial": int(trial["trial"]),
                "seed": int(trial["seed"]),
                "rate": int(trial["rate"]),
                "scenario": scenario,
                "primary_detected": bool(primary.get("detected")),
                "fast_path_expected": bool(primary.get("fast_path_expected")),
                "capture_sha256": feature["sha256"],
                **observed,
            })

    if len(outcomes) != expected_trials:
        raise ValueError(f"observability trial count mismatch: {len(outcomes)}/{expected_trials}")
    primary_detected = sum(item["primary_detected"] for item in outcomes)
    observable = sum(item["semantic_signal_observed"] for item in outcomes)
    observable_misses = sum(
        item["semantic_signal_observed"] and not item["primary_detected"]
        for item in outcomes
    )
    return {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "complete",
        "valid": True,
        "post_hoc_construct_validity_analysis": True,
        "primary_outcomes_redefined": False,
        "attack_root": str(root),
        "source_report": str(top_path),
        "source_report_sha256": sha256(top_path),
        "expected_trials": expected_trials,
        "completed_trials": len(outcomes),
        "summary": {
            "primary_detected": primary_detected,
            "primary_misses": len(outcomes) - primary_detected,
            "semantic_signal_observable": observable,
            "semantic_signal_unobservable": len(outcomes) - observable,
            "observable_primary_misses": observable_misses,
            "unobservable_primary_misses": (
                len(outcomes) - primary_detected - observable_misses
            ),
        },
        "by_scenario": breakdown(outcomes, "scenario"),
        "by_workload": breakdown(outcomes, "workload"),
        "outcomes": outcomes,
        "methodology": {
            "scope": "target-pod feature windows overlapping each injection interval",
            "semantic_family_contract": {
                name: [list(family) for family in families]
                for name, families in SCENARIO_FAMILIES.items()
            },
            "interpretation": (
                "Secondary observability audit only; primary blind detections and misses "
                "remain unchanged. Window overlap can include boundary background events."
            ),
            "labels_used_for_training_or_threshold_tuning": False,
            "raw_arguments_or_payloads_persisted": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-trials", type=int, default=200)
    args = parser.parse_args()
    if args.expected_trials < 1:
        parser.error("--expected-trials must be positive")
    report = build_audit(args.attack_root, args.expected_trials)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
