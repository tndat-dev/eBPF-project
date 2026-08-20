"""Validate a failed normal-soak rejection against immutable raw evidence."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path


def _timestamp(value: str) -> float:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("evidence timestamp must include a timezone")
    return parsed.timestamp()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_raw_paths(root: Path) -> list[Path]:
    checksum_path = root / "RAW_SHA256SUMS"
    verified = []
    for line_number, line in enumerate(
        checksum_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        expected, separator, relative = line.partition("  ")
        if not separator or len(expected) != 64:
            raise ValueError(f"invalid raw checksum line {line_number}")
        target = (root / relative).resolve()
        if root.resolve() not in target.parents:
            raise ValueError(f"raw checksum escapes evidence root: {relative}")
        if _sha256(target) != expected:
            raise ValueError(f"raw checksum mismatch: {relative}")
        verified.append(target)
    if not verified:
        raise ValueError("raw checksum index is empty")
    return verified


def validate(root: Path, maximum_correlation_seconds: float = 10.0) -> dict:
    errors = []
    try:
        marker = json.loads((root / "SOAK_START.json").read_text(encoding="utf-8"))
        disposition = json.loads(
            (root / "infrastructure-failure" / "DISPOSITION.json").read_text(
                encoding="utf-8"
            )
        )
        events = json.loads(
            (root / "infrastructure-failure" / "cnpg-2-events.json").read_text(
                encoding="utf-8"
            )
        ).get("items", [])
        failed = (root / "FAILED").read_text(encoding="utf-8")
        raw_paths = _verified_raw_paths(root)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        return {
            "schema": "sentinel-pulse-infrastructure-rejection-validation-v1",
            "valid": False,
            "errors": [str(error)],
        }

    if disposition.get("run_id") != marker.get("run_id"):
        errors.append("run identity mismatch")
    if disposition.get("terminal_run_status") != "rejected_infrastructure_failure":
        errors.append("disposition is not an infrastructure rejection")
    if disposition.get("candidate_status") != "not_evaluated_by_this_run":
        errors.append("candidate status is not fail-closed")
    data_use = disposition.get("data_use", {})
    for prohibited in ("normal_gate", "training", "tuning", "blind_attack"):
        if data_use.get(prohibited) is not False:
            errors.append(f"rejected run permits prohibited use: {prohibited}")
    if "reason=normal_alert_observed" not in failed:
        errors.append("monitor failure does not record a normal alert")

    started = _timestamp(str(marker.get("started_not_before")))
    recorded = float(disposition.get("recorded_at_unix", 0.0))
    eviction_times = []
    for event in events:
        if event.get("reason") != "Evicted":
            continue
        if "ephemeral-storage" not in str(event.get("message", "")):
            continue
        timestamp = event.get("eventTime") or event.get("lastTimestamp") or event.get(
            "metadata", {}
        ).get("creationTimestamp")
        if timestamp:
            eviction_times.append(_timestamp(str(timestamp)))
    eviction_times = [item for item in eviction_times if started <= item <= recorded]
    if len(eviction_times) != 1:
        errors.append("expected exactly one in-run ephemeral-storage eviction")

    alert_paths = [path for path in raw_paths if path.name == "alerts.jsonl"]
    raw_alerts = []
    for path in alert_paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line:
                raw_alerts.append(json.loads(line))
    declared_alerts = disposition.get("alert_evidence", [])
    if disposition.get("observed_alerts") != len(raw_alerts):
        errors.append("observed alert count does not match raw alert files")
    raw_identity = sorted(
        (str(item.get("pod_name")), float(item.get("alerted_at", 0.0)))
        for item in raw_alerts
    )
    declared_identity = sorted(
        (str(item.get("pod_name")), float(item.get("alerted_at", 0.0)))
        for item in declared_alerts
    )
    if raw_identity != declared_identity:
        errors.append("declared alerts do not match raw alert evidence")
    if eviction_times:
        eviction = eviction_times[0]
        if any(
            not 0.0 <= alert_time - eviction <= maximum_correlation_seconds
            for _pod, alert_time in raw_identity
        ):
            errors.append("alert is outside the registered eviction correlation bound")

    return {
        "schema": "sentinel-pulse-infrastructure-rejection-validation-v1",
        "run_id": marker.get("run_id"),
        "valid": not errors,
        "errors": errors,
        "verified_raw_files": len(raw_paths),
        "raw_alerts": len(raw_alerts),
        "ephemeral_storage_evictions": len(eviction_times),
        "maximum_correlation_seconds": maximum_correlation_seconds,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--maximum-correlation-seconds", type=float, default=10.0)
    args = parser.parse_args()
    report = validate(args.evidence_root, args.maximum_correlation_seconds)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    raise SystemExit(0 if report["valid"] else 1)


if __name__ == "__main__":
    main()
