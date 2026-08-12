"""Freeze retrospective live fast-path evidence over V8 normal holdout phases."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any


REPORT_SCHEMA = "sentinel-fast-path-normal-evidence/v1"
WARNING_KEYS = {
    "kind", "ts", "pod_key", "model_key", "rule", "first_syscall",
    "second_syscall", "sequence_seconds", "severity", "detection_latency",
    "event_to_warning_seconds", "processing_ms",
}
STABLE_HEALTH_COUNTERS = (
    "backpressure_events", "coverage_failures", "membership_failures",
    "stale_streams_removed", "stream_failures",
)


class EvidenceError(ValueError):
    pass


class EvidenceNotReady(EvidenceError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def read_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"unreadable JSON: {path}") from exc
    if not isinstance(document, dict):
        raise EvidenceError(f"JSON object required: {path}")
    return document


def load_phases(
    capture_root: Path, split_path: Path, release_path: Path,
    contract: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], dict[str, str]]:
    split, release = read_json(split_path), read_json(release_path)
    if split.get("release_id") != contract.get("release_id"):
        raise EvidenceError("split release mismatch")
    parents = contract.get("parent_contracts", {})
    if parents.get(split_path.name) != sha256(split_path):
        raise EvidenceError("split contract digest mismatch")
    if parents.get(release_path.name) != sha256(release_path):
        raise EvidenceError("release contract digest mismatch")
    targets = list(release.get("eligible_targets", []))
    if not targets:
        raise EvidenceError("eligible target contract is empty")
    regimes = list(split.get("normal", {}).get("regimes", []))
    runs = [
        row for row in split.get("normal", {}).get("runs", [])
        if row.get("role") == contract.get("normal_role")
    ]
    if len(runs) != int(contract.get("expected_runs", -1)) or len(regimes) != 4:
        raise EvidenceError("independent normal split mismatch")
    phases, provenance = [], {}
    for run in runs:
        run_id = str(run["run_id"])
        run_number = int(run_id.rsplit("-", 1)[1])
        for regime in regimes:
            phase_id = f"aims-{regime}-run-{run_number:02d}"
            path = capture_root / phase_id / "collection_manifest.json"
            if not path.is_file():
                raise EvidenceNotReady(f"normal phase is incomplete: {phase_id}")
            manifest = read_json(path)
            if manifest.get("phase") != phase_id:
                raise EvidenceError(f"phase identity mismatch: {phase_id}")
            start = parse_time(str(manifest["collection_started_at"]))
            end = parse_time(str(manifest["collection_ended_at"]))
            if start >= end or manifest.get("minimum_duration_satisfied") is not True:
                raise EvidenceError(f"invalid phase interval: {phase_id}")
            if manifest.get("sensor_health", {}).get("coverage_healthy") is not True:
                raise EvidenceError(f"capture sensor unhealthy: {phase_id}")
            phases.append({
                "phase": phase_id, "run_id": run_id,
                "traffic_regime": regime, "start": start, "end": end,
                "exposure_seconds": end - start,
            })
            provenance[f"phase_manifest:{phase_id}"] = sha256(path)
    phases.sort(key=lambda row: row["start"])
    if len(phases) != int(contract.get("expected_phases", -1)):
        raise EvidenceError("normal phase count mismatch")
    for previous, current in zip(phases, phases[1:]):
        if previous["end"] > current["start"]:
            raise EvidenceError("normal phase intervals overlap")
    return phases, targets, provenance


def systemd_state(service_name: str) -> dict[str, str]:
    properties = (
        "ActiveState", "SubState", "NRestarts", "ExecMainStartTimestamp",
        "FragmentPath", "MainPID",
    )
    command = ["systemctl", "show", service_name]
    for name in properties:
        command.extend(("-p", name))
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def validate_runtime(
    contract: dict[str, Any], detector_source: Path, fast_path_source: Path,
    service_unit: Path, state: dict[str, str], first_phase_start: float,
) -> dict[str, Any]:
    expected = contract["runtime"]
    observed = {
        "detector_source_sha256": sha256(detector_source),
        "fast_path_source_sha256": sha256(fast_path_source),
        "service_unit_sha256": sha256(service_unit),
    }
    for field, digest in observed.items():
        if expected.get(field) != digest:
            raise EvidenceError(f"runtime provenance mismatch: {field}")
    if state.get("ActiveState") != "active" or state.get("SubState") != "running":
        raise EvidenceError("live detector service is not active/running")
    if int(state.get("NRestarts", -1)) != 0:
        raise EvidenceError("live detector restarted during evidence collection")
    if state.get("ExecMainStartTimestamp") != expected.get("service_started_at"):
        raise EvidenceError("live detector start identity mismatch")
    started = datetime.strptime(
        state["ExecMainStartTimestamp"], "%a %Y-%m-%d %H:%M:%S %Z"
    ).replace(tzinfo=timezone.utc).timestamp()
    if started >= first_phase_start:
        raise EvidenceError("live detector started after normal evidence")
    if Path(state.get("FragmentPath", "")).resolve() != service_unit.resolve():
        raise EvidenceError("live detector unit path mismatch")
    return {**state, **observed}


def phase_for_timestamp(timestamp: float, phases: list[dict[str, Any]]) -> dict | None:
    return next(
        (phase for phase in phases if phase["start"] <= timestamp <= phase["end"]),
        None,
    )


def validate_warning(row: dict[str, Any], targets: set[str], rules: set[str]) -> None:
    if set(row) - WARNING_KEYS:
        raise EvidenceError("early-warning row contains non-privacy-safe fields")
    if row.get("kind") != "early_warning" or row.get("severity") != "early-warning":
        raise EvidenceError("early-warning row schema mismatch")
    if row.get("model_key") not in targets:
        raise EvidenceError("AIMS early warning has an unknown model key")
    if row.get("rule") not in rules:
        raise EvidenceError("early-warning rule is outside the frozen contract")
    if not str(row.get("pod_key", "")).startswith("production/"):
        raise EvidenceError("early warning escaped the production namespace")
    for field in ("sequence_seconds", "event_to_warning_seconds", "processing_ms"):
        if float(row.get(field, -1)) < 0:
            raise EvidenceError(f"invalid early-warning timing: {field}")


def corruption_overlaps_phases(
    before: float | None, after: float | None, phases: list[dict[str, Any]],
) -> bool:
    lower = float("-inf") if before is None else before
    upper = float("inf") if after is None else after
    return any(lower <= phase["end"] and upper >= phase["start"] for phase in phases)


def load_metrics(
    metrics_path: Path, phases: list[dict[str, Any]], targets: set[str],
    rules: set[str],
) -> tuple[list[dict], dict[str, list[dict]], dict[str, Any]]:
    warnings, health = [], {phase["phase"]: [] for phase in phases}
    source_counts: dict[str, int] = {}
    corruptions, pending = [], []
    previous_timestamp: float | None = None
    digest = hashlib.sha256()
    lines = 0
    with metrics_path.open("rb") as handle:
        for line_number, payload in enumerate(handle, 1):
            digest.update(payload)
            lines = line_number
            try:
                row = json.loads(payload)
                timestamp = float(row["ts"])
            except (UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
                pending.append({
                    "line": line_number, "bytes": len(payload),
                    "before": previous_timestamp, "error": type(exc).__name__,
                })
                continue
            for item in pending:
                item["after"] = timestamp
                if corruption_overlaps_phases(item["before"], timestamp, phases):
                    raise EvidenceError(
                        f"metrics corruption may overlap evaluation phases: line {item['line']}"
                    )
                corruptions.append(item)
            pending.clear()
            previous_timestamp = timestamp
            kind = str(row.get("kind", "unknown"))
            source_counts[kind] = source_counts.get(kind, 0) + 1
            phase = phase_for_timestamp(timestamp, phases)
            if phase is None:
                continue
            if kind == "runtime_health":
                health[phase["phase"]].append(row)
            elif kind == "early_warning":
                if row.get("model_key") in targets:
                    validate_warning(row, targets, rules)
                    warnings.append({
                        **row, "phase": phase["phase"],
                        "run_id": phase["run_id"],
                        "traffic_regime": phase["traffic_regime"],
                    })
    for item in pending:
        item["after"] = None
        if corruption_overlaps_phases(item["before"], None, phases):
            raise EvidenceError(
                f"terminal metrics corruption may overlap phases: line {item['line']}"
            )
        corruptions.append(item)
    return warnings, health, {
        "sha256": digest.hexdigest(), "bytes": metrics_path.stat().st_size,
        "lines": lines, "kind_counts": dict(sorted(source_counts.items())),
        "corruptions_outside_evaluation_intervals": corruptions,
    }


def validate_health(
    phases: list[dict[str, Any]], health: dict[str, list[dict]], max_gap: float,
) -> list[dict[str, Any]]:
    outcomes = []
    for phase in phases:
        rows = sorted(health[phase["phase"]], key=lambda row: float(row["ts"]))
        if not rows:
            raise EvidenceError(f"no runtime-health coverage: {phase['phase']}")
        timestamps = [float(row["ts"]) for row in rows]
        gaps = [timestamps[0] - phase["start"], phase["end"] - timestamps[-1]]
        gaps.extend(right - left for left, right in zip(timestamps, timestamps[1:]))
        if max(gaps) > max_gap:
            raise EvidenceError(f"runtime-health gap in {phase['phase']}: {max(gaps):.3f}s")
        counters = {field: [] for field in STABLE_HEALTH_COUNTERS}
        for row in rows:
            sensor = row.get("sensor_health", {})
            if sensor.get("coverage_healthy") is not True:
                raise EvidenceError(f"unhealthy fast-path coverage: {phase['phase']}")
            expected = int(sensor.get("expected_tetragon_pods", -1))
            if expected < 1 or len(sensor.get("active_tetragon_pods", [])) != expected:
                raise EvidenceError(f"incomplete active Tetragon set: {phase['phase']}")
            if len(sensor.get("ready_tetragon_pods", [])) != expected:
                raise EvidenceError(f"incomplete ready Tetragon set: {phase['phase']}")
            if int(sensor.get("queue_size", -1)) < 0 or int(sensor["queue_size"]) > int(sensor["queue_capacity"]):
                raise EvidenceError(f"invalid detector queue state: {phase['phase']}")
            for field in counters:
                counters[field].append(int(sensor.get(field, -1)))
        for field, values in counters.items():
            if min(values) < 0 or max(values) != min(values):
                raise EvidenceError(f"{field} changed during {phase['phase']}")
        outcomes.append({
            **phase, "health_samples": len(rows), "maximum_health_gap_seconds": max(gaps),
            "sensor_counters": {field: values[0] for field, values in counters.items()},
        })
    return outcomes


def verify_existing(output_root: Path) -> dict[str, Any]:
    checksum = output_root / "SHA256SUMS"
    report_path = output_root / "fast-path-normal-evidence.report.json"
    if not checksum.is_file() or not report_path.is_file():
        raise EvidenceError("existing fast-path derivative is incomplete")
    for line in checksum.read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        path = output_root / name.strip()
        if not path.is_file() or sha256(path) != digest:
            raise EvidenceError(f"existing fast-path checksum mismatch: {name}")
    report = read_json(report_path)
    if report.get("valid") is not True or report.get("schema") != REPORT_SCHEMA:
        raise EvidenceError("existing fast-path report is invalid")
    return report


def finalize(
    capture_root: Path, metrics_path: Path, split_path: Path, release_path: Path,
    contract_path: Path, detector_source: Path, fast_path_source: Path,
    service_unit: Path, output_root: Path, *, state: dict[str, str] | None = None,
    now: float | None = None, settle_seconds: float = 30.0,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    if output_root.exists():
        return verify_existing(output_root)
    contract = read_json(contract_path)
    if contract.get("schema") != "sentinel-fast-path-normal-contract/v1":
        raise EvidenceError("fast-path normal contract schema mismatch")
    if contract.get("automatic_promotion") is not False:
        raise EvidenceError("fast-path contract permits promotion")
    phases, targets, phase_provenance = load_phases(
        capture_root.resolve(), split_path.resolve(), release_path.resolve(), contract,
    )
    now = time.time() if now is None else now
    if now - phases[-1]["end"] < settle_seconds:
        raise EvidenceNotReady("normal telemetry has not reached terminal settle")
    state = state or systemd_state(contract["runtime"]["service_name"])
    runtime = validate_runtime(
        contract, detector_source.resolve(), fast_path_source.resolve(),
        service_unit.resolve(), state, phases[0]["start"],
    )
    warnings, health, metrics = load_metrics(
        metrics_path.resolve(), phases, set(targets), set(contract["allowed_rules"]),
    )
    phase_outcomes = validate_health(
        phases, health, float(contract["runtime"]["maximum_health_gap_seconds"]),
    )
    warning_counts = {phase["phase"]: 0 for phase in phases}
    for warning in warnings:
        warning_counts[warning["phase"]] += 1
    for phase in phase_outcomes:
        phase["early_warning_count"] = warning_counts[phase["phase"]]
    exposure = sum(phase["exposure_seconds"] for phase in phase_outcomes)
    report = {
        "schema": REPORT_SCHEMA, "valid": True,
        "created_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "release_id": contract["release_id"],
        "evidence_class": contract["evidence_class"],
        "claim_limit": contract["registration_boundary"]["claim_limit"],
        "phase_count": len(phases), "independent_runs": len({p["run_id"] for p in phases}),
        "normal_duration_seconds": exposure,
        "early_warning_count": len(warnings),
        "early_warnings_per_hour": len(warnings) / (exposure / 3600.0),
        "false_positive_rate": None,
        "false_positive_rate_reason": (
            "fast path emits event warnings, not scored Bernoulli opportunities; "
            "report normal warning count/rate rather than statistical FPR"
        ),
        "phase_outcomes": phase_outcomes,
        "runtime": runtime,
        "metrics_source": metrics,
        "provenance_sha256": {
            "contract": sha256(contract_path), "split": sha256(split_path),
            "release": sha256(release_path), **phase_provenance,
        },
        "privacy": contract["privacy"],
        "automatic_promotion": False,
    }
    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        warning_path = staging / "fast-path-normal-warnings.jsonl"
        warning_path.write_text("".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in warnings
        ))
        report_path = staging / "fast-path-normal-evidence.report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (staging / "SHA256SUMS").write_text(
            f"{sha256(warning_path)}  {warning_path.name}\n"
            f"{sha256(report_path)}  {report_path.name}\n"
        )
        for path in staging.iterdir():
            os.chmod(path, 0o600)
        os.replace(staging, output_root)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--split-contract", type=Path, required=True)
    parser.add_argument("--release-contract", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--detector-source", type=Path, required=True)
    parser.add_argument("--fast-path-source", type=Path, required=True)
    parser.add_argument("--service-unit", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = finalize(
            args.capture_root, args.metrics, args.split_contract,
            args.release_contract, args.contract, args.detector_source,
            args.fast_path_source, args.service_unit, args.output_root,
        )
    except EvidenceNotReady as exc:
        print(f"WAITING: {exc}")
        return 75
    except EvidenceError as exc:
        print(f"REFUSING: {exc}")
        return 4
    print(json.dumps({
        "valid": report["valid"], "phase_count": report["phase_count"],
        "early_warning_count": report["early_warning_count"],
        "output_root": str(args.output_root.resolve()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
