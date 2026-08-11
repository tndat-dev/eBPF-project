"""Freeze privacy-safe Falco normal evidence against V8 phase manifests.

The live collector intentionally keeps running for the later blind-attack
campaign.  This finalizer takes an immutable, phase-bounded derivative after
the normal campaign.  It fails closed on incomplete stream coverage, stale
collector state, malformed rows, provenance mismatches, or phase overlap.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any


ALERT_SCHEMA = "sentinel-falco-alert/v1"
STATE_SCHEMA = "sentinel-falco-collector-state/v1"
CONTRACT_SCHEMA = "sentinel-falco-collection-contract/v1"
REPORT_SCHEMA = "sentinel-falco-normal-evidence/v1"
REGIMES = ("steady", "burst", "recovery", "toolmix")
ALLOWED_ALERT_KEYS = {
    "schema", "kind", "event_ts", "priority", "rule",
    "source_falco_pod", "source_node", "target_namespace", "target_pod",
    "release_id", "contains_arguments_or_payloads", "raw_output_stored",
    "event_id",
}


class EvidenceError(RuntimeError):
    """The evidence is invalid and must not be published."""


class EvidenceNotSettled(EvidenceError):
    """The live stream has not passed the terminal phase settle boundary."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        payload = path.read_bytes()
        document = json.loads(payload)
    except (OSError, ValueError, TypeError) as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise EvidenceError(f"JSON object required: {path}")
    return document, payload


def validate_collector(
    falco_root: Path,
    *,
    release_id: str,
    first_phase_start: float,
    last_phase_end: float,
    now: float,
    max_state_age: float,
    minimum_settle_seconds: float,
) -> tuple[dict[str, Any], dict[str, str]]:
    state, state_bytes = read_json(falco_root / "collector-state.json")
    contract, contract_bytes = read_json(falco_root / "collection-contract.json")
    if state.get("schema") != STATE_SCHEMA:
        raise EvidenceError("Falco collector state schema mismatch")
    if contract.get("schema") != CONTRACT_SCHEMA:
        raise EvidenceError("Falco collection contract schema mismatch")
    if state.get("release_id") != release_id or contract.get("release_id") != release_id:
        raise EvidenceError("Falco release ID does not match the capture split")
    if parse_time(str(contract.get("since_time"))) > first_phase_start:
        raise EvidenceError("Falco backfill begins after the first evaluation phase")
    if now < last_phase_end + minimum_settle_seconds:
        raise EvidenceNotSettled("Falco terminal phase has not settled")
    updated_at = parse_time(str(state.get("updated_at")))
    if updated_at < last_phase_end + minimum_settle_seconds:
        raise EvidenceNotSettled("Falco state has not advanced past the settle boundary")
    if now - updated_at > max_state_age:
        raise EvidenceError("Falco collector state is stale")

    expected = int(state.get("expected_readers", 0))
    ready = set(state.get("ready_falco_pods", []))
    active = set(state.get("active_readers", []))
    if expected < 1 or len(ready) != expected or ready != active:
        raise EvidenceError("Falco reader membership is incomplete")
    if state.get("coverage_healthy") is not True:
        raise EvidenceError("Falco collector coverage is unhealthy")
    if int(state.get("stream_failures", -1)) != 0:
        raise EvidenceError("Falco collector recorded stream failures")

    code_path = falco_root / "code" / "falco_evidence_collector.py"
    if not code_path.is_file() or sha256(code_path) != contract.get("collector_sha256"):
        raise EvidenceError("Falco collector source digest mismatch")
    provenance: dict[str, str] = {
        "collector_state": sha256_bytes(state_bytes),
        "collection_contract": sha256_bytes(contract_bytes),
        "collector_source": sha256(code_path),
    }
    for name in ("falco-daemonset.yaml", "falco-configmap.yaml", "falco-pods.json", "nodes.txt"):
        path = falco_root / name
        if not path.is_file():
            raise EvidenceError(f"missing Falco provenance snapshot: {name}")
        provenance[name] = sha256(path)
    return state, provenance


def load_phases(
    capture_root: Path, split_contract: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    release_id = str(split_contract.get("release_id", ""))
    normal = split_contract.get("normal", {})
    runs = normal.get("runs", [])
    evaluation_runs = [
        str(row.get("run_id"))
        for row in runs
        if isinstance(row, dict) and row.get("role") == "independent_evaluation"
    ]
    if len(evaluation_runs) < 1 or normal.get("regimes") != list(REGIMES):
        raise EvidenceError("capture split has no valid independent normal matrix")

    phases: list[dict[str, Any]] = []
    provenance: dict[str, str] = {}
    for run_id in evaluation_runs:
        try:
            run_number = int(run_id.rsplit("-", 1)[1])
        except (IndexError, ValueError) as exc:
            raise EvidenceError(f"invalid run ID: {run_id}") from exc
        for regime in REGIMES:
            phase = f"aims-{regime}-run-{run_number:02d}"
            path = capture_root / phase / "collection_manifest.json"
            manifest, payload = read_json(path)
            if manifest.get("phase") != phase:
                raise EvidenceError(f"phase manifest identity mismatch: {phase}")
            start = parse_time(str(manifest.get("collection_started_at")))
            end = parse_time(str(manifest.get("collection_ended_at")))
            if start >= end or manifest.get("minimum_duration_satisfied") is not True:
                raise EvidenceError(f"invalid collection interval: {phase}")
            health = manifest.get("sensor_health", {})
            if health.get("coverage_healthy") is not True:
                raise EvidenceError(f"capture sensor coverage is unhealthy: {phase}")
            phases.append({
                "phase": phase,
                "run_id": run_id,
                "dataset_role": "independent_evaluation",
                "start": start,
                "end": end,
                "duration_seconds": end - start,
                "alert_count": 0,
            })
            provenance[f"phase_manifest:{phase}"] = sha256_bytes(payload)

    phases.sort(key=lambda item: item["start"])
    for previous, current in zip(phases, phases[1:]):
        if previous["end"] > current["start"]:
            raise EvidenceError(
                f"overlapping phase intervals: {previous['phase']} and {current['phase']}"
            )
    if len(phases) != len(evaluation_runs) * len(REGIMES):
        raise EvidenceError("independent phase matrix is incomplete")
    if not release_id:
        raise EvidenceError("capture split release ID is missing")
    return phases, provenance


def validate_alert(row: dict[str, Any], release_id: str) -> None:
    if set(row) - ALLOWED_ALERT_KEYS:
        raise EvidenceError("Falco row contains fields outside the privacy schema")
    if row.get("schema") != ALERT_SCHEMA or row.get("kind") != "falco_alert":
        raise EvidenceError("Falco alert schema mismatch")
    if row.get("release_id") != release_id:
        raise EvidenceError("Falco row release mismatch")
    if row.get("target_namespace") != "production":
        raise EvidenceError("Falco row escaped the production namespace filter")
    if row.get("contains_arguments_or_payloads") is not False:
        raise EvidenceError("Falco row may contain arguments or payloads")
    if row.get("raw_output_stored") is not False:
        raise EvidenceError("Falco row may contain raw output")
    identity = dict(row)
    event_id = identity.pop("event_id", None)
    expected = sha256_bytes(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    if event_id != expected:
        raise EvidenceError("Falco event identity digest mismatch")
    try:
        float(row["event_ts"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceError("Falco event timestamp is invalid") from exc


def load_alerts(
    falco_root: Path,
    *,
    release_id: str,
    phases: list[dict[str, Any]],
    state: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, str | None]:
    path = falco_root / "falco-alerts.jsonl"
    payload = path.read_bytes() if path.is_file() else b""
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    for line in payload.splitlines():
        if not line.strip():
            continue
        total += 1
        try:
            row = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise EvidenceError("malformed Falco JSONL row") from exc
        if not isinstance(row, dict):
            raise EvidenceError("Falco JSONL row must be an object")
        validate_alert(row, release_id)
        if row["event_id"] in seen:
            raise EvidenceError("duplicate Falco event ID in source evidence")
        seen.add(row["event_id"])
        timestamp = float(row["event_ts"])
        matches = [phase for phase in phases if phase["start"] <= timestamp <= phase["end"]]
        if len(matches) > 1:
            raise EvidenceError("Falco event maps to overlapping phases")
        if matches:
            phase = matches[0]
            phase["alert_count"] += 1
            derived = dict(row)
            derived.update({
                "phase": phase["phase"],
                "run_id": phase["run_id"],
                "dataset_role": phase["dataset_role"],
            })
            rows.append(derived)

    state_rows = int(state.get("privacy_safe_rows_written", -1))
    if not path.is_file() and state_rows != 0:
        raise EvidenceError("collector reports rows but its alert file is absent")
    if path.is_file() and total < state_rows:
        raise EvidenceError("Falco alert file has fewer rows than collector state")
    return rows, total, sha256_bytes(payload) if path.is_file() else None


def finalize(
    capture_root: Path,
    falco_root: Path,
    split_path: Path,
    output_root: Path,
    *,
    now: float | None = None,
    max_state_age: float = 120.0,
    minimum_settle_seconds: float = 30.0,
) -> dict[str, Any]:
    now = time.time() if now is None else now
    split, split_bytes = read_json(split_path)
    phases, capture_provenance = load_phases(capture_root.resolve(), split)
    release_id = str(split["release_id"])
    state, falco_provenance = validate_collector(
        falco_root.resolve(), release_id=release_id,
        first_phase_start=phases[0]["start"], last_phase_end=phases[-1]["end"],
        now=now, max_state_age=max_state_age,
        minimum_settle_seconds=minimum_settle_seconds,
    )
    alerts, source_row_count, source_alert_sha = load_alerts(
        falco_root.resolve(), release_id=release_id, phases=phases, state=state,
    )

    total_seconds = sum(item["duration_seconds"] for item in phases)
    ranges = state.get("reader_ranges", {})
    ready = list(state["ready_falco_pods"])
    zero_output = sorted(set(ready) - set(ranges))
    provenance = {
        "capture_split": sha256_bytes(split_bytes),
        **capture_provenance,
        **falco_provenance,
    }
    if source_alert_sha is not None:
        provenance["source_falco_alerts"] = source_alert_sha
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "valid": True,
        "release_id": release_id,
        "created_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "dataset_role": "independent_evaluation",
        "phase_count": len(phases),
        "normal_duration_seconds": total_seconds,
        "normal_alert_count": len(alerts),
        "normal_alerts_per_hour": (
            len(alerts) / (total_seconds / 3600.0) if total_seconds else None
        ),
        "false_positive_rate": None,
        "false_positive_rate_reason": (
            "Falco emits event alerts rather than scored opportunities; report the "
            "normal alert count/rate and do not relabel it as a statistical FPR."
        ),
        "source_privacy_safe_row_count": source_row_count,
        "source_rows_outside_normal_intervals": source_row_count - len(alerts),
        "phases": phases,
        "coverage": {
            "expected_readers": state["expected_readers"],
            "ready_falco_pods": ready,
            "active_readers": list(state["active_readers"]),
            "stream_failures": state["stream_failures"],
            "raw_lines_observed": state["lines_seen"],
            "reader_ranges": ranges,
            "active_readers_with_zero_log_output": zero_output,
            "healthy_at_finalization": True,
        },
        "privacy": {
            "raw_falco_output_stored": False,
            "command_arguments_stored": False,
            "file_paths_stored": False,
            "network_payloads_stored": False,
        },
        "claim_scope": (
            "Independent normal-traffic Falco rule-only evidence only; attack "
            "recall and cross-cluster generalization require separate campaigns."
        ),
        "provenance_sha256": dict(sorted(provenance.items())),
    }

    output_root = output_root.resolve()
    output_root.parent.mkdir(parents=True, exist_ok=True)
    if output_root.exists():
        checksum = output_root / "SHA256SUMS"
        if not checksum.is_file():
            raise EvidenceError("existing Falco derivative is incomplete")
        raise EvidenceError("Falco derivative already exists; evidence is immutable")
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        alert_path = staging / "falco-normal-alerts.jsonl"
        with alert_path.open("w") as handle:
            for row in alerts:
                handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        report_path = staging / "falco-normal-evidence.report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        checksum_path = staging / "SHA256SUMS"
        checksum_path.write_text(
            f"{sha256(alert_path)}  {alert_path.name}\n"
            f"{sha256(report_path)}  {report_path.name}\n"
        )
        os.chmod(alert_path, 0o600)
        os.chmod(report_path, 0o600)
        os.chmod(checksum_path, 0o600)
        staging.replace(output_root)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-root", required=True, type=Path)
    parser.add_argument("--falco-root", required=True, type=Path)
    parser.add_argument("--split-contract", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--max-state-age", type=float, default=120.0)
    parser.add_argument("--minimum-settle-seconds", type=float, default=30.0)
    args = parser.parse_args()
    try:
        report = finalize(
            args.capture_root, args.falco_root, args.split_contract,
            args.output_root, max_state_age=args.max_state_age,
            minimum_settle_seconds=args.minimum_settle_seconds,
        )
    except EvidenceNotSettled as exc:
        print(f"WAITING: {exc}")
        return 75
    except EvidenceError as exc:
        print(f"REFUSING: {exc}")
        return 4
    print(json.dumps({
        "valid": report["valid"],
        "phase_count": report["phase_count"],
        "normal_alert_count": report["normal_alert_count"],
        "output_root": str(args.output_root.resolve()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
