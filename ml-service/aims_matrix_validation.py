"""Fail-closed validation for an AIMS multi-regime normal matrix.

The collector already validates each phase before returning success.  This
module adds a matrix-level gate so incomplete, time-collapsed, sensor-degraded,
or tampered evidence cannot be mistaken for a paper-ready normal dataset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


CONTINUITY_COUNTERS = (
    "backpressure_events",
    "membership_failures",
    "coverage_failures",
    "stream_failures",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_phases(regimes: list[str], runs_per_regime: int) -> list[str]:
    return [
        f"aims-{regime}-run-{run:02d}"
        for run in range(1, runs_per_regime + 1)
        for regime in regimes
    ]


def _run_roles(normal: dict[str, Any], runs_per_regime: int) -> tuple[dict[int, str], list[str]]:
    """Validate that each run belongs to exactly one frozen experiment role."""
    roles = normal.get("phase_roles")
    if roles is None:
        return {}, []
    errors: list[str] = []
    mapping: dict[int, str] = {}
    if not isinstance(roles, dict) or not roles:
        return {}, ["normal_protocol.phase_roles must be a non-empty object"]
    for role, spec in roles.items():
        runs = spec.get("runs") if isinstance(spec, dict) else None
        if not isinstance(runs, list) or not runs:
            errors.append(f"phase role {role} has no runs")
            continue
        for run in runs:
            if not isinstance(run, int) or not 1 <= run <= runs_per_regime:
                errors.append(f"phase role {role} has invalid run {run!r}")
            elif run in mapping:
                errors.append(
                    f"run {run} assigned to both {mapping[run]} and {role}"
                )
            else:
                mapping[run] = role
    missing = sorted(set(range(1, runs_per_regime + 1)) - set(mapping))
    if missing:
        errors.append(f"runs missing phase roles: {missing}")
    if normal.get("holdout_training_forbidden") is not True:
        errors.append("holdout_training_forbidden must be true")
    return mapping, errors


def validate_matrix(
    evidence_root: Path,
    contract: dict[str, Any],
    *,
    runs_per_regime: int,
    minutes_per_run: int,
) -> dict[str, Any]:
    """Return a deterministic validation report; never silently drops errors."""
    root = evidence_root.resolve()
    normal = contract["normal_protocol"]
    regimes = list(normal["regimes"])
    eligible_targets = set(contract["eligible_targets"])
    expected = _expected_phases(regimes, runs_per_regime)
    expected_set = set(expected)
    errors: list[str] = []
    captures: list[dict[str, Any]] = []
    total_actual_seconds = 0.0
    artifact_digests: dict[str, set[str]] = {
        "vocabulary": set(),
        "tetragon_policy": set(),
        "loadgen_manifest": set(),
    }
    run_roles, role_errors = _run_roles(normal, runs_per_regime)
    errors.extend(role_errors)

    manifest_paths = sorted(root.glob("aims-*-run-*/collection_manifest.json"))
    by_phase: dict[str, Path] = {}
    for path in manifest_paths:
        try:
            phase = str(json.loads(path.read_text())["phase"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"unreadable manifest {path.relative_to(root)}: {exc}")
            continue
        if phase in by_phase:
            errors.append(f"duplicate phase manifest: {phase}")
        else:
            by_phase[phase] = path

    missing = sorted(expected_set - set(by_phase))
    unexpected = sorted(set(by_phase) - expected_set)
    if missing:
        errors.append(f"missing phases: {','.join(missing)}")
    if unexpected:
        errors.append(f"unexpected phases: {','.join(unexpected)}")

    for phase in expected:
        path = by_phase.get(phase)
        if path is None:
            continue
        doc = json.loads(path.read_text())
        phase_errors: list[str] = []
        actual = float(doc.get("actual_duration_seconds", -1))
        minimum = float(doc.get("minimum_duration_seconds", -1))
        requested = float(doc.get("requested_duration_seconds", -1))
        required = minutes_per_run * 60
        if doc.get("minimum_duration_satisfied") is not True:
            phase_errors.append("minimum_duration_satisfied is not true")
        if minimum != required or requested != required:
            phase_errors.append(
                f"duration contract mismatch requested={requested} minimum={minimum} "
                f"required={required}"
            )
        if actual + 2.0 < minimum:
            phase_errors.append(f"time collapsed actual={actual} minimum={minimum}")
        total_actual_seconds += max(0.0, actual)

        targets = doc.get("targets", {})
        target_names = set(targets)
        if target_names != eligible_targets:
            absent = sorted(eligible_targets - target_names)
            extra = sorted(target_names - eligible_targets)
            phase_errors.append(f"target mismatch missing={absent} extra={extra}")

        minimum_windows = int(doc.get("minimum_windows", 0))
        vocab_size = int(doc.get("vocabulary", {}).get("size", 0))
        for target in sorted(eligible_targets & target_names):
            item = targets[target]
            shape = item.get("shape", [])
            if (
                len(shape) != 2
                or int(shape[0]) < minimum_windows
                or int(shape[1]) != vocab_size
            ):
                phase_errors.append(
                    f"invalid shape for {target}: {shape}, "
                    f"minimum_windows={minimum_windows}, vocab_size={vocab_size}"
                )
                continue
            data_path = path.parent / f"{target.replace('/', '__')}.npy"
            if not data_path.is_file():
                phase_errors.append(f"missing data file for {target}")
            elif _sha256(data_path) != item.get("sha256"):
                phase_errors.append(f"data digest mismatch for {target}")
            metadata_value = item.get("metadata")
            metadata_path = Path(metadata_value) if metadata_value else Path()
            if metadata_value and not metadata_path.is_absolute():
                candidates = (path.parent / metadata_path, root.parent / metadata_path)
                metadata_path = next((item for item in candidates if item.is_file()), candidates[0])
            if not metadata_value or not metadata_path.is_file():
                phase_errors.append(f"missing metadata file for {target}")
            elif sum(1 for line in metadata_path.open() if line.strip()) != int(shape[0]):
                phase_errors.append(f"metadata row mismatch for {target}")
            elif item.get("metadata_sha256") and _sha256(metadata_path) != item.get(
                "metadata_sha256"
            ):
                phase_errors.append(f"metadata digest mismatch for {target}")

        health = doc.get("sensor_health", {})
        for counter in CONTINUITY_COUNTERS:
            if counter not in health:
                phase_errors.append(f"sensor health missing {counter}")
            elif int(health[counter]) != 0:
                phase_errors.append(f"sensor health {counter}={health[counter]}")
        if health.get("require_full_coverage") is not True:
            phase_errors.append("full sensor coverage was not required")
        if health.get("coverage_healthy") is not True:
            phase_errors.append("sensor coverage was unhealthy")
        if int(health.get("expected_tetragon_pods", 0)) <= 0:
            phase_errors.append("expected Tetragon pod count is missing")
        elif len(health.get("active_tetragon_pods", [])) != int(
            health["expected_tetragon_pods"]
        ):
            phase_errors.append("active Tetragon membership is incomplete")

        provenance = doc.get("experiment_artifacts", {})
        digest_fields = {
            "vocabulary": doc.get("vocabulary", {}).get("sha256"),
            "tetragon_policy": provenance.get("tetragon_policy", {}).get("sha256"),
            "loadgen_manifest": provenance.get("loadgen_manifest", {}).get("sha256"),
        }
        for name, digest in digest_fields.items():
            if not digest:
                phase_errors.append(f"missing {name} provenance digest")
            else:
                artifact_digests[name].add(str(digest))

        errors.extend(f"{phase}: {message}" for message in phase_errors)
        captures.append(
            {
                "phase": phase,
                "path": str(path.relative_to(root)),
                "manifest_sha256": _sha256(path),
                "actual_duration_seconds": actual,
                "target_count": len(target_names),
                "valid": not phase_errors,
                "dataset_role": run_roles.get(int(phase.rsplit("-", 1)[1])),
            }
        )

    for name, digests in artifact_digests.items():
        if len(digests) > 1:
            errors.append(f"{name} changed during matrix: {sorted(digests)}")

    minimum_total_seconds = float(normal["minimum_total_hours"]) * 3600.0
    if total_actual_seconds < minimum_total_seconds:
        errors.append(
            f"total capture duration {total_actual_seconds:.3f}s is below "
            f"contract minimum {minimum_total_seconds:.3f}s"
        )

    return {
        "contract_version": contract.get("contract_version"),
        "release_track": contract.get("release_track"),
        "evidence_root": str(root),
        "runs_per_regime": runs_per_regime,
        "minutes_per_run": minutes_per_run,
        "expected_phases": expected,
        "completed_phases": len(captures),
        "eligible_targets": sorted(eligible_targets),
        "total_actual_seconds": round(total_actual_seconds, 6),
        "minimum_total_seconds": minimum_total_seconds,
        "captures": captures,
        "artifact_digests": {
            name: sorted(digests) for name, digests in artifact_digests.items()
        },
        "phase_roles": {
            role: [run for run, assigned in sorted(run_roles.items()) if assigned == role]
            for role in sorted(set(run_roles.values()))
        },
        "errors": errors,
        "valid": not errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--runs-per-regime", type=int, required=True)
    parser.add_argument("--minutes-per-run", type=int, required=True)
    args = parser.parse_args()
    if args.runs_per_regime <= 0 or args.minutes_per_run <= 0:
        parser.error("run count and duration must be positive")
    contract = json.loads(args.contract.read_text())
    report = validate_matrix(
        args.evidence_root,
        contract,
        runs_per_regime=args.runs_per_regime,
        minutes_per_run=args.minutes_per_run,
    )
    output = args.evidence_root / "matrix_manifest.json"
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
