"""Extend a semantic envelope from a frozen failed normal-soak bundle.

The failed run is never relabelled as a successful evaluation.  Once its
candidate has failed, its normal-only observations may be promoted to explicit
development evidence for a *new* policy.  A fresh independent soak is still
required for that policy.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import tempfile
import time

from .decision_policy import load_decision_policy
from .integrity import sha256_file


ALLOWED_STATUSES = frozenset({"normal", "suppressed", "alert", "warming"})


def _load_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    evidence_root = path.parent.resolve()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split(maxsplit=1)
        if (
            len(fields) != 2
            or len(fields[0]) != 64
            or any(character not in "0123456789abcdef" for character in fields[0])
        ):
            raise ValueError(f"line {line_number}: malformed evidence checksum")
        relative = fields[1].removeprefix("*").removeprefix("./")
        if relative in checksums:
            raise ValueError(f"duplicate evidence checksum for {relative}")
        candidate = (evidence_root / relative).resolve()
        try:
            candidate.relative_to(evidence_root)
        except ValueError as error:
            raise ValueError(
                f"line {line_number}: evidence checksum target is outside the bundle"
            ) from error
        if not candidate.is_file():
            raise ValueError(
                f"line {line_number}: evidence checksum target is missing: {relative}"
            )
        checksums[relative] = fields[0]
    if not checksums:
        raise ValueError("evidence checksum index is empty")
    return checksums


def _verify_evidence_file(root: Path, path: Path, checksums: dict[str, str]) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise ValueError(f"evidence file is outside the frozen bundle: {path}") from error
    expected = checksums.get(relative)
    if expected is None:
        raise ValueError(f"evidence checksum is missing for {relative}")
    observed = sha256_file(path)
    if observed != expected:
        raise ValueError(f"evidence checksum mismatch for {relative}")
    return observed


def extend_envelope(
    base_policy_path: Path,
    failure_summary_path: Path,
    checksum_path: Path,
    decision_paths: list[Path],
) -> dict:
    if not decision_paths:
        raise ValueError("at least one failed normal decision file is required")
    base_policy, base_policy_sha256 = load_decision_policy(base_policy_path)
    summary = json.loads(failure_summary_path.read_text(encoding="utf-8"))
    if not str(summary.get("schema", "")).startswith(
        "sentinel-pulse-normal-soak-failure-"
    ):
        raise ValueError("development evidence is not a failed normal-soak summary")
    if summary.get("status") != "failed":
        raise ValueError("development normal evidence did not fail its old candidate")
    if summary.get("blind_evaluation_started") is not False:
        raise ValueError("refusing evidence that may contain blind outcomes")
    if int(summary.get("total_invalid_json", 0)) != 0:
        raise ValueError("failed normal evidence contains invalid JSON")
    if summary.get("decision_policy_sha256") != base_policy_sha256:
        raise ValueError("failed run does not belong to the base decision policy")

    model_sha256 = summary.get("model_manifest_sha256")
    run_id = summary.get("run_id")
    if not isinstance(model_sha256, str) or len(model_sha256) != 64:
        raise ValueError("failed normal summary model identity is invalid")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("failed normal summary run identity is invalid")

    evidence_root = checksum_path.parent
    checksums = _load_checksums(checksum_path)
    summary_sha256 = _verify_evidence_file(
        evidence_root, failure_summary_path, checksums
    )
    envelope = base_policy["same_window_corroboration"][
        "workload_normal_envelope"
    ]
    signal_groups = {
        group["name"]: tuple(group["fields"])
        for group in envelope["signal_groups"]
    }
    base_maxima = envelope["workload_group_maxima"]
    extended_maxima = {
        workload: dict(maxima) for workload, maxima in base_maxima.items()
    }
    source_reports = []
    status_counts: Counter[str] = Counter()
    observed_rows = 0
    usable_rows = 0
    changed: dict[str, dict[str, dict[str, int]]] = {}
    started = time.perf_counter()

    expected_workers = summary.get("workers", {})
    for path in decision_paths:
        digest = _verify_evidence_file(evidence_root, path, checksums)
        worker = path.parent.name
        worker_summary = expected_workers.get(worker)
        if not isinstance(worker_summary, dict):
            raise ValueError(f"decision source has no summary entry: {worker}")
        source_rows = 0
        source_alerts = 0
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                record = json.loads(line)
                status = record.get("status")
                if status not in ALLOWED_STATUSES:
                    raise ValueError(f"{path}:{line_number}: unsupported decision status")
                # Historical warming records predate the decision schema field.
                # They carry no semantic counts and are provenance/count checks
                # only. Scored records must always have the complete schema.
                if status != "warming" and record.get("schema") != "sentinel-pulse-decision-v1":
                    raise ValueError(f"{path}:{line_number}: unsupported decision schema")
                if status == "warming" and record.get("schema") not in (
                    None,
                    "sentinel-pulse-decision-v1",
                ):
                    raise ValueError(f"{path}:{line_number}: unsupported warming schema")
                if record.get("decision_policy_sha256") != base_policy_sha256:
                    raise ValueError(f"{path}:{line_number}: policy identity mismatch")
                if record.get("model_manifest_sha256") != model_sha256:
                    raise ValueError(f"{path}:{line_number}: model identity mismatch")
                if record.get("run_id") != run_id:
                    raise ValueError(f"{path}:{line_number}: run identity mismatch")
                if any(
                    key in record
                    for key in ("injection_id", "attack_injected_at", "scenario_id")
                ):
                    raise ValueError(f"{path}:{line_number}: attack marker in normal evidence")
                source_rows += 1
                observed_rows += 1
                status_counts[status] += 1
                if status == "alert":
                    source_alerts += 1
                if status == "warming":
                    continue
                workload = record.get("workload_key")
                if workload not in extended_maxima:
                    raise ValueError(f"{path}:{line_number}: unknown workload {workload}")
                counts = record.get("security_activity_fields")
                if not isinstance(counts, dict):
                    raise ValueError(f"{path}:{line_number}: semantic counts are missing")
                usable_rows += 1
                for name, fields in signal_groups.items():
                    observed = sum(int(counts.get(field, 0)) for field in fields)
                    if observed < 0:
                        raise ValueError(f"{path}:{line_number}: negative semantic count")
                    previous = extended_maxima[workload][name]
                    if observed > previous:
                        extended_maxima[workload][name] = observed
                        changed.setdefault(workload, {})[name] = {
                            "base_max": base_maxima[workload][name],
                            "extended_max": observed,
                        }
        if source_rows != int(worker_summary.get("decision_rows", -1)):
            raise ValueError(f"decision row count mismatch for {worker}")
        if source_alerts != int(worker_summary.get("alert_rows", -1)):
            raise ValueError(f"alert row count mismatch for {worker}")
        source_reports.append(
            {
                "worker": worker,
                "path": str(path),
                "sha256": digest,
                "rows": source_rows,
                "alerts": source_alerts,
            }
        )

    if observed_rows != int(summary.get("total_decisions", -1)):
        raise ValueError("aggregate decision row count does not match failure summary")
    if status_counts["alert"] != int(summary.get("observed_alerts", -1)):
        raise ValueError("aggregate alert count does not match failure summary")
    return {
        "schema": "sentinel-pulse-semantic-envelope-extension-v1",
        "normal_only": True,
        "blind_outcome_used": False,
        "source_role": (
            "failed_independent_normal_reclassified_as_development_after_candidate_failure"
        ),
        "base_policy": str(base_policy_path),
        "base_policy_sha256": base_policy_sha256,
        "model_manifest_sha256": model_sha256,
        "failed_run_id": run_id,
        "failure_summary": str(failure_summary_path),
        "failure_summary_sha256": summary_sha256,
        "evidence_checksums": str(checksum_path),
        "evidence_checksums_sha256": sha256_file(checksum_path),
        "decision_sources": source_reports,
        "rows": observed_rows,
        "usable_semantic_rows": usable_rows,
        "status_counts": dict(sorted(status_counts.items())),
        "signal_groups": {name: list(fields) for name, fields in signal_groups.items()},
        "base_workload_group_maxima": base_maxima,
        "workload_group_maxima": extended_maxima,
        "changed_maxima": changed,
        "elapsed_seconds": time.perf_counter() - started,
    }


def _atomic_write(path: Path, payload: dict) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite semantic extension: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as output:
            temporary_name = output.name
            json.dump(payload, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-policy", type=Path, required=True)
    parser.add_argument("--failure-summary", type=Path, required=True)
    parser.add_argument("--evidence-checksums", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = extend_envelope(
        args.base_policy,
        args.failure_summary,
        args.evidence_checksums,
        args.decisions,
    )
    _atomic_write(args.output, report)


if __name__ == "__main__":
    main()
