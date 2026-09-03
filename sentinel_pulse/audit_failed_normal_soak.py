#!/usr/bin/env python3
"""Create an immutable sidecar audit for an archived failed normal soak.

The source evidence is never modified.  The audit verifies its checksum
manifest, reads detector streams directly from the worker tar archives, and
distinguishes a normal-gate rejection from an infrastructure rejection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tarfile
from typing import Any, Iterator


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_failed(path: Path) -> dict[str, str]:
    return {
        key: value
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line
        for key, value in [line.split("=", 1)]
    }


def verify_sha256_manifest(root: Path, manifest: Path) -> int:
    verified = 0
    for number, line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            expected, relative = line.split(maxsplit=1)
        except ValueError as exc:
            raise ValueError(f"invalid checksum line {number}") from exc
        relative = relative.lstrip(" *")
        candidate = (root / relative).resolve()
        if root.resolve() not in candidate.parents and candidate != root.resolve():
            raise ValueError(f"checksum path escapes evidence root: {relative}")
        if sha256(candidate) != expected:
            raise ValueError(f"checksum mismatch: {relative}")
        verified += 1
    if verified == 0:
        raise ValueError("empty checksum manifest")
    return verified


def iter_jsonl_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> Iterator[dict[str, Any]]:
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError(f"cannot read archive member: {member.name}")
    for number, raw in enumerate(stream, start=1):
        if not raw.strip():
            continue
        try:
            yield json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL {member.name}:{number}") from exc


def inspect_worker_archive(path: Path) -> tuple[int, list[dict[str, Any]]]:
    with tarfile.open(path, "r:gz") as archive:
        decisions = [m for m in archive.getmembers() if m.name.endswith("/decisions.jsonl")]
        alerts = [m for m in archive.getmembers() if m.name.endswith("/alerts.jsonl")]
        if len(decisions) != 1 or len(alerts) != 1:
            raise ValueError(
                f"expected one decision and alert stream in {path}, got "
                f"{len(decisions)} and {len(alerts)}"
            )
        decision_count = sum(1 for _ in iter_jsonl_member(archive, decisions[0]))
        alert_rows = list(iter_jsonl_member(archive, alerts[0]))
    return decision_count, alert_rows


def node_is_ready(node: dict[str, Any]) -> bool:
    conditions = node.get("status", {}).get("conditions", [])
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)


def pod_is_ready(pod: dict[str, Any]) -> bool:
    status = pod.get("status", {})
    containers = status.get("containerStatuses") or []
    return status.get("phase") == "Running" and bool(containers) and all(
        item.get("ready") is True for item in containers
    )


def build_audit(root: Path) -> dict[str, Any]:
    required = [
        "SOAK_START.json",
        "FAILED",
        "RAW_SHA256SUMS",
        "ARCHIVE_COMPLETE",
        "FAILURE_NODES.json",
        "FAILURE_PRODUCTION_PODS.json",
        "FAILURE_LONGHORN_VOLUMES.json",
        "FAILURE_CNPG_CLUSTERS.json",
        "infrastructure-failure/DISPOSITION.json",
    ]
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        raise ValueError(f"missing required evidence: {', '.join(missing)}")
    if (root / "ACTIVE").exists() or (root / "NORMAL_PASS").exists():
        raise ValueError("source run is not a terminal failed soak")

    checksum_count = verify_sha256_manifest(root, root / "RAW_SHA256SUMS")
    marker = load_json(root / "SOAK_START.json")
    failed = parse_failed(root / "FAILED")
    workers_root = root / "infrastructure-failure" / "workers"
    worker_rows: dict[str, Any] = {}
    all_alerts: list[dict[str, Any]] = []
    for tar_path in sorted(workers_root.glob("*/raw.tar.gz")):
        host = tar_path.parent.name
        decision_count, alerts = inspect_worker_archive(tar_path)
        finalizer = load_json(tar_path.parent / "node-finalize.json")
        worker_rows[host] = {
            "decision_count": decision_count,
            "alert_count": len(alerts),
            "collector_rows": finalizer.get("rows"),
            "workload_count": finalizer.get("workload_count"),
            "service_ok": finalizer.get("service_ok"),
            "evidence_valid": finalizer.get("valid"),
            "validation_errors": finalizer.get("validation_errors", []),
            "interval_seconds": finalizer.get("interval_seconds"),
            "window_start_to_emit_seconds": finalizer.get(
                "window_start_to_emit_seconds"
            ),
            "collector_max_drops": finalizer.get("collector_max_drops"),
        }
        for alert in alerts:
            all_alerts.append({"archive_host": host, "alert": alert})

    nodes = load_json(root / "FAILURE_NODES.json").get("items", [])
    pods = load_json(root / "FAILURE_PRODUCTION_PODS.json").get("items", [])
    volumes = load_json(root / "FAILURE_LONGHORN_VOLUMES.json").get("items", [])
    clusters = load_json(root / "FAILURE_CNPG_CLUSTERS.json").get("items", [])
    unhealthy_nodes = [n["metadata"]["name"] for n in nodes if not node_is_ready(n)]
    unhealthy_pods = [p["metadata"]["name"] for p in pods if not pod_is_ready(p)]
    unhealthy_volumes = [
        v["metadata"]["name"]
        for v in volumes
        if v.get("status", {}).get("robustness") != "healthy"
    ]
    unhealthy_cnpg = [
        c["metadata"]["name"]
        for c in clusters
        if c.get("status", {}).get("phase") != "Cluster in healthy state"
        or c.get("status", {}).get("readyInstances")
        != c.get("status", {}).get("instances")
    ]

    reason = failed.get("reason")
    if reason != "normal_alert_observed":
        raise ValueError(f"not a normal-alert failure: {reason!r}")
    if not all_alerts:
        raise ValueError("FAILED records a normal alert but archives contain none")
    evaluable_alerts = [
        row
        for row in all_alerts
        if worker_rows[row["archive_host"]]["evidence_valid"] is True
        and worker_rows[row["archive_host"]]["service_ok"] is True
    ]
    cluster_healthy = not (
        unhealthy_nodes or unhealthy_pods or unhealthy_volumes or unhealthy_cnpg
    )
    if not evaluable_alerts:
        raise ValueError("no alert has a valid, healthy source-worker archive")

    previous_disposition = root / "infrastructure-failure" / "DISPOSITION.json"
    return {
        "schema": "sentinel-pulse-failed-normal-posthoc-audit-v1",
        "run_id": marker["run_id"],
        "classification": "rejected_normal_gate",
        "candidate_status": "rejected_normal_gate",
        "normal_gate_result": False,
        "accuracy_claim_allowed": False,
        "false_positive_observed": True,
        "reason": reason,
        "source_evidence": {
            "path": str(root),
            "raw_sha256sums_sha256": sha256(root / "RAW_SHA256SUMS"),
            "raw_manifest_entries_verified": checksum_count,
            "soak_start_sha256": sha256(root / "SOAK_START.json"),
            "previous_disposition_sha256": sha256(previous_disposition),
            "previous_disposition_preserved": True,
        },
        "totals": {
            "decisions": sum(row["decision_count"] for row in worker_rows.values()),
            "alerts": len(all_alerts),
            "evaluable_alerts": len(evaluable_alerts),
        },
        "workers": worker_rows,
        "alerts": all_alerts,
        "failure_time_health": {
            "cluster_healthy": cluster_healthy,
            "node_count": len(nodes),
            "unhealthy_nodes": unhealthy_nodes,
            "production_pod_count": len(pods),
            "unhealthy_production_pods": unhealthy_pods,
            "longhorn_volume_count": len(volumes),
            "unhealthy_longhorn_volumes": unhealthy_volumes,
            "cnpg_cluster_count": len(clusters),
            "unhealthy_cnpg_clusters": unhealthy_cnpg,
        },
        "methodology": {
            "normal_gate": True,
            "training": False,
            "tuning": False,
            "blind_attack": False,
            "blind_accuracy_evaluation": False,
            "statement": (
                "A valid alert during the preregistered normal-only interval "
                "rejects the zero-alert gate. The source archive remains immutable."
            ),
        },
        "supersedes_interpretation_only": {
            "artifact": "infrastructure-failure/DISPOSITION.json",
            "reason": (
                "the legacy freezer classified every monitor failure as an "
                "infrastructure rejection"
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    root = args.evidence_root.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    audit = build_audit(root)
    audit_path = output / "POSTHOC_CLASSIFICATION.json"
    audit_path.write_text(
        json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = output / "SHA256SUMS"
    manifest.write_text(
        f"{sha256(audit_path)}  {audit_path.name}\n", encoding="utf-8"
    )
    os.chmod(audit_path, 0o444)
    os.chmod(manifest, 0o444)
    print(json.dumps({
        "output_dir": str(output),
        "classification": audit["classification"],
        "decisions": audit["totals"]["decisions"],
        "alerts": audit["totals"]["alerts"],
        "cluster_healthy": audit["failure_time_health"]["cluster_healthy"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
