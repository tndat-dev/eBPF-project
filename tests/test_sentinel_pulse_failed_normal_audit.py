import hashlib
import io
import json
from pathlib import Path
import tarfile

import pytest

from sentinel_pulse.audit_failed_normal_soak import build_audit


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def add_jsonl(archive: tarfile.TarFile, name: str, rows: list[dict]) -> None:
    payload = b"".join((json.dumps(row) + "\n").encode() for row in rows)
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))


def make_run(tmp_path: Path, reason: str = "normal_alert_observed") -> Path:
    root = tmp_path / "run"
    root.mkdir()
    write_json(root / "SOAK_START.json", {"run_id": "normal-r1"})
    (root / "FAILED").write_text(f"reason={reason}\nhost=10.0.0.1\n", encoding="utf-8")
    (root / "ARCHIVE_COMPLETE").write_text("done\n", encoding="utf-8")
    write_json(root / "FAILURE_NODES.json", {"items": [{
        "metadata": {"name": "worker1"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }]})
    write_json(root / "FAILURE_PRODUCTION_PODS.json", {"items": [{
        "metadata": {"name": "database"},
        "status": {"phase": "Running", "containerStatuses": [{"ready": True}]},
    }]})
    write_json(root / "FAILURE_LONGHORN_VOLUMES.json", {"items": [{
        "metadata": {"name": "volume1"}, "status": {"robustness": "healthy"},
    }]})
    write_json(root / "FAILURE_CNPG_CLUSTERS.json", {"items": [{
        "metadata": {"name": "postgres"},
        "status": {"phase": "Cluster in healthy state", "instances": 3, "readyInstances": 3},
    }]})
    write_json(root / "infrastructure-failure/DISPOSITION.json", {
        "terminal_run_status": "rejected_infrastructure_failure"
    })
    worker = root / "infrastructure-failure/workers/10.0.0.1"
    worker.mkdir(parents=True)
    write_json(worker / "node-finalize.json", {
        "valid": True, "service_ok": True, "rows": 3, "workload_count": 1,
        "validation_errors": [], "collector_max_drops": {},
    })
    with tarfile.open(worker / "raw.tar.gz", "w:gz") as archive:
        add_jsonl(archive, "var/lib/run/decisions.jsonl", [{"score": 0.1}, {"score": 0.9}])
        add_jsonl(archive, "var/lib/run/alerts.jsonl", [{"score": 0.9, "workload": "postgres"}])
    indexed = [
        "SOAK_START.json", "FAILED", "ARCHIVE_COMPLETE", "FAILURE_NODES.json",
        "FAILURE_PRODUCTION_PODS.json", "FAILURE_LONGHORN_VOLUMES.json",
        "FAILURE_CNPG_CLUSTERS.json", "infrastructure-failure/DISPOSITION.json",
        "infrastructure-failure/workers/10.0.0.1/node-finalize.json",
        "infrastructure-failure/workers/10.0.0.1/raw.tar.gz",
    ]
    lines = []
    for relative in indexed:
        digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        lines.append(f"{digest}  {relative}\n")
    (root / "RAW_SHA256SUMS").write_text("".join(lines), encoding="utf-8")
    return root


def test_audit_classifies_valid_normal_alert_as_normal_gate_rejection(tmp_path: Path) -> None:
    report = build_audit(make_run(tmp_path))

    assert report["classification"] == "rejected_normal_gate"
    assert report["false_positive_observed"] is True
    assert report["totals"] == {"decisions": 2, "alerts": 1, "evaluable_alerts": 1}
    assert report["failure_time_health"]["cluster_healthy"] is True
    assert report["methodology"]["tuning"] is False
    assert report["source_evidence"]["raw_manifest_entries_verified"] == 10


def test_audit_rejects_infrastructure_failure(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a normal-alert failure"):
        build_audit(make_run(tmp_path, reason="collector_failed"))


def test_audit_fails_closed_on_checksum_mismatch(tmp_path: Path) -> None:
    root = make_run(tmp_path)
    (root / "FAILED").write_text("reason=normal_alert_observed\ntampered=true\n")

    with pytest.raises(ValueError, match="checksum mismatch"):
        build_audit(root)
