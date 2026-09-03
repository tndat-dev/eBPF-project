import hashlib
import io
import json
from pathlib import Path
import tarfile

import pytest

from sentinel_pulse.materialize_failed_normal_decisions import materialize


def create_run(tmp_path: Path, attack_row: bool = False) -> Path:
    root = tmp_path / "run"
    worker = root / "infrastructure-failure" / "workers" / "10.0.0.1"
    worker.mkdir(parents=True)
    marker = {
        "run_id": "normal-r1",
        "model_manifest_sha256": "a" * 64,
        "decision_policy_sha256": "b" * 64,
    }
    (root / "SOAK_START.json").write_text(json.dumps(marker) + "\n")
    (root / "FAILED").write_text("reason=normal_alert_observed\n")
    record = {"schema": "sentinel-pulse-decision-v1", "status": "normal"}
    if attack_row:
        record["injection_id"] = "forbidden"
    payload = (json.dumps(record) + "\n").encode()
    archive_path = worker / "raw.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("var/lib/detector/decisions.jsonl")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    indexed = ["SOAK_START.json", "FAILED", "infrastructure-failure/workers/10.0.0.1/raw.tar.gz"]
    (root / "RAW_SHA256SUMS").write_text("".join(
        f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n"
        for name in indexed
    ))
    return root


def test_materializes_only_bound_normal_decisions(tmp_path: Path) -> None:
    output = tmp_path / "output"
    binding = materialize(create_run(tmp_path), output)

    assert binding["run_id"] == "normal-r1"
    assert binding["sources"][0]["rows"] == 1
    assert (output / "10.0.0.1-decisions.jsonl").stat().st_mode & 0o222 == 0
    lines = (output / "DECISIONS_SHA256SUMS").read_text().splitlines()
    assert len(lines) == 2


def test_refuses_attack_attribution_in_normal_archive(tmp_path: Path) -> None:
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="attack-attributed"):
        materialize(create_run(tmp_path, attack_row=True), output)
    assert not output.exists()
