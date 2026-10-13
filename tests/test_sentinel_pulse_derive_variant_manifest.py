import hashlib
import json

import pytest

from sentinel_pulse.derive_variant_manifest import derive_manifest


def _write(path, value):
    path.write_text(json.dumps(value, sort_keys=True))


def _fixture(root):
    (root / "models").mkdir()
    key = "production/example:app"
    variants = {}
    manifest_variants = {}
    for variant in ("full", "drop_read"):
        filename = f"{variant}.pkl"
        content = f"model:{variant}".encode()
        artifact = root / "models" / filename
        artifact.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        variants[variant] = {
            "status": "measured",
            "model_artifact": f"models/{filename}",
            "model_sha256": digest,
            "model_bytes": len(content),
            "masked_columns": ["log_count:read"] if variant == "drop_read" else [],
        }
        manifest_variants[variant] = {
            "artifact": f"models/models/{filename}",
            "sha256": digest,
            "bytes": len(content),
            "masked_columns": variants[variant]["masked_columns"],
        }
    start = {"workloads": [key], "expected_fits": 2}
    _write(root / "START.json", start)
    start_hash = hashlib.sha256((root / "START.json").read_bytes()).hexdigest()
    results = {"start_sha256": start_hash, "workloads": {key: {"variants": variants}}}
    _write(root / "RESULTS.json", results)
    results_hash = hashlib.sha256((root / "RESULTS.json").read_bytes()).hexdigest()
    terminal = {"state": "completed", "errors": [], "start_sha256": start_hash, "completed_fits": 2}
    _write(root / "TERMINAL.json", terminal)
    _write(root / "VARIANT_MODEL_MANIFEST.json", {
        "schema": "sentinel-pulse-syscall-variant-models-v1",
        "start_sha256": start_hash,
        "results_sha256": results_hash,
        "workloads": {key: manifest_variants},
        "automatic_promotion": False,
    })


def test_derives_separate_manifest_and_preserves_sealed_inputs(tmp_path):
    _fixture(tmp_path)
    original_hashes = {
        name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        for name in ("START.json", "RESULTS.json", "TERMINAL.json", "VARIANT_MODEL_MANIFEST.json")
    }

    derived = derive_manifest(tmp_path)

    key = "production/example:app"
    assert derived["workloads"][key]["full"]["artifact"] == "models/full.pkl"
    assert derived["derivation"]["verified_model_count"] == 2
    assert derived["derivation"]["original_evidence_modified"] is False
    for name, digest in original_hashes.items():
        assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == digest
    checksum = (tmp_path / "VARIANT_MODEL_MANIFEST.derived.json.sha256").read_text()
    actual = hashlib.sha256((tmp_path / "VARIANT_MODEL_MANIFEST.derived.json").read_bytes()).hexdigest()
    assert checksum.startswith(actual)


@pytest.mark.parametrize("tamper", ["model", "path", "terminal", "source_manifest"])
def test_rejects_tampering_and_does_not_create_sidecar(tmp_path, tamper):
    _fixture(tmp_path)
    if tamper == "model":
        (tmp_path / "models/full.pkl").write_bytes(b"changed")
    elif tamper == "path":
        path = tmp_path / "VARIANT_MODEL_MANIFEST.json"
        data = json.loads(path.read_text())
        data["workloads"]["production/example:app"]["full"]["artifact"] = "models/other.pkl"
        _write(path, data)
    elif tamper == "terminal":
        path = tmp_path / "TERMINAL.json"
        data = json.loads(path.read_text())
        data["state"] = "failed"
        _write(path, data)
    else:
        path = tmp_path / "VARIANT_MODEL_MANIFEST.json"
        data = json.loads(path.read_text())
        data["results_sha256"] = "0" * 64
        _write(path, data)

    with pytest.raises((ValueError, FileNotFoundError)):
        derive_manifest(tmp_path)
    assert not (tmp_path / "VARIANT_MODEL_MANIFEST.derived.json").exists()
