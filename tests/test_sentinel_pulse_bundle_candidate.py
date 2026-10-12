import hashlib
import json

import pytest

from sentinel_pulse.bundle_candidate import bundle_candidate
from sentinel_pulse.idle_candidate import SCHEMA


def _candidate(tmp_path, *, artifact=b"frozen model bytes"):
    source = tmp_path / "source"
    source.mkdir()
    name = "model-test.pkl"
    (source / name).write_bytes(artifact)
    manifest = tmp_path / "CANDIDATE_MANIFEST.json"
    manifest.write_text(json.dumps({
        "schema": SCHEMA,
        "serving_compatible": False,
        "workloads": {"production/test:app": {
            "artifact": name,
            "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        }},
    }))
    return source, manifest


def test_bundle_copies_only_hash_verified_candidate_and_preserves_manifest(tmp_path):
    source, manifest = _candidate(tmp_path)
    output = tmp_path / "bundle"
    count = bundle_candidate(manifest, source, output)

    assert count == 1
    assert (output / "CANDIDATE_MANIFEST.json").read_bytes() == manifest.read_bytes()
    assert (output / "model-test.pkl").read_bytes() == b"frozen model bytes"
    assert (output / "model-test.pkl").stat().st_mode & 0o777 == 0o440


def test_bundle_refuses_hash_mismatch_without_publishing_output(tmp_path):
    source, manifest = _candidate(tmp_path)
    (source / "model-test.pkl").write_bytes(b"changed")
    output = tmp_path / "bundle"

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        bundle_candidate(manifest, source, output)
    assert not output.exists()


def test_bundle_refuses_overwrite(tmp_path):
    source, manifest = _candidate(tmp_path)
    output = tmp_path / "bundle"
    output.mkdir()

    with pytest.raises(ValueError, match="refusing to overwrite"):
        bundle_candidate(manifest, source, output)


def test_bundle_rejects_manifest_traversal_before_staging(tmp_path):
    source, manifest = _candidate(tmp_path)
    payload = json.loads(manifest.read_text())
    payload["workloads"]["production/test:app"]["artifact"] = "../outside.pkl"
    manifest.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="unsafe artifact path"):
        bundle_candidate(manifest, source, tmp_path / "bundle")
