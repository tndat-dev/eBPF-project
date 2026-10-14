import json
import pytest
from sentinel_pulse.feature_profile import training_profile
from sentinel_pulse.integrity import sha256_file


def provenance(tmp_path,profile='exact-ebpf-500ms-rolling-10'):
    capture=tmp_path/'capture.json';capture.write_text(json.dumps(dict(capture_profile=profile)))
    dataset=tmp_path/'features.jsonl.manifest.json'
    dataset.write_text(json.dumps(dict(source_manifest_sha256=dict(node=dict(path=str(capture),sha256=sha256_file(capture))))))
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps(dict(dataset_manifest_sha256=sha256_file(dataset))))
    return manifest,capture


def test_profile_not_inferred_from_vector_dimension(tmp_path):
    manifest,_=provenance(tmp_path)
    profile=training_profile(manifest)
    assert profile['rolling_windows']==10 and profile['interval_ms']==500


def test_modified_capture_receipt_rejected(tmp_path):
    manifest,capture=provenance(tmp_path);capture.write_text('{}')
    with pytest.raises(ValueError,match='SHA-256'):training_profile(manifest)


def test_unknown_profile_not_assumed_compatible(tmp_path):
    manifest,_=provenance(tmp_path,'unknown')
    with pytest.raises(ValueError,match='unsupported'):training_profile(manifest)
