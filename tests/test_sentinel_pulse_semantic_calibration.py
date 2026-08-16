import json

from sentinel_pulse.calibrate_semantic_envelope import calibrate
from sentinel_pulse.integrity import sha256_file


def test_semantic_calibration_uses_exact_normal_maxima_and_provenance(tmp_path):
    dataset = tmp_path / "normal.jsonl"
    records = [
        {
            "schema": "sentinel-pulse-feature-v1",
            "workload_key": "production/catalog:app",
            "exact_counts": {
                "socket": 1,
                "connect": 7,
                "clone": 2,
                "openat": 20,
                "unshare": 0,
            },
        },
        {
            "schema": "sentinel-pulse-feature-v1",
            "workload_key": "production/catalog:app",
            "exact_counts": {
                "socket": 2,
                "connect": 10,
                "clone3": 1,
                "openat": 4,
                "unshare": 1,
            },
        },
    ]
    dataset.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    manifest = {
        "schema": "sentinel-pulse-dataset-manifest-v1",
        "normal_only": True,
        "dataset_sha256": sha256_file(dataset),
        "contract_sha256": "a" * 64,
        "source_sha256": "b" * 64,
        "source_manifest_sha256": "c" * 64,
    }
    dataset.with_suffix(".jsonl.manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    report = calibrate(dataset)
    maxima = report["workload_group_maxima"]["production/catalog:app"]
    assert report["rows"] == 2
    assert report["normal_only"] is True
    assert report["blind_outcome_used"] is False
    assert maxima["local_socket_beacon"] == 12
    assert maxima["process_fanout"] == 2
    assert maxima["credential_open"] == 20
    assert maxima["namespace_probe"] == 1
