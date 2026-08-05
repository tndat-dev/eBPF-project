import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "ml-service"))
from build_feature_replay_dataset import build_dataset, injection_intervals


def feature(start):
    return {
        "kind": "feature_window", "ts": start + 10,
        "schema": "sentinel-feature-window/v1",
        "pod_key": "production/service-pod", "model_key": "production/service",
        "node_name": "worker-1", "window_start": start, "window_end": start + 10,
        "event_count": 2, "vector_size": 3, "sparse_vector": [[1, 1.0]],
        "syscall_counts": {"execve": 2},
        "contains_arguments_or_payloads": False, "capture_mode": "sequence",
        "syscall_sequence": ["execve", "execve"],
    }


def test_replay_builder_labels_only_same_pod_intersecting_windows(tmp_path):
    rows = [
        feature(0),
        {"kind": "injection", "ts": 12, "injection_id": "trial:escape",
         "pod_key": "production/service-pod", "attack_type": "escape",
         "rate": 6, "seed": 101},
        feature(10), feature(20),
        {"kind": "injection_end", "ts": 22, "injection_id": "trial:escape",
         "pod_key": "production/service-pod", "attack_type": "escape",
         "attack_exit_code": 0},
        feature(30),
    ]
    path = tmp_path / "capture.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    dataset, manifest = build_dataset(path, require_injections=True)
    assert [row["label"] for row in dataset] == [
        "normal", "attack", "attack", "normal",
    ]
    assert dataset[1]["scenario"] == "escape"
    assert manifest["attack_windows"] == 2
    assert manifest["labels_used_for_training"] is False


def test_replay_builder_rejects_unclosed_or_failed_injection(tmp_path):
    with pytest.raises(ValueError, match="without end"):
        injection_intervals([{
            "kind": "injection", "ts": 1, "injection_id": "open",
            "pod_key": "p", "attack_type": "a",
        }])

    rows = [
        feature(0),
        {"kind": "injection", "ts": 1, "injection_id": "failed",
         "pod_key": "production/service-pod", "attack_type": "escape"},
        {"kind": "injection_end", "ts": 2, "injection_id": "failed",
         "pod_key": "production/service-pod", "attack_type": "escape",
         "attack_exit_code": 1},
    ]
    path = tmp_path / "capture.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(ValueError, match="failed injection"):
        build_dataset(path, require_injections=True)
