import json
import sys
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("sklearn")

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = (
    REPOSITORY_ROOT / "ml-service"
    if (REPOSITORY_ROOT / "ml-service").is_dir()
    else REPOSITORY_ROOT
)
sys.path.insert(0, str(SERVICE_ROOT))

from evaluate_aims_attack_replay import (
    capture_groups, dense_vector, validate_protocol_policy,
    validate_release_identity, wilson,
)


def test_attack_evaluator_source_is_hashable_for_report_identity():
    from evaluate_aims_normal_split import sha256
    digest = sha256(SERVICE_ROOT / "evaluate_aims_attack_replay.py")
    assert len(digest) == 64
    assert all(character in "0123456789abcdef" for character in digest)


def test_release_identity_keeps_production_and_experiment_contracts_distinct():
    release = {
        "production_release_frozen": "V7",
        "release_track": "aims-syscall-candidate",
    }
    split = {"release_id": "v8-paired-replay-20260811"}
    attack = {"release_id": "v8-paired-replay-20260811"}
    protocol = {"release_id": "v8-paired-replay-20260811"}
    assert validate_release_identity(
        release, split, attack, protocol,
    ) == "v8-paired-replay-20260811"
    with pytest.raises(ValueError, match="release contract mismatch"):
        validate_release_identity(
            release, split, {"release_id": "different"}, protocol,
        )


def row(kind, ts, injection_id="i-1"):
    base = {
        "kind": kind, "run_id": "trial-01", "phase_id": "probe",
        "release_id": "v8", "traffic_regime": "attack",
    }
    if kind == "injection":
        return {**base, "ts": ts, "injection_id": injection_id,
                "pod_key": "production/api-abcdef12-abcde", "attack_type": "probe",
                "rate": 6, "seed": 1901}
    if kind == "injection_end":
        return {**base, "ts": ts, "injection_id": injection_id,
                "pod_key": "production/api-abcdef12-abcde", "attack_type": "probe",
                "attack_exit_code": 0}
    return {**base, "window_start": ts, "window_end": ts + 10,
            "pod_key": "production/api-abcdef12-abcde"}


def test_capture_groups_requires_one_complete_interval_per_group():
    groups = capture_groups([
        row("feature_window", 0), row("injection", 2),
        row("feature_window", 10), row("injection_end", 12),
    ])
    assert len(groups) == 1
    assert groups[0]["interval"]["seed"] == 1901
    assert groups[0]["workload_key"] == "production/api"
    assert len(groups[0]["features"]) == 2
    with pytest.raises(ValueError, match="without end"):
        capture_groups([row("feature_window", 0), row("injection", 2)])


def test_dense_vector_is_dimension_and_duplicate_safe():
    value = dense_vector({
        "vector_size": 3, "sparse_vector": [[0, 0.5], [2, 1.0]],
    }, 3)
    assert value.tolist() == [0.5, 0.0, 1.0]
    with pytest.raises(ValueError, match="invalid sparse"):
        dense_vector({"vector_size": 3, "sparse_vector": [[0, 1], [0, 2]]}, 3)
    with pytest.raises(ValueError, match="size"):
        dense_vector({"vector_size": 2, "sparse_vector": []}, 3)


def test_wilson_interval_is_finite_for_complete_miss():
    interval = wilson(0, 200)
    assert interval["estimate"] == 0
    assert interval["lower"] == 0
    assert 0 < interval["upper"] < 0.05


def test_protocol_policy_rejects_mislabeled_ablation():
    protocol = {"methods": {
        "full_v7": {
            "behavior_gate": True, "extreme_volume_gate": True,
            "adaptive_threshold": True, "confirmation_windows": 2,
        },
        "without_behavior_gate": {
            "inherits": "full_v7", "behavior_gate": False,
        },
    }}
    policy = {
        "require_behavior_gate": False,
        "enable_extreme_volume_gate": True,
        "enable_adaptive_threshold": True,
        "confirmation_windows": 2,
        "score_component": "ensemble", "model_routing": "per_workload",
        "fast_path_replayed": False,
    }
    resolved = validate_protocol_policy(
        protocol, "without_behavior_gate", policy
    )
    assert resolved["behavior_gate"] is False
    with pytest.raises(ValueError, match="frozen protocol"):
        validate_protocol_policy(
            protocol, "without_behavior_gate",
            {**policy, "confirmation_windows": 1},
        )
