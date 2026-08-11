import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT


def test_syscall_protocol_exactly_covers_frozen_matrix_contract():
    matrix = json.loads(
        (SERVICE_ROOT / "evaluation_matrix_contract.json").read_text()
    )
    protocol = json.loads(
        (SERVICE_ROOT / "syscall_evaluation_protocol.json").read_text()
    )
    expected = set(matrix["tracks"]["syscall"]["baselines"])
    expected.update(matrix["tracks"]["syscall"]["ablations"])
    assert protocol["schema"] == "sentinel-syscall-evaluation-protocol/v1"
    assert protocol["release_id"] == matrix["release_id"]
    assert set(protocol["methods"]) == expected
    assert protocol["shared_replay"]["attack_intervals"] == 200
    assert protocol["shared_replay"]["normal_run_ids"] == [
        f"normal-run-{index:02d}" for index in range(2, 7)
    ]


def test_syscall_protocol_discloses_registration_limit_and_forbids_leakage():
    protocol = json.loads(
        (SERVICE_ROOT / "syscall_evaluation_protocol.json").read_text()
    )
    boundary = protocol["registration_boundary"]
    assert boundary["normal_capture_had_started"] is True
    assert boundary["candidate_training_had_started"] is False
    assert boundary["blind_attack_had_started"] is False
    assert boundary["holdout_scores_or_alerts_inspected"] is False
    assert "not before normal capture" in boundary["claim_limit"]
    assert protocol["shared_replay"]["labels_used_for_training_or_tuning"] is False
    assert protocol["automatic_promotion"] is False


def test_only_full_method_and_matching_ablation_enable_fast_path():
    methods = json.loads(
        (SERVICE_ROOT / "syscall_evaluation_protocol.json").read_text()
    )["methods"]
    assert methods["full_v7"]["fast_path"] is True
    assert methods["without_fast_path"]["fast_path"] is False
    assert methods["full_v7"]["fast_path_role"].startswith("early warning")
    assert methods["shared_workload_model"]["holdout_or_attack_fit"] is False
