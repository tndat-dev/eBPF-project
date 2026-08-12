from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT


def test_v8_normal_ablation_runner_is_frozen_resumable_and_non_promoting():
    path = SERVICE_ROOT / "run_v8_normal_ablation_matrix.sh"
    script = path.read_text()
    assert path.stat().st_mode & stat.S_IXUSR
    assert "POST_CAPTURE_COMPLETE" in script
    assert "syscall_evaluation_protocol.json" in script
    assert "evaluate_tetragon_rule_replay.py" in script
    assert "audit_attack_observability.py" in script
    assert "attack-observability-audit.json" in script
    assert "evaluate_aims_attack_replay.py" in script
    assert "assemble_syscall_evaluation_matrix.py" in script
    assert "evaluation_matrix_manifest.json" in script
    assert "paired_statistics.json" in script
    assert "syscall_results.md" in script
    assert "syscall_results.csv" in script
    assert "completed_experiments\") != 11" in script
    assert "pairwise_comparisons\") != 55" in script
    assert "paper-evaluation-results" in script
    assert "frozen-normal-feature-capture.jsonl" in script
    assert "frozen-attack-feature-capture.jsonl" in script
    assert "independent_evaluation" in script
    assert "--initial-calibration-report" in script
    assert "syscall__isolation_forest" in script
    assert "--score-component isolation_forest" in script
    assert "syscall__lstm_only" in script
    assert "--disable-adaptive-threshold" in script
    assert "syscall__evt_pot" in script
    assert "syscall__without_behavior_gate" in script
    assert "syscall__without_extreme_volume_gate" in script
    assert "syscall__without_two_window_confirmation" in script
    assert "train_shared_workload_candidate.py" in script
    assert "syscall__shared_workload_model" in script
    assert "--model-routing shared_workload" in script
    assert "syscall__full_v7" in script
    assert "syscall__without_fast_path" in script
    assert "completed_trials\") == 200" in script
    assert "v8-shared-workload-calibration" in script
    assert "rc != 0 && $rc != 3" in script
    assert "SHA256SUMS" in script
    assert "NORMAL_ABLATION_REPLAY_COMPLETE" in script
    assert "promote_candidate.py" not in script


def test_v8_normal_ablation_systemd_waits_for_attack_and_is_bounded():
    systemd_root = ROOT / "sentinel" / "systemd"
    service = (systemd_root / "aims-v8-normal-ablation.service").read_text()
    timer = (systemd_root / "aims-v8-normal-ablation.timer").read_text()
    assert "POST_CAPTURE_COMPLETE" in service
    assert "FALCO_ATTACK_EVIDENCE_COMPLETE" in service
    assert "NORMAL_ABLATION_REPLAY_COMPLETE" in service
    assert "run_v8_normal_ablation_matrix.sh" in service
    assert "User=dat" in service
    assert "NoNewPrivileges=true" in service
    assert "CPUQuota=100%" in service
    assert "MemoryMax=8G" in service
    assert "TimeoutStartSec=36h" in service
    assert "SuccessExitStatus=75" in service
    assert "OnCalendar=*:0/5" in timer
    assert "OnUnitInactiveSec" not in timer
    assert "Persistent=true" in timer
    assert "promote" not in service.lower()
