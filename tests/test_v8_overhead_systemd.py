from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = ROOT / "sentinel" / "benchmarks"
SYSTEMD_ROOT = ROOT / "sentinel" / "systemd"


def test_v8_overhead_runner_is_terminal_gated_and_immutable():
    path = BENCHMARK_ROOT / "run_v8_overhead_counterbalanced.sh"
    script = path.read_text()
    assert path.stat().st_mode & stat.S_IXUSR
    assert "NORMAL_ABLATION_REPLAY_COMPLETE" in script
    assert "V8_OVERHEAD_COMPLETE" in script
    assert "v8-paired-replay-20260811" in script
    assert "evidence_release" in script
    assert "train_" not in script
    assert "promote" not in script


def test_v8_overhead_unit_cannot_start_before_terminal_marker():
    service = (SYSTEMD_ROOT / "aims-v8-overhead.service").read_text()
    timer = (SYSTEMD_ROOT / "aims-v8-overhead.timer").read_text()
    assert "ConditionPathExists=/home/dat/ml-service/aims-v8-derived" in service
    assert "NORMAL_ABLATION_REPLAY_COMPLETE" in service
    assert "ConditionPathExists=!" in service
    assert "V8_OVERHEAD_COMPLETE" in service
    assert "User=root" in service
    assert ".aims-normal-matrix.lock" in service
    assert "TimeoutStartSec=12h" in service
    assert "OnCalendar=*:0/10" in timer
    assert "OnUnitInactiveSec" not in timer
    assert "Persistent=true" in timer


def test_v8_overhead_environment_matches_frozen_evaluator_policy():
    environment = (SYSTEMD_ROOT / "aims-v8-overhead.env").read_text()
    assert "AIMS_EVIDENCE_RELEASE=v8" in environment
    assert "SENTINEL_CONFIRMATION_FLOOR_RATIO=1.0" in environment
    assert "SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR=0.80" in environment
    assert "SENTINEL_FAST_PATH_CONFIRMATION_FLOOR=0.80" in environment
    assert "SENTINEL_EXTREME_VOLUME_FACTOR=2.0" in environment
