from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT
SYSTEMD_ROOT = ROOT / "sentinel" / "systemd"


def test_split_evaluation_runner_has_no_train_or_promotion_path():
    path = SERVICE_ROOT / "run_aims_split_evaluation.sh"
    script = path.read_text()
    assert path.stat().st_mode & stat.S_IXUSR
    assert "evaluate_aims_normal_split.py" in script
    assert "build_aims_fit_calibration.py" in script
    assert "waiting_for_phases" not in script  # exit code is the stable API
    assert "train_candidate.py" not in script
    assert "promote_candidate.py" not in script
    assert "--prerequisite-report" in script
    assert "aims-normal-matrix.service aims-v8-capture.service" in script
    assert "systemctl is-active --quiet \"$active_capture\"" in script
    assert "WAITING: %s is active" in script
    assert "aims-v8-capture.service" in script
    assert "independent_evaluation" in script


def test_split_evaluation_unit_is_bounded_and_non_privileged():
    unit = (SYSTEMD_ROOT / "aims-split-evaluation@.service").read_text()
    assert "User=dat" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CPUQuota=100%" in unit
    assert "MemoryMax=8G" in unit
    assert "EnvironmentFile=/home/dat/ml-service/aims-evaluation.env" in unit
    assert "Environment=OMP_NUM_THREADS=1" in unit
    assert "Environment=MKL_NUM_THREADS=1" in unit
    assert "/usr/bin/flock -n -E 75" in unit
    assert "SuccessExitStatus=75" in unit
    assert "TimeoutStartSec=6h" in unit
    assert "promote" not in unit.lower()


def test_v8_capture_is_release_bound_and_snapshots_runtime_and_traffic():
    unit = (SYSTEMD_ROOT / "aims-v8-capture.service").read_text()
    script = (SERVICE_ROOT / "run_aims_normal_matrix.sh").read_text()
    assert "User=dat" in unit
    assert "NoNewPrivileges=true" in unit
    assert "EnvironmentFile=/home/dat/ml-service/v8-capture.env" in unit
    assert "RUNS_PER_REGIME=6" in unit
    assert "MINUTES_PER_RUN=72" in unit
    assert "Conflicts=aims-overhead-counterbalanced-v2.service" in unit
    assert 'aims-v8-capture-$CAPTURE_RELEASE_ID' in script
    assert "snapshot_runtime" in script
    assert 'snapshot_file "$VOCAB"' in script
    assert "endpoint-probe-before.txt" in script
    assert "endpoint-probe-after.txt" in script
    assert "traffic-errors-$deployment.log" in script
    assert "merge_feature_captures.py" in script
