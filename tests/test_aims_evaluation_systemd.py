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
    assert "systemctl is-active --quiet aims-normal-matrix.service" in script
    assert "WAITING: aims-normal-matrix.service is active" in script


def test_split_evaluation_unit_is_bounded_and_non_privileged():
    unit = (SYSTEMD_ROOT / "aims-split-evaluation@.service").read_text()
    assert "User=dat" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CPUQuota=100%" in unit
    assert "MemoryMax=8G" in unit
    assert "EnvironmentFile=/home/dat/ml-service/aims-evaluation.env" in unit
    assert "/usr/bin/flock -w 300" in unit
    assert "TimeoutStartSec=2h" in unit
    assert "promote" not in unit.lower()
