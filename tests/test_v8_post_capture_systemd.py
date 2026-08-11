from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT
SYSTEMD_ROOT = ROOT / "sentinel" / "systemd"


def test_v8_post_capture_deployer_is_hash_gated_and_atomic():
    path = SERVICE_ROOT / "deploy_and_run_v8_post_capture.sh"
    script = path.read_text()
    assert path.stat().st_mode & stat.S_IXUSR
    assert "sha256sum -c STAGING_SHA256SUMS" in script
    assert "installed systemd unit differs from staging" in script
    assert "aims-v8-capture.service is active" in script
    assert "Result=success" in script
    assert ".$name.v8-staging" in script
    assert "pytest -q" in script
    assert "anomaly_detector2.py" in script
    assert "tests/test_sentinel.py" in script
    assert "falco_evidence_finalizer.py" in script
    assert "tests/test_falco_evidence_finalizer.py" in script
    assert "run_v8_blind_attack.sh" in script
    assert "aims-v8-blind-attack.service" in script
    assert "tests/test_v8_blind_attack.py" in script
    assert "falco_attack_evidence_finalizer.py" in script
    assert "tests/test_falco_attack_evidence_finalizer.py" in script
    assert "V8 blind attack binary digest mismatch" in script
    assert "run_v8_post_capture.sh" in script
    assert "promote_candidate.py" not in script


def test_v8_post_capture_service_is_bounded_and_timer_driven():
    service = (SYSTEMD_ROOT / "aims-v8-post-capture.service").read_text()
    timer = (SYSTEMD_ROOT / "aims-v8-post-capture.timer").read_text()
    assert "User=dat" in service
    assert "NoNewPrivileges=true" in service
    assert "CPUQuota=100%" in service
    assert "MemoryMax=8G" in service
    assert "TimeoutStartSec=36h" in service
    assert ".aims-normal-matrix.lock" in service
    assert "POST_CAPTURE_COMPLETE" in service
    assert "ExecStartPost" not in service
    assert "SuccessExitStatus=75" in service
    assert "OnUnitInactiveSec=15min" in timer
    assert "Persistent=true" in timer
    assert "promote" not in service.lower()
