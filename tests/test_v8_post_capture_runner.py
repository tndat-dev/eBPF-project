from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT


def test_v8_post_capture_runner_is_fit_only_and_never_promotes():
    path = SERVICE_ROOT / "run_v8_post_capture.sh"
    script = path.read_text()
    assert path.stat().st_mode & stat.S_IXUSR
    assert "aims-v8-capture.service is active" in script
    assert "Result=success" in script
    assert ".aims-normal-matrix.lock" in script
    assert "sha256sum -c SHA256SUMS" in script
    assert "completed_phases\") != 24" in script
    assert "aims-{steady,burst,recovery,toolmix}-run-01" in script
    assert "--dataset-role candidate_fit" in script
    assert "--role independent_evaluation" in script
    assert "--initial-calibration-report" in script
    assert "falco_evidence_finalizer.py" in script
    assert "falco-rule-only-normal" in script
    assert "fast_path_normal_evidence_finalizer.py" in script
    assert "fast-path-live-normal" in script
    assert "retrospective_operational_normal_evidence" in script
    assert 'doc.get("phase_count") != 20' in script
    assert "POST_CAPTURE_COMPLETE" in script
    assert "syscall_evaluation_protocol.json" in script
    assert "protocol method mismatch" in script
    assert "run-02" not in script
    assert "train_candidate.py" in script
    assert "promote_candidate.py" not in script
    assert "models/" not in script


def test_deployer_freezes_live_fast_path_before_overwriting_runtime_source():
    script = (SERVICE_ROOT / "deploy_and_run_v8_post_capture.sh").read_text()
    finalizer = script.index("fast_path_normal_evidence_finalizer.py")
    runtime_copy = script.index("for name in anomaly_detector2.py")
    assert finalizer < runtime_copy
    assert "v8_fast_path_normal_contract.json" in script
    assert "tests/test_fast_path_normal_evidence_finalizer.py" in script
