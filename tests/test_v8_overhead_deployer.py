from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT


def test_v8_overhead_deployer_is_hash_gated_atomic_and_timer_only():
    path = SERVICE_ROOT / "deploy_v8_overhead.sh"
    script = path.read_text()
    assert path.stat().st_mode & stat.S_IXUSR
    assert "sha256sum -c STAGING_SHA256SUMS" in script
    assert "pytest -q" in script
    assert "install_atomic" in script
    assert ".v8-overhead-staging" in script
    assert "systemctl enable --now aims-v8-overhead.timer" in script
    assert "systemctl start aims-v8-overhead.service" not in script
    assert "NORMAL_ABLATION_REPLAY_COMPLETE" in script
