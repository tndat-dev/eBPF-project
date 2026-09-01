import json
import os
from pathlib import Path
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = ROOT / "sentinel_pulse" / "supervise_500ms_candidate_lifecycle.sh"


def evidence_fixture(root: Path) -> None:
    (root / "SOAK_START.json").write_text(
        json.dumps({"run_id": "supervisor-test"}) + "\n", encoding="utf-8"
    )
    (root / "workers.txt").write_text(
        "10.1.16.237 worker /tmp/features.jsonl\n", encoding="utf-8"
    )
    (root / "ACTIVE").touch()


def supervisor_env(local_root: Path) -> dict[str, str]:
    return {
        **os.environ,
        "SSHPASS": "test-only",
        "LOCAL_ROOT": str(local_root),
        "POLL_SECONDS": "1",
        "EXIT_GRACE_SECONDS": "1",
    }


def test_supervisor_does_not_mutate_a_live_lifecycle(tmp_path):
    evidence_fixture(tmp_path)
    lifecycle = subprocess.Popen(["sleep", "10"])
    supervisor = subprocess.Popen(
        [str(SUPERVISOR), str(tmp_path), str(lifecycle.pid)],
        env=supervisor_env(ROOT),
    )
    try:
        deadline = time.monotonic() + 3
        while not (tmp_path / "LIFECYCLE_SUPERVISOR.json").exists():
            assert time.monotonic() < deadline
            time.sleep(0.05)
        time.sleep(1.1)
        assert (tmp_path / "ACTIVE").exists()
        assert not (tmp_path / "FAILED").exists()

        (tmp_path / "NORMAL_PASS").touch()
        assert supervisor.wait(timeout=3) == 0
        assert not (tmp_path / "FAILED").exists()
    finally:
        lifecycle.terminate()
        lifecycle.wait(timeout=3)
        if supervisor.poll() is None:
            supervisor.terminate()
            supervisor.wait(timeout=3)


def test_supervisor_archives_a_dead_failed_finalizer(tmp_path):
    evidence_fixture(tmp_path)
    (tmp_path / "FINALIZE_FAILED").write_text("exit_code=7\n", encoding="utf-8")
    fake_root = tmp_path / "fake-root"
    freezer = fake_root / "sentinel_pulse" / "freeze_failed_500ms_normal_soak.sh"
    freezer.parent.mkdir(parents=True)
    freezer.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "test -f \"$1/FAILED\"\n"
        "test ! -e \"$1/ACTIVE\"\n"
        "touch \"$1/ARCHIVE_COMPLETE\"\n",
        encoding="utf-8",
    )
    freezer.chmod(0o755)

    result = subprocess.run(
        [str(SUPERVISOR), str(tmp_path), "99999999"],
        env=supervisor_env(fake_root),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "reason=normal_finalize_failed" in (tmp_path / "FAILED").read_text()
    assert not (tmp_path / "ACTIVE").exists()
    assert (tmp_path / "ARCHIVE_COMPLETE").exists()
