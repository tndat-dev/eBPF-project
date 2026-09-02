from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_attachment_waits_for_launch_commit_not_early_soak_marker():
    script = (
        ROOT / "sentinel_pulse" / "attach_lifecycle_supervisor_when_ready.sh"
    ).read_text()
    active = script.index('-f "$EVIDENCE_ROOT/ACTIVE"')
    marker = script.index('-f "$EVIDENCE_ROOT/SOAK_START.json"')
    workers = script.index('wc -l <"$EVIDENCE_ROOT/workers.txt"')
    supervisor = script.index("supervise_500ms_candidate_lifecycle.sh")

    assert active < supervisor
    assert marker < supervisor
    assert workers < supervisor
    assert "-eq 3" in script
    assert "WAIT_TIMEOUT_SECONDS" in script
