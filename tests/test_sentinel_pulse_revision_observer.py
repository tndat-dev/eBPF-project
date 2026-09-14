from pathlib import Path


def test_revision_observer_is_bounded_and_fail_closed():
    source = (
        Path(__file__).resolve().parents[1]
        / "sentinel_pulse"
        / "observe_revision_baseline.sh"
    ).read_text(encoding="utf-8")
    assert "DURATION_SECONDS=${DURATION_SECONDS:-86400}" in source
    assert "PREFLIGHT_STABILITY_SECONDS=${PREFLIGHT_STABILITY_SECONDS:-300}" in source
    assert "test ! -e \"$EVIDENCE_ROOT\"" in source
    assert "fail workload_revision_changed" in source
    assert "APPROVED_FINGERPRINT.json" in source
    assert "FINAL_SHA256SUMS" in source
    assert "export KUBECONFIG=\"$KUBECONFIG_PATH\"" in source
    assert '>"$EVIDENCE_ROOT/$prefix-pods.json" || return 1' in source
    assert "fail preflight_not_stable" in source
    assert '(.status.phase // "") == "Healthy"' in source
    assert 'RUNTIME_ROOT="$EVIDENCE_ROOT/runtime"' in source
    assert 'PYTHONPATH="$RUNTIME_ROOT"' in source
    assert "SOURCE_SHA256SUMS" in source
