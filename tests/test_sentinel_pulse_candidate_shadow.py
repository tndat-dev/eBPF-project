import numpy as np

from sentinel_pulse.candidate_shadow import CandidateShadowRuntime
from sentinel_pulse.encoding import compact_record


class _Scorer:
    manifest_sha256 = "a" * 64
    manifest = {"history_windows": 3}

    def __init__(self):
        self.contexts = []

    def score_context(self, workload, context):
        self.contexts.append((workload, context.copy()))
        return {"status": "candidate-raw-score-only", "raw_model_anomaly": True,
                "alert": False, "policy_applied": False, "serving_compatible": False}


class _PreviewPolicy:
    def __init__(self, scorer):
        self.scorer = scorer

    def evaluate(self, _score):
        return {"policy_evaluated": True, "candidate_alert_preview": True,
                "alert": False, "policy_applied": False, "serving_compatible": False}


def _row(end, *, uid="uid", revision="r1", value=0.0):
    record = {
        "schema": "sentinel-pulse-extended-feature-v2",
        "telemetry_contract": "pulse-entered-plus-seccomp-skip-idle-v2",
        "workload_key": "production/catalog:app",
        "pod_uid": uid,
        "container_name": "app",
        "workload_revision": revision,
        "cgroup_id": 42,
        "window_start": end - 0.5,
        "window_end": end,
        "columns": [f"feature_{i}" for i in range(249)],
        "vector": np.full(249, value, dtype=np.float32),
        "exact_counts": {"seccomp_skipped_or_emulated": 0},
    }
    return compact_record(record)[0]


def test_shadow_scores_only_after_four_contiguous_windows_and_never_alerts():
    scorer = _Scorer()
    runtime = CandidateShadowRuntime(scorer, policy=_PreviewPolicy(scorer))
    results = [runtime.observe(_row(10 + i * 0.5, value=float(i)), processed_at=20)
               for i in range(4)]

    assert [row["status"] for row in results[:3]] == ["warming"] * 3
    assert results[3]["status"] == "candidate-raw-score-only"
    assert results[3]["history_available"] == 4
    assert results[3]["raw_model_anomaly"] is True
    assert results[3]["alert"] is False
    assert results[3]["policy_applied"] is False
    assert results[3]["candidate_alert_preview"] is True
    assert len(scorer.contexts) == 1
    assert scorer.contexts[0][1].shape == (996,)
    assert scorer.contexts[0][1][-1] == 3


def test_shadow_resets_on_gap_and_does_not_bridge_revision_or_uid():
    scorer = _Scorer()
    runtime = CandidateShadowRuntime(scorer)
    runtime.observe(_row(10), processed_at=20)
    gap = runtime.observe(_row(11.1), processed_at=20)
    changed_uid = runtime.observe(_row(11.6, uid="uid-2"), processed_at=20)
    changed_revision = runtime.observe(_row(12.1, revision="r2"), processed_at=20)

    assert gap["status"] == "warming" and gap["reset_reason"] == "non_contiguous_window"
    assert changed_uid["history_available"] == 1
    assert changed_revision["history_available"] == 1
    assert scorer.contexts == []


def test_shadow_rejects_wrong_contract_and_vector_dimension():
    runtime = CandidateShadowRuntime(_Scorer())
    row = _row(10)
    row["telemetry_contract"] = "legacy"
    try:
        runtime.observe(row)
    except ValueError as exc:
        assert "contract" in str(exc)
    else:
        raise AssertionError("wrong telemetry contract was accepted")

    row = _row(10)
    row["vector_dim"] = 248
    try:
        runtime.observe(row)
    except ValueError as exc:
        assert "249" in str(exc)
    else:
        raise AssertionError("wrong vector dimension was accepted")


def test_collector_integrity_error_resets_history_and_is_not_scored():
    scorer = _Scorer()
    runtime = CandidateShadowRuntime(scorer)
    runtime.observe(_row(10), processed_at=20)
    degraded = _row(10.5)
    degraded["collector_stats"] = {"snapshot_projection_fail": 1}

    result = runtime.observe(degraded, processed_at=20)

    assert result["status"] == "degraded_telemetry"
    assert result["reset_reason"] == "collector_integrity_error"
    assert result["alert"] is False
    assert scorer.contexts == []
