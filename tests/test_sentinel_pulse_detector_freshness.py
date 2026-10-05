import math

import pytest

from sentinel_pulse.detector_freshness import CONTRACT, CONTRACT_SHA256, check, complete
from sentinel_pulse.telemetry_recovery import digest
from sentinel_pulse.audit_recovery_smoke_latency import quantiles


def test_processing_age_is_not_capture_emission_age():
    row = {"window_end": 100, "emitted_at": 100.01}
    assert check(row, 100.1)["eligible"]
    state = check(row, 112)
    assert not state["eligible"]
    assert state["reason"] == "detector_queue_stale"
    assert state["feature_age_at_processing_start_seconds"] == 12
    assert state["contract_sha256"] == digest(CONTRACT) == CONTRACT_SHA256


@pytest.mark.parametrize("now,eligible", [(101, True), (101.0001, False)])
def test_processing_age_boundary(now, eligible):
    assert check({"window_end": 100, "emitted_at": 100.01}, now)["eligible"] is eligible


@pytest.mark.parametrize("field,value", [("window_end", math.nan), ("emitted_at", math.inf),
                                         ("window_end", True)])
def test_invalid_timestamp_rejected(field, value):
    row = {"window_end": 100, "emitted_at": 100.01, field: value}
    with pytest.raises(ValueError, match="timestamps"):
        check(row, 101)


def test_processing_clock_errors_fail_closed():
    row = {"window_end": 100, "emitted_at": 100.01}
    with pytest.raises(ValueError, match="backwards"):
        check(row, 101, previous_checked_at=102)
    with pytest.raises(ValueError, match="precedes"):
        check(row, 99.9)
    with pytest.raises(ValueError, match="completion clock"):
        complete(check(row, 100.1), 100, 100.09)


def test_completion_timestamp_has_explicit_scope():
    state = complete(check({"window_end": 100, "emitted_at": 100.01}, 100.1), 100, 100.13)
    assert state["decision_completed_at"] == 100.13
    assert state["window_end_to_decision_completed_seconds"] == pytest.approx(.13)
    assert not CONTRACT["kernel_to_alert_claim_allowed"]


def test_audit_nearest_rank_quantiles():
    assert quantiles([]) == {"n": 0}
    assert quantiles([5, 1, 2, 3, 4]) == {"n": 5, "p50": 3, "p95": 5, "p99": 5, "max": 5}
