"""Separate, opt-in processing-age contract; never changes capture eligibility."""
from __future__ import annotations

import math

from .telemetry_recovery import digest

CONTRACT = {
    "schema": "sentinel-pulse-detector-freshness-contract-v1",
    "maximum_age_at_processing_start_seconds": 1.0,
    "maximum_future_clock_skew_seconds": 0.05,
    "reset_source_history_on_stale": True,
    "offline_replay": False,
    "kernel_to_alert_claim_allowed": False,
}
CONTRACT_SHA256 = digest(CONTRACT)


def check(record: dict, checked_at: float, previous_checked_at: float | None = None) -> dict:
    end, emitted, now = record["window_end"], record["emitted_at"], checked_at
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
           for v in (end, emitted, now)):
        raise ValueError("invalid detector freshness timestamps")
    if previous_checked_at is not None and now < previous_checked_at:
        raise ValueError("detector processing clock moved backwards")
    tolerance = CONTRACT["maximum_future_clock_skew_seconds"]
    if now < max(end, emitted) - tolerance:
        raise ValueError("detector clock precedes feature/capture clock")
    age = max(0.0, now - end)
    eligible = age <= CONTRACT["maximum_age_at_processing_start_seconds"]
    return {"schema": "sentinel-pulse-detector-freshness-v1",
            "contract_sha256": CONTRACT_SHA256, "checked_at": now,
            "feature_age_at_processing_start_seconds": age,
            "eligible": eligible, "reason": "fresh" if eligible else "detector_queue_stale"}


def complete(state: dict, window_end: float, completed_at: float) -> dict:
    if not math.isfinite(completed_at) or completed_at < state["checked_at"]:
        raise ValueError("invalid detector completion clock")
    return {**state, "decision_completed_at": completed_at,
            "window_end_to_decision_completed_seconds": max(0.0, completed_at - window_end)}
