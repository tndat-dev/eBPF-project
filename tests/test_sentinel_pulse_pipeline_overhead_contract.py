import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_overhead_contract_is_preregistered_and_counterbalanced():
    contract = json.loads(
        (ROOT / "sentinel_pulse/protocol/pipeline-overhead-contract-v1.json").read_text()
    )
    assert contract["registered_before_blind_outcomes"] is True
    assert contract["automatic_promotion"] is False
    assert contract["candidate_interlock"]["required_status"] == (
        "eligible_for_overhead_evaluation"
    )
    order = contract["design"]["phase_order"]
    assert len(order) == 12
    pairs = [order[index:index + 2] for index in range(0, len(order), 2)]
    assert all(set(pair) == {"off", "on"} for pair in pairs)
    assert sum(pair == ["off", "on"] for pair in pairs) == 3
    assert sum(pair == ["on", "off"] for pair in pairs) == 3
    assert len(contract["scope"]["workers"]) == 3
    assert contract["scope"]["minimum_independent_dates"] >= 2


def test_pipeline_overhead_contract_measures_full_ml_increment_and_equivalence():
    contract = json.loads(
        (ROOT / "sentinel_pulse/protocol/pipeline-overhead-contract-v1.json").read_text()
    )
    assert "sentinel_pulse_500ms_collector" not in contract["conditions"]["off"]
    assert "sentinel_pulse_extratrees_detector" not in contract["conditions"]["off"]
    assert "sentinel_pulse_500ms_collector" in contract["conditions"]["on"]
    assert "sentinel_pulse_extratrees_detector" in contract["conditions"]["on"]
    assert contract["quality_gates"]["maximum_normal_alerts"] == 0
    assert contract["statistics"]["equivalence_claim_requires_confidence_interval_inside_margin"] is True
    assert contract["statistics"]["holm_correction"] is True
