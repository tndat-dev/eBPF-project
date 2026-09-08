from copy import deepcopy

import pytest

from sentinel_pulse.aggregate_formal_telemetry import aggregate


CONTRACT = {
    "nominal_interval_seconds": 0.5,
    "minimum_availability": 0.999,
    "maximum_single_gap_seconds": 10.0,
}


def marker():
    return {"run_id": "formal-r8", "telemetry_availability_contract": CONTRACT}


def report():
    return {
        "valid": True,
        "duration_seconds": 90001.0,
        "rows": 100000,
        "workload_count": 10,
        "telemetry_availability_contract": CONTRACT,
        "telemetry_availability": {
            "availability": 0.9995,
            "maximum_gap_seconds": 4.0,
            "estimated_missing_snapshots": 90,
        },
        "collector_max_drops": {},
    }


def reports():
    return {f"worker-{index}": report() for index in range(3)}


def test_formal_telemetry_passes_three_nodes_within_frozen_contract():
    result = aggregate(marker(), reports())
    assert result["valid"] is True
    assert len(result["nodes"]) == 3
    assert all(node["valid"] for node in result["nodes"].values())


@pytest.mark.parametrize("failure", ["availability", "gap", "hard_integrity"])
def test_formal_telemetry_rejects_contract_failures(failure):
    node_reports = reports()
    broken = node_reports["worker-1"]
    if failure == "availability":
        broken["telemetry_availability"]["availability"] = 0.998
    elif failure == "gap":
        broken["telemetry_availability"]["maximum_gap_seconds"] = 10.1
    else:
        broken["collector_max_drops"]["count_insert_fail"] = 1
    result = aggregate(marker(), node_reports)
    assert result["valid"] is False
    assert result["nodes"]["worker-1"]["valid"] is False


def test_formal_telemetry_rejects_node_contract_drift():
    node_reports = reports()
    node_reports["worker-1"]["telemetry_availability_contract"] = deepcopy(CONTRACT)
    node_reports["worker-1"]["telemetry_availability_contract"][
        "minimum_availability"
    ] = 0.99
    with pytest.raises(ValueError, match="contract mismatch"):
        aggregate(marker(), node_reports)


def test_formal_telemetry_requires_exactly_three_nodes():
    node_reports = reports()
    node_reports.pop("worker-2")
    assert aggregate(marker(), node_reports)["valid"] is False
