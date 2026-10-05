import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_pulse.collector_contract import bind, check_resume, check_runtime


def plan_fixture(tmp_path):
    data = {"schema": "sentinel-pulse-projected-ml-canary-plan-v1",
            "model_manifest_sha256": "a" * 64, "decision_policy_sha256": "b" * 64,
            "workers": {h: "/var/lib/sentinel-pulse-projection-canary/safety-c1"
                        for h in ("10.1.16.237", "10.1.16.238", "10.1.16.239")}}
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(data))
    return plan, data


def test_bind_requires_matching_frozen_model_and_policy(tmp_path):
    plan, _ = plan_fixture(tmp_path)
    result = bind("projected", plan, "a" * 64, "b" * 64)
    assert result["variant"] == "projected"
    assert len(result["plan_sha256"]) == 64
    with pytest.raises(ValueError, match="identity"):
        bind("projected", plan, "c" * 64, "b" * 64)


@pytest.mark.parametrize("bad_path", ["/tmp/safety", "/var/lib/sentinel-pulse-projection-canary/..",
                                      "/var/lib/sentinel-pulse-projection-canary/foo/bar", 123])
def test_bind_rejects_unsafe_paths(tmp_path, bad_path):
    plan, data = plan_fixture(tmp_path)
    data["workers"]["10.1.16.237"] = bad_path
    plan.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unsafe"):
        bind("projected", plan, "a" * 64, "b" * 64)


def test_bind_rejects_missing_worker_and_missing_plan(tmp_path):
    plan, data = plan_fixture(tmp_path)
    del data["workers"]["10.1.16.239"]
    plan.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="three worker"):
        bind("projected", plan, "a" * 64, "b" * 64)
    with pytest.raises(ValueError, match="requires"):
        bind("projected", None, "a" * 64, "b" * 64)
    with pytest.raises(ValueError, match="legacy"):
        bind("legacy", plan, "a" * 64, "b" * 64)


def test_resume_never_switches_collector_or_plan(tmp_path):
    plan, _ = plan_fixture(tmp_path)
    contract = bind("projected", plan, "a" * 64, "b" * 64)
    check_resume({"collector_contract": contract}, contract)
    check_resume({}, {"variant": "legacy"})  # old markers retain legacy only
    for supplied in ({"variant": "legacy"}, {**contract, "plan_sha256": "c" * 64},
                     {**contract, "safety_runs": {}}):
        with pytest.raises(ValueError, match="differs"):
            check_resume({"collector_contract": contract}, supplied)
    with pytest.raises(ValueError, match="differs"):
        check_resume({}, contract)


def runtime_fixture():
    prefix = "/opt/sentinel-pulse/experiments/test-run"
    loader = prefix + "/pulse_counter_projected_loader"
    obj = prefix + "/pulse_counter_projected.bpf.o"
    marker = {"run_id": "test-run", "collector_contract": {
        "variant": "projected", "unit_sha256": "u" * 64,
        "artifacts": {"10.1.16.237": {"loader_sha256": "l" * 64,
                                        "bpf_object_sha256": "o" * 64}}}}
    start = {"collector_variant": "projected", "collector_loader": loader,
             "collector_bpf_object": obj,
             "sha256": {"loader": "l" * 64, "bpf_object": "o" * 64, "unit": "u" * 64}}
    env = {"PULSE_500MS_COLLECTOR_VARIANT": "projected", "PULSE_500MS_RUN_ID": "test-run",
           "PULSE_500MS_LOADER": loader, "PULSE_500MS_BPF_OBJECT": obj}
    return marker, start, env


def mocked_hash(path):
    return ("l" if str(path).endswith("_loader") else
            "o" if str(path).endswith(".bpf.o") else "u") * 64


def test_runtime_matches_registered_pair_and_unit():
    marker, start, env = runtime_fixture()
    with patch("sentinel_pulse.collector_contract.sha256_file", side_effect=mocked_hash):
        assert check_runtime(marker, "10.1.16.237", start, env, Path("unit"))["valid"]


@pytest.mark.parametrize("field,value", [
    ("PULSE_500MS_COLLECTOR_VARIANT", "legacy"), ("PULSE_500MS_RUN_ID", "other"),
    ("PULSE_500MS_LOADER", "/opt/sentinel-pulse/bin/pulse_counter_loader"),
    ("PULSE_500MS_BPF_OBJECT", "/tmp/other.bpf.o")])
def test_runtime_rejects_variant_run_and_path_drift(field, value):
    marker, start, env = runtime_fixture()
    env[field] = value
    with patch("sentinel_pulse.collector_contract.sha256_file", side_effect=mocked_hash):
        with pytest.raises(ValueError, match="drift"):
            check_runtime(marker, "10.1.16.237", start, env, Path("unit"))


@pytest.mark.parametrize("field", ["loader", "bpf_object", "unit"])
def test_runtime_rejects_checksum_drift(field):
    marker, start, env = runtime_fixture()
    start = copy.deepcopy(start)
    start["sha256"][field] = "0" * 64
    with patch("sentinel_pulse.collector_contract.sha256_file", side_effect=mocked_hash):
        with pytest.raises(ValueError, match="checksum drift"):
            check_runtime(marker, "10.1.16.237", start, env, Path("unit"))


def test_runtime_rejects_actual_binary_tamper_even_with_unchanged_start():
    marker, start, env = runtime_fixture()
    with patch("sentinel_pulse.collector_contract.sha256_file", return_value="0" * 64):
        with pytest.raises(ValueError, match="checksum drift"):
            check_runtime(marker, "10.1.16.237", start, env, Path("unit"))
