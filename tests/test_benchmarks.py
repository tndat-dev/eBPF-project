import importlib.util
from pathlib import Path

import pytest


HERE = Path(__file__).resolve()
MODULE_PATH = next(path for path in (
    HERE.with_name("measure_phase.py"),  # flat VM deployment
    HERE.parents[1] / "sentinel" / "benchmarks" / "measure_phase.py",
) if path.is_file())
spec = importlib.util.spec_from_file_location("measure_phase", MODULE_PATH)
measure_phase = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure_phase)
compare_path = next(path for path in (
    HERE.with_name("compare_overhead.py"),
    HERE.parents[1] / "sentinel" / "benchmarks" / "compare_overhead.py",
) if path.is_file())
compare_spec = importlib.util.spec_from_file_location("compare_overhead", compare_path)
compare_overhead = importlib.util.module_from_spec(compare_spec)
compare_spec.loader.exec_module(compare_overhead)


def test_kubernetes_quantity_parsing():
    assert measure_phase.cpu_millicores("1500m") == 1500
    assert measure_phase.cpu_millicores("1000000n") == 1
    assert measure_phase.memory_mib("2Gi") == 2048
    assert measure_phase.memory_mib("512Ki") == 0.5


def test_ab_output_parsing():
    output = """
Failed requests:        0
Requests per second:    1234.50 [#/sec] (mean)
Time per request:       8.100 [ms] (mean, across all concurrent requests)
  99%     17
"""
    parsed = measure_phase.parse_ab(output)
    assert parsed == {
        "requests_per_second": 1234.5,
        "time_per_request_concurrent_ms": 8.1,
        "failed_requests": 0.0,
        "latency_p99_ms": 17.0,
    }


def test_wrk_output_parsing_and_latency_units():
    output = """
  Latency   237.55us  310.00us   5.41ms   90.00%
  Latency Distribution
     50%  190.00us
     75%  290.00us
     90%  510.00us
     99%    1.22ms
Requests/sec: 32100.25
Socket errors: connect 0, read 1, write 0, timeout 2
Non-2xx or 3xx responses: 4
"""
    assert measure_phase.parse_wrk(output) == {
        "requests_per_second": 32100.25,
        "time_per_request_concurrent_ms": 0.23755,
        "failed_requests": 7.0,
        "socket_errors": 3,
        "non_2xx_or_3xx": 4,
        "latency_p99_ms": 1.22,
    }


def test_quality_gate_rejects_http_errors_even_when_wrk_exits_zero():
    report = {
        "warmup": {"exit_code": 0, "failed_requests": 0},
        "runs": [{
            "run": 1,
            "exit_code": 0,
            "requests_per_second": 100,
            "time_per_request_concurrent_ms": 10,
            "latency_p99_ms": 20,
            "failed_requests": 1,
        }],
    }
    gate = measure_phase.quality_gate(report)
    assert gate["passed"] is False
    assert "failed/non-success" in gate["reasons"][0]


def test_overhead_effect_direction_is_explicit():
    throughput = compare_overhead.effect([80, 80], [100, 100], "throughput_loss")
    latency = compare_overhead.effect([2, 2], [1, 1], "latency_increase")
    assert throughput["estimate_percent"] == pytest.approx(20.0)
    assert latency["estimate_percent"] == pytest.approx(100.0)


def test_resource_summary_aggregates_selected_workload_replicas():
    snapshots = [{"rows": [
        {"namespace": "production", "pod": "api-gateway-a",
         "cpu_millicores": 10, "memory_mib": 20},
        {"namespace": "production", "pod": "api-gateway-b",
         "cpu_millicores": 15, "memory_mib": 25},
        {"namespace": "production", "pod": "unrelated-a",
         "cpu_millicores": 100, "memory_mib": 100},
    ]}]
    result = measure_phase.resource_summaries(
        snapshots, "production", ["api-gateway-"]
    )
    assert result["cpu_millicores"]["median"] == 25
    assert result["memory_mib"]["median"] == 45


def test_file_hash_binds_overhead_environment(tmp_path):
    path = tmp_path / "environment.txt"
    path.write_bytes(b"cluster-state")
    import hashlib
    assert compare_overhead.file_sha256(path) == hashlib.sha256(
        b"cluster-state"
    ).hexdigest()


def test_aims_overhead_interlock_is_not_bound_to_a_stale_training_unit():
    root = HERE.parents[1]
    script = root / "sentinel" / "benchmarks" / "run_aims_overhead_matrix.sh"
    if not script.is_file():
        pytest.skip("repository-only orchestration script")
    text = script.read_text()
    assert "aims-normal-matrix.service" in text
    assert "aims-candidate-fit-v1.service" not in text
