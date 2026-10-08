import json
import pytest
from sentinel_pulse.benchmark_support import benchmark
from test_sentinel_pulse_support_analysis import fixture


def test_support_timing_is_single_context_and_not_kernel_latency(tmp_path):
    root,analysis,_,output=fixture(tmp_path)
    report=benchmark(root,analysis,output,samples=20)
    assert report['batches_of_one'] is True
    assert report['kernel_to_alert_seconds'] is None
    assert len(report['workloads']['workload']['individual_inference_ms'])==20
    assert report['workloads']['missing']['status']=='missing_normal_contexts'


def test_timing_does_not_accept_too_few_samples(tmp_path):
    with pytest.raises(ValueError,match='20'):
        benchmark(tmp_path,tmp_path/'a',tmp_path/'b',samples=1)


def test_expectations_do_not_stop_run_on_nonzero_false_positive():
    from pathlib import Path
    protocol=Path(__file__).resolve().parents[1]/'sentinel_pulse/protocol/pulse-improvement-expectations-c1.json'
    d=json.loads(protocol.read_text())
    assert d['zero_false_positive_gate'] is False and d['stop_on_quality_failure'] is False
    m=d['example_only_confusion_matrix_for_475_positive_and_475_negative_intervals']
    assert m['TP_minimum']/(m['TP_minimum']+m['FN_maximum'])>=d['recall_minimum']
    assert m['FP_maximum']/(m['FP_maximum']+m['TN_minimum'])<=d['interval_false_positive_rate_maximum']
