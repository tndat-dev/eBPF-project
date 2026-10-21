import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('ideas_verdict', Path(__file__).parents[1]/'scripts'/'analysis'/'ideas_verdict.py')
iv = importlib.util.module_from_spec(spec); spec.loader.exec_module(iv)
REF = dict(attack=0.99, control=0.04, p95=1.9, burden=6.0)


def test_lower_burden_wins_only_within_recall_control_and_latency_limits():
    assert iv.verdict(REF, dict(REF, burden=5.4))['clause_a']
    assert not iv.verdict(REF, dict(REF, burden=5.5))['better']                 # only 8% lower
    assert not iv.verdict(REF, dict(REF, burden=5.0, attack=0.975))['better']   # recall -1.5 points
    assert not iv.verdict(REF, dict(REF, burden=5.0, control=0.05))['better']
    assert not iv.verdict(REF, dict(REF, burden=5.0, p95=2.2))['better']


def test_faster_alert_wins_when_burden_does_not_grow():
    assert iv.verdict(REF, dict(REF, p95=1.7))['clause_b']
    assert not iv.verdict(REF, dict(REF, p95=1.7, burden=6.1))['better']
