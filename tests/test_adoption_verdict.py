import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('adoption_verdict', Path(__file__).parents[1]/'scripts'/'analysis'/'adoption_verdict.py')
av = importlib.util.module_from_spec(spec); spec.loader.exec_module(av)


def arm(recall, recall_lo, sep, sep_lo):
    return dict(recall_diff=dict(point=recall, ci95=[recall_lo, recall + .02]), separation_diff=dict(point=sep, ci95=[sep_lo, sep + .1]))


def test_rule_needs_recall_separation_and_latency():
    assert av.verdict(arm(0.0, -0.005, 0.01, -0.04), dict(delay_p95=1.1), av.RULE)['adopt']
    assert not av.verdict(arm(0.017, 0.005, -0.181, -0.301), dict(delay_p95=1.09), av.RULE)['adopt']   # dev autoencoder
    assert not av.verdict(arm(0.0, -0.02, 0.05, 0.0), dict(delay_p95=1.0), av.RULE)['adopt']
    assert not av.verdict(arm(0.0, 0.0, 0.05, 0.0), dict(delay_p95=2.4), av.RULE)['adopt']


def test_main_reads_real_bootstrap_and_budget_receipts(tmp_path):
    import json, subprocess, sys
    e = Path(__file__).parents[1]/'validation-evidence'/'results-20261021'/'baselines'
    out = tmp_path/'v.json'
    subprocess.run([sys.executable, str(Path(av.__file__)), '--bootstrap', str(e/'BOOTSTRAP.json'),
                    '--budget-results', str(e/'RESULTS-budget.json'), '--output', str(out)], check=True, capture_output=True)
    v = json.loads(out.read_text())
    assert v['next_scorer'] == 'base29' and v['candidates']['autoencoder']['checks'] == dict(recall=True, separation=False, latency=True)
