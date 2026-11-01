import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
spec = importlib.util.spec_from_file_location('mls', ROOT / 'scripts' / 'analysis' / 'lidds_ml_select.py')
mls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mls)


def part(tmp_path, scenario, outcomes):
    p = tmp_path / f'{scenario}.json'
    p.write_text(json.dumps(dict(scenario=scenario, outcomes=outcomes)))
    return str(p)


def rows(detect, lat, normal_fa, subset_split=0.3):
    a = [['test-normal_and_attack', i >= 100 - detect, lat if i >= 100 - detect else None, 0, 9,
          'development' if i < 30 else 'official', f'a{i}'] for i in range(100)]
    n = [['test-normal', False, None, 1 if i < normal_fa else 0, 9, None, f'n{i}'] for i in range(400)]
    return a + n


def test_selection_respects_precision_latency_and_cbds_then_scores_official_once(tmp_path):
    lid = {'g0|plain|bonferroni': rows(60, 1.0, 0),            # baseline: low recall
           'g0+g1|plain|bonferroni': rows(98, 1.0, 1),         # good
           'g0+g1+g2|plain|bonferroni': rows(100, 5.0, 0),     # too slow
           'g0+g2|plain|bonferroni': rows(100, 1.0, 60)}       # too many false alarms
    cb = {k: rows(100, 1.0, 0) for k in lid}
    out = tmp_path / 'sel.json'
    sys.argv = ['x', '--lidds2021', part(tmp_path, 'SCN', lid), '--cbds', part(tmp_path / '..', 'CB-DS', cb), '--output', str(out)]
    mls.main()
    doc = json.loads(out.read_text())
    assert doc['qualified'] and doc['selected']['config'] == 'g0+g1|plain|bonferroni'
    assert doc['baseline_official']['pooled']['recall'] < doc['official']['pooled']['recall']
    assert set(doc['criteria']) == {'recall', 'precision_base_rate', 'latency_p95'}
