"""LID-DS 2019 driver (lidds2019-confirmation-v2): token-branch decision as lidds-ml-v5, gate, once-only scoring."""
import gzip
import io
import json
from pathlib import Path
import sys
import zipfile

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import lidds2019_token as d  # noqa: E402


def write_scenario(dirpath, name, recordings):
    """val maxima 1..60 (threshold well above 60 is impossible: a moment Gumbel of 1..60 at 1.8e-4 is about 120)."""
    arrays = {f'val/v{i}': np.asarray([[float(i), float(i)]]) for i in range(1, 61)}
    meta = {}
    for rec, (split, exploit, scores) in recordings.items():
        arrays[rec] = np.asarray([[t, s] for t, s in scores], float).reshape(-1, 2)
        meta[rec] = dict(split=split, exploit=exploit)
    np.savez_compressed(dirpath / f'{name}.npz', **arrays)
    (dirpath / f'{name}.json').write_text(json.dumps(dict(scenario=name, columns=['window_end', 'xfit'], recordings=meta)))


def test_decisions_detection_latency_and_false_alarms(tmp_path):
    write_scenario(tmp_path, 'S', {'a1': ('test-normal_and_attack', 10.0, [(9.0, 500.0), (11.0, 500.0)]),
                                   'a2': ('test-normal_and_attack', 10.0, [(11.0, 1.0)]),
                                   'n1': ('test-normal', None, [(5.0, 500.0)]),
                                   'n2': ('test-normal', None, [(5.0, 2.0)])})
    scn = d.TokenScenario('S', tmp_path)
    assert 60 < scn.threshold < 500
    primary, library = d.inventory({'S': scn})
    p, per = d.score_part({'S': scn}, primary, 'all')
    assert (p['detected'], p['attack_recordings'], p['false_alarm_recordings'], p['normal_recordings']) == (1, 2, 1, 2)
    assert abs(p['latency_p95'] - 1.0) < 1e-9 and library is None


def test_score_needs_a_passed_gate_and_reads_library_times(tmp_path):
    tok, arc = tmp_path / 'tok', tmp_path / 'arc'
    tok.mkdir()
    arc.mkdir()
    write_scenario(tok, 'S', {'a1': ('test-normal_and_attack', 10.0, [(9.0, 500.0)]), 'n1': ('test-normal', None, [(5.0, 1.0)])})
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, 'w') as z:
        z.writestr('a1.sc', '')
        z.writestr('a1.json', json.dumps(dict(exploit=True, time=dict(exploit=[dict(absolute=10.0)], exploit_library=[dict(absolute=8.0)]))))
    with zipfile.ZipFile(arc / 'S.zip', 'w') as z:
        z.writestr('S/test/normal_and_attack/a1.zip', inner.getvalue())
    bad = tmp_path / 'gate-bad.json'
    bad.write_text(json.dumps(dict(passed=False)))
    with pytest.raises(SystemExit):
        d.score(tok, arc, bad)
    good = tmp_path / 'gate.json'
    good.write_text(json.dumps(dict(passed=True)))
    out = d.score(tok, arc, good)
    assert out['primary']['pooled']['detected'] == 0                      # alarm at 9 s is before the primary time 10 s
    assert out['library_exploit_time']['pooled']['detected'] == 1         # but after the library time 8 s
    assert out['C1']['all'] is False and out['C2_named'] == ['S']


def test_gate_compares_with_the_registered_2021_result(tmp_path):
    write_scenario(tmp_path, 'S', {'a1': ('test-normal_and_attack', 10.0, [(11.0, 500.0)]), 'n1': ('test-normal', None, [(5.0, 1.0)])})
    alarms = tmp_path / 'alarms.json.gz'
    with gzip.open(alarms, 'wt') as f:
        json.dump(dict(scenarios=dict(S=dict(alarms=dict(a1=dict(split='test-normal_and_attack', exploit=10.0, subset='official'),
                                                        n1=dict(split='test-normal', exploit=None, subset='official'))))), f)
    g = d.gate(tmp_path, alarms)
    assert g['reproduced']['detected'] == 1 and g['passed'] is False


def test_tolerance_counts_an_alarm_within_the_label_resolution(tmp_path):
    write_scenario(tmp_path, 'S', {'a1': ('test-normal_and_attack', 10.0, [(9.5, 500.0)]), 'n1': ('test-normal', None, [(5.0, 500.0)])})
    scn = d.TokenScenario('S', tmp_path)
    prim, _ = d.inventory({'S': scn})
    base, _ = d.score_part({'S': scn}, prim, 'all')
    tol, _ = d.score_part({'S': scn}, d.shifted(prim, 1.0), 'all')
    assert base['detected'] == 0 and tol['detected'] == 1
    assert tol['false_alarm_recordings'] == base['false_alarm_recordings'] == 1     # normal recordings unchanged
    assert abs(tol['latency_p95'] - 0.5) < 1e-9
