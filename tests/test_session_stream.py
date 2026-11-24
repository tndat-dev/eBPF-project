"""session-stream-v1: session features and the burden of each system."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import session_stream as ss  # noqa: E402


def test_features_count_calls_and_error_tokens():
    ptrace_err = (101 << 23) | (1 << 21) | 1          # ptrace, kind 1 (errno)
    read_size = (0 << 23) | (2 << 21) | 12            # read, kind 2 (size)
    calls, events, errors = ss.features([[0, 0, 0, ptrace_err, 3], [0, 0, 0, read_size, 2]])
    assert calls == {101: 3, 0: 2} and events == 5 and errors == 3


def test_burden_merges_alarms_into_episodes_per_system():
    alarms = [(('p', 'c'), 'w', t, dict(S0=True, S1=t < 5, S2=False), True, True) for t in (0.0, 1.0, 2.0, 40.0)]
    out = ss.burden(alarms, {'w': 3600.0})
    assert out['replica_hours'] == 1.0
    assert out['systems']['S0']['episodes'] == 2 and out['systems']['S1']['episodes'] == 1
    assert out['systems']['S2']['episodes'] == 0


def test_branch_threshold_is_the_gumbel_quantile():
    assert abs(ss.gumbel_threshold((4.0, 1.0), 0.0003) - (4.0 + 8.1115)) < 1e-3


def test_session_branch_config_takes_native_thresholds_from_the_t3_gumbel():
    import session_branch_config as sbc
    fit = dict(workloads={'w': dict(gumbel=[4.0, 1.0]), 'x': dict(gumbel=None)})
    pooled = {'pool/session': dict(lm='/m', lm_sha256='0' * 64, threshold=9.0, top=3)}
    doc = sbc.build(fit, pooled, None, 0.0003)
    assert list(doc['native_thresholds']) == ['w'] and abs(doc['native_thresholds']['w'] - 12.1115) < 1e-3
    assert doc['pooled']['threshold'] == 9.0 and doc['per'] == {}


class Max:
    """A stand-in model: the window score is the largest count of the grams."""

    def window_score(self, grams):
        return max((g[4] for g in grams), default=0.0)


def test_b2_scores_each_program_by_its_model_and_the_rest_by_the_pooled_one(monkeypatch):
    monkeypatch.setattr(ss, 'M', dict(prog={7: ('/m7', 5.0)}, prog_lm={7: Max()}, pooled=('/p', 3.0), pooled_lm=Max()))
    w = lambda *rows: dict(session_prog=[[0, 0, 0, 1, c, prog] for c, prog in rows])
    assert ss.by_program(w((4, 7)), pooled=True) is False          # find (7) has its own model: 4 <= 5
    assert ss.by_program(w((6, 7)), pooled=False) is True          # 6 > 5
    assert ss.by_program(w((4, 7), (4, 9)), pooled=True) is True   # program 9 has no model: pooled, 4 > 3
    assert ss.by_program(w((4, 7), (2, 9)), pooled=True) is False
    assert ss.by_program(dict(session=[]), pooled=True) is True    # no program split: the pooled verdict


def test_admin_by_command_splits_routine_and_held_out():
    rows = [dict(label='admin', family='find', hits=dict(S0=True, B2=False)),
            dict(label='admin', family='head', hits=dict(S0=True, B2=True)),
            dict(label='attack', family='x', hits=dict(S0=True, B2=True))]
    out = ss.admin_by_command(rows, ('S0', 'B2'), ['find'])
    assert out['routine'] == dict(S0=[1, 1], B2=[0, 1]) and out['held-out'] == dict(S0=[1, 1], B2=[1, 1])
    assert out['find']['B2'] == [0, 1] and 'x' not in out


def test_alpha_scale_lowers_only_the_native_branch_level(tmp_path):
    import json
    models = tmp_path / 'MODELS.json'
    models.write_text(json.dumps({'w': dict(lm='/a', threshold=1.0), 'v': dict(lm='/b', threshold=1.0)}))
    fit = tmp_path / 'FIT.json'
    fit.write_text(json.dumps(dict(workloads={'w': dict(gumbel=[4.0, 1.0]), 'v': dict(gumbel=[4.0, 1.0])})))
    scale = tmp_path / 'scale.json'
    scale.write_text(json.dumps({'w': 0.5}))
    _, thr, *_ = ss.load(models, fit, None, None, 0.0003, None, scale)
    assert abs(thr['v'] - ss.gumbel_threshold((4.0, 1.0), 0.0003)) < 1e-12
    assert abs(thr['w'] - ss.gumbel_threshold((4.0, 1.0), 0.00015)) < 1e-12


def test_session_branch_config_applies_the_a6_scale():
    import session_branch_config as sbc
    fit = dict(workloads={'w': dict(gumbel=[4.0, 1.0]), 'v': dict(gumbel=[4.0, 1.0])})
    pooled = {'pool/session': dict(lm='/m', lm_sha256='0' * 64, threshold=9.0, top=3)}
    doc = sbc.build(fit, pooled, None, 0.0003, {'w': 0.5, 'v': 1.3})
    assert abs(doc['native_thresholds']['w'] - ss.gumbel_threshold((4.0, 1.0), 0.00015)) < 1e-12
    assert abs(doc['native_thresholds']['v'] - ss.gumbel_threshold((4.0, 1.0), 0.0003)) < 1e-12
    assert doc['alpha_scale'] == {'v': 1.3, 'w': 0.5}
