"""The probe-side token model equals the offline lidds-ml-v3 TokenLM, and token windows are checked."""
from collections import Counter
import math
from pathlib import Path
import random
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

from sentinel_pulse.collector.token_capture import token_window  # noqa: E402
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM, strip  # noqa: E402

lt = pytest.importorskip('lidds_ml_tokens')


def tok(nr, kind=0, detail=0):
    return (nr << 23) | (kind << 21) | detail


def thread_grams(rng, length, alphabet):
    hist, out = [], []
    for _ in range(length):
        hist = (hist + [rng.choice(alphabet)])[-4:]
        out.append(tuple(hist))
    return out


def as_names(gram):
    """the offline model's string tokens for the same events: call name = 'c<nr>', detail after '#'"""
    return tuple(f'c{t >> 23}' if t & 0x7FFFFF == 0 else f'c{t >> 23}#{t & 0x7FFFFF}' for t in gram)


def probe_rows(grams):
    """what the probe sends for one window: distinct (padded) grams with counts"""
    c = Counter((TOK_NONE,) * (4 - len(g)) + g for g in grams)
    return [[*g, n] for g, n in c.items()]


def test_count_model_equals_offline_model():
    rng = random.Random(3)
    alphabet = [tok(0, 2, 12), tok(0, 2, 9), tok(1, 2, 4), tok(3), tok(202), tok(202, 1, 110), tok(257, 3, 77), tok(9)]
    train = [thread_grams(rng, 400, alphabet[:6]) for _ in range(5)]
    ours, offline = CountTokenLM(), lt.TokenLM()
    for grams in train:
        ours.learn_window(probe_rows(grams))
        offline.learn([as_names(g) for g in grams])
    ours.finalize()
    offline.finalize()
    test = thread_grams(rng, 300, alphabet)        # includes calls and tokens never seen in training
    for g in set(test):
        assert math.isclose(ours.prob(g), offline.prob(as_names(g)), rel_tol=1e-12)
    for start in range(0, 300, 50):
        window = test[start:start + 50]
        expected = lt.window_scores({1.0: [as_names(g) for g in window]}, offline)[0][1]
        assert math.isclose(ours.window_score(probe_rows(window)), expected, rel_tol=1e-12)


def test_round_trip(tmp_path):
    rng = random.Random(5)
    lm = CountTokenLM()
    lm.learn_window(probe_rows(thread_grams(rng, 200, [tok(0, 2, 3), tok(3), tok(202)])))
    lm.finalize()
    lm.save(tmp_path / 'lm.json.gz')
    back = CountTokenLM.load(tmp_path / 'lm.json.gz')
    for g in [(tok(3),), (tok(0, 2, 3), tok(3)), (tok(202), tok(202), tok(3), tok(9))]:
        assert back.prob(g) == lm.prob(g)


def test_strip_and_bad_grams():
    assert strip((TOK_NONE, TOK_NONE, 5, 6)) == (5, 6)
    with pytest.raises(ValueError):
        strip((5, TOK_NONE, 6, 7))


META = {'42': dict(namespace='production', workload_name='api', container_name='app', node_name='w1',
                   pod_uid='u1', pod_name='api-1', workload_revision='r1'),
        '43': dict(namespace='kube-system', workload_name='dns', container_name='c', node_name='w1',
                   pod_uid='u2', workload_revision='r1')}


def row(cg=42, grams=None, events=None):
    grams = grams if grams is not None else [[TOK_NONE, TOK_NONE, TOK_NONE, tok(3), 2], [1, 2, 3, tok(0, 2, 4), 5]]
    return dict(type='token_grams', contract='pulse-token-select1f-v1', cgroup_id=cg, window=100, window_end=1.5,
                events=sum(g[-1] for g in grams) if events is None else events, grams=grams)


def test_token_window_identity_and_checks():
    out = token_window(row(), META)
    assert out is not None
    assert out['workload_key'] == 'production/api:app' and out['events'] == 7 and out['pod_uid'] == 'u1'
    assert token_window(row(43), META) is None          # not production
    assert token_window(row(44), META) is None          # unknown cgroup
    with pytest.raises(ValueError):
        token_window(row(events=8), META)               # counts differ from events
    with pytest.raises(ValueError):
        token_window(row(grams=[[1, TOK_NONE, 2, 3, 1]]), META)   # empty slot inside
    with pytest.raises(ValueError):
        token_window(row(grams=[[1, 2, 3, TOK_NONE, 1]]), META)   # no token emitted
    with pytest.raises(ValueError):
        token_window(dict(row(), contract='other'), META)


def test_token_branch_scores_and_checks_models(tmp_path):
    from sentinel_pulse.detector.token_model import TokenBranch
    from sentinel_pulse.integrity import sha256_file
    rng = random.Random(9)
    normal = [tok(0, 2, 12), tok(3), tok(202)]
    lm = CountTokenLM()
    for _ in range(20):
        lm.learn_window(probe_rows(thread_grams(rng, 100, normal)))
    lm.finalize()
    path = tmp_path / 'api.json.gz'
    lm.save(path)
    spec = {'production/api:app': dict(lm=str(path), lm_sha256=sha256_file(path), threshold=6.0)}
    branch = TokenBranch(spec, sha256_file)
    usual = dict(workload_key='production/api:app', grams=probe_rows(thread_grams(rng, 50, normal)))
    odd = dict(workload_key='production/api:app', grams=probe_rows(thread_grams(rng, 50, normal + [tok(59, 1, 13)])))
    assert branch.score(usual)['token_alert'] is False
    assert branch.score(odd)['token_alert'] is True
    assert branch.score(dict(workload_key='production/other:c', grams=[])) is None
    with pytest.raises(ValueError):
        TokenBranch({**spec, 'production/api:app': dict(spec['production/api:app'], lm_sha256='0' * 64)}, sha256_file)


def test_count_branches(tmp_path):
    import json as _json
    from sentinel_pulse.detector.v3_policy import CountBranches, tree_logit
    from sentinel_pulse.integrity import sha256_file
    path = tmp_path / 'counts.json'
    path.write_text(_json.dumps(dict(schema='pulse-v3-count-thresholds-v1',
                                     workloads={'production/api:app': dict(tree=tree_logit(0.9), support=5.0)})))
    cb = CountBranches(path, sha256_file(path), sha256_file)
    base = dict(status='candidate-raw-score-only', workload_key='production/api:app', candidate_alert_preview=False)
    assert cb.apply(dict(base, tree_score=0.5, support_score=1.0))['candidate_alert_preview'] is False
    hit = cb.apply(dict(base, tree_score=0.95, support_score=1.0))
    assert hit['v3_tree_alert'] and not hit['v3_support_alert'] and hit['candidate_alert_preview'] is True
    assert cb.apply(dict(base, tree_score=0.5, support_score=6.0))['v3_support_alert'] is True
    assert cb.apply(dict(base, status='record_rejected')) is None
    assert cb.apply(dict(base, workload_key='production/other:c', tree_score=1, support_score=9)) is None
    with pytest.raises(ValueError):
        CountBranches(path, '0' * 64, sha256_file)


# --- gate of the token branch (protocol lidds-ml-v5)

def gate_branch(tmp_path, hold=1.0):
    from sentinel_pulse.detector.token_model import TokenBranch
    common = [TOK_NONE, TOK_NONE, tok(1), tok(2)]
    lm, pool = CountTokenLM(), CountTokenLM()
    lm.learn_window([common + [50]])
    pool.learn_window([common + [50], [TOK_NONE, TOK_NONE, tok(3), tok(4)] + [50]])
    lm.finalize(); pool.finalize()
    a, b = tmp_path / 'lm.json.gz', tmp_path / 'pool.json.gz'
    lm.save(a); pool.save(b)
    sha = lambda path: str(path)
    spec = {'w': dict(lm=str(a), lm_sha256=str(a), threshold=2.0, pool_threshold=5.0)}
    gate = dict(pool=dict(lm=str(b), lm_sha256=str(b)), exec_hold_seconds=hold)
    return TokenBranch(spec, sha, gate)


def window(end, grams):
    return dict(workload_key='w', pod_uid='p', container_name='c', window_end=end, grams=grams)


def test_gate_needs_surprise_to_the_pool(tmp_path):
    branch = gate_branch(tmp_path)
    known_to_pool = branch.score(window(10.0, [[TOK_NONE, TOK_NONE, tok(3), tok(4), 5]]))
    assert known_to_pool['token_alert_raw'] is True and known_to_pool['token_alert'] is False
    unknown = branch.score(window(11.0, [[TOK_NONE, TOK_NONE, tok(7), tok(8), 5]]))
    assert unknown['token_alert_raw'] is True and unknown['token_alert'] is True
    assert unknown['token_pool_score'] > unknown['token_pool_threshold']


def test_gate_holds_after_execve_only(tmp_path):
    branch = gate_branch(tmp_path, hold=1.0)
    odd = [TOK_NONE, TOK_NONE, tok(7), tok(8), 5]
    start = branch.score(window(10.0, [odd, [TOK_NONE, TOK_NONE, tok(7), tok(59), 1]]))
    assert start['token_exec_held'] is True and start['token_alert'] is False
    assert branch.score(window(10.5, [odd]))['token_exec_held'] is True
    assert branch.score(window(11.0, [odd]))['token_exec_held'] is True      # exactly hold seconds later
    later = branch.score(window(11.5, [odd]))
    assert later['token_exec_held'] is False and later['token_alert'] is True


def test_no_gate_keeps_the_plain_branch(tmp_path):
    from sentinel_pulse.detector.token_model import TokenBranch
    lm = CountTokenLM()
    lm.learn_window([[TOK_NONE, TOK_NONE, tok(1), tok(2), 50]])
    lm.finalize()
    path = tmp_path / 'lm.json.gz'
    lm.save(path)
    branch = TokenBranch({'w': dict(lm=str(path), lm_sha256=str(path), threshold=2.0)}, str)
    out = branch.score(window(1.0, [[TOK_NONE, TOK_NONE, tok(7), tok(8), 5]]))
    assert out['token_alert'] is True and set(out) == {'token_score', 'token_threshold', 'token_alert'}


def test_phase_threshold_replaces_the_hold(tmp_path):
    branch = gate_branch(tmp_path, hold=1.0)
    branch.phase_threshold = 1e6
    odd = [TOK_NONE, TOK_NONE, tok(7), tok(8), 5]
    held_low = branch.score(window(10.0, [odd, [TOK_NONE, TOK_NONE, tok(7), tok(59), 1]]))
    assert held_low['token_exec_held'] is True and held_low['token_alert'] is False
    branch.phase_threshold = 1.0
    held_high = branch.score(window(10.5, [odd]))
    assert held_high['token_exec_held'] is True and held_high['token_alert'] is True
    branch.phase_threshold = 1e6
    outside = branch.score(window(11.5, [odd]))
    assert outside['token_exec_held'] is False and outside['token_alert'] is True
