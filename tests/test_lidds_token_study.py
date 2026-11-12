"""Token design study (protocol token-design-study-v1): the fact-gram cache gives the registered scores, and the study logic."""
import json
from pathlib import Path
import sys
import types

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import test_lidds_evaluate_v2 as base  # noqa: E402
import lidds_ml_token_alphabets as al  # noqa: E402
import lidds_ml_token_crossfit as xf  # noqa: E402
import lidds_token_cache as tc  # noqa: E402
import lidds_token_study as st  # noqa: E402
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM  # noqa: E402

LINES = ['1000000000 0 1 p 7 openat > dirfd=-100 name=/etc/x flags=1(O_RDONLY) mode=0',
         '1000000100 0 1 p 7 openat < fd=4(<f>/etc/x) dirfd=-100 name=/etc/x flags=1(O_RDONLY) mode=0',
         '1000000300 0 1 p 7 openat < fd=-2(ENOENT) dirfd=-100 name=/etc/y flags=1(O_RDONLY) mode=0',
         '1000000500 0 1 p 7 read < res=100 data=A',
         '1000000700 0 1 p 7 mmap < res=-12(ENOMEM)',
         '1000000800 0 1 p 8 getdents64 < res=480',
         '1000000900 0 1 p 8 pread < res=-9(EBADF)',
         '1600000000 0 1 p 7 getpid < res=77']


def test_a_fact_is_the_finest_token_with_one_detail():
    exits = [ln.split(' ', 7) for ln in LINES if ' < ' in ln]
    assert [tc.fact(p[5], p[7]) for p in exits] == [
        ('openat', 'o', 'r:/etc'), ('openat', 'e', 'ENOENT'), ('read', 's', '6'), ('mmap', 'e', 'ENOMEM'),
        ('getdents64', 's', '8'), ('pread', 'e', 'EBADF'), ('getpid', '', '')]


def test_rows_are_per_thread_grams_padded_in_front_with_their_window():
    vocab = {}
    rows = tc.recording_rows(LINES, vocab, n=3)
    assert sum(rows.values()) == 7
    ids = {f[0] + f[1]: i for f, i in vocab.items()}
    assert rows[(1.5, -1, -1, ids['openato'])] == 1                       # first event of thread 7
    assert rows[(1.5, ids['openate'], ids['reads'], ids['mmape'])] == 1   # history of thread 7 only
    assert rows[(1.5, -1, ids['getdents64s'], ids['preade'])] == 1        # thread 8 has its own history
    assert rows[(2.0, ids['reads'], ids['mmape'], ids['getpid'])] == 1    # history crosses the window border


@pytest.mark.parametrize('alphabet', ['select1f', 'full1', 'name', 'noerr', 'nosize', 'noopen'])
def test_a_spec_merges_exactly_the_facts_its_alphabet_merges(alphabet):
    a = al.ALPHABETS[alphabet]
    halve = a.get('halve', True)
    names = {ln.split(' ', 7)[5] for ln in LINES}
    spec = dict(err=sorted(names if a['err'] == 'all' else a['err'] or ()), open=sorted(al.signals.OPENS if a['open'] else ()),
                size=sorted(al.signals.READS | al.signals.WRITES if a['size'] == 'exit' else ()))
    exits = [ln.split(' ', 7) for ln in LINES if ' < ' in ln]
    facts = [tc.fact(p[5], p[7]) for p in exits]
    tokens = st.token_map(sorted(set(facts)), spec)
    mine = [int(tokens[sorted(set(facts)).index(f)]) for f in facts]
    theirs = [al.atoken(p[5], al.facts(p[5], p[7], None), a) for p in exits]
    if not halve:
        assert [mine.index(x) for x in mine] == [theirs.index(x) for x in theirs]
    assert all((mine[i] >> 23 == mine[j] >> 23) == (exits[i][5] == exits[j][5]) for i in range(len(exits)) for j in range(len(exits)))
    assert tokens[-1] == TOK_NONE


def test_the_hooked_syscalls_are_39_units():
    units = st.units()
    assert len(units) == 39 and units['pread+pread64'] == {'pread', 'pread64'}
    spec = st.without(st.base_spec(), units['recv+recvfrom'])
    assert 'recvfrom' not in spec['err'] + spec['size'] and 'read' in spec['size']
    assert 'getdents64' in st.with_detail(st.base_spec(), 'size', 'getdents64')['size']


def test_window_table_equals_the_window_score_of_the_cluster_model():
    rng = np.random.default_rng(3)
    lm = CountTokenLM()
    grams = [[int(x) << 23 for x in rng.integers(1, 6, 4)] for _ in range(60)]
    for g in grams:
        lm.learn(tuple(g), int(rng.integers(1, 4)))
    lm.finalize()
    rows = [(float(rng.integers(0, 3)), grams[int(rng.integers(0, 60))], int(rng.integers(1, 7))) for _ in range(40)]
    w = np.asarray([r[0] for r in rows])
    s = np.asarray([-np.log(lm.prob(tuple(r[1]))) for r in rows])
    c = np.asarray([r[2] for r in rows])
    ends, scores, total, (weighted,) = st.window_table(w, s, c, (1, 10, 20), (np.ones(len(rows)),))
    for i, end in enumerate(ends):
        mine = [[*g, k] for e, g, k in rows if e == end]
        for j, top in enumerate((1, 10, 20)):
            assert scores[j][i] == pytest.approx(lm.window_score(mine, top), abs=1e-12)
        assert total[i] == weighted[i] == sum(k for *_, k in mine)


def test_cached_scores_equal_the_registered_cross_fit(tmp_path):
    archive = base._archive(tmp_path)
    ref, meta, _ = xf.evaluate(archive, 5, lambda name, split: True)
    cache = tmp_path / 'SCN.npz'
    vocab, recs, events = tc.build(archive, cache, lambda name, split: True)
    cache.with_suffix('.json').write_text(json.dumps(dict(n=tc.N, vocab=vocab, recordings=recs, events=events)))
    spec = st.base_spec(tops=[1, 10], seen_only=True)
    out = st.score_scenario(cache, spec)
    i = st.columns_of(spec).index('top10')
    assert set(out) == set(ref) and len(ref) == 40 + 45 + 6 + 10
    for key, a in ref.items():
        assert np.array_equal(a[:, 0], out[key][:, 0])
        assert np.abs(a[:, 1] - out[key][:, i]).max() < 1e-9
    assert {k for k in meta} == {k for k, r in recs.items() if r['split'].startswith('test')}
    # shorter grams follow from the same cache; an unseen-gram count never exceeds the events of its window
    short = st.score_scenario(cache, st.base_spec(n=2))
    cols = st.columns_of(st.base_spec())
    for key, a in short.items():
        assert (a[:, cols.index('unseen_grams')] <= a[:, cols.index('unseen_any')]).all()
        assert (a[:, cols.index('unseen_any')] <= a[:, cols.index('events')]).all()
    # seen-only: the score without the novel rows is never above the full score
    full = st.columns_of(spec)
    for a in out.values():
        assert (a[:, full.index('seen_top')] <= a[:, full.index('top10')] + 1e-12).all()


def test_a_coarser_alphabet_changes_the_scores_and_a_spec_without_effect_does_not(tmp_path):
    archive = base._archive(tmp_path)
    cache = tmp_path / 'SCN.npz'
    vocab, recs, events = tc.build(archive, cache, lambda name, split: True)
    cache.with_suffix('.json').write_text(json.dumps(dict(n=tc.N, vocab=vocab, recordings=recs, events=events)))
    full = st.score_scenario(cache, st.base_spec())
    same = st.score_scenario(cache, st.without(st.base_spec(), {'openat2'}))          # never called in the archive
    bare = st.score_scenario(cache, dict(st.base_spec(), err=[], open=[], size=[]))
    assert all(np.array_equal(full[k], same[k]) for k in full)
    assert any(not np.array_equal(full[k][:, 1], bare[k][:, 1]) for k in full)


def metrics(detected, fa=6):
    return dict(detected=detected, false_alarm_recordings=fa, latency_p95=1.5, cb_detected=891, cb_false_alarm_recordings=3)


def test_backward_elimination_keeps_only_units_that_cannot_go():
    needed = {'read', 'openat'}
    calls = []

    def evaluate(removed):
        calls.append(removed)
        return metrics(530 if not needed & set(removed) else 500)
    removed, log = st.eliminate(['close', 'read', 'futex', 'openat'], evaluate)
    assert removed == ['close', 'futex']
    assert [e['tried'] for e in log][:4] == ['close', 'read', 'futex', 'openat']
    assert [e['keeps'] for e in log] == [True, False, True, False, False, False]   # the second pass tries the two left once more


def test_keeps_is_the_registered_criterion():
    assert st.keeps(metrics(530)) and not st.keeps(metrics(529)) and not st.keeps(metrics(531, fa=7))
    assert not st.keeps(dict(metrics(530), cb_detected=890)) and not st.keeps(dict(metrics(530), latency_p95=1.53))


def test_budget_frontier_takes_the_most_detections_within_the_false_alarm_budget():
    maxima = {'s': (np.asarray([1.0, 2.0, 3.0]), np.asarray([2.5, 3.5, 0.5]))}
    points = st.frontier(maxima, lambda s, level: level, (0.0, 1.5, 2.2, 3.2))
    assert points == [(0.0, 3, 3), (1.5, 2, 2), (2.2, 2, 1), (3.2, 1, 0)]
    best = st.at_budgets(points, (0, 1, 5))
    assert best[0] == (3.2, 1, 0) and best[1] == (2.2, 2, 1) and best[5] == (0.0, 3, 3)


def test_gumbel_threshold_is_mean_plus_k_sigma_and_ad_accepts_gumbel_data():
    rng = np.random.default_rng(5)
    x = 3.0 - 2.0 * np.log(-np.log(rng.uniform(size=400)))
    fit = st.m.gumbel(x)
    k = np.sqrt(6) / np.pi * (-0.5772 - np.log(-np.log(1 - st.ALPHA)))
    assert st.m.threshold(fit, st.ALPHA) == pytest.approx(np.mean(x) + k * np.std(x), rel=1e-9)
    _, p = st.ad_gumbel(x, draws=200)
    _, p_normal_tail = st.ad_gumbel(np.concatenate([x, np.full(40, x.max() * 3)]), draws=200)
    assert p > 0.05 > p_normal_tail
    assert list(st.holm(np.asarray([0.01, 0.04, 0.03]))) == pytest.approx([0.03, 0.06, 0.06])


def test_paired_bootstrap_counts_the_difference_at_fixed_thresholds():
    model = {'s': (np.zeros(0), np.asarray([5.0, 5.0, 1.0, 5.0]))}
    rule = {'s': (np.zeros(0), np.asarray([5.0, 0.0, 0.0, 0.0]))}
    point, ci = st.paired_bootstrap(model, {'s': 2.0}, {'s': 2.0}, rule, draws=500)
    assert point == 2 and 0 <= ci[0] <= 2 <= ci[1] <= 4


def test_scored_reads_the_development_part_and_the_registered_threshold(tmp_path):
    archive = base._archive(tmp_path)
    caches = tmp_path / 'caches'
    caches.mkdir()
    vocab, recs, events = tc.build(archive, caches / 'SCN.npz', lambda name, split: True)
    (caches / 'SCN.json').write_text(json.dumps(dict(n=tc.N, vocab=vocab, recordings=recs, events=events)))
    alarms = {name: dict(split=r['split'], exploit=r['exploit'], subset='development' if i % 2 else 'official')
              for i, (name, r) in enumerate(sorted(recs.items())) if r['split'].startswith('test')}
    a = types.SimpleNamespace(caches=caches, out=tmp_path / 'out', jobs=1,
                              docs=(dict(scenarios=dict(SCN=dict(alarms=alarms))), dict(scenarios={})))
    st.ensure(a, {'base': st.base_spec(tops=[1, 10], seen_only=True)})
    scored = st.Scored(a, 'base')
    r = scored.metrics()
    dev_attacks = sum(1 for v in alarms.values() if v['exploit'] is not None and v['subset'] == 'development')
    assert r['attack_recordings'] == dev_attacks and 0 <= r['detected'] <= dev_attacks
    nor, att = scored.maxima()['SCN']
    assert len(att) == dev_attacks and len(nor) == r['normal_recordings']
    t = st.m.threshold(scored.lid['SCN'].fit, st.ALPHA)
    assert int((att > t).sum()) == r['detected'] and int((nor > t).sum()) == r['false_alarm_recordings']


def test_every_step_runs_end_to_end_on_a_small_archive(tmp_path, monkeypatch):
    archive = base._archive(tmp_path)
    caches = tmp_path / 'caches'
    caches.mkdir()
    vocab, recs, events = tc.build(archive, caches / 'SCN.npz', lambda name, split: True)
    (caches / 'SCN.json').write_text(json.dumps(dict(n=tc.N, vocab=vocab, recordings=recs, events=events)))
    alarms = {name: dict(split=r['split'], exploit=r['exploit'], subset='development')
              for name, r in recs.items() if r['split'].startswith('test')}
    a = types.SimpleNamespace(caches=caches, out=tmp_path / 'out', jobs=2, reference=None,
                              docs=(dict(scenarios=dict(SCN=dict(alarms=alarms))), dict(scenarios={})))
    a.out.mkdir()
    with pytest.raises(SystemExit):                       # the tiny archive is not lidds-ml-v5: the gate must refuse
        st.gate(a)
    assert json.loads((a.out / 'gate.json').read_text())['passed'] is False
    with pytest.raises(SystemExit):
        st.q2(a)
    monkeypatch.setattr(st, 'need_gate', lambda a: None)
    for step in (st.q1, st.q2, st.q3, st.q4):
        step(a)
    q1 = json.loads((a.out / 'q1.json').read_text())
    present = {f[0] for f in vocab}
    assert set(q1['leave_one_out']) == {u for u, names in st.units().items() if names & present}
    assert len(q1['absent_from_data']) + len(q1['leave_one_out']) == 39
    assert q1['removed'] == [] and len(q1['smallest_subset']) == len(q1['leave_one_out'])   # no CB-DS here: nothing keeps
    q2 = json.loads((a.out / 'q2.json').read_text())
    assert set(q2['grid']) == {'n', 'top', 'alpha', 'folds', 'trim'} and len(q2['grid']['n']) == 5
    detected = [q2['grid']['alpha'][k]['detected'] for k in sorted(q2['grid']['alpha'], key=float, reverse=True)]
    assert detected == sorted(detected, reverse=True)      # a stricter level never detects more
    q3 = json.loads((a.out / 'q3.json').read_text())
    assert len(q3['calibration']) == 7 and set(q3['scenarios']) == {'SCN'} and 'gumbel_holds' in q3
    assert set(q3['alternatives_at_false_alarm_budgets']) >= {'gumbel moments, trimmed (registered)', 'split conformal order statistic'}
    q4 = json.loads((a.out / 'q4.json').read_text())
    sim = q4['seen_only_simulation']['pooled']
    assert sim['detected_seen_only'] <= sim['detected'] <= sim['attack_recordings']
    assert set(q4['registered_point']) == {'model', 'unseen_grams', 'unseen_any'}


def test_official_scoring_needs_official_caches_a_reproduced_base_and_runs_once(tmp_path, monkeypatch):
    archive = base._archive(tmp_path)
    caches = tmp_path / 'caches'
    caches.mkdir()
    vocab, recs, events = tc.build(archive, caches / 'SCN.npz', lambda name, split: True)
    alarms = {name: dict(split=r['split'], exploit=r['exploit'], subset='official') for name, r in recs.items() if r['split'].startswith('test')}
    q1 = tmp_path / 'q1.json'
    q1.write_text(json.dumps(dict(removed=['close', 'futex'], smallest_subset=['open', 'read'])))
    a = types.SimpleNamespace(caches=caches, out=tmp_path / 'out', jobs=1, spec_from=q1,
                              docs=(dict(scenarios=dict(SCN=dict(alarms=alarms))), dict(scenarios={})))
    a.out.mkdir()
    (caches / 'SCN.json').write_text(json.dumps(dict(n=tc.N, vocab=vocab, recordings=recs, events=events, part='development')))
    with pytest.raises(SystemExit, match='not an official cache'):
        st.official(a)
    (caches / 'SCN.json').write_text(json.dumps(dict(n=tc.N, vocab=vocab, recordings=recs, events=events, part='official')))
    with pytest.raises(SystemExit, match='does not reproduce'):
        st.official(a)
    ref = st.Scored(a, 'base').metrics(part='official')
    monkeypatch.setattr(st, 'OFFICIAL', {k: ref[k] for k in st.OFFICIAL})
    monkeypatch.setattr(st, 'round', lambda x, n: 1.47, raising=False)
    st.official(a)
    doc = json.loads((a.out / 'official-smallest-subset.json').read_text())
    assert doc['subset']['attack_recordings'] == 10 and doc['removed'] == ['close', 'futex']
    with pytest.raises(SystemExit, match='scored once'):
        st.official(a)
