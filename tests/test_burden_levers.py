import importlib.util
from pathlib import Path

import numpy as np

from sentinel_pulse.attack.confirmation_study import EpisodeCounter
from sentinel_pulse.attack.window_table import Signals

ROOT = Path(__file__).resolve().parents[1]


def _module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/'analysis'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bl = _module('burden_levers')
screen = _module('ideas_screen')


def _stream(seed, n=4000):
    rng = np.random.default_rng(seed)
    ident = np.sort(rng.integers(0, 5, n))
    start = np.zeros(n); end = np.zeros(n)
    for k in np.unique(ident):
        idx = np.flatnonzero(ident == k)
        t = 100.0
        for i in idx:
            t += 0.5 if rng.random() > 0.03 else rng.choice([1.7, 30.0])   # some gaps restart the history
            start[i], end[i] = t, t + 0.5
    p = np.clip(rng.uniform(0, 1, n) ** 4, 1e-9, 1)
    return ident, start, end, p


def _rows(ident, start, end, p, k):
    sel = ident == k
    return [dict(start=s, end=e, joint_p=q, tree_p=q, support_p=q, alpha=0.01)
            for s, e, q in zip(start[sel], end[sel], p[sel])]


def test_vectorised_cusum_equals_the_screen_recursion():
    ident, start, end, p = _stream(1)
    new = bl.segments(ident, start, end)
    x = -np.log(np.maximum(p, 1e-12))
    for b, h in ((2.0, 1.0), (3.0, 6.0), (5.0, 3.0)):
        s = bl.cusum(x - b, new)
        for k in np.unique(ident):
            assert list(s[ident == k] >= h) == screen.alarms_cusum(_rows(ident, start, end, p, k), b, h)


def test_discounted_windows_leave_cusum_unchanged():
    y = np.array([2.0, 0.0, 0.0, 1.5, -10.0, 0.0])
    new = np.array([True, False, False, False, False, False])
    assert np.allclose(bl.cusum(y, new), [2.0, 2.0, 2.0, 3.5, 0.0, 0.0])


def test_vectorised_k2of2_equals_the_screen_rule():
    ident, start, end, p = _stream(2)
    new = bl.segments(ident, start, end)
    alpha = np.full(len(p), 0.01)
    for scale in (3.0, 10.0):
        alarm = bl.kofn2(p <= alpha * scale, new)
        for k in np.unique(ident):
            assert list(alarm[ident == k]) == screen.alarms_kofn(_rows(ident, start, end, p, k), 'joint_p', scale)


def test_episodes_match_the_episode_counter():
    ident, start, end, p = _stream(3)
    positive = p < 0.05
    counter = EpisodeCounter()
    for k, e, pos in zip(ident, end, positive):
        if pos:
            counter.add('w', k, e)
    assert bl.episodes(ident, end, positive, 15.0) == sum(counter.episodes.values())


def test_peer_and_self_novelty():
    s = Signals(bucket=2.0, peer=(30.0,), self_=(60.0,))
    bit = lambda *ids: sum(1 << i for i in ids)
    # replica B keeps running a "probe" (IDs 1, 2); replica A is alone at first
    first = s.observe(('A',), 'W', 0.0, 0.5, bit(1), want=True)
    assert first['novel_peer30'] == -1 and first['novel_self60'] == -1
    t = 0.5
    for i in range(140):                       # 70 s of both replicas
        s.observe(('B',), 'W', t, t + 0.5, bit(1, 2) if i % 20 == 0 else 0)
        s.observe(('A',), 'W', t, t + 0.5, bit(1) if i % 20 == 0 else 0, want=False)
        t += 0.5
    probe = s.observe(('A',), 'W', t, t + 0.5, bit(1, 2, 59), want=True)
    assert probe['launch'] and probe['novel_peer30'] == 1        # 59 never seen on B, 1 and 2 were
    assert probe['novel_self60'] == 2                            # A itself only ever showed ID 1
    s.observe(('B',), 'W', t, t + 0.5, bit(59, 101))
    t += 0.5
    again = s.observe(('A',), 'W', t, t + 0.5, bit(1, 2, 59), want=True)
    assert again['novel_peer30'] == 0                            # B showed 59 in the last 30 s
    assert again['novel_self60'] == 2                            # the previous window is context, not history


def test_trial_outcome_takes_the_first_alarm_in_the_interval():
    tr = bl.Trials.__new__(bl.Trials)
    tr.label = np.array(['attack', 'control']); tr.scenario = np.array(['x', 'x'])
    tr.lo, tr.hi, tr.kernel = np.array([2, 6]), np.array([6, 9]), np.array([1.0, np.nan])
    alarm = np.array([1, 0, 0, 0, 1, 1, 0, 0, 0], bool)
    end = np.arange(9, dtype=float)
    hit, delay = tr.outcome(alarm, end)
    assert list(hit) == [True, False] and delay[0] == 3.0


def test_light_row_drops_the_vector_and_other_workloads():
    import json
    from sentinel_pulse.attack.window_table import light_row
    row = dict(workload_key='production/a:app', window_end=1.5, vector_f32_zlib_b64='eJzt+/8A==',
               full_counts_delta={'59': 1}, node_name='n')
    line = json.dumps(row, separators=(',', ':')) + '\n'
    parsed = light_row(line, {'production/a:app'})
    assert parsed['full_counts_delta'] == {'59': 1} and parsed['node_name'] == 'n' and 'vector_f32_zlib_b64' not in parsed
    assert light_row(line, {'production/b:app'}) is None
    last = json.dumps(dict(workload_key='production/a:app', vector_f32_zlib_b64='abc'), separators=(',', ':'))
    assert light_row(last, {'production/a:app'}) == {'workload_key': 'production/a:app', '_': 0}


def test_end_to_end_on_a_synthetic_run(tmp_path, monkeypatch):
    import json, sys
    from sentinel_pulse.attack.window_table import save
    rng = np.random.default_rng(7)
    from sentinel_pulse.detector.confirmation import IDENTITY
    idents = [['production/w:app', 'n1', 'pod-a', 'app', 'r1', '1'], ['production/w:app', 'n2', 'pod-b', 'app', 'r1', '2']]

    def table(n, path, t0, attack_at=None):
        rows = {k: [] for k in ('ident', 'workload', 'start', 'end', 'tree_score', 'support_score', 'tree_p',
                                'support_p', 'joint_p', 'alpha', 'eligible', 'launch', 'novel_peer30',
                                'novel_peer60', 'novel_self60', 'novel_self300')}
        for k in range(2):
            for i in range(n):
                s = t0 + i * 0.5
                bump = attack_at is not None and k == 0 and attack_at <= s < attack_at + 3
                for name, v in (('ident', k), ('workload', 0), ('start', s), ('end', s + 0.5),
                                ('tree_score', rng.normal() + (8 if bump else 0)), ('support_score', rng.normal()),
                                ('tree_p', .5), ('support_p', .5), ('joint_p', 1.0), ('alpha', 0.05 / 30),
                                ('eligible', 1), ('launch', int(i % 20 == 0)), ('novel_peer30', 1 if bump else 0),
                                ('novel_peer60', 0), ('novel_self60', 0), ('novel_self300', 1 if bump else 0)):
                    rows[name].append(v)
        dtypes = dict(ident='i4', workload='i2', eligible='i1', launch='i1', novel_peer30='i2', novel_peer60='i2',
                      novel_self60='i2', novel_self300='i2')
        arrays = {k: np.array(v, dtype=dtypes.get(k, 'f8')) for k, v in rows.items()}
        save(path, arrays, dict(workloads=['production/w:app'], identities=idents, identity_fields=list(IDENTITY)))
        return arrays

    cal = table(1500, tmp_path/'cal.npz', 0.0)
    np.savez(tmp_path/'calibration.npz', **{'tree::production/w:app': cal['tree_score'],
                                            'support::production/w:app': cal['support_score']})
    runs = []
    for r in ('r1', 'r2'):
        camp = tmp_path/r/'campaign'
        t0, start = 10000.0, 10600.0
        table(3000, tmp_path/f'{r}.npz', t0, attack_at=start + 2)
        (camp/'trials'/'1').mkdir(parents=True)
        trial = lambda label, at, k: dict(node_name=idents[k][1], pod_uid=idents[k][2], container_name='app',
                                          workload_revision='r1', cgroup_id='1' if k == 0 else '2',
                                          start_at=at, kernel_event_at=at + 2, scenario='s')
        doc = dict(attack=trial('attack', start, 0), control=trial('control', start + 100, 0),
                   benign=trial('benign', start + 200, 1))
        (camp/'trials'/'1'/'EVALUATION_INPUT.json').write_text(json.dumps(doc))
        (camp/'INTERVALS.jsonl').write_text(json.dumps(dict(start_at=start)) + '\n')
        (camp/'TERMINAL.json').write_text(json.dumps(dict(finished_at_unix=start + 300)))
        runs += ['--run', f'name={r},table={tmp_path/r}.npz,since={t0},campaign={camp}']
    out = tmp_path/'out.json'
    monkeypatch.setattr(sys, 'argv', ['burden_levers', *runs, '--calibration', str(tmp_path/'calibration.npz'),
                                      '--calibration-table', str(tmp_path/'cal.npz'), '--output', str(out)])
    bl.main()
    result = json.loads(out.read_text())
    assert result['calibration_reproduced']['all'] is True
    ref = result['candidates']['r1'][bl.REFERENCE]
    assert ref['attack'] == 1.0 and ref['p95'] is not None
    assert set(result['selection']) == {'lt2s', 'le3s'}
    assert len(result['candidates']['r1']) == len(bl.VARIANTS) * len(bl.MODES) * (
        len(bl.CUSUM_B) * len(bl.CUSUM_H) + 0) + 2 * len(bl.MODES) * (len(bl.KOFN['joint']) + len(bl.KOFN['and']))



def test_cusum_alarm_modes_match_the_live_cusum_state():
    from sentinel_pulse.detector.confirmation import CusumPolicy, CusumState
    ident, start, end, p = _stream(5)
    new = bl.segments(ident, start, end)
    x = -np.log(np.maximum(p, 1e-12))
    for mode in ('keep', 'cap', 'restart'):
        alarm = bl.cusum_alarms(x - 3.0, new, 6.0, mode)
        state = CusumState(CusumPolicy(drift=3.0, threshold=6.0, on_alarm=mode))
        ref = [state.update(dict(workload_key='w', node_name='n', pod_uid=str(k), container_name='c', workload_revision='r',
                                 cgroup_id=1, window_start=s0, window_end=e0, joint_p=float(q)))
               for k, s0, e0, q in zip(ident, start, end, p)]
        assert list(alarm) == ref, mode
    # a long anomaly: keep alarms on afterwards, cap stops at the first quiet window, restart re-arms
    y = np.array([30.0] * 5 + [-3.0] * 6)
    new = np.zeros(11, bool); new[0] = True
    assert bl.cusum_alarms(y, new, 6.0, 'keep').sum() == 11
    assert list(bl.cusum_alarms(y, new, 6.0, 'cap')) == [True] * 5 + [False] * 6
    assert list(bl.cusum_alarms(y, new, 6.0, 'restart')) == [True] * 5 + [False] * 6


def test_carryover_rule_prefers_cap_and_falls_back_to_k2of2():
    import importlib.util, sys
    sys.path.insert(0, str(ROOT/'scripts'/'analysis'))
    spec = importlib.util.spec_from_file_location('cusum_carryover', ROOT/'scripts'/'analysis'/'cusum_carryover.py')
    cc = importlib.util.module_from_spec(spec); spec.loader.exec_module(cc)
    m = lambda burden, control=0.03, p95=1.7, attack=1.0: dict(burden=burden, control=control, p95=p95, attack=attack, precision=0.97)
    good = {'k2of2_a10': m(5.0, 0.04, 2.3), 'cusum_b3_h6_cap': m(4.0), 'cusum_b3_h6_restart': m(3.9)}
    runs = {'pulse-stable-candidate': good, 'pulse-stable-refreshed': good}
    assert cc.choose(runs)[0] == 'cusum_b3_h6_cap'                 # within 5 %: cap
    bad = dict(good, cusum_b3_h6_cap=m(4.0, control=0.06), cusum_b3_h6_restart=m(5.5, p95=2.4))
    assert cc.choose({'pulse-stable-candidate': bad, 'pulse-stable-refreshed': bad})[0] == 'k2of2_a10'
