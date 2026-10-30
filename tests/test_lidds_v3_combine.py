import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('v3', ROOT/'scripts'/'analysis'/'lidds_v3_combine.py')
v3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v3)
ARMS = ('ml', 'tripwire', 'system', 'path', 'errno', 'bytes', 'ngram', 'step3')


def doc(n_normal=100, n_attack=40, noisy=('bytes', 'step3')):
    """One scenario: every attack seen by system, path and ngram (bytes and step3 too); normals alarm only in the
    noisy branches (10 % of them), so voting removes the false alarms and keeps the attacks."""
    arms = {a: [] for a in ARMS}
    for i in range(n_attack):
        for a in ARMS:
            hit = a in ('system', 'path', 'ngram', 'bytes', 'step3', 'ml')
            arms[a].append(['test-normal_and_attack', hit, 1.0 + ARMS.index(a) if hit else None, 0, 30,
                            'development' if i < 12 else 'official', f'a{i}'])
    for i in range(n_normal):
        for a in ARMS:
            arms[a].append(['test-normal', False, None, 1 if (a in noisy and i % 10 == 0) else 0, 60, 'official', f'n{i}'])
    return dict(recordings={'SCN': arms})


def test_vote_keeps_attacks_and_drops_single_branch_false_alarms():
    d = doc()
    off = v3.evaluate(d, 'official')
    assert off['C0_step3']['pooled']['recall'] == 1.0 and off['C0_step3']['pooled']['false_alarm_rate'] > 0.05
    assert off['C2_vote2_core']['pooled']['false_alarm_rate'] == 0.0 and off['C2_vote2_core']['pooled']['recall'] == 1.0
    assert off['C4_system_or_ngram']['pooled']['false_alarm_rate'] == 0.0


def test_vote_latency_is_the_kth_branch_and_or_takes_the_earliest():
    rows = v3.combine(doc()['recordings']['SCN'], (v3.CORE, 2, None))
    assert rows['a0'][2] == 1.0 + ARMS.index('path')            # system (2.0) then path (3.0): second is 3.0
    assert v3.combine(doc()['recordings']['SCN'], (('system', 'ngram'), 1, None))['a0'][2] == 1.0 + ARMS.index('system')


def test_development_split_is_seeded_and_disjoint_from_official():
    d = doc()
    rows = v3.combine(d['recordings']['SCN'], v3.CANDIDATES['C1_union_core'])
    dev, off = v3.subset_of('SCN', rows, 'development'), v3.subset_of('SCN', rows, 'official')
    assert not set(dev) & set(off) and len(dev) + len(off) == len(rows)
    assert sum(r[0] == 'test-normal' for r in dev.values()) == 30
    assert dev == v3.subset_of('SCN', rows, 'development')


def test_selection_prefers_recall_under_the_development_false_alarm_limit():
    d = doc()
    chosen, ok = v3.select(v3.evaluate(d, 'development'))
    assert ok and chosen in ('C2_vote2_core', 'C4_system_or_ngram', 'C3_system_or_vote2')
    crit = v3.criteria(v3.evaluate(d, 'official')[chosen])
    assert crit['H1'] and crit['H2']
