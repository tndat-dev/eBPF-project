import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
spec = importlib.util.spec_from_file_location('v4', ROOT / 'scripts' / 'analysis' / 'lidds_v4_select.py')
v4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v4)


def rec(split, subset, exploit, **arms):
    return dict(split=split, subset=subset, exploit=exploit, arms=arms)


def lidds():
    """Attacks: path at 21 s and ngram at 22 s (exploit 20 s); half also tripwire at 21 s. Normals: errno and ngram
    together in 1 of 40, so any rule using errno pays false alarms."""
    a = {f'a{i}': rec('test-normal_and_attack', 'development' if i < 6 else 'official', 20.0,
                      path=[21.0], ngram=[22.0], **({'tripwire': [21.0], 'system': [21.0]} if i % 2 else {}))
         for i in range(20)}
    n = {f'n{i}': rec('test-normal', 'official', None, **(dict(errno=[5.0], ngram=[5.0]) if i == 0 else {}))
         for i in range(40)}
    return dict(scenarios={'SCN': dict(alarms={**a, **n})})


def cbds():
    a = {f'c{i}': rec('test-normal_and_attack', 'official', 0.0, tripwire=[1.0], system=[1.0], path=[1.0], ngram=[2.0])
         for i in range(10)}
    n = {f'm{i}': rec('test-normal', 'official', None) for i in range(50)}
    return dict(scenarios={'CB-DS': dict(alarms={**a, **n})})


def test_search_space_and_names():
    configs = list(v4.configurations())
    assert len(configs) == (10 * 2 + 10 * 3 + 5 * 4 + 1 * 5) * len(v4.HORIZONS) * 2
    assert v4.name((('path', 'ngram'), 2, 5.0, True)) == 'path+ngram|k2|H5s|tripwire'


def test_tripwire_alone_fires_without_a_second_branch():
    arms = dict(tripwire=[3.0], path=[10.0])
    assert v4.firings(arms, (('system', 'path'), 2, 2.0, False)) == []
    assert v4.firings(arms, (('system', 'path'), 2, 2.0, True)) == [3.0]


def test_selection_takes_the_highest_recall_then_the_simplest_configuration():
    v4.DOCS.update(lidds2021=lidds(), cbds=cbds())
    results = [v4.screen(c) for c in v4.configurations()]
    best = v4.select(results)
    assert best['development']['recall'] == 1.0 and best['development']['false_alarm_recordings'] == 0
    assert 'errno' not in best['branches'] and best['hooks'] == 1          # path alone (k1) or ngram alone needs one hook
    assert best['horizon_seconds'] == 0.5 and best['cbds']['recall'] == 1.0
