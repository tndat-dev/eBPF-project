import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cbds_confirmation', ROOT/'scripts'/'analysis'/'cbds_confirmation.py')
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)


def _o(split, detected, fa, name):
    return [split, detected, 1.0 if detected else None, fa, 60, 'official', name]


def _doc(step3_misses, system_misses, normal_fa):
    def arm(misses, fa):
        att = [_o('test-normal_and_attack', i >= misses, 0, f'{"M-MKNOD" if i % 2 else "CVE-2019-5736"}_{i}') for i in range(100)]
        nor = [_o('test-normal', False, int(i < fa), f'normal_{i}') for i in range(200)]
        return att + nor
    raw = {a: arm(system_misses, normal_fa) for a in ('ml', 'tripwire', 'system', 'step1', 'step2')}
    raw['step3'] = arm(step3_misses, normal_fa + 2)
    return dict(recordings={'CB-DS': raw}, scenarios={'CB-DS': dict(fit={}, limits={})})


def test_criteria_and_breakdown_follow_the_protocol():
    d = cc.confirm(_doc(step3_misses=4, system_misses=30, normal_fa=2))
    s3 = d['arms']['step3']
    assert s3['detection_rate'] == 0.96 and s3['false_alarm_rate'] == 0.02
    assert d['criteria'] == {'C1': True, 'C2': True}
    assert set(s3['by_attack']) == {'CVE-2019-5736', 'M-MKNOD'}
    assert sum(v['recordings'] for v in s3['by_attack'].values()) == 100
    diff = d['differences']['step3-system']
    assert abs(diff['detection']['diff'] - 0.26) < 1e-9 and diff['detection']['only_a'] == 26
    assert diff['detection']['ci95'][0] > 0 and abs(diff['false_alarm']['diff'] - 0.01) < 1e-9
    assert cc.confirm(_doc(step3_misses=4, system_misses=30, normal_fa=5))['criteria'] == {'C1': False, 'C2': False}
    assert cc.confirm(_doc(step3_misses=8, system_misses=30, normal_fa=2))['criteria'] == {'C1': True, 'C2': False}
