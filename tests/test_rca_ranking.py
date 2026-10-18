import pytest

from sentinel_pulse.rca.ranking import ground_truth_rank, hit_rates, rank_suspects, workload_of
from sentinel_pulse.rca.runtime_events import POLICY, normalize_runtime_event
from sentinel_pulse.rca.runtime_tree import build_runtime_tree, render_runtime_markdown

from test_rca_runtime_events import record, trigger


@pytest.mark.parametrize('pod,expected', [
    ('inventory-service-695bf6f445-ttlgj', 'production/inventory-service:app'),
    ('aims-kafka-dual-role-1', 'production/aims-kafka-dual-role:app'),
    ('aims-minio-pool-0-0', 'production/aims-minio-pool-0:app'),
    ('standalone', 'production/standalone:app'),
    ('api-gateway-5bk9m7zq-x2v4c', 'production/api-gateway:app'),
])
def test_workload_key_matches_pulse_controller_naming(pod, expected):
    assert workload_of('production', pod, 'app') == expected


def _exec(binary, eid, at=99.):
    raw = dict(node_name='worker1', time=at, process_exec=dict(process=dict(
        pid=50, exec_id=eid, parent_exec_id='parent', binary=binary,
        pod=dict(namespace='production', name='app-1', uid='pod1', container=dict(name='app', id='cri1')))))
    return normalize_runtime_event(raw)


def test_novel_binary_with_security_failures_ranks_first():
    attack = _exec('/tmp/sentinel-runtime-attack-blind', 'atk')
    setns = record('sys_setns', [dict(label='namespace_fd', int_arg=-1)], ret=-9)
    setns['process_kprobe']['process'].update(exec_id='atk', binary='/tmp/sentinel-runtime-attack-blind')
    normal = _exec('/app/worker', 'w1')
    events = [attack, normalize_runtime_event(setns), normal]
    tree = build_runtime_tree(trigger(), events)
    baseline = {'/app/worker': 10., '/tmp/sentinel-runtime-attack-blind': 95.}
    ranked = rank_suspects(tree, baseline, frozen_at=50.)
    assert ranked[0]['binary'] == '/tmp/sentinel-runtime-attack-blind'
    assert {'novel_binary', 'security_operation', 'started_in_window', 'failed_syscall'} <= set(ranked[0]['reasons'])
    assert ground_truth_rank(ranked, binary='/tmp/sentinel-runtime-attack-blind') == 1
    assert ground_truth_rank(ranked, binary='/absent') is None
    tree['suspects'] = ranked
    assert 'Process nghi vấn' in render_runtime_markdown(tree)


def test_hit_rates_count_absent_as_miss():
    assert hit_rates([1, 2, None, 7]) == dict(cases=4, top1=.25, top3=.5, top5=.5, absent=1)


def test_evaluator_matches_case_to_attack_and_reports_rank(tmp_path):
    import json
    from sentinel_pulse.rca.evaluate_ranking import evaluate
    cases = tmp_path / 'cases'; cases.mkdir()
    trig = dict(trigger(), window_end=121.)
    tree = dict(case_id='c1', nodes=[dict(id='s', kind='signal', trigger=trig)], edges=[],
                suspects=[dict(rank=1, binary='/app/worker', exec_id='w'),
                          dict(rank=2, binary='/tmp/sentinel-runtime-attack-blind', exec_id='a')])
    (cases / 'c1.json').write_text(json.dumps(tree))
    trial = tmp_path / 'campaign' / 'trials' / '0001'; trial.mkdir(parents=True)
    attack = dict(trial_id='1:attack', scenario='s', workload_key='production/app:app', node_name='worker1',
                  pod_uid='pod1', container_name='app', start_at=120., binary_path='/tmp/sentinel-runtime-attack-blind')
    (trial / 'EVALUATION_INPUT.json').write_text(json.dumps(dict(attack=attack)))
    result = evaluate(cases, [tmp_path / 'campaign'])
    assert result['trials_with_case'] == 1 and result['rows'][0]['rank'] == 2
    assert result['ranking']['top1'] == 0 and result['ranking']['top3'] == 1
