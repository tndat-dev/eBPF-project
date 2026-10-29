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


def test_container_runtime_parent_is_never_a_suspect():
    from sentinel_pulse.rca.ranking import is_container_runtime
    assert is_container_runtime('/usr/bin/containerd-shim-runc-v2') and is_container_runtime('/usr/sbin/runc')
    assert not is_container_runtime('/usr/local/bin/python') and not is_container_runtime(None)
    tree = dict(nodes=[dict(id='shim', kind='process_parent', binary='/usr/bin/containerd-shim-runc-v2'),
                       dict(id='p', kind='process', binary='/tmp/x'),
                       dict(id='e', kind='runtime_event', operation='exec', category='process')],
                edges=[dict(source='shim', target='p', relation='parent_of'),
                       dict(source='p', target='e', relation='performed')])
    ranked = rank_suspects(tree, {}, frozen_at=0.)
    assert [r['binary'] for r in ranked] == ['/tmp/x']


def test_offline_rerank_uses_binaries_seen_before_the_case(tmp_path):
    import json, sqlite3
    from sentinel_pulse.rca.evaluate_ranking import evaluate
    db = tmp_path / 'context.sqlite3'
    with sqlite3.connect(db) as conn:
        conn.execute('create table binaries(workload text, binary text, first_seen real)')
        conn.executemany('insert into binaries values(?,?,?)', [
            ('production/app:app', '/app/worker', 10.), ('production/app:app', '/tmp/sentinel-runtime-attack-blind', 119.)])
    cases = tmp_path / 'cases'; cases.mkdir()
    trig = dict(trigger(), window_end=121., workload_key='production/app:app')
    tree = dict(case_id='c1', created_at=125., edges=[dict(source='a', target='e', relation='performed'),
                                                       dict(source='w', target='e2', relation='performed')],
                nodes=[dict(id='s', kind='signal', trigger=trig),
                       dict(id='a', kind='process', binary='/tmp/sentinel-runtime-attack-blind', exec_id='a'),
                       dict(id='w', kind='process', binary='/app/worker', exec_id='w'),
                       dict(id='e', kind='runtime_event', operation='exec', category='process'),
                       dict(id='e2', kind='runtime_event', operation='exec', category='process')],
                suspects=[])
    (cases / 'c1.json').write_text(json.dumps(tree))
    trial = tmp_path / 'campaign' / 'trials' / '0001'; trial.mkdir(parents=True)
    attack = dict(trial_id='1:attack', scenario='s', workload_key='production/app:app', node_name='worker1',
                  pod_uid='pod1', container_name='app', start_at=120., binary_path='/tmp/sentinel-runtime-attack-blind')
    (trial / 'EVALUATION_INPUT.json').write_text(json.dumps(dict(attack=attack)))
    result = evaluate(cases, [tmp_path / 'campaign'], rerank_db=db, frozen_at=50.)
    assert result['reranked'] and result['rows'][0]['rank'] == 1


def _probe_tree(uid=1000, delay_ms=1):
    from datetime import datetime, timedelta, timezone
    start = datetime(2026, 10, 20, 4, 57, 25, 766714, tzinfo=timezone.utc)
    stamp = lambda ms: (start + timedelta(milliseconds=ms)).strftime('%Y-%m-%dT%H:%M:%S.%f') + '123Z'
    nodes = [dict(id='p', kind='process', binary='/bin/sh', exec_id='e1', pid=1, start_time=stamp(0)),
             dict(id='x', kind='runtime_event', category='process', operation='exec'),
             dict(id='c1', kind='runtime_event', category='credential', operation='setuid', details=dict(uid=uid),
                  observed_at=stamp(delay_ms), outcome=dict(status='success')),
             dict(id='c2', kind='runtime_event', category='credential', operation='setgid', details=dict(gid=uid),
                  observed_at=stamp(delay_ms), outcome=dict(status='success'))]
    edges = [dict(source='p', target=t, relation='performed') for t in ('x', 'c1', 'c2')]
    return dict(nodes=nodes, edges=edges)


def test_privilege_drop_at_launch_is_not_a_security_operation():
    from sentinel_pulse.rca.ranking import rank_suspects
    row = rank_suspects(_probe_tree())[0]
    assert row['score'] == 2 and 'privilege_drop_at_start' in row['reasons'] and 'security_operation' not in row['reasons']


def test_raise_to_root_or_late_change_still_counts():
    from sentinel_pulse.rca.ranking import rank_suspects
    assert rank_suspects(_probe_tree(uid=0))[0]['score'] == 2 + 6
    assert rank_suspects(_probe_tree(delay_ms=5000))[0]['score'] == 2 + 6


def test_old_rule_switch_scores_launch_drop_as_security_operation(monkeypatch):
    from sentinel_pulse.rca import ranking
    monkeypatch.setattr(ranking, 'DROP_AT_START_SECONDS', -1.0)   # what --without-privilege-drop-rule sets
    assert ranking.rank_suspects(_probe_tree())[0]['score'] == 2 + 6


def test_recency_tie_break_puts_the_later_launch_first():
    benign = _exec('/operator/sentinel-benign-exec-control', 'ben', at=85.)
    attack = _exec('/operator/sentinel-runtime-attack-blind', 'atk', at=99.)
    tree = build_runtime_tree(trigger(), [benign, attack])
    for node in tree['nodes']:                              # Tetragon's process start time, as in live cases
        if node['kind'] == 'process':
            node['start_time'] = {'ben': '2026-10-25T16:41:18.957048Z', 'atk': '2026-10-25T16:41:33.571360Z'}.get(node['exec_id'])
    baseline = {'/operator/sentinel-benign-exec-control': 60., '/operator/sentinel-runtime-attack-blind': 70.}
    by_name = rank_suspects(tree, baseline, frozen_at=50.)
    by_time = rank_suspects(tree, baseline, frozen_at=50., tie_break='recency')
    assert by_name[0]['score'] == by_name[1]['score']                                 # a tie: both novel, both started in the window
    assert by_name[0]['binary'] == '/operator/sentinel-benign-exec-control'           # the alphabetical order
    assert ground_truth_rank(by_time, binary='/operator/sentinel-runtime-attack-blind') == 1
    assert 'started_at' not in by_time[0]
    with pytest.raises(ValueError):
        rank_suspects(tree, baseline, 50., tie_break='random')
