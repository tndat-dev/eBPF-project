import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('label_review', Path(__file__).parents[1]/'scripts'/'analysis'/'label_review.py')
lr = importlib.util.module_from_spec(spec); spec.loader.exec_module(lr)


def case(execs=(), dests=(), parent='/usr/bin/runc'):
    nodes = [dict(id='s', kind='signal', trigger=dict(window_start=1000.0, window_end=1000.5, workload_key='w'))]
    edges = []
    for i, (t, binary) in enumerate(execs):
        nodes += [dict(id=f'r{i}', kind='process_parent', exec_id=f'R{i}', binary=parent, container_name=None),
                  dict(id=f'p{i}', kind='process', exec_id=f'P{i}', parent_exec_id=f'R{i}', binary=binary, container_name='app'),
                  dict(id=f'e{i}', kind='runtime_event', operation='exec', observed_at=t)]
        edges.append(dict(source=f'p{i}', target=f'e{i}', relation='performed_exec'))
    return dict(nodes=nodes, edges=edges, network_destinations=[f'["{ip}", 443]' for ip in dests])


def test_label_order_and_rules():
    probe = case([(999.8, '/usr/local/bin/python')])
    assert lr.label(probe, [], {'python'})[0] == 'benign_probe'
    assert lr.label(probe, [dict(reasons=['started_in_window', 'unknown_binary'])], {'python'})[0] == 'suspicious'
    assert lr.label(probe, [dict(reasons=['unknown_binary'])], {'python'})[0] == 'benign_probe'   # long-running, not executed here
    assert lr.label(case([(999.8, '/usr/bin/df')]), [], {'python'})[0] == 'benign_routine_exec'
    assert lr.label(case(), [], set())[0] == 'benign_no_process_cause'
    lab, flags, _, public = lr.label(case(dests=['10.0.5.50', '8.8.8.8']), [], set())
    assert lab == 'suspicious' and flags == ['public_destination'] and public == ['8.8.8.8']
    assert lr.label(case(dests=['10.1.16.238', '172.20.0.1', '127.0.0.1']), [], set())[0] == 'benign_no_process_cause'
    assert lr.wilson(0, 10)[0] == 0.0
