import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('rca_case_graph', Path(__file__).parents[1]/'scripts/analysis/rca_case_graph.py')
graph = importlib.util.module_from_spec(spec); spec.loader.exec_module(graph)


def test_case_is_drawn_with_suspects_lineage_and_collapsed_evidence():
    case = dict(trigger_kind='candidate_alert_preview', triage=dict(probe_only=False, probe_execs=0, execs=1),
                suspects=[dict(process='p2', rank=1, reasons=['novel_binary'])],
                nodes=[dict(id='s', kind='signal', trigger=dict(window_end=10.0, joint_p=1e-5)),
                       dict(id='c', kind='container', workload_key='production/api:app', node_name='w1'),
                       dict(id='p1', kind='process_parent', binary='/usr/bin/runc', pid=1),
                       dict(id='p2', kind='process', binary='/tmp/x', pid=2),
                       dict(id='e1', kind='runtime_event', operation='ptrace'),
                       dict(id='e2', kind='runtime_event', operation='ptrace'),
                       dict(id='k', kind='connect_attempt'),
                       dict(id='d', kind='destination', address='10.1.16.238', kubernetes=dict(kind='Node', name='w4'))],
                edges=[dict(relation='signal_on_container', source='s', target='c'),
                       dict(relation='parent_of', source='p1', target='p2'),
                       dict(relation='performed_ptrace', source='p2', target='e1'),
                       dict(relation='performed_ptrace', source='p2', target='e2'),
                       dict(relation='called_connect', source='p2', target='k'),
                       dict(relation='attempted_destination', source='k', target='d')])
    dot = graph.to_dot(case)
    assert 'nghi phạm hạng 1: novel_binary' in dot and '"p1" -> "p2" [label="cha của"]' in dot
    assert 'ptrace ×2' in dot and 'connect ×1 → Node w4 (IP dùng chung, peer thật không rõ)' in dot
    assert 'triage: probe_only=False' in dot
