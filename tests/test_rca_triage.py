import importlib.util
import json
from pathlib import Path

from sentinel_pulse.rca.triage import probe_entries, triage

spec = importlib.util.spec_from_file_location('alarm_taxonomy', Path(__file__).parents[1]/'scripts'/'analysis'/'alarm_taxonomy.py')
at = importlib.util.module_from_spec(spec); spec.loader.exec_module(at)


def case(execs):
    """execs: [(observed_at, binary, parent binary, child binary or None)]"""
    nodes = [dict(id='s', kind='signal', trigger=dict(window_start=1000.0, window_end=1000.5, workload_key='w'))]
    edges = []
    for i, (t, binary, parent, child) in enumerate(execs):
        nodes += [dict(id=f'r{i}', kind='process_parent', exec_id=f'R{i}', binary=parent, container_name=None),
                  dict(id=f'p{i}', kind='process', exec_id=f'P{i}', parent_exec_id=f'R{i}', binary=binary, container_name='app'),
                  dict(id=f'e{i}', kind='runtime_event', operation='exec', observed_at=t)]
        edges.append(dict(source=f'p{i}', target=f'e{i}', relation='performed_exec'))
        if child:
            nodes += [dict(id=f'c{i}', kind='process', exec_id=f'C{i}', parent_exec_id=f'P{i}', binary=child, container_name='app'),
                      dict(id=f'f{i}', kind='runtime_event', operation='exec', observed_at=t + 0.1)]
            edges.append(dict(source=f'c{i}', target=f'f{i}', relation='performed_exec'))
    return dict(nodes=nodes, edges=edges)


CASES = [
    case([(999.5, '/usr/local/bin/python', '/usr/bin/runc', None)]),                                    # probe only
    case([(999.5, '/bin/sh', '/usr/bin/containerd-shim-runc-v2', '/usr/local/bin/redis-cli')]),          # probe tree
    case([(999.5, '/usr/local/bin/python', '/usr/bin/runc', None),
          (999.0, '/tmp/sentinel-runtime-attack-blind', '/usr/bin/runc', None)]),                          # probe + other exec
    case([(990.0, '/usr/local/bin/python', '/usr/bin/runc', None)]),                                    # exec outside window
    case([]),                                                                                           # no exec
]


def test_triage_equals_the_offline_taxonomy_rule():
    entries = {'python', 'sh'}
    for c in CASES:
        kind, _, _ = at.classify(c)
        execs, probes = at.probe_flags(c, entries)
        offline = kind == 'exec_in_window' and execs > 0 and probes == execs
        out = triage(c, entries)
        assert out['probe_only'] == offline and (out['execs'], out['probe_execs']) == (execs, probes)
    assert [triage(c, entries)['probe_only'] for c in CASES] == [True, True, False, False, False]


def test_probe_entries_from_a_pod_spec():
    pod = json.loads(json.dumps({'spec': {'containers': [
        {'name': 'app', 'readinessProbe': {'exec': {'command': ['python', '-c', 'import urllib']}},
         'livenessProbe': {'httpGet': {'path': '/'}}},
        {'name': 'redis', 'livenessProbe': {'exec': {'command': ['/bin/sh', '-ec', 'redis-cli ping']}}},
        {'name': 'web'}]}}))
    assert probe_entries(pod) == {'app': {'python'}, 'redis': {'sh'}}
