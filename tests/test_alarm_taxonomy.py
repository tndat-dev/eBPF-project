import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('alarm_taxonomy', Path(__file__).parents[1]/'scripts'/'analysis'/'alarm_taxonomy.py')
at = importlib.util.module_from_spec(spec); spec.loader.exec_module(at)


def case(exec_times, ws=1000.0):
    nodes = [dict(id='s', kind='signal', trigger=dict(window_start=ws, window_end=ws + 0.5, workload_key='w'))]
    edges = []
    for i, t in enumerate(exec_times):
        nodes += [dict(id=f'p{i}', kind='process', binary=f'/bin/b{i}'),
                  dict(id=f'e{i}', kind='runtime_event', operation='exec', observed_at=t)]
        edges.append(dict(source=f'p{i}', target=f'e{i}', relation='performed'))
    return dict(nodes=nodes, edges=edges)


def test_iso_seconds_keeps_sub_second_precision():
    assert abs(at.iso_seconds('1970-01-01T00:00:10.250000000Z') - 10.25) < 1e-9
    assert at.iso_seconds(12.5) == 12.5 and at.iso_seconds(None) is None


def test_exec_inside_lookback_is_a_benign_trigger_candidate():
    kind, _, inside = at.classify(case([998.0]))                 # 2.0 s before window start
    assert kind == 'exec_in_window' and inside == [(998.0, '/bin/b0')]
    assert at.classify(case([990.0]))[0] == 'exec_in_case_only'  # 10 s before: in the case, not the window
    assert at.classify(case([]))[0] == 'no_exec'
    assert at.classify(case([1000.9]))[0] == 'exec_in_window'    # within the 0.5 s after the window end


def probe_case(entry='python', parent='/usr/bin/runc', child=None):
    """One exec in the window: an in-container process started by ``parent``; optional child under it."""
    nodes = [dict(id='s', kind='signal', trigger=dict(window_start=1000.0, window_end=1000.5, workload_key='w')),
             dict(id='r', kind='process_parent', exec_id='R', binary=parent, container_name=None),
             dict(id='p', kind='process', exec_id='P', parent_exec_id='R', binary=f'/usr/local/bin/{entry}', container_name='app'),
             dict(id='e', kind='runtime_event', operation='exec', observed_at=999.5)]
    edges = [dict(source='p', target='e', relation='performed_exec')]
    if child:
        nodes += [dict(id='c', kind='process', exec_id='C', parent_exec_id='P', binary=child, container_name='app'),
                  dict(id='e2', kind='runtime_event', operation='exec', observed_at=999.7)]
        edges.append(dict(source='c', target='e2', relation='performed_exec'))
    return dict(nodes=nodes, edges=edges)


def test_probe_tree_detection_requires_runc_parent_and_declared_entry():
    assert at.probe_flags(probe_case(), {'python'}) == (1, 1)
    assert at.probe_flags(probe_case(child='/usr/local/bin/redis-cli'), {'python'}) == (2, 2)   # child of the probe
    assert at.probe_flags(probe_case(entry='sentinel-runtime-attack'), {'python'}) == (1, 0)
    assert at.probe_flags(probe_case(parent='/usr/local/bin/uvicorn'), {'python'}) == (1, 0)   # spawned by the app
    assert at.probe_flags(probe_case(parent='/usr/bin/containerd-shim-runc-v2'), {'python'}) == (1, 1)   # handed to the shim
