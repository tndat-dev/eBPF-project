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
