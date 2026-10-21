import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).parents[1]/'scripts'/'analysis'/'novel_syscalls.py'
spec = importlib.util.spec_from_file_location('novel_syscalls', SCRIPT)
ns = importlib.util.module_from_spec(spec); spec.loader.exec_module(ns)


def test_first_novel_delay_uses_first_window_with_a_non_exec_novel_id():
    windows = [(101.0, ('0', '59')), (101.5, ('0', '101')), (102.0, ('101',))]
    assert ns.first_novel_delay(windows, {'0'}, {'59'}, 100.2) == (True, 101.5 - 100.2, False)
    assert ns.first_novel_delay(windows, {'0', '101'}, {'59'}, 100.2) == (False, None, False)
    assert ns.first_novel_delay(windows, {'0'}, set(), 101.2) == (True, None, True)   # novel before the kernel event


def capture(tmp_path):
    seg = tmp_path/'workers'/'n1'/'segments'/'s00001'; seg.mkdir(parents=True); (seg/'TERMINAL.json').write_text('{}')
    rows = []
    for i in range(400):                      # reference 0..100 s, campaign 150..200 s
        a = i * .5
        ident = dict(node_name='n1', pod_uid='p', cgroup_id=7, workload_key='w')
        ids = {'0': 1, '1': 1}
        if 150 <= a < 165 and a >= 151:      # attack interval: 101 (ptrace) from 151 s, 59 (exec) always
            ids.update({'101': 1, '59': 1})
        if 170 <= a < 185:                   # benign launch: only exec IDs
            ids.update({'59': 1})
        rows.append(dict(ident, window_start=a, window_end=a + .5, full_counts_delta=ids))
    (seg/'features.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    trial = dict(node_name='n1', pod_uid='p', cgroup_id=7, workload_key='w')
    camp = tmp_path/'campaign'; (camp/'trials'/'1').mkdir(parents=True)
    (camp/'trials'/'1'/'EVALUATION_INPUT.json').write_text(json.dumps(dict(
        attack=dict(trial, scenario='child_ptrace_handshake', start_at=150., kernel_event_at=150.9),
        benign=dict(trial, start_at=170.), control=dict(trial, start_at=186.))))
    (tmp_path/'E.json').write_text(json.dumps([59]))
    return camp


def test_end_to_end_with_exec_set_and_secondary_reference(tmp_path):
    camp = capture(tmp_path)
    out = tmp_path/'out.json'
    subprocess.run([sys.executable, str(SCRIPT), '--workers-root', str(tmp_path/'workers'), '--campaign', str(camp),
                    '--reference-span', '0:100', '--secondary-reference-span', '0:160', '--exec-set', str(tmp_path/'E.json'),
                    '--output', str(out)], check=True, capture_output=True)
    d = json.loads(out.read_text())
    assert d['overall'] == dict(attack=1.0, benign=0.0, control=0.0)
    assert d['reference_ids_by_workload']['w'] == ['0', '1']
    assert abs(d['attack_delay']['p50'] - (151.5 - 150.9)) < 1e-9
    # the secondary reference already contains 101 (seen 151..160 s), so nothing is novel against it
    assert d['secondary']['overall']['attack'] == 0.0


def test_tripwire_verdict_against_registered_criteria():
    spec = importlib.util.spec_from_file_location('tripwire_verdict', SCRIPT.parent/'tripwire_verdict.py')
    tv = importlib.util.module_from_spec(spec); spec.loader.exec_module(tv)
    criteria = json.loads((Path(__file__).parents[1]/'sentinel_pulse'/'protocol'/'tripwire-a1-blind-v1.json').read_text())['primary']['criteria']
    rare = {s: dict(attack=dict(share=1.0, delay_p95=0.8)) for s in criteria['rare_syscall_scenarios']}
    good = dict(overall=dict(attack=0.6, benign=0.003, control=0.0), by_scenario=rare)
    assert tv.verdict(good, criteria)['passed']
    slow = dict(good, by_scenario={**rare, 'invalid_setns_burst': dict(attack=dict(share=1.0, delay_p95=2.5))})
    assert not tv.verdict(slow, criteria)['passed']
    noisy = dict(good, overall=dict(attack=0.6, benign=0.2, control=0.0))
    assert tv.verdict(noisy, criteria)['checks']['benign'] is False
