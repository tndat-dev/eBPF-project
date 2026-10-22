import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('falco_baseline', Path(__file__).parents[1]/'scripts'/'analysis'/'falco_baseline.py')
fb = importlib.util.module_from_spec(spec); spec.loader.exec_module(fb)

LINE = ('2026-10-21T06:04:34.615218902Z stdout F 06:04:34.612337206: Notice Unexpected connection to K8s API Server '
        'from container | connection=10.0.4.136:59646->10.96.0.1:443 evt_type=connect container_id=0661c06cee7f '
        'container_name=vault k8s_pod_name=vault-1 k8s_ns_name=vault')


def test_parse_reads_time_priority_rule_and_fields():
    t, priority, rule, fields = fb.parse(LINE)
    assert abs(t - (1792562674.612337206)) < 1e-3
    assert priority == 'Notice' and rule == 'Unexpected connection to K8s API Server from container'
    assert fields['container_id'] == '0661c06cee7f' and fields['k8s_ns_name'] == 'vault'
    assert fb.parse('garbage') is None


def test_event_logged_after_midnight_keeps_its_own_day():
    line = LINE.replace('2026-10-21T06:04:34.615218902Z', '2026-10-22T00:00:00.100000000Z').replace('06:04:34.612337206', '23:59:59.900000000')
    t = fb.parse(line)[0]
    assert abs(t - (1792627200.0 - 0.1)) < 1e-3    # 21/10 23:59:59.9 UTC


def test_main_writes_per_trial_outcomes_and_normal_events(tmp_path, monkeypatch):
    import json, sys
    logs = tmp_path/'logs'; logs.mkdir()
    hit = LINE.replace('container_id=0661c06cee7f', 'container_id=abcdefabcdef').replace('k8s_ns_name=vault', 'k8s_ns_name=production')
    (logs/'0.log').write_text(hit + '\n')
    camp = tmp_path/'camp'; (camp/'trials'/'0001').mkdir(parents=True)
    t0 = 1792562674.0
    base = dict(container_id='containerd://abcdefabcdef0000', scenario='s', rate_per_second=6)
    doc = dict(attack=dict(base, trial_id='1:attack', start_at=t0 - 5, kernel_event_at=t0 - 4),
               control=dict(base, trial_id='1:control', start_at=t0 - 100), benign=dict(base, trial_id='1:benign', start_at=t0 - 60))
    (camp/'trials'/'0001'/'EVALUATION_INPUT.json').write_text(json.dumps(doc))
    (camp/'INTERVALS.jsonl').write_text(json.dumps(dict(start_at=t0 - 100)) + '\n')
    (camp/'TERMINAL.json').write_text(json.dumps(dict(finished_at_unix=t0 + 10)))
    out = tmp_path/'out.json'
    monkeypatch.setattr(sys, 'argv', ['falco_baseline', '--logs', str(logs), '--campaign', str(camp), '--normal-since', str(t0 - 1000),
                                      '--normal-until', str(t0 + 1000), '--output', str(out)])
    fb.main()
    r = json.loads(out.read_text())
    by_kind = {t['kind']: t for t in r['trials']}
    assert by_kind['attack']['detected'] and by_kind['attack']['rate'] == 6 and by_kind['attack']['trial_id'] == '1:attack'
    assert not by_kind['control']['detected'] and by_kind['attack']['rules'] == ['Unexpected connection to K8s API Server from container']
    assert r['normal_events'] == []          # the only event falls inside the campaign span
