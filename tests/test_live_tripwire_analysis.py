import gzip
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('live_tripwire', ROOT/'scripts'/'analysis'/'live_tripwire.py')
lt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lt)


def _run(tmp_path):
    run = tmp_path/'workers'
    for node, rows in (('k8s-a', [(100.5, 'judged', False), (101.0, 'judged', True), (130.0, 'judged', True), (140.0, 'judged', False)]),
                       ('k8s-b', [(101.0, 'reference_pending', False)])):
        seg = run/node/'segments'/'s00001'; seg.mkdir(parents=True)
        with gzip.open(seg/'decisions.jsonl.gz', 'wt') as f:
            for end, st, al in rows:
                f.write(json.dumps(dict(window_start=end - .5, window_end=end, preview_emitted_at=end + .2, node_name=node,
                                        pod_uid='u', cgroup_id=1, container_name='app', workload_key='production/w:app',
                                        tripwire_status=st, tripwire_alert=al, tripwire_novel_ids=[308] if al else [])) + '\n')
    camp = tmp_path/'camp'/'trials'/'0001'; camp.mkdir(parents=True)
    t = dict(node_name='k8s-a', pod_uid='u', cgroup_id=1, start_at=100.0, kernel_event_at=100.2, trial_id='1:attack')
    (camp/'EVALUATION_INPUT.json').write_text(json.dumps(dict(attack=dict(t, scenario='s'))))
    return run, tmp_path/'camp'


def test_trials_normal_alerts_lag_and_agreement_with_offline(tmp_path):
    run, camp = _run(tmp_path)
    per_trial, alerts, judged, status, lag = lt.scan(run, lt.trials_of(camp), (120.0, 200.0))
    assert per_trial[0]['novel'] is True and per_trial[0]['first_novel_end'] == 101.0
    assert [a['end'] for a in alerts] == [130.0] and len(judged) == 2
    assert status == {'judged': 4, 'reference_pending': 1}
    assert abs(lag['k8s-a']['p50'] - .2) < 1e-9 and lag['k8s-b']['n'] == 1
    offline = dict(normal=dict(alerts=[dict(end=130.0, node_name='k8s-a', pod_uid='u', container_name='app'),
                                       dict(end=140.0, node_name='k8s-a', pod_uid='u', container_name='app'),    # disagrees
                                       dict(end=150.0, node_name='k8s-a', pod_uid='u', container_name='app')]))  # not judged live
    agree = lt.agreement(alerts, judged, offline)
    assert agree['offline_only'] == 1 and agree['live_only'] == 0 and agree['offline_alerts_on_windows_not_judged_live'] == 1
    assert agree['agreement'] == .5


def test_an_interval_without_judged_windows_is_unknown(tmp_path):
    run, camp = _run(tmp_path)
    trials = lt.trials_of(camp); trials[0]['ident'] = ('k8s-b', 'u', '1')
    per_trial, *_ = lt.scan(run, trials, (120.0, 200.0))
    assert per_trial[0]['novel'] is None
