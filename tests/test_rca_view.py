import json
from pathlib import Path
import shutil
import time
import urllib.error
import urllib.request

import pytest

from sentinel_pulse.ops import rca_view
from sentinel_pulse.ops.alert_bridge import Bridge, serve
from sentinel_pulse.rca.tree import case_id

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT/'validation-evidence'/'rca'/'examples-20261023'
ATTACK = EXAMPLES/'attack-ptrace-api-gateway-2e6d889a740dd5b609786274.json'
PROBE = EXAMPLES/'normal-probe-inventory-service-00a0b1e0f074049e0b62676c.json'
CFG = dict(model_hash='m' * 64, policy_hash='p' * 64, resolve_after_seconds=3, refresh_seconds=5)


def row(t, pod='pod-a', **extra):
    return dict(dict(schema='sentinel-pulse-candidate-shadow-score-v1', status='candidate-raw-score-only',
                     policy_evaluated=True, candidate_alert_preview=True, alert=False, run_id='run',
                     capture_segment='s00001', node_name='k8s-worker1.local', pod_uid=pod, container_name='postgres',
                     cgroup_id=7, workload_key='production/aims-postgres-cnpg:postgres', window_start=t - .5,
                     window_end=t, preview_emitted_at=t + .1, joint_p=1e-5, candidate_manifest_sha256='m' * 64,
                     policy_sha256='p' * 64), **extra)


def case(cid, trigger_kind='candidate_alert_preview', suspects=(), probe_only=False, created=100.0):
    return dict(case_id=cid, created_at=created, trigger_kind=trigger_kind, network_destinations=['["10.0.0.1", 80]'],
                matched_connect_events=1, matched_flow_events=2, suspects=list(suspects), triage=dict(probe_only=probe_only),
                event_categories=dict(process=3), limitations=['aggregate_anomaly_does_not_prove_process_causality'],
                nodes=[dict(id='signal:' + cid, kind='signal', trigger=dict(node_name='k8s-worker1.local', pod_uid='pod-a',
                       container_name='postgres', workload_key='production/aims-postgres-cnpg:postgres', window_end=100.0))],
                edges=[])


def suspect(binary, *reasons, score=4):
    return dict(binary=binary, reasons=list(reasons), score=score, rank=1, pid=10, exec_id='e')


def test_real_cases_are_classified_for_routing():
    attack = rca_view.summarize(json.loads(ATTACK.read_text()), 'http://bridge:9478')
    assert attack['rca_class'] == 'security_operation' and attack['notify'] == 'immediate'
    assert attack['top_binary'] == '/tmp/sentinel-runtime-attack-blind' and attack['connections'] == 32
    assert attack['url'] == 'http://bridge:9478/cases/2e6d889a740dd5b609786274'
    probe = rca_view.summarize(json.loads(PROBE.read_text()))
    assert probe['rca_class'] == 'probe_only' and probe['notify'] == 'dashboard' and probe['probe_only'] is True


@pytest.mark.parametrize('kw, cls', [
    (dict(trigger_kind='tripwire_alert'), 'tripwire'),
    (dict(suspects=[suspect('/bin/x', 'novel_binary'), suspect('/bin/y', 'security_operation')]), 'security_operation'),
    (dict(suspects=[suspect('/bin/sh', 'started_in_window')], probe_only=True), 'probe_only'),
    (dict(suspects=[suspect('/tmp/new', 'novel_binary', 'started_in_window')]), 'new_binary'),
    (dict(suspects=[suspect('/bin/sh', 'started_in_window')]), 'other'),
    (dict(), 'other'),
])
def test_classes_and_their_notify_level(kw, cls):
    c = case('a' * 24, **kw)
    assert rca_view.classify(c) == cls
    assert rca_view.summarize(c)['notify'] == ('immediate' if cls in ('tripwire', 'security_operation') else 'dashboard')


def test_annotations_are_strings_with_the_operator_facts():
    s = rca_view.summarize(case('b' * 24, suspects=[suspect('/tmp/x', 'novel_binary', 'security_operation', score=7)]),
                           'http://h:1')
    a = rca_view.alert_annotations(s)
    assert all(isinstance(v, str) for v in a.values())
    assert a['rca_top_suspect'] == '/tmp/x' and a['rca_top_reasons'] == 'novel_binary, security_operation'
    assert a['rca_connections'] == '1' and a['rca_url'] == 'http://h:1/cases/' + 'b' * 24 and a['rca_class'] == 'security_operation'


def test_case_index_parses_each_file_once_and_rejects_bad_names(tmp_path):
    idx = rca_view.CaseIndex(tmp_path, 'http://h')
    (tmp_path/('c' * 24 + '.json')).write_text(json.dumps(case('c' * 24, created=50.0)))
    (tmp_path/'notes.json').write_text('{}')
    (tmp_path/('d' * 24 + '.json')).write_text('{partial')
    new = idx.refresh()
    assert [s['case_id'] for s in new] == ['c' * 24] and idx.refresh() == []
    assert idx.get('c' * 24)['created_at'] == 50.0 and idx.recent(since=60.0) == []
    assert idx.path('../etc/passwd', '.json') is None and idx.path('c' * 24, '.json') is not None


def test_episode_alert_is_enriched_when_its_case_appears_and_triage_alert_routes_it(tmp_path):
    cases = tmp_path/'cases'; cases.mkdir()
    old = 'e' * 24
    (cases/(old + '.json')).write_text(json.dumps(case(old)))           # written before the bridge started
    bridge = Bridge(dict(CFG, rca_cases_dir=str(cases), case_base_url='http://h:9478'), tmp_path)
    ep = bridge.ingest(row(100.0), 100.3)
    bridge.pushes.get_nowait()                                          # the start push, before any case
    bridge.tick(100.4)
    assert bridge.pushes.empty()                                        # the old case is never pushed
    cid = ep['episode']
    assert cid == case_id(row(100.0))
    (cases/(cid + '.json')).write_text(json.dumps(case(cid, suspects=[suspect('/tmp/x', 'novel_binary', 'security_operation')])))
    bridge.tick(103.0)
    _, (anomaly, triage) = bridge.pushes.get_nowait()
    assert anomaly['labels']['alertname'] == 'SentinelPulseAnomaly' and anomaly['labels']['episode'] == cid
    assert anomaly['annotations']['rca_top_suspect'] == '/tmp/x' and 'path' in anomaly['labels']
    assert triage['labels']['alertname'] == 'SentinelPulseTriage' and triage['labels']['notify'] == 'immediate'
    assert triage['labels']['rca_class'] == 'security_operation' and triage['labels']['severity'] == 'critical'
    bridge.tick(105.5)                                                  # refresh keeps the RCA annotations
    _, (refresh,) = bridge.pushes.get_nowait()
    assert refresh['annotations']['rca_class'] == 'security_operation'
    assert json.loads((tmp_path/'rca.jsonl').read_text())['rca_class'] == 'security_operation'


def test_tripwire_episode_is_routed_at_once_and_probe_only_case_to_the_dashboard(tmp_path):
    cases = tmp_path/'cases'; cases.mkdir()
    bridge = Bridge(dict(CFG, rca_cases_dir=str(cases)), tmp_path)
    bridge.ingest(row(100.0, tripwire_alert=True, tripwire_status='judged', status='x', policy_evaluated=False), 100.3)
    bridge.pushes.get_nowait()
    _, (triage,) = bridge.pushes.get_nowait()
    assert triage['labels']['rca_class'] == 'tripwire' and triage['labels']['notify'] == 'immediate'
    assert triage['annotations']['rca_status'] == 'case pending'
    ep = bridge.ingest(row(100.0, pod='pod-b'), 100.3)
    bridge.pushes.get_nowait()
    (cases/(ep['episode'] + '.json')).write_text(json.dumps(case(ep['episode'], probe_only=True,
                                                                  suspects=[suspect('/bin/sh', 'started_in_window')])))
    bridge.tick(102.0)
    _, (_, routed) = bridge.pushes.get_nowait()
    assert routed['labels']['notify'] == 'dashboard' and routed['labels']['severity'] == 'info'


def test_http_serves_case_list_page_files_and_refuses_other_paths(tmp_path):
    cases = tmp_path/'cases'; cases.mkdir()
    cid = ATTACK.stem[-24:]                                         # the service names files <case_id>.json
    real = json.loads(ATTACK.read_text()); real['created_at'] = time.time()   # /cases.json lists at most 7 days back
    (cases/(cid + '.json')).write_text(json.dumps(real))
    (cases/(cid + '.md')).write_text('# case')
    bridge = Bridge(dict(CFG, rca_cases_dir=str(cases), case_base_url='http://h'), tmp_path)
    server = serve(bridge, '127.0.0.1', 0)
    base = f'http://127.0.0.1:{server.server_address[1]}'
    try:
        rows = json.loads(urllib.request.urlopen(base + '/cases.json?hours=1').read())
        assert [r['case_id'] for r in rows] == [cid]
        page = urllib.request.urlopen(base + f'/cases/{cid}').read().decode()
        assert 'Sentinel Pulse RCA case' in page and '/tmp/sentinel-runtime-attack-blind' in page
        assert urllib.request.urlopen(base + f'/cases/{cid}.md').read() == b'# case'
        assert json.loads(urllib.request.urlopen(base + f'/cases/{cid}.json').read())['case_id'] == cid
        assert 'Recent RCA cases' in urllib.request.urlopen(base + '/cases').read().decode()
        for bad in ('/cases/..%2F..%2Fetc%2Fpasswd', '/cases/' + 'f' * 24, f'/cases/{cid}.exe'):
            with pytest.raises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(base + bad)
            assert err.value.code == 404
        try:
            svg = urllib.request.urlopen(base + f'/cases/{cid}.svg')
            assert shutil.which('dot') and svg.headers['Content-Type'] == 'image/svg+xml'
        except urllib.error.HTTPError as err:
            assert err.code == 503 and not shutil.which('dot')
    finally:
        server.shutdown()


def test_notify_webhook_logs_triage_alerts_only(tmp_path):
    bridge = Bridge(CFG, tmp_path)
    bridge.notification(dict(alerts=[
        dict(status='firing', labels=dict(alertname='SentinelPulseTriage', rca_class='tripwire', episode='x', workload='w'),
             annotations=dict(rca_top_suspect='/tmp/x')),
        dict(status='firing', labels=dict(alertname='SentinelPulseAnomaly')),
        dict(status='resolved', labels=dict(alertname='SentinelPulseTriage', rca_class='tripwire'))]), time.time())
    assert bridge.counters['notifications_tripwire'] == 1
    assert len((tmp_path/'notifications.jsonl').read_text().splitlines()) == 1
