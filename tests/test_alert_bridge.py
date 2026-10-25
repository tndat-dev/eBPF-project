import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import sys
import threading
import time
import urllib.request

from sentinel_pulse.ops.alert_bridge import FOLLOWER, NEEDLE, Bridge, push_worker, serve
from sentinel_pulse.rca.tree import case_id

CFG = dict(model_hash='m' * 64, policy_hash='p' * 64, resolve_after_seconds=3, refresh_seconds=5)


def row(t, preview=True, pod='pod-a', **extra):
    return dict(dict(schema='sentinel-pulse-candidate-shadow-score-v1', status='candidate-raw-score-only',
                     policy_evaluated=True, candidate_alert_preview=preview, alert=False, run_id='run',
                     capture_segment='s00001', node_name='k8s-worker1.local', pod_uid=pod, container_name='postgres',
                     cgroup_id=7, workload_key='production/aims-postgres-cnpg:postgres', window_start=t - .5,
                     window_end=t, preview_emitted_at=t + .1, joint_p=1e-5, candidate_manifest_sha256='m' * 64,
                     policy_sha256='p' * 64), **extra)


def test_episode_starts_on_first_preview_continues_and_resolves_after_the_gap(tmp_path):
    bridge = Bridge(CFG, tmp_path)
    assert bridge.ingest(row(100.0, policy_sha256='x' * 64), 100.3) is None      # other policy: never an alert
    assert bridge.ingest(row(100.0, preview=False), 100.3) is None
    ep = bridge.ingest(row(100.0), 100.3)
    assert ep['episode'] == case_id(row(100.0))                                  # names the RCA case of the trigger
    assert bridge.ingest(row(100.5), 100.8) is ep and ep['rows'] == 2
    other = bridge.ingest(row(100.5, pod='pod-b'), 100.8)
    assert other is not ep and len(bridge.active) == 2
    _, (first,) = bridge.pushes.get_nowait()
    assert first['labels'] == dict(alertname='SentinelPulseAnomaly', namespace='sentinel-pulse', severity='warning',
                                   path='push', node='k8s-worker1.local', target_namespace='production',
                                   workload='aims-postgres-cnpg:postgres', pod_uid='pod-a', container='postgres',
                                   episode=ep['episode'])
    assert first['startsAt'] == '1970-01-01T00:01:40Z' and first['annotations']['rca_case'] == ep['episode']
    bridge.pushes.get_nowait()                                                   # pod-b start
    bridge.tick(103.0)                                                           # 2.2 s gap: still active
    assert len(bridge.active) == 2 and bridge.pushes.empty()
    bridge.tick(105.9)                                                           # > 3 s gap: both resolve
    assert not bridge.active
    ends = sorted(alerts[0]['endsAt'] for _, alerts in (bridge.pushes.get_nowait(), bridge.pushes.get_nowait()))
    assert ends == ['1970-01-01T00:01:45.900000Z'] * 2
    events = [json.loads(l)['event'] for l in (tmp_path/'episodes.jsonl').read_text().splitlines()]
    assert events == ['start', 'start', 'end', 'end']


def test_long_episode_is_refreshed_before_alertmanager_would_resolve_it():
    bridge = Bridge(CFG)
    for i in range(30):                                                         # 15 s of consecutive previews
        bridge.ingest(row(100.0 + i / 2), 100.3 + i / 2)
        bridge.tick(100.3 + i / 2)
    alerts = []
    while not bridge.pushes.empty():
        alerts += bridge.pushes.get_nowait()[1]
    assert len(alerts) == 3                                                     # start + refresh every 5 s
    assert all(a['endsAt'] > '1970-01-01T00:01:54Z' for a in alerts[1:])        # ends after the next refresh
    assert len(bridge.active) == 1


def test_first_delivery_per_path_and_episode_is_logged_with_its_latency(tmp_path):
    bridge = Bridge(CFG, tmp_path)
    ep = bridge.ingest(row(100.0), 100.3)
    bridge.pushed(ep['episode'], 100.35)
    push = dict(status='firing', labels=dict(alertname='SentinelPulseAnomaly', path='push', episode=ep['episode']))
    pull = dict(status='firing', labels=dict(alertname='SentinelPulseAnomalyPull', path='pull-fast', episode=ep['episode']))
    other = dict(status='firing', labels=dict(alertname='KubePodCrashLooping'))
    resolved = dict(push, status='resolved')
    first = bridge.webhook(dict(alerts=[push, other, resolved]), 100.6)
    assert [(r['path'], round(r['latency_from_preview'], 3), round(r['latency_from_window_end'], 3)) for r in first] == \
        [('push', 0.5, 0.6)]
    assert first[0]['first_push_at'] == 100.35
    assert bridge.webhook(dict(alerts=[push]), 101.0) == []                     # a repeat is not a new delivery
    assert [r['path'] for r in bridge.webhook(dict(alerts=[pull]), 112.1)] == ['pull-fast']
    unknown = bridge.webhook(dict(alerts=[dict(push, labels=dict(push['labels'], episode='gone'))]), 113.0)
    assert unknown[0]['known_episode'] is False and 'latency_from_preview' not in unknown[0]
    assert len((tmp_path/'deliveries.jsonl').read_text().splitlines()) == 3


def test_metrics_expose_the_active_gauge_and_delivery_histogram():
    bridge = Bridge(CFG)
    ep = bridge.ingest(row(100.0, pod='a"b'), 100.3)
    bridge.webhook(dict(alerts=[dict(status='firing', labels=dict(alertname='SentinelPulseAnomaly', path='push',
                                                                  episode=ep['episode']))]), 101.4)
    text = bridge.metrics()
    assert ('sentinel_pulse_preview_active{node="k8s-worker1.local",target_namespace="production",'
            'workload="aims-postgres-cnpg:postgres",pod_uid="a\\"b",container="postgres",'
            f'episode="{ep["episode"]}"}} 1') in text
    assert 'sentinel_pulse_alert_delivery_seconds_bucket{path="push",le="1"} 0' in text
    assert 'sentinel_pulse_alert_delivery_seconds_bucket{path="push",le="1.5"} 1' in text
    assert 'sentinel_pulse_alert_delivery_seconds_count{path="push"} 1' in text
    assert 'sentinel_pulse_bridge_events_total{event="positive_rows"} 1' in text


def test_http_server_serves_metrics_and_receives_alertmanager_webhooks():
    bridge = Bridge(CFG)
    ep = bridge.ingest(row(100.0), 100.3)
    server = serve(bridge, '127.0.0.1', 0)
    base = f'http://127.0.0.1:{server.server_address[1]}'
    try:
        body = json.dumps(dict(alerts=[dict(status='firing', labels=dict(alertname='SentinelPulseAnomaly',
                                                                        path='push', episode=ep['episode']))]))
        request = urllib.request.Request(base + '/alertmanager', data=body.encode(), method='POST',
                                         headers={'Content-Type': 'application/json'})
        assert urllib.request.urlopen(request, timeout=3).status == 200
        assert 'sentinel_pulse_preview_active{' in urllib.request.urlopen(base + '/metrics', timeout=3).read().decode()
        assert bridge.counters['deliveries_push'] == 1
    finally:
        server.shutdown()


def test_push_worker_posts_to_the_alertmanager_v2_api_and_records_the_first_push():
    received = []

    class Alertmanager(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
            self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Alertmanager)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    bridge, stop = Bridge(CFG), threading.Event()
    ep = bridge.ingest(row(100.0), 100.3)
    worker = threading.Thread(target=push_worker, args=(bridge, f'http://127.0.0.1:{server.server_address[1]}', stop))
    worker.start()
    try:
        deadline = time.time() + 5
        while ep['first_push_at'] is None and time.time() < deadline:
            time.sleep(0.02)
    finally:
        stop.set(); worker.join(); server.shutdown()
    assert received[0][0] == '/api/v2/alerts' and received[0][1][0]['labels']['episode'] == ep['episode']
    assert ep['first_push_at'] is not None and bridge.counters['pushes_ok'] == 1


def test_push_worker_retries_a_failed_episode_push(tmp_path):
    received = []

    class Alertmanager(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(503 if len(received) == 1 else 200)       # first attempt fails
            self.send_header('Content-Length', '0'); self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Alertmanager)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    bridge, stop = Bridge(CFG, tmp_path), threading.Event()
    ep = bridge.ingest(row(100.0), 100.3)
    worker = threading.Thread(target=push_worker, args=(bridge, f'http://127.0.0.1:{server.server_address[1]}', stop))
    worker.start()
    try:
        deadline = time.time() + 5
        while ep['first_push_at'] is None and time.time() < deadline:
            time.sleep(0.02)
    finally:
        stop.set(); worker.join(); server.shutdown()
    assert len(received) == 2 and received[0] == received[1]
    assert ep['first_push_at'] is not None
    assert [bridge.counters[k] for k in ('pushes_failed', 'pushes_retried', 'pushes_ok')] == [1, 1, 1]
    issue = json.loads((tmp_path/'issues.jsonl').read_text())
    assert issue['episode'] == ep['episode'] and issue['attempt'] == 1 and issue['retry'] is True


def test_worker_follower_prints_only_positive_rows_from_the_newest_segment(tmp_path):
    seg = tmp_path/'segments'/'s00001'; seg.mkdir(parents=True)
    log = seg/'decisions.jsonl'
    log.write_text('{"old":1,"candidate_alert_preview":true}\n')               # before start: not replayed
    child = subprocess.Popen([sys.executable, '-u', '-c', FOLLOWER, str(tmp_path), NEEDLE], stdout=subprocess.PIPE)
    try:
        time.sleep(0.5)
        with open(log, 'a') as handle:
            handle.write('{"a":1,"candidate_alert_preview":false}\n{"a":2,"candidate_alert_preview":true}\n')
        new = tmp_path/'segments'/'s00002'; new.mkdir()
        (new/'decisions.jsonl').write_text('')
        time.sleep(0.5)
        with open(new/'decisions.jsonl', 'a') as handle:
            handle.write('{"a":3,"candidate_alert_preview":true}\n')
        lines = [json.loads(child.stdout.readline()) for _ in range(2)]
    finally:
        child.kill()
    assert [l['a'] for l in lines] == [2, 3]


def test_first_delivery_of_an_episode_writes_one_rca_trigger_with_the_original_row(tmp_path):
    bridge = Bridge(CFG, tmp_path)
    first = row(100.0)
    ep = bridge.ingest(first, 100.3)
    alert = lambda path: dict(status='firing', labels=dict(alertname='SentinelPulseAnomaly', path=path, episode=ep['episode']))
    bridge.webhook(dict(alerts=[alert('push')]), 100.4)
    bridge.webhook(dict(alerts=[alert('pull-fast')]), 105.0)               # a later path does not trigger again
    triggers = [json.loads(l) for l in (tmp_path/'triggers.jsonl').read_text().splitlines()]
    assert len(triggers) == 1 and triggers[0]['path'] == 'push' and triggers[0]['delivered_at'] == 100.4
    assert triggers[0]['row'] == first
    assert 'row' not in json.loads((tmp_path/'episodes.jsonl').read_text().splitlines()[0])


def test_tripwire_rows_open_and_extend_the_same_container_episode(tmp_path):
    bridge = Bridge(CFG, tmp_path)
    trip = row(100.0, preview=False, tripwire_alert=True, tripwire_status='judged', tripwire_novel_ids=[308])
    ep = bridge.ingest(trip, 100.3)
    assert ep is not None and ep['first_kind'] == 'tripwire_alert'
    assert bridge.ingest(row(100.5), 100.8) is ep and ep['rows'] == 2            # ML preview joins the episode
    assert bridge.ingest(row(101.0, preview=False, tripwire_status='reference_pending', tripwire_alert=True), 101.3) is None
    _, (alert,) = bridge.pushes.get_nowait()
    assert alert['annotations']['trigger'] == 'tripwire_alert' and alert['labels']['episode'] == case_id(trip)
    assert bridge.counters['rows_tripwire_alert'] == 1 and bridge.counters['rows_candidate_alert_preview'] == 1


def test_follower_passes_preview_and_tripwire_rows(tmp_path):
    from sentinel_pulse.ops.alert_bridge import NEEDLES
    seg = tmp_path/'segments'/'s00001'; seg.mkdir(parents=True)
    log = seg/'decisions.jsonl'; log.write_text('')
    child = subprocess.Popen([sys.executable, '-u', '-c', FOLLOWER, str(tmp_path), *NEEDLES], stdout=subprocess.PIPE)
    try:
        time.sleep(0.5)
        with open(log, 'a') as handle:
            handle.write('{"a":1,"candidate_alert_preview":false}\n{"a":2,"candidate_alert_preview":false,"tripwire_alert":true}\n'
                         '{"a":3,"candidate_alert_preview":true,"tripwire_alert":false}\n')
        lines = [json.loads(child.stdout.readline()) for _ in range(2)]
    finally:
        child.kill()
    assert [l['a'] for l in lines] == [2, 3]
