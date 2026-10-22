"""Pulse previews as operational alerts in the cluster's Prometheus / Alertmanager / Grafana (test of the alert path).

Pulse itself stays shadow: this process only reads decisions. On .234 it follows each worker's decision log over SSH
(only rows carrying ``"candidate_alert_preview":true`` leave the worker) and keeps one episode per container: a gap of
more than ``resolve_after_seconds`` without a positive row ends it; the episode id is the RCA case id of its first row,
so an alert names the RCA case built for the same trigger. Every episode is delivered three ways, so the latency of
the paths is compared on the same alerts:

- ``push``: POST /api/v2/alerts to Alertmanager at episode start, refreshed while the episode lasts;
- ``pull-fast`` / ``pull-default``: gauge ``sentinel_pulse_preview_active`` on /metrics, scraped every 5 s / 30 s and
  turned into alerts by a PrometheusRule (``testbed/k8s/monitoring/``), i.e. the standard Prometheus path.

The same HTTP server is Alertmanager's webhook receiver. The first delivery of each (path, episode) is logged with its
latency from the decision's ``preview_emitted_at`` (Pulse wrote the preview, worker clock) and ``window_end``. The
first delivery of an episode on any path also appends the episode's first decision row to ``triggers.jsonl``: an RCA
service with ``alert_trigger_file`` builds its case from that operational alert instead of from the preview stream.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import select
import shlex
import signal
import subprocess
import threading
import time
import urllib.request

from ..rca.tree import case_id, identity, trigger_kind

NEEDLE = '"candidate_alert_preview":true'
ALERTNAMES = ('SentinelPulseAnomaly', 'SentinelPulseAnomalyPull')
BUCKETS = (0.25, 0.5, 1, 1.5, 2, 3, 5, 10, 20, 30, 45, 60, 90, 120)

# Runs on the worker: follow the newest decision segment from its end, print only the lines holding the needle.
FOLLOWER = r'''
import glob, sys, time
root, needle = sys.argv[1], sys.argv[2].encode()
def newest():
    paths = sorted(glob.glob(root + "/segments/s*/decisions.jsonl"))
    return paths[-1] if paths else None
path = None
while path is None:
    path = newest(); time.sleep(0.5) if path is None else None
stream = open(path, "rb"); stream.seek(0, 2); buf = b""
while True:
    chunk = stream.read(1 << 20)
    if chunk:
        *lines, buf = (buf + chunk).split(b"\n")
        hits = [line for line in lines if needle in line]
        if hits:
            sys.stdout.buffer.write(b"\n".join(hits) + b"\n"); sys.stdout.flush()
        continue
    latest = newest()
    if latest != path:
        if stream.read(1):
            stream.seek(-1, 1); continue
        path, stream, buf = latest, open(latest, "rb"), b""
        continue
    time.sleep(0.05)
'''


def iso(t):
    return datetime.fromtimestamp(float(t), timezone.utc).isoformat().replace('+00:00', 'Z')


def escape(value):
    return str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def series(name, labels, value):
    inner = ','.join(f'{k}="{escape(v)}"' for k, v in labels.items())
    return f'{name}{{{inner}}} {value}' if inner else f'{name} {value}'


class Histogram:
    def __init__(self, name, help_text):
        self.name, self.help, self.data = name, help_text, {}

    def observe(self, labels: dict, value):
        key = tuple(sorted(labels.items()))
        counts = self.data.setdefault(key, [0] * len(BUCKETS) + [0.0, 0])
        for i, bound in enumerate(BUCKETS):
            if value <= bound:
                counts[i] += 1
        counts[-2] += value; counts[-1] += 1

    def render(self):
        out = [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} histogram']
        for key, counts in sorted(self.data.items()):
            labels = dict(key)
            for i, bound in enumerate(BUCKETS):
                out.append(series(self.name + '_bucket', {**labels, 'le': bound}, counts[i]))
            out.append(series(self.name + '_bucket', {**labels, 'le': '+Inf'}, counts[-1]))
            out.append(series(self.name + '_sum', labels, round(counts[-2], 6)))
            out.append(series(self.name + '_count', labels, counts[-1]))
        return out


class Bridge:
    """Episode bookkeeping, alert payloads, metrics and the webhook side; I/O-free apart from the JSONL logs."""

    def __init__(self, cfg, out: Path | None = None):
        self.cfg, self.out = cfg, out
        self.resolve_after = float(cfg.get('resolve_after_seconds', 3.0))
        self.refresh = float(cfg.get('refresh_seconds', 5.0))
        self.active, self.episodes, self.delivered = {}, {}, set()
        self.counters = defaultdict(int)
        self.stream_up = {}
        self.lock = threading.Lock()
        self.pushes = queue.Queue()
        self.lag = Histogram('sentinel_pulse_preview_to_bridge_seconds',
                             'Bridge receipt of an episode first row minus preview_emitted_at (worker clock)')
        self.delivery = Histogram('sentinel_pulse_alert_delivery_seconds',
                                  'Alertmanager webhook receipt of an episode alert minus preview_emitted_at, by path')

    def log(self, name, record):
        if self.out is not None:
            with open(self.out / f'{name}.jsonl', 'a') as handle:
                handle.write(json.dumps(record, sort_keys=True) + '\n')

    def count(self, name, amount=1):
        self.counters[name] += amount

    def ingest(self, row, received_at):
        if trigger_kind(row, self.cfg['model_hash'], self.cfg['policy_hash']) != 'candidate_alert_preview':
            self.count('rows_ignored'); return None
        key = identity(row)
        with self.lock:
            self.count('positive_rows')
            ep = self.active.get(key)
            if ep is None:
                ep = dict(episode=case_id(row), node=row['node_name'], pod_uid=row['pod_uid'],
                          container=row['container_name'], workload_key=row['workload_key'],
                          window_end=float(row['window_end']), preview_emitted_at=float(row['preview_emitted_at']),
                          joint_p=row.get('joint_p'), bridge_received_at=received_at, rows=0, first_push_at=None,
                          last_push=received_at, ended_at=None, row=row, triggered=False)
                self.active[key] = ep; self.episodes[ep['episode']] = ep
                self.count('episodes_started')
                self.lag.observe({}, received_at - ep['preview_emitted_at'])
                self.log('episodes', dict(event='start', **{k: v for k, v in ep.items() if k != 'row'}))
                self.pushes.put((ep['episode'], [self.alert(ep, received_at + 3 * self.refresh)]))
            ep['rows'] += 1; ep['last_seen'] = received_at; ep['last_window_end'] = float(row['window_end'])
            return ep

    def tick(self, now):
        with self.lock:
            for key, ep in list(self.active.items()):
                if now - ep['last_seen'] > self.resolve_after:
                    ep['ended_at'] = now
                    del self.active[key]
                    self.pushes.put((None, [self.alert(ep, now)]))
                    self.log('episodes', dict(event='end', episode=ep['episode'], ended_at=now, rows=ep['rows'],
                                              last_window_end=ep['last_window_end']))
                elif now - ep['last_push'] >= self.refresh:
                    ep['last_push'] = now
                    self.pushes.put((None, [self.alert(ep, ep['last_seen'] + 3 * self.refresh)]))
            for eid, ep in list(self.episodes.items()):
                if ep['ended_at'] is not None and now - ep['ended_at'] > 3600:
                    del self.episodes[eid]
                    self.delivered = {d for d in self.delivered if d[1] != eid}

    def labels(self, ep):
        target, _, workload = ep['workload_key'].partition('/')
        return dict(node=ep['node'], target_namespace=target, workload=workload, pod_uid=ep['pod_uid'],
                    container=ep['container'], episode=ep['episode'])

    def alert(self, ep, ends_at):
        labels = dict(alertname='SentinelPulseAnomaly', namespace=self.cfg.get('alert_namespace', 'sentinel-pulse'),
                      severity='warning', path='push', **self.labels(ep))
        return dict(labels=labels, startsAt=iso(ep['window_end']), endsAt=iso(ends_at),
                    annotations=dict(summary=f"Pulse preview on {labels['workload']} ({ep['node']})",
                                     window_end=str(ep['window_end']), preview_emitted_at=str(ep['preview_emitted_at']),
                                     joint_p=str(ep['joint_p']), rca_case=ep['episode'],
                                     stage='shadow preview of the frozen model and policy; not an automatic response'))

    def pushed(self, episode, at):
        with self.lock:
            ep = self.episodes.get(episode)
            if ep is not None and ep['first_push_at'] is None:
                ep['first_push_at'] = at
                self.log('pushes', dict(episode=episode, first_push_at=at))

    def webhook(self, payload, received_at):
        records = []
        with self.lock:
            self.count('webhook_requests')
            for alert in payload.get('alerts', []):
                labels = alert.get('labels', {})
                if alert.get('status') != 'firing' or labels.get('alertname') not in ALERTNAMES:
                    continue
                key = (labels.get('path', 'unknown'), labels.get('episode', ''))
                if key in self.delivered:
                    continue
                self.delivered.add(key)
                ep = self.episodes.get(key[1])
                record = dict(path=key[0], episode=key[1], received_at=received_at, workload=labels.get('workload'),
                              node=labels.get('node'), known_episode=ep is not None)
                if ep is not None:
                    record.update(preview_emitted_at=ep['preview_emitted_at'], window_end=ep['window_end'],
                                  bridge_received_at=ep['bridge_received_at'], first_push_at=ep['first_push_at'],
                                  latency_from_preview=received_at - ep['preview_emitted_at'],
                                  latency_from_window_end=received_at - ep['window_end'])
                    self.delivery.observe({'path': key[0]}, record['latency_from_preview'])
                    if not ep['triggered']:             # the operational alert reached a recipient: RCA trigger
                        ep['triggered'] = True
                        self.log('triggers', dict(delivered_at=received_at, path=key[0], episode=key[1], row=ep['row']))
                        self.count('rca_triggers_written')
                self.count(f'deliveries_{key[0]}')
                self.log('deliveries', record)
                records.append(record)
        return records

    def metrics(self):
        with self.lock:
            out = ['# HELP sentinel_pulse_preview_active 1 while a Pulse preview episode of the container lasts',
                   '# TYPE sentinel_pulse_preview_active gauge']
            out += [series('sentinel_pulse_preview_active', self.labels(ep), 1) for ep in self.active.values()]
            out += ['# HELP sentinel_pulse_bridge_events_total Bridge counters', '# TYPE sentinel_pulse_bridge_events_total counter']
            out += [series('sentinel_pulse_bridge_events_total', {'event': k}, v) for k, v in sorted(self.counters.items())]
            out += ['# HELP sentinel_pulse_decision_stream_up 1 while the decision stream of the worker is connected',
                    '# TYPE sentinel_pulse_decision_stream_up gauge']
            out += [series('sentinel_pulse_decision_stream_up', {'node': n}, int(v)) for n, v in sorted(self.stream_up.items())]
            out += self.lag.render() + self.delivery.render()
            return '\n'.join(out) + '\n'

    def status(self):
        with self.lock:
            return dict(active=len(self.active), episodes_known=len(self.episodes), counters=dict(self.counters),
                        stream_up=dict(self.stream_up), at=time.time())


def push_worker(bridge: Bridge, url, stop: threading.Event):
    while not stop.is_set():
        try:
            episode, alerts = bridge.pushes.get(timeout=0.5)
        except queue.Empty:
            continue
        request = urllib.request.Request(url.rstrip('/') + '/api/v2/alerts', data=json.dumps(alerts).encode(),
                                         headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                response.read()
            if episode:
                bridge.pushed(episode, time.time())
            with bridge.lock:
                bridge.count('pushes_ok')
        except OSError as error:
            with bridge.lock:
                bridge.count('pushes_failed')
            bridge.log('issues', dict(at=time.time(), issue='push_failed', error=str(error)[:200]))


def serve(bridge: Bridge, host, port):
    class Handler(BaseHTTPRequestHandler):
        def reply(self, code, body, kind='text/plain; version=0.0.4'):
            data = body.encode()
            self.send_response(code); self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)

        def do_GET(self):
            if self.path == '/metrics':
                self.reply(200, bridge.metrics())
            elif self.path == '/healthz':
                self.reply(200, 'ok\n')
            else:
                self.reply(404, 'not found\n')

        def do_POST(self):
            received_at = time.time()
            if self.path != '/alertmanager':
                self.reply(404, 'not found\n'); return
            try:
                payload = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            except (ValueError, TypeError):
                self.reply(400, 'bad json\n'); return
            bridge.webhook(payload, received_at)
            self.reply(200, 'ok\n')

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Streams:
    """One SSH follower per worker (same transport as the RCA service's decision stream)."""

    def __init__(self, bridge: Bridge, cfg):
        self.bridge, self.cfg, self.children = bridge, cfg, {}

    def start(self, worker):
        spec = self.cfg['ssh']
        remote = ['timeout', str(int(spec.get('rotate_seconds', 3600))), 'python3', '-u', '-c', FOLLOWER,
                  worker['output'], NEEDLE]
        args = ['sshpass', '-f', spec['credential'], 'ssh', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + spec.get('known_hosts', '/home/dat/.ssh/known_hosts'),
                '-o', 'ServerAliveInterval=10', f"{spec.get('user', 'dat')}@{worker['host']}",
                ' '.join(shlex.quote(a) for a in remote)]
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        self.children[worker['node_name']] = dict(child=child, buffer=b'')
        self.bridge.stream_up[worker['node_name']] = True
        self.bridge.log('issues', dict(at=time.time(), issue='decision_stream_started', node=worker['node_name'],
                                       continuity='no backfill; rows written while disconnected are not seen'))

    def drain(self):
        for worker in self.cfg['workers']:
            node = worker['node_name']; stream = self.children.get(node)
            if stream and stream['child'].poll() is not None:
                self.bridge.stream_up[node] = False
                self.bridge.log('issues', dict(at=time.time(), issue='decision_stream_disconnected', node=node))
                del self.children[node]; stream = None
            if stream is None:
                self.start(worker)
        lookup = {s['child'].stdout: (n, s) for n, s in self.children.items()}
        for pipe in (select.select(list(lookup), [], [], 0.1)[0] if lookup else []):
            node, stream = lookup[pipe]
            chunk = os.read(pipe.fileno(), 1 << 20)
            if not chunk:
                continue
            *lines, stream['buffer'] = (stream['buffer'] + chunk).split(b'\n')
            now = time.time()
            for line in lines:
                try:
                    row = json.loads(line)
                    if row.get('node_name') != node:
                        raise ValueError('node identity differs from the configured worker')
                    self.bridge.ingest(row, now)
                except (ValueError, TypeError, KeyError):
                    with self.bridge.lock:
                        self.bridge.count('invalid_rows')

    def stop(self):
        for stream in self.children.values():
            try:
                os.killpg(stream['child'].pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


def atomic(path: Path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=1, sort_keys=True)); os.replace(tmp, path)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--config', type=Path, required=True)
    a = p.parse_args()
    cfg = json.loads(a.config.read_text())
    out = Path(cfg['output']); out.mkdir(parents=True, exist_ok=True)
    bridge = Bridge(cfg, out)
    atomic(out / 'START.json', dict(started_at=time.time(), config=cfg, code_commit=os.environ.get('CODE_COMMIT')))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set()); signal.signal(signal.SIGINT, lambda *_: stop.set())
    server = serve(bridge, *cfg.get('listen', ['0.0.0.0', 9478]))
    threading.Thread(target=push_worker, args=(bridge, cfg['alertmanager_url'], stop), daemon=True).start()
    streams = Streams(bridge, cfg)
    status_at = 0.0
    while not stop.is_set():
        streams.drain()
        now = time.time()
        bridge.tick(now)
        if now >= status_at:
            atomic(out / 'STATUS.json', bridge.status()); status_at = now + 10
    streams.stop(); server.shutdown()
    atomic(out / 'STATUS.json', dict(bridge.status(), stopped=True))


if __name__ == '__main__':
    main()
