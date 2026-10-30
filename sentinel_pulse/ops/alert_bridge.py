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

RCA integration (``rca_cases_dir`` in the config, 30/10; ``sentinel_pulse/ops/rca_view.py``):

- when the RCA case of an episode appears (about 2.7 s after the alert), the same ``SentinelPulseAnomaly`` alert is
  pushed again with RCA annotations (top suspect, reasons, binary, network destinations, case link); later refreshes
  keep them. Labels are unchanged, so it stays one alert and the latency measurement is unaffected;
- a second alert ``SentinelPulseTriage`` carries the routing labels ``rca_class`` and ``notify``: tripwire episodes at
  once (``notify=immediate``), ML episodes when their case is ready (security operation -> immediate; probe-only, new
  binary, other -> dashboard). Alertmanager routes on ``notify`` (``testbed/k8s/monitoring/``); the measured alert
  path and every evaluation metric are unchanged;
- the HTTP server also serves the cases: ``/cases`` (HTML list), ``/cases.json`` (Grafana Infinity table),
  ``/cases/<id>`` (English page with suspects and the tree), ``/cases/<id>.json|.md|.svg``; ``/alertmanager/notify``
  is the webhook of the ``immediate`` route (logged to ``notifications.jsonl``; no external receiver).
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
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
from . import rca_view

NEEDLE = '"candidate_alert_preview":true'
NEEDLES = (NEEDLE, '"tripwire_alert":true')     # ML preview and tripwire A1 rows (final system, 25/10)
TRIGGERS = ('candidate_alert_preview', 'tripwire_alert')
ALERTNAMES = ('SentinelPulseAnomaly', 'SentinelPulseAnomalyPull')
BUCKETS = (0.25, 0.5, 1, 1.5, 2, 3, 5, 10, 20, 30, 45, 60, 90, 120)
PUSH_ATTEMPTS, PUSH_RETRY_SECONDS = 3, 0.5

# Runs on the worker: follow the newest decision segment from its end, print only the lines holding the needle.
FOLLOWER = r'''
import glob, sys, time
root, needles = sys.argv[1], [n.encode() for n in sys.argv[2:]]
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
        hits = [line for line in lines if any(n in line for n in needles)]
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
        self.cases = None
        if cfg.get('rca_cases_dir'):
            listen = cfg.get('listen', ['0.0.0.0', 9478])
            base = cfg.get('case_base_url') or f"http://{listen[0]}:{listen[1]}"
            self.cases = rca_view.CaseIndex(cfg['rca_cases_dir'], base)
            self.cases.refresh()                    # cases written before this bridge started: indexed, never pushed
        self.case_scan_at = 0.0
        self.case_wait = float(cfg.get('case_wait_seconds', 120))
        self.triage_hold = float(cfg.get('triage_hold_seconds', 600))
        self.svg_cache = (out or Path('/tmp'))/'svg-cache'

    def log(self, name, record):
        if self.out is not None:
            with open(self.out / f'{name}.jsonl', 'a') as handle:
                handle.write(json.dumps(record, sort_keys=True) + '\n')

    def count(self, name, amount=1):
        self.counters[name] += amount

    def ingest(self, row, received_at):
        kind = trigger_kind(row, self.cfg['model_hash'], self.cfg['policy_hash'])
        if kind not in TRIGGERS:
            self.count('rows_ignored'); return None
        key = identity(row)
        with self.lock:
            self.count('positive_rows'); self.count(f'rows_{kind}')
            ep = self.active.get(key)
            if ep is None:
                ep = dict(episode=case_id(row), node=row['node_name'], pod_uid=row['pod_uid'],
                          container=row['container_name'], workload_key=row['workload_key'],
                          window_end=float(row['window_end']), preview_emitted_at=float(row['preview_emitted_at']),
                          joint_p=row.get('joint_p'), bridge_received_at=received_at, rows=0, first_push_at=None,
                          last_push=received_at, ended_at=None, row=row, triggered=False, first_kind=kind)
                self.active[key] = ep; self.episodes[ep['episode']] = ep
                self.count('episodes_started')
                self.lag.observe({}, received_at - ep['preview_emitted_at'])
                self.log('episodes', dict(event='start', **{k: v for k, v in ep.items() if k != 'row'}))
                self.pushes.put((ep['episode'], [self.alert(ep, received_at + 3 * self.refresh)]))
                if kind == 'tripwire_alert' and self.cases is not None:   # a rule hit: notify without waiting for RCA
                    self.pushes.put((None, [self.triage_alert(ep, received_at)]))
                    self.count('triage_tripwire_at_start')
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
                    ep['last_push'] = now           # a refresh also counts as the first push if the start push failed
                    self.pushes.put((ep['episode'], [self.alert(ep, ep['last_seen'] + 3 * self.refresh)]))
            if self.cases is not None and now >= self.case_scan_at:
                self.case_scan_at = now + 1.0
                self.attach_cases(now)
            for eid, ep in list(self.episodes.items()):
                if ep['ended_at'] is not None and now - ep['ended_at'] > 3600:
                    del self.episodes[eid]
                    self.delivered = {d for d in self.delivered if d[1] != eid}

    def attach_cases(self, now):
        """Caller holds the lock. New case files of known episodes: re-push the alert with RCA annotations and push
        the triage alert that Alertmanager routes on."""
        for summary in self.cases.refresh():
            ep = self.episodes.get(summary['case_id'])
            self.count(f"rca_cases_{summary['rca_class']}")
            if ep is None or ep.get('rca') is not None or now - ep['bridge_received_at'] > self.case_wait:
                continue
            ep['rca'] = summary
            ends = ep['ended_at'] if ep['ended_at'] is not None else ep['last_seen'] + 3 * self.refresh
            self.pushes.put((None, [self.alert(ep, ends), self.triage_alert(ep, now)]))
            self.count('rca_enriched_alerts')
            self.log('rca', dict(episode=ep['episode'], at=now, case_after_alert=now - ep['bridge_received_at'],
                                 rca_class=summary['rca_class'], notify=summary['notify'], top_binary=summary['top_binary']))

    def triage_alert(self, ep, now):
        rca = ep.get('rca')
        cls = 'tripwire' if ep.get('first_kind') == 'tripwire_alert' else rca['rca_class']
        notify = rca_view.NOTIFY[cls]
        labels = dict(alertname='SentinelPulseTriage', namespace=self.cfg.get('alert_namespace', 'sentinel-pulse'),
                      severity='critical' if notify == 'immediate' else 'info', rca_class=cls, notify=notify,
                      **self.labels(ep))
        notes = dict(summary=f"Pulse {cls} alert on {labels['workload']} ({ep['node']})", rca_case=ep['episode'],
                     stage='routing alert of the operational path; detection metrics are computed on SentinelPulseAnomaly')
        notes.update(rca_view.alert_annotations(rca) if rca else dict(rca_status='case pending'))
        return dict(labels=labels, startsAt=iso(ep['window_end']), endsAt=iso(now + self.triage_hold),
                    annotations=notes)

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
                                     trigger=ep.get('first_kind', 'candidate_alert_preview'),
                                     stage='shadow preview of the frozen model and policy; not an automatic response',
                                     **(rca_view.alert_annotations(ep['rca']) if ep.get('rca') else {})))

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

    def notification(self, payload, received_at):
        """Webhook of the ``immediate`` route: the stand-in for a person being notified (no external receiver)."""
        with self.lock:
            for alert in payload.get('alerts', []):
                labels = alert.get('labels', {})
                if alert.get('status') != 'firing' or labels.get('alertname') != 'SentinelPulseTriage':
                    continue
                self.count(f"notifications_{labels.get('rca_class', 'unknown')}")
                self.log('notifications', dict(received_at=received_at, episode=labels.get('episode'),
                                               rca_class=labels.get('rca_class'), workload=labels.get('workload'),
                                               rca_top_suspect=alert.get('annotations', {}).get('rca_top_suspect')))

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
    """POST each queued alert; a failed push of an episode alert is tried again (``PUSH_ATTEMPTS`` in all,
    ``PUSH_RETRY_SECONDS`` apart). An episode shorter than the refresh period has no other push before it resolves:
    on pulse-peer-discount-confirm 13 pushes timed out (3 s) and 6 of 5,181 episodes never arrived by push (25/10)."""
    retries = deque()                                   # (due, episode, alerts, attempt), due in order
    while not stop.is_set():
        if retries and retries[0][0] <= time.time():
            _, episode, alerts, attempt = retries.popleft()
        else:
            wait = 0.5 if not retries else min(0.5, max(0.01, retries[0][0] - time.time()))
            try:
                episode, alerts = bridge.pushes.get(timeout=wait)
            except queue.Empty:
                continue
            attempt = 1
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
            retry = bool(episode) and attempt < PUSH_ATTEMPTS
            with bridge.lock:
                bridge.count('pushes_failed')
                if retry:
                    bridge.count('pushes_retried')
            bridge.log('issues', dict(at=time.time(), issue='push_failed', error=str(error)[:200], episode=episode,
                                      attempt=attempt, retry=retry))
            if retry:
                retries.append((time.time() + PUSH_RETRY_SECONDS, episode, alerts, attempt + 1))


def serve(bridge: Bridge, host, port):
    class Handler(BaseHTTPRequestHandler):
        def reply(self, code, body, kind='text/plain; version=0.0.4'):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code); self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)

        def do_GET(self):
            if self.path == '/metrics':
                self.reply(200, bridge.metrics())
            elif self.path == '/healthz':
                self.reply(200, 'ok\n')
            elif self.path.startswith('/cases') and bridge.cases is not None:
                self.case_view(self.path)
            else:
                self.reply(404, 'not found\n')

        def case_view(self, path):
            route, _, query = path.partition('?')
            if route in ('/cases', '/cases/'):
                self.reply(200, rca_view.render_index(bridge.cases.recent(limit=200)), 'text/html; charset=utf-8'); return
            if route == '/cases.json':
                hours = 6.0
                for part in query.split('&'):
                    if part.startswith('hours='):
                        try:
                            hours = max(0.1, min(168.0, float(part[6:])))
                        except ValueError:
                            pass
                rows = bridge.cases.recent(since=time.time() - hours * 3600)
                self.reply(200, json.dumps(rows), 'application/json'); return
            name = route[len('/cases/'):]
            cid, dot, suffix = name.partition('.')
            if suffix not in ('', 'json', 'md', 'svg'):
                self.reply(404, 'not found\n'); return
            source = bridge.cases.path(cid, '.json')
            if source is None:
                self.reply(404, 'no such case\n'); return
            if suffix == 'json':
                self.reply(200, source.read_bytes(), 'application/json'); return
            if suffix == 'md':
                md = bridge.cases.path(cid, '.md')
                self.reply(200, md.read_bytes() if md else b'', 'text/markdown; charset=utf-8'); return
            try:
                svg = rca_view.case_svg(source, bridge.svg_cache)
            except (OSError, ValueError, subprocess.SubprocessError):
                svg = None
            if suffix == 'svg':
                if svg is None:
                    self.reply(503, 'Graphviz dot is not installed on the bridge host\n')
                else:
                    self.reply(200, svg, 'image/svg+xml')
                return
            case = json.loads(source.read_text())
            summary = bridge.cases.get(cid) or rca_view.summarize(case, bridge.cases.base_url)
            self.reply(200, rca_view.render_html(summary, case, svg), 'text/html; charset=utf-8')

        def do_POST(self):
            received_at = time.time()
            if self.path not in ('/alertmanager', '/alertmanager/notify'):
                self.reply(404, 'not found\n'); return
            try:
                payload = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            except (ValueError, TypeError):
                self.reply(400, 'bad json\n'); return
            if self.path == '/alertmanager/notify':
                bridge.notification(payload, received_at)
            else:
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
                  worker.get('stream_root', worker['output']), *NEEDLES]
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
