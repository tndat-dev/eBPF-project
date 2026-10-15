"""Independent read-only Tetragon/Pulse subscriber with durable RCA checkpoints.

The model, captures, frozen studies and Kubernetes workloads are never mutated.
Only this service's local SQLite ring, cases and health journal are written.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import time

from .rca_connect import kubernetes_target_index, normalize_connect_event
from .rca_tree import build_tree, case_id, event_time, identity, render_markdown, trigger_kind


def atomic(path, value):
    temporary = path.with_suffix(path.suffix+'.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


def database(path):
    db = sqlite3.connect(path)
    db.execute('pragma journal_mode=WAL')
    db.execute('pragma synchronous=FULL')
    db.executescript('''
      create table if not exists events(hash text primary key, at real, node text,
        pod text, container text, document text);
      create index if not exists event_identity_time on events(node,pod,container,at);
      create table if not exists cursors(path text primary key, offset integer, inode integer);
      create table if not exists cases(id text primary key, created real, emitted integer,
        identity text, trigger text);
      create index if not exists case_identity on cases(identity,created);
      create table if not exists metadata(key text primary key, value text);
    ''')
    return db


def read_complete(path, offset, limit=1024*1024):
    with path.open('rb') as stream:
        stream.seek(offset)
        data = stream.read(limit)
    end = data.rfind(b'\n')+1
    return data[:end].splitlines(), offset+end


def initial_offset(path):
    with path.open('rb') as stream:
        # Open before inspecting length: NFS path.stat() can lag the writer.
        size = stream.seek(0, os.SEEK_END)
        if not size:
            return 0
        stream.seek(max(0, size-65536)); data = stream.read()
    last = data.rfind(b'\n')
    if last < 0:
        raise ValueError('no complete tail boundary in decision log')
    return size-len(data)+last+1


class Service:
    def __init__(self, config):
        self.cfg = json.loads(config.read_text()); self.root = Path(self.cfg['output'])
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = (self.root/'service.lock').open('a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.db = database(self.root/'context.sqlite3')
        binding = dict(config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
            source_sha256={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                           for name in ('rca_service.py', 'rca_tree.py', 'rca_connect.py')})
        old = self.db.execute("select value from metadata where key='binding'").fetchone()
        if old and json.loads(old[0]) != binding:
            raise ValueError('RCA config/source changed; use a separate registered output')
        self.db.execute("insert or ignore into metadata values('binding',?)", (json.dumps(binding),))
        self.db.commit()
        if not (self.root/'START.json').exists():
            atomic(self.root/'START.json', dict(binding=binding, registered_at=time.time(),
                model_hash=self.cfg['model_hash'], policy_hash=self.cfg['policy_hash'],
                trigger='candidate_alert_preview', automatic_response=False,
                previous_output=self.cfg.get('previous_output'),
                registration_reason=self.cfg.get('registration_reason')))
        self.streams = {}; self.index = {}; self.inventory = {}; self.target_inventory = {}
        self.inventory_at = None; self.stop = False; self.counts = {}
        status = self.root/'STATUS.json'
        if status.exists(): self.counts = json.loads(status.read_text()).get('counts', {})
        self.issue('subscriber_started_or_resumed', pre_restart_stream_continuity='unknown')

    def count(self, name, amount=1):
        self.counts[name] = self.counts.get(name, 0)+amount

    def issue(self, reason, **extra):
        self.count('issues')
        # Bound our own journals; no Pulse/study/evidence file is ever rotated.
        path = self.root/'issues.jsonl'
        if path.exists() and path.stat().st_size > 4*1024**2:
            os.replace(path, self.root/'issues.previous.jsonl')
        with path.open('a') as stream:
            stream.write(json.dumps(dict(at=time.time(), reason=reason, **extra))+'\n')

    def kubectl(self, *args):
        result = subprocess.run(['kubectl', '--request-timeout=5s', *args],
            env=dict(os.environ, KUBECONFIG=self.cfg['kubeconfig']),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8, check=True)
        return json.loads(result.stdout)

    def collect_inventory(self):
        pods = self.kubectl('get', 'pods', '-A', '-o', 'json')
        services = self.kubectl('get', 'services', '-A', '-o', 'json')
        endpoints = self.kubectl('get', 'endpointslices', '-A', '-o', 'json')
        sensors = {p['spec']['nodeName']: p['metadata']['name'] for p in pods['items']
            if p['metadata']['namespace']=='kube-system'
            and p['metadata'].get('labels', {}).get('app.kubernetes.io/name')=='tetragon'
            and p.get('status', {}).get('phase')=='Running'}
        targets = {p['metadata']['uid']: dict(name=p['metadata']['name'],
            connect_policy_selected=p['metadata'].get('labels', {}).get('aims.hust.vn/runtime-hardened')=='true')
            for p in pods['items'] if p['metadata']['namespace']=='production'}
        return sensors, targets, kubernetes_target_index(pods, services, endpoints), time.time()

    def start_stream(self, node, sensor):
        now = time.time()
        args = ['kubectl', 'exec', '-n', 'kube-system', sensor, '-c', 'tetragon', '--',
            'tetra', 'getevents', '-o', 'json', '--policy-names', self.cfg['connect_policy'],
            '--event-types', 'PROCESS_KPROBE']
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, KUBECONFIG=self.cfg['kubeconfig']), start_new_session=True)
        self.streams[node] = dict(child=child, buffer=b'', started_at=now, last_event_at=None,
            normalized_events=0, sensor=sensor)
        self.issue('tetragon_subscription_started', node=node, sensor=sensor,
                   readiness='unconfirmed_until_event_received')

    def stop_stream(self, stream):
        child = stream['child']
        if child.poll() is None:
            child.terminate()
            try: child.wait(timeout=2)
            except subprocess.TimeoutExpired: child.kill(); child.wait()
        child.stdout.close()

    def drain_streams(self):
        lookup = {s['child'].stdout: (n, s) for n, s in self.streams.items()}
        readable = select.select(list(lookup), [], [], .1)[0] if lookup else []
        for pipe in readable:
            node, stream = lookup[pipe]
            chunk = os.read(pipe.fileno(), 256*1024)
            if not chunk: continue
            stream['buffer'] += chunk
            if len(stream['buffer']) > 2*1024**2:
                self.issue('oversized_tetragon_record', node=node)
                self.stop_stream(stream); del self.streams[node]; continue
            while b'\n' in stream['buffer']:
                line, stream['buffer'] = stream['buffer'].split(b'\n', 1)
                try:
                    raw = json.loads(line)
                    if raw.get('node_name') != node:
                        raise ValueError('sensor node identity mismatch')
                    edge = normalize_connect_event(raw, self.index, policy_name=self.cfg['connect_policy'])
                    if edge is None: continue
                    if edge['source']['namespace'] != 'production': continue
                    if not edge['source']['pod_uid'] or not edge['source']['container_name']:
                        self.count('connect_missing_identity'); continue
                    at = event_time(edge['observed_at'])
                    self.db.execute('insert or ignore into events values(?,?,?,?,?,?)',
                        (edge['raw_event_sha256'], at, node, edge['source']['pod_uid'],
                         edge['source']['container_name'], json.dumps(edge, separators=(',', ':'))))
                    stream['last_event_at'] = time.time(); stream['normalized_events'] += 1
                    self.count('connect_events')
                except (ValueError, TypeError, KeyError):
                    self.count('invalid_or_unjoinable_events')

    def observe_trigger(self, row, now):
        kind = trigger_kind(row, self.cfg['model_hash'], self.cfg['policy_hash'])
        if kind is None: return
        self.count('positive_decisions_observed')
        key = json.dumps(identity(row))
        recent = self.db.execute('select created from cases where identity=? order by created desc limit 1', (key,)).fetchone()
        if recent and now-recent[0] < self.cfg['case_cooldown_seconds']:
            self.count('positive_decisions_grouped_by_cooldown'); return
        safe = {k: row.get(k) for k in ('schema', 'status', 'run_id', 'capture_segment', 'node_name',
            'workload_key', 'pod_uid', 'container_name', 'cgroup_id', 'window_start', 'window_end',
            'preview_emitted_at', 'candidate_manifest_sha256', 'policy_sha256', 'candidate_alert_preview',
            'policy_evaluated', 'serving_compatible', 'container_id',
            'joint_p', 'tree_p', 'support_p', 'candidate_policy_alpha', 'alert', 'policy_applied')}
        self.db.execute('insert or ignore into cases values(?,?,?,?,?)',
            (case_id(row), now, 0, key, json.dumps(safe)))

    def tail_decisions(self):
        for worker in self.cfg['workers']:
            root = Path(worker['output'])
            # New service starts at current tail, explicitly no historical backfill.
            known = {p: (off, ino) for p, off, ino in
                self.db.execute('select path,offset,inode from cursors where path like ?', (str(root)+'/%',))}
            if not known:
                state = json.loads((root/'STATUS.json').read_text())
                path = root/'segments'/state['current_segment']/'decisions.jsonl'
                offset = initial_offset(path)
                self.db.execute('insert into cursors values(?,?,?)', (str(path), offset, path.stat().st_ino))
                self.issue('initial_tail_no_historical_backfill', node=worker['node_name'], path=str(path), skipped_bytes=offset)
                continue
            first = min(known)
            paths = [p for p in sorted((root/'segments').glob('s*/decisions.jsonl')) if str(p)>=first]
            remaining = 2*1024**2
            for path in paths:
                if remaining <= 0: break
                # Revalidate NFS on open before the unchanged-size shortcut.
                with path.open('rb') as probe:
                    st = os.fstat(probe.fileno())
                off, ino = known.get(str(path), (0, st.st_ino))
                if st.st_ino != ino or st.st_size < off:
                    self.issue('decision_source_replaced_or_truncated', path=str(path))
                    # Preserve current receipt; use a new registration to re-admit a replaced source.
                    continue
                if st.st_size == off:
                    continue
                lines, end = read_complete(path, off, min(remaining, 1024**2))
                for line in lines:
                    try:
                        row = json.loads(line)
                        if row.get('node_name') != worker['node_name']:
                            raise ValueError('decision node identity differs from configured worker')
                        self.observe_trigger(row, time.time())
                        self.count('decision_rows_read')
                    except (ValueError, TypeError, KeyError): self.count('invalid_decisions')
                self.db.execute('insert or replace into cursors values(?,?,?)', (str(path), end, ino))
                remaining -= end-off

    def emit_cases(self):
        now = time.time()
        for cid, created, trigger_json in self.db.execute(
                'select id,created,trigger from cases where emitted=0 and created<=? limit 20',
                (now-self.cfg['after_seconds']-2,)).fetchall():
            row = json.loads(trigger_json); at = event_time(row['window_end'])
            source = self.db.execute('select document from events where node=? and pod=? and container=? and at between ? and ? order by at limit 10001',
                (*identity(row), at-self.cfg['before_seconds'], at+self.cfg['after_seconds'])).fetchall()
            stream = self.streams.get(row['node_name'], {})
            target = self.target_inventory.get(row['pod_uid'], {})
            coverage = dict(inventory_at=self.inventory_at,
                inventory_age_seconds=now-self.inventory_at if self.inventory_at else None,
                pod_name=target.get('name'), connect_policy_selected=target.get('connect_policy_selected'),
                connect_policy=self.cfg['connect_policy'],
                subscription_started_at=stream.get('started_at'), last_connect_received_at=stream.get('last_event_at'),
                subscription_started_before_pre_window=bool(stream.get('last_event_at') and
                    stream['started_at']<=at-self.cfg['before_seconds']),
                transport_loss='not_measured_no_exact_event_completeness_guarantee',
                subscriber_lag_seconds=max(0, created-at),
                query_event_cap=10001, query_event_cap_reached=len(source)==10001,
                ring_retention_seconds=self.cfg['ring_seconds'],
                initial_history_backfill=False)
            tree = build_tree(row, [json.loads(e[0]) for e in source],
                before_seconds=self.cfg['before_seconds'], after_seconds=self.cfg['after_seconds'], coverage=coverage)
            tree['created_at'] = now
            out = self.root/'cases'; out.mkdir(exist_ok=True)
            atomic(out/(cid+'.json'), tree)
            md = out/(cid+'.md'); temp = md.with_suffix('.md.tmp')
            temp.write_text(render_markdown(tree)); os.replace(temp, md)
            self.db.execute('update cases set emitted=1 where id=?', (cid,))
            self.count('cases_emitted'); self.count('cases_without_connect_context', not source)

    def maintenance(self):
        now = time.time()
        self.db.execute('delete from events where at<?', (now-self.cfg['ring_seconds'],))
        # Explicit, bounded retention only for this new service's own derived cases.
        expired = self.db.execute('select id from cases where emitted=1 order by created desc limit -1 offset ?',
                                 (self.cfg['max_cases'],)).fetchall()
        for (cid,) in expired:
            for suffix in ('.json', '.md'):
                (self.root/'cases'/(cid+suffix)).unlink(missing_ok=True)
            self.db.execute('delete from cases where id=?', (cid,))
            self.count('derived_cases_expired_by_retention')
        count = self.db.execute('select count(*) from events').fetchone()[0]
        if count > self.cfg['max_ring_events']:
            self.db.execute('delete from events where hash in (select hash from events order by at limit ?)',
                            (count-self.cfg['max_ring_events'],))
            self.issue('event_ring_count_cap', dropped_oldest=count-self.cfg['max_ring_events'])
        self.db.commit()
        self.db.execute('pragma wal_checkpoint(TRUNCATE)')
        atomic(self.root/'STATUS.json', dict(state='running', updated_at_unix=now, counts=self.counts,
            model_hash=self.cfg['model_hash'], policy_hash=self.cfg['policy_hash'],
            ring_events=self.db.execute('select count(*) from events').fetchone()[0],
            pending_cases=self.db.execute('select count(*) from cases where emitted=0').fetchone()[0],
            retained_cases=self.db.execute('select count(*) from cases where emitted=1').fetchone()[0],
            automatic_response=False, trigger='candidate_alert_preview', causal_root_confirmed=False,
            streams={n:{k:v for k,v in s.items() if k not in ('child', 'buffer')} for n,s in self.streams.items()}))

    def run(self):
        def stopped(*_): self.stop = True
        for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, stopped)
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = None; refresh = 0; checkpoint = 0; retry = {}; tail = 0
        try:
            while not self.stop:
                now = time.time()
                if future is None and now>=refresh:
                    future = pool.submit(self.collect_inventory); refresh = now+60
                if future is not None and future.done():
                    try:
                        self.inventory, self.target_inventory, self.index, self.inventory_at = future.result()
                    except Exception as exc: self.issue('inventory_unavailable', error_type=type(exc).__name__)
                    future = None
                for worker in self.cfg['workers']:
                    node = worker['node_name']; stream = self.streams.get(node)
                    sensor = self.inventory.get(node)
                    if stream and (stream['child'].poll() is not None or sensor and stream['sensor']!=sensor):
                        self.issue('tetragon_stream_disconnected', node=node)
                        self.stop_stream(stream); del self.streams[node]; retry[node] = now+5
                    if node not in self.streams and sensor and now>=retry.get(node, 0):
                        self.start_stream(node, sensor)
                self.drain_streams()
                if now>=tail:
                    try: self.tail_decisions(); self.emit_cases()
                    except OSError as exc: self.issue('decision_or_case_storage_unavailable', error_type=type(exc).__name__)
                    tail = now+1
                if now>=checkpoint:
                    self.maintenance(); checkpoint = now+5
                time.sleep(.05)
        finally:
            for stream in self.streams.values(): self.stop_stream(stream)
            self.db.commit(); self.db.close(); pool.shutdown(wait=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    Service(parser.parse_args().config).run()


if __name__ == '__main__': main()
