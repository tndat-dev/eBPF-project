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
import shlex
import signal
import sqlite3
import subprocess
import time

from .connect import kubernetes_target_index, normalize_connect_event
from .tree import build_tree, case_id, event_time, identity, render_markdown, trigger_kind
from .runtime_events import normalize_runtime_event
from .runtime_tree import build_runtime_tree, render_runtime_markdown
from .ranking import rank_suspects, workload_of

STREAM_ROTATE_SECONDS = 900  # upper bound on any orphaned in-container event client
EXEC_LOG_SECONDS = 900       # exec history kept for follow-up novelty (longer than the 180 s ring)

# Runs on a worker (system python3) and prints new decision lines of the newest segment as the
# matched worker writes them. Reading on the writer's own NFS client sees appended bytes at once;
# reading from .234 waited ~5 s for NFS write-back (19/10 measurement). No backfill: starts at
# the end of the current file; drains a segment fully before following its successor.
DECISION_FOLLOWER = r'''
import glob, sys, time
root = sys.argv[1]
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
        buf += chunk
        *lines, buf = buf.split(b"\n")
        if lines:
            sys.stdout.buffer.write(b"\n".join(lines) + b"\n"); sys.stdout.flush()
        continue
    latest = newest()
    if latest != path:
        rest = stream.read()
        if rest:
            buf += rest
            continue
        path, stream, buf = latest, open(latest, "rb"), b""
        continue
    time.sleep(0.05)
'''


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
      create table if not exists binaries(workload text, binary text, first_seen real,
        primary key(workload, binary));
      create table if not exists exec_log(node text, pod text, container text, binary text, at real);
      create index if not exists exec_log_identity on exec_log(node,pod,container,at);
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
                           for name in ('service.py', 'tree.py', 'connect.py',
                                        'runtime_events.py', 'runtime_tree.py')})
        old = self.db.execute("select value from metadata where key='binding'").fetchone()
        if old and json.loads(old[0]) != binding:
            raise ValueError('RCA config/source changed; use a separate registered output')
        self.db.execute("insert or ignore into metadata values('binding',?)", (json.dumps(binding),))
        self.db.commit()
        if not (self.root/'START.json').exists():
            atomic(self.root/'START.json', dict(binding=binding, registered_at=time.time(),
                model_hash=self.cfg['model_hash'], policy_hash=self.cfg['policy_hash'],
                trigger='candidate_alert_preview', automatic_response=False,
                runtime_events=self.cfg.get('runtime_events', False),
                telemetry_policy=self.cfg['connect_policy'],
                previous_output=self.cfg.get('previous_output'),
                registration_reason=self.cfg.get('registration_reason')))
        self.streams = {}; self.index = {}; self.inventory = {}; self.target_inventory = {}
        self.decision_streams = {}
        self.inventory_at = None; self.stop = False; self.counts = {}; self.started_at = time.time()
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
            connect_policy_selected=bool(self.cfg.get('runtime_events') or
                p['metadata'].get('labels', {}).get('aims.hust.vn/runtime-hardened')=='true'))
            for p in pods['items'] if p['metadata']['namespace']=='production'}
        return sensors, targets, kubernetes_target_index(pods, services, endpoints), time.time()

    def start_stream(self, node, sensor, channel='policy'):
        now = time.time()
        # Killing the local kubectl does not stop the process inside the sensor
        # container; without a remote bound, every reconnect leaked a full event
        # client (hundreds per node, several cores of Tetragon CPU). The remote
        # side now exits on its own and the stream is rotated.
        args = ['kubectl', 'exec', '-n', 'kube-system', sensor, '-c', 'tetragon', '--',
            'timeout', str(int(self.cfg.get('stream_rotate_seconds', STREAM_ROTATE_SECONDS))),
            'tetra', 'getevents', '-o', 'json']
        if self.cfg.get('runtime_events') and channel == 'lifecycle':
            args += ['--namespace', 'production', '--event-types', 'PROCESS_EXEC,PROCESS_EXIT']
        else:
            policies = self.cfg.get('runtime_policies', [self.cfg['connect_policy']])
            args += ['--policy-names', ','.join(policies), '--event-types',
                     'PROCESS_KPROBE,PROCESS_TRACEPOINT' if self.cfg.get('runtime_events') else 'PROCESS_KPROBE']
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, KUBECONFIG=self.cfg['kubeconfig']), start_new_session=True)
        key = node if channel == 'policy' else node+'/lifecycle'
        self.streams[key] = dict(child=child, buffer=b'', started_at=now, last_event_at=None,
            normalized_events=0, sensor=sensor, node_name=node, channel=channel)
        self.issue('tetragon_subscription_started', node=node, sensor=sensor, channel=channel,
                   readiness='unconfirmed_until_event_received')

    def ingest_event(self, raw, node):
        if raw.get('node_name') != node:
            raise ValueError('sensor node identity mismatch')
        if raw.get('rate_limit_info') is not None or raw.get('process_throttle') is not None:
            self.issue('tetragon_rate_limit_or_throttle', node=node)
            return None
        if self.cfg.get('runtime_events'):
            edge = normalize_runtime_event(raw, self.index,
                policy_names=self.cfg.get('runtime_policies', [self.cfg['connect_policy']]))
        else:
            edge = normalize_connect_event(raw, self.index, policy_name=self.cfg['connect_policy'])
        if edge is None or edge['source']['namespace'] != 'production':
            return None
        if not edge['source']['pod_uid'] or not edge['source']['container_name']:
            self.count('runtime_missing_identity')
            return None
        at = event_time(edge['observed_at'])
        self.db.execute('insert or ignore into events values(?,?,?,?,?,?)',
            (edge['raw_event_sha256'], at, node, edge['source']['pod_uid'],
             edge['source']['container_name'], json.dumps(edge, separators=(',', ':'))))
        if edge.get('operation') == 'exec' and edge['source'].get('binary'):
            # Never expires with the ring: first sighting per workload feeds suspect ranking.
            self.db.execute('insert or ignore into binaries values(?,?,?)', (workload_of(
                edge['source']['namespace'], edge['source'].get('pod_name'), edge['source']['container_name']),
                edge['source']['binary'], at))
            # Longer than the ring: follow-up cases compare against execs up to ~6 min old.
            self.db.execute('insert into exec_log values(?,?,?,?,?)', (node, edge['source']['pod_uid'],
                edge['source']['container_name'], edge['source']['binary'], at))
        if edge.get('operation', 'connect') == 'connect':
            self.count('connect_events')
        self.count('runtime_events')
        self.count('runtime_category_'+edge.get('category', 'network'))
        return edge

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
            key, stream = lookup[pipe]
            node = stream['node_name']
            chunk = os.read(pipe.fileno(), 256*1024)
            if not chunk: continue
            stream['buffer'] += chunk
            if len(stream['buffer']) > 2*1024**2:
                self.issue('oversized_tetragon_record', node=node)
                self.stop_stream(stream); del self.streams[key]; continue
            while b'\n' in stream['buffer']:
                line, stream['buffer'] = stream['buffer'].split(b'\n', 1)
                try:
                    raw = json.loads(line)
                    edge = self.ingest_event(raw, node)
                    if edge is None:
                        continue
                    stream['last_event_at'] = time.time(); stream['normalized_events'] += 1
                except (ValueError, TypeError, KeyError):
                    self.count('invalid_or_unjoinable_events')

    def observe_trigger(self, row, now):
        kind = trigger_kind(row, self.cfg['model_hash'], self.cfg['policy_hash'])
        if kind is None: return
        self.count('positive_decisions_observed')
        key = json.dumps(identity(row))
        recent = self.db.execute('select created, trigger from cases where identity=? order by created desc limit 1',
                                 (key,)).fetchone()
        follow_up_of = None
        if recent and now-recent[0] < self.cfg['case_cooldown_seconds']:
            if not self.follow_up_allowed(row, key, recent, now):
                self.count('positive_decisions_grouped_by_cooldown'); return
            follow_up_of = case_id(json.loads(recent[1]))
            self.count('follow_up_cases_on_new_exec')
        safe = {k: row.get(k) for k in ('schema', 'status', 'run_id', 'capture_segment', 'node_name',
            'workload_key', 'pod_uid', 'container_name', 'cgroup_id', 'window_start', 'window_end',
            'preview_emitted_at', 'candidate_manifest_sha256', 'policy_sha256', 'candidate_alert_preview',
            'policy_evaluated', 'serving_compatible', 'container_id',
            'joint_p', 'tree_p', 'support_p', 'candidate_policy_alpha', 'alert', 'policy_applied')}
        if follow_up_of:
            safe['follow_up_of'] = follow_up_of
        self.db.execute('insert or ignore into cases values(?,?,?,?,?)',
            (case_id(row), now, 0, key, json.dumps(safe)))

    def follow_up_allowed(self, row, key, recent, now):
        """Within the cooldown, a new process exec since the previous case opens a follow-up case.

        With a fixed per-container cooldown, a second process started shortly after
        a first (e.g. an attack after a benign launch) never got its own case
        (pulse-live-recalibrated: 218 of 315 attacks). Bounded: >= 10 s apart, <= 5 follow-ups per cooldown.
        """
        if not self.cfg.get('follow_up_on_new_exec'):
            return False
        if now - recent[0] < self.cfg.get('follow_up_min_seconds', 10):
            return False
        followups = self.db.execute("select count(*) from cases where identity=? and created>? and instr(trigger, 'follow_up_of')>0",
                                    (key, now - self.cfg['case_cooldown_seconds'])).fetchone()[0]
        if followups >= self.cfg.get('follow_up_max_per_cooldown', 5):
            return False
        since = event_time(json.loads(recent[1])['window_end'])
        window_start = since - self.cfg.get('before_seconds', 30)
        lookback = self.cfg.get('follow_up_novelty_seconds', 300)
        # The exec log must cover the whole novelty lookback before a follow-up can be judged.
        if now - getattr(self, 'started_at', 0) < lookback + self.cfg.get('before_seconds', 30):
            return False
        node, pod, container = identity(row)

        def execs(lo, hi):
            return {b for (b,) in self.db.execute('select distinct binary from exec_log where node=? and pod=? and container=? '
                                                 'and at>? and at<=?', (node, pod, container, lo, hi))}
        # Periodic probes (python health checks, redis-cli, pg_isready) re-run within minutes;
        # a binary counts as new only if it did not run in the lookback before the previous case.
        return bool(execs(since, event_time(row['window_end'])) - execs(window_start - lookback, window_start))

    def start_decision_stream(self, worker):
        """Follow a worker's decisions on the worker itself (cfg 'decision_stream')."""
        spec = self.cfg['decision_stream']
        remote = ['timeout', str(int(spec.get('rotate_seconds', 3600))), 'python3', '-u', '-c',
                  DECISION_FOLLOWER, worker['output']]
        args = ['sshpass', '-f', spec['credential'], 'ssh', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + spec.get('known_hosts', '/home/dat/.ssh/known_hosts'),
                '-o', 'ServerAliveInterval=10', f"{spec.get('user', 'dat')}@{worker['host']}",
                ' '.join(shlex.quote(a) for a in remote)]
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        self.decision_streams[worker['node_name']] = dict(child=child, buffer=b'', started_at=time.time())
        self.issue('decision_stream_started', node=worker['node_name'], host=worker['host'],
                   continuity='no backfill; decisions written while disconnected are not seen')

    def ingest_decision_line(self, line, node, now):
        row = json.loads(line)
        if row.get('node_name') != node:
            raise ValueError('decision node identity differs from configured worker')
        self.observe_trigger(row, now)
        self.count('decision_rows_read')

    def drain_decision_streams(self):
        for worker in self.cfg['workers']:
            node = worker['node_name']; stream = self.decision_streams.get(node)
            if stream and stream['child'].poll() is not None:
                self.issue('decision_stream_disconnected', node=node)
                self.stop_stream(stream); del self.decision_streams[node]; stream = None
            if stream is None:
                self.start_decision_stream(worker); continue
        lookup = {s['child'].stdout: (n, s) for n, s in self.decision_streams.items()}
        for pipe in (select.select(list(lookup), [], [], 0)[0] if lookup else []):
            node, stream = lookup[pipe]
            chunk = os.read(pipe.fileno(), 1 << 20)
            if not chunk:
                continue
            *lines, stream['buffer'] = (stream['buffer'] + chunk).split(b'\n')
            now = time.time()
            for line in lines:
                try:
                    self.ingest_decision_line(line, node, now)
                except (ValueError, TypeError, KeyError):
                    self.count('invalid_decisions')

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
        ready_after = self.cfg['after_seconds'] + self.cfg.get('case_ready_grace_seconds', 2)
        for cid, created, trigger_json in self.db.execute(
                'select id,created,trigger from cases where emitted=0 and created<=? limit 20',
                (now-ready_after,)).fetchall():
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
            if self.cfg.get('runtime_events'):
                coverage.update(runtime_policy=self.cfg['connect_policy'],
                    runtime_policy_scope='production namespace, all pods',
                    file_detail_sampling='1s per process per open/write hook',
                post_context_seconds=self.cfg['after_seconds'],
                case_ready_grace_seconds=self.cfg.get('case_ready_grace_seconds', 2),
                target_preview_to_case_seconds=ready_after,
                    lifecycle_subscription_started_at=self.streams.get(row['node_name']+'/lifecycle', {}).get('started_at'),
                    last_runtime_event_received_at=stream.get('last_event_at'))
                coverage.pop('last_connect_received_at', None)
            builder = build_runtime_tree if self.cfg.get('runtime_events') else build_tree
            tree = builder(row, [json.loads(e[0]) for e in source],
                before_seconds=self.cfg['before_seconds'], after_seconds=self.cfg['after_seconds'], coverage=coverage)
            tree['created_at'] = now
            if self.cfg.get('runtime_events'):
                baseline = dict(self.db.execute('select binary, first_seen from binaries where workload=?',
                                                (row['workload_key'],)).fetchall())
                frozen = self.cfg.get('binary_baseline_frozen_at')
                tree['suspects'] = rank_suspects(tree, baseline, frozen)[:20]
                tree['suspect_ranking'] = dict(method='heuristic_triage_order_not_probability',
                    binary_baseline_frozen_at=frozen, baseline_binaries=len(baseline))
            out = self.root/'cases'; out.mkdir(exist_ok=True)
            atomic(out/(cid+'.json'), tree)
            md = out/(cid+'.md'); temp = md.with_suffix('.md.tmp')
            renderer = render_runtime_markdown if self.cfg.get('runtime_events') else render_markdown
            temp.write_text(renderer(tree)); os.replace(temp, md)
            self.db.execute('update cases set emitted=1 where id=?', (cid,))
            self.count('cases_emitted'); self.count('cases_without_connect_context', not tree['matched_connect_events'])
            self.count('cases_without_runtime_context', not source)

    def maintenance(self):
        now = time.time()
        self.db.execute('delete from events where at<?', (now-self.cfg['ring_seconds'],))
        self.db.execute('delete from exec_log where at<?', (now-EXEC_LOG_SECONDS,))
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
                    node = worker['node_name']; sensor = self.inventory.get(node)
                    for channel in (('policy', 'lifecycle') if self.cfg.get('runtime_events') else ('policy',)):
                        key = node if channel == 'policy' else node+'/lifecycle'
                        stream = self.streams.get(key)
                        if stream and (stream['child'].poll() is not None or sensor and stream['sensor']!=sensor):
                            # kubectl does not always relay the remote `timeout` exit code (124):
                            # an exit at the rotation age is a rotation, reconnect without the 5 s pause.
                            rotate = self.cfg.get('stream_rotate_seconds', STREAM_ROTATE_SECONDS)
                            rotated = stream['child'].poll() == 124 or now - stream['started_at'] >= rotate - 5
                            self.issue('tetragon_stream_rotated' if rotated else 'tetragon_stream_disconnected',
                                       node=node, channel=channel)
                            self.stop_stream(stream); del self.streams[key]; retry[key] = now if rotated else now+5
                        if key not in self.streams and sensor and now>=retry.get(key, 0):
                            self.start_stream(node, sensor, channel)
                self.drain_streams()
                if self.cfg.get('decision_stream'):
                    self.drain_decision_streams()
                if now>=tail:
                    try:
                        if not self.cfg.get('decision_stream'): self.tail_decisions()
                        self.emit_cases()
                    except OSError as exc: self.issue('decision_or_case_storage_unavailable', error_type=type(exc).__name__)
                    # streamed decisions arrive continuously; check case readiness more often
                    tail = now + (.25 if self.cfg.get('decision_stream') else 1)
                if now>=checkpoint:
                    self.maintenance(); checkpoint = now+5
                time.sleep(.05)
        finally:
            for stream in [*self.streams.values(), *self.decision_streams.values()]: self.stop_stream(stream)
            self.db.commit(); self.db.close(); pool.shutdown(wait=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    Service(parser.parse_args().config).run()


if __name__ == '__main__': main()
