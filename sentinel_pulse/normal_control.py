"""Queued, boot-persistent paired normal controls of a frozen attack candidate.

No generator dispatch, no training and no zero-alert gate. Reuses the frozen
collection adapter, not its attack injection function. Missing telemetry is
unknown, never a fabricated TN. Interrupted epochs are retained, not replayed.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
from pathlib import Path
import shlex
import time

from .integrity import sha256_file
from .observation_attack import AttackRuntime, close_leg, remote_python, rows, start_leg
from .paired_evaluation import audit_attack, confusion, control_plan, finalize
from .recovery_worker_probe import clean_source
from .run_500ms_blind_matrix import append_jsonl, atomic_json, cluster_gate, ready_pods, select_cgroup

DURATION = 45
HORIZON = 15
MINIMUM = 81


def select_targets(pods, metadata, plan, epoch):
    selected = {}
    for item in plan:
        key = item['workload_key']
        namespace, name = key.split('/', 1)
        workload, container = name.split(':', 1)
        if namespace != 'production':
            raise ValueError('control outside registered namespace')
        matches = []
        for pod in ready_pods(pods, workload):
            if pod['node_name'] not in metadata:
                continue
            try:
                cg, value = select_cgroup(metadata[pod['node_name']], pod['uid'], container)
            except ValueError:
                continue
            # Prefix matches alone confuse Redis server and Redis Sentinel.
            if value.get('workload_name') == workload and value.get('namespace') == namespace:
                matches.append(dict(pod_uid=pod['uid'], node_name=pod['node_name'],
                                    pod_name=pod['name'], cgroup_id=str(cg)))
        selected[item['control_id']] = matches[(epoch - 1) % len(matches)] if matches else None
    return selected


def evaluate_control(item, target, records, begin, model_sha, policy_sha, healthy):
    result = dict(item, interval_start=begin, interval_seconds=DURATION,
                  attribution_horizon_seconds=HORIZON, status='infrastructure_unknown',
                  label_status='protocol_assumed_normal' if healthy else 'uncertain_infrastructure_context',
                  predicted_alert=None, all_alert_rows_45s=0)
    if target is None:
        return dict(result, error='no ready exact workload/container cgroup')
    result.update(target)
    matching = []
    for record in records:
        if (record.get('workload_key') != item['workload_key']
                or record.get('pod_uid') != target['pod_uid']
                or record.get('node_name') != target['node_name']
                or str(record.get('cgroup_id')) != target['cgroup_id']
                or not begin <= float(record.get('window_end', 0)) <= begin + DURATION):
            continue
        if record.get('status') in {'normal', 'suppressed', 'alert'} and (
                record.get('model_manifest_sha256') != model_sha or record.get('decision_policy_sha256') != policy_sha):
            raise ValueError('control decision model/policy drift')
        matching.append(record)
    scored = [r for r in matching if r.get('status') in {'normal', 'suppressed', 'alert'}]
    if len({r['window_end'] for r in scored}) != len(scored):
        raise ValueError('duplicate scored control window')
    alerts = [r for r in matching if r.get('status') == 'alert']
    result.update(scored_target_windows=len(scored), minimum_scored_target_windows=MINIMUM,
                  all_alert_rows_45s=len(alerts),
                  target_status_counts={s: sum(r.get('status') == s for r in matching)
                                        for s in sorted({r.get('status', 'missing') for r in matching})})
    if len(scored) < MINIMUM:
        return dict(result, error='insufficient scored control coverage')
    for alert in alerts:
        if 'alerted_at' not in alert or alert.get('injection_id'):
            raise ValueError('normal control carries injection or lacks alert timestamp')
    return dict(result, status='observed',
                predicted_alert=any(begin <= float(r['alerted_at']) <= begin + HORIZON for r in alerts))


def recover_epochs(root):
    done = {r['control_id'] for r in rows(root / 'CONTROLS.jsonl')}
    for intent in rows(root / 'EPOCHS.jsonl'):
        for item in intent['items']:
            if item['control_id'] not in done:
                append_jsonl(root / 'CONTROLS.jsonl', dict(item, status='infrastructure_unknown',
                    predicted_alert=None, label_status='uncertain_interrupted_epoch',
                    error='controller interrupted after epoch intent; not replayed'))
                done.add(item['control_id'])


def health(runtime):
    try:
        cluster_gate(runtime)
        return {'healthy': True, 'at_unix': time.time()}
    except Exception as exc:
        return {'healthy': False, 'error': str(exc), 'at_unix': time.time()}


def seal(root):
    atomic_json(root / 'EVIDENCE_SEAL.json', {str(p.relative_to(root)): sha256_file(p)
                for p in sorted(root.rglob('*')) if p.is_file() and p.name != 'EVIDENCE_SEAL.json'})


def run(args):
    root = args.root
    root.mkdir(parents=True, exist_ok=True)
    # A boot-enabled oneshot runs again after reboot. Never rewrite QUEUE (or
    # any other sealed receipt) after terminal; only regenerate the separate
    # derived report. Also recover the terminal-to-seal crash boundary.
    if (root / 'TERMINAL.json').exists():
        if not (root / 'EVIDENCE_SEAL.json').exists():
            seal(root)
        finalize(args.attack_root, root, args.output)
        return
    if args.password_file.stat().st_mode & 0o077:
        raise ValueError('credential must be private')
    cfg = json.loads(args.config.read_text())
    runtime = AttackRuntime(args.password_file.read_text().strip())
    # Do not take shared worker ownership while the existing attack is active.
    while not ((args.attack_root / 'TERMINAL.json').exists() and (args.attack_root / 'EVIDENCE_SEAL.json').exists()):
        if (args.attack_root / 'BLOCKED.json').exists():
            raise ValueError('attack binding blocked; cannot assume a completed attack evaluation')
        atomic_json(root / 'QUEUE.json', {'status': 'waiting_for_sealed_attack', 'checked_at_unix': time.time(),
                                       'attack_root': str(args.attack_root), 'no_worker_mutations': True})
        time.sleep(30)
    with Path('/home/dat/.pulse-attack-campaign.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        atomic_json(root / 'QUEUE.json', {'status': 'auditing_sealed_attack', 'checked_at_unix': time.time(),
                                       'attack_root': str(args.attack_root), 'no_worker_mutations': True})
        attack_start, trials, attack_report = audit_attack(args.attack_root)
        if cfg != attack_start['config']:
            raise ValueError('control config differs from frozen attack config')
        commit, files = clean_source(Path(cfg['source']))
        if commit != attack_start['source_commit'] or files != attack_start['runtime_files']:
            raise ValueError('frozen worker source differs from attack')
        controller_commit, controller_files = clean_source(Path(__file__).resolve().parents[1])
        binding = {k: attack_start[k] for k in ('source_commit', 'runtime_files', 'model_manifest_sha256',
                                               'decision_policy_sha256', 'recovery_profile_sha256')}
        binding.update(run_id=root.name, schema='sentinel-pulse-normal-control-start-v1',
                       attack_start_sha256=sha256_file(args.attack_root / 'START.json'),
                       attack_evidence_seal_sha256=attack_report['controller_evidence_seal_sha256'],
                       controller_commit=controller_commit, controller_runtime_files=controller_files,
                       config=cfg, plan=control_plan(attack_start['schedule']), interval_seconds=DURATION,
                       horizon_seconds=HORIZON, minimum_scored_windows=MINIMUM,
                       normal_label_basis='protocol assumption, not adjudication',
                       zero_alert_gate=False, automatic_promotion=False, maximum_collection_wall_seconds=21600)
        if (root / 'START.json').exists():
            start = json.loads((root / 'START.json').read_text())
            if any(start.get(k) != v for k, v in binding.items()):
                raise ValueError('normal-control registration drift')
        else:
            start = dict(binding, started_at_unix=time.time())
            atomic_json(root / 'START.json', start); (root / 'START.json').chmod(0o444)
        if (root / 'TERMINAL.json').exists():
            if not (root / 'EVIDENCE_SEAL.json').exists():
                seal(root)
            finalize(args.attack_root, root, args.output)
            return
        recover_epochs(root)
        atomic_json(root / 'STATUS.json', dict(confusion(trials, rows(root / 'CONTROLS.jsonl'), start['plan']),
                                               status='starting_normal_controls', updated_at_unix=time.time()))
        active = rows(root / 'ACTIVE_LEG.jsonl')
        if active:
            close_leg(runtime, cfg, root, active[-1]['run_id'])
        leg = None
        workers = {}
        number = len(active)
        deadline = start['started_at_unix'] + start['maximum_collection_wall_seconds']
        # Last generator may outlive an SSH. Never overlap it with normal labels.
        until = max((r['injected_at'] + attack_start['attack_seconds'] + attack_start['post_attack_wait_seconds']
                     for r in rows(args.attack_root / 'INTENTS.jsonl')), default=0)
        while time.time() < until:
            time.sleep(min(10, until - time.time()))
        try:
            for epoch in sorted({r['epoch'] for r in start['plan']}):
                done = {r['control_id'] for r in rows(root / 'CONTROLS.jsonl')}
                items = [r for r in start['plan'] if r['epoch'] == epoch and r['control_id'] not in done]
                if not items:
                    continue
                while time.time() < deadline:
                    try:
                        if leg is None:
                            number += 1
                            prospective = start['run_id'] + f'-a{number:04d}'
                            append_jsonl(root / 'ACTIVE_LEG.jsonl', {'run_id': prospective, 'started_at_unix': time.time()})
                            leg, workers = start_leg(runtime, cfg, root, start, number)
                        states = {node: json.loads(remote_python(runtime, cfg, w['host'], 'attack_worker',
                                                               ['probe', '--run-id', leg]).stdout)
                                  for node, w in workers.items()}
                        if any(s['detector']['ActiveState'] != 'active' or not s['capture']['valid']
                               or s['capture']['status'] != 'ready' for s in states.values()):
                            raise RuntimeError('control capture not ready')
                        break
                    except Exception as exc:
                        append_jsonl(root / 'INFRASTRUCTURE.jsonl', {'epoch': epoch, 'error': str(exc), 'at_unix': time.time()})
                        close_leg(runtime, cfg, root, leg or prospective); leg = None
                        time.sleep(30)
                if time.time() >= deadline:
                    break
                pre = health(runtime)
                pods = runtime.kubectl_json('get', 'pods', '-n', 'production', '-o', 'json')
                metadata = {node: json.loads(runtime.remote_sudo(w['host'], 'cat /run/sentinel-pulse/cgroups.json').stdout)
                            for node, w in workers.items()}
                targets = select_targets(pods, metadata, items, epoch)
                begin = time.time()
                intent = dict(epoch=epoch, items=items, targets=targets, interval_start=begin, leg_run_id=leg, pre_health=pre)
                append_jsonl(root / 'EPOCHS.jsonl', intent)
                while time.time() < begin + DURATION + 3:
                    time.sleep(min(5, begin + DURATION + 3 - time.time()))
                raw = root / 'epochs' / f'{epoch:03d}'; raw.mkdir(parents=True, exist_ok=True)

                def fetch(pair):
                    node, worker = pair
                    path = str(Path(worker['injections']).parent / 'decisions.jsonl')
                    data = runtime.remote_sudo(worker['host'], 'tail -n 16000 -- ' + shlex.quote(path), timeout=40).stdout
                    (raw / (worker['host'] + '.jsonl')).write_bytes(data)
                    # Tail can see a partial final line; retain raw and omit only
                    # that incomplete line, never discard a complete bad record.
                    complete = data if data.endswith(b'\n') else data[:data.rfind(b'\n') + 1]
                    return node, [json.loads(line) for line in complete.splitlines()]

                with ThreadPoolExecutor(max_workers=3) as pool:
                    fetched = {}
                    for pair in workers.items():
                        # Futures fetched below preserve failures as unknown.
                        fetched[pair[0]] = pool.submit(fetch, pair)
                    records, errors = {}, {}
                    for node, future in fetched.items():
                        try:
                            _, records[node] = future.result()
                        except Exception as exc:
                            errors[node] = str(exc)
                post = health(runtime)
                atomic_json(raw / 'context.json', dict(intent, post_health=post, fetch_errors=errors))
                for item in items:
                    target = targets[item['control_id']]
                    try:
                        if target and target['node_name'] in errors:
                            raise RuntimeError(errors[target['node_name']])
                        outcome = evaluate_control(item, target, records.get(target['node_name'], []) if target else [],
                                                   begin, start['model_manifest_sha256'], start['decision_policy_sha256'],
                                                   pre['healthy'] and post['healthy'])
                    except Exception as exc:
                        outcome = dict(item, status='infrastructure_unknown', predicted_alert=None,
                                       label_status='uncertain_evidence', error=str(exc))
                    append_jsonl(root / 'CONTROLS.jsonl', dict(outcome, leg_run_id=leg))
                atomic_json(root / 'STATUS.json', dict(confusion(trials, rows(root / 'CONTROLS.jsonl'), start['plan']),
                                                       status='running', finished_epoch=epoch, updated_at_unix=time.time()))
            final = confusion(trials, rows(root / 'CONTROLS.jsonl'), start['plan'])
        finally:
            if leg:
                close_leg(runtime, cfg, root, leg)
        atomic_json(root / 'TERMINAL.json', dict(final, status='completed' if not final['normal_receipts_missing']
                   else 'completed_with_incomplete_controls', finished_at_unix=time.time()))
        seal(root)
        finalize(args.attack_root, root, args.output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('config', 'attack-root', 'root', 'output', 'password-file'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    with Path('/home/dat/.pulse-normal-control.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            run(args)
        except ValueError as exc:
            args.root.mkdir(parents=True, exist_ok=True)
            atomic_json(args.root / 'BLOCKED.json', {'error': str(exc), 'at_unix': time.time(), 'automatic_promotion': False})
            raise SystemExit(65) from exc


if __name__ == '__main__':
    main()
