"""Persistent observation campaign: retain sealed prefixes and retry recovery.

Quality outcomes do not stop observation. Each finite segment has independent
source/model binding and raw seals; missing or corrupt evidence is never normal.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import signal
import time

from . import recovery_coordinator as coordinator
from .integrity import sha256_file
from .operational_soak import merge_intervals
from .recovery_formal import write_new
from .telemetry_recovery import digest


def validate_protocol(p):
    if p.get('schema') != 'sentinel-pulse-observation-campaign-v1':
        raise ValueError('unsupported campaign protocol')
    for k in ('stop_on_alert', 'stop_on_quality_gate', 'automatic_training', 'automatic_promotion'):
        if p.get(k) is not False:
            raise ValueError('campaign cannot stop on quality or modify model: ' + k)
    if not (180 <= p['segment_seconds'] <= 1800 and 0 < p['retry_seconds'] <= 300
            and 0 < p['minimum_wall_seconds'] <= p['maximum_wall_seconds']
            and 0 < p['target_valid_seconds_per_workload'] <= p['maximum_wall_seconds']):
        raise ValueError('invalid campaign timing')
    m = p['expected_confusion_matrix_not_measured']
    if (m['TP'] + m['FN'] != m['attack_intervals'] or m['TN'] + m['FP'] != m['normal_intervals']
            or m['FP'] <= 0 or m['FN'] <= 0):
        raise ValueError('invalid expected confusion matrix or zero gate')
    return p


def summarize(reports, expected, protocol, elapsed):
    intervals, alerts, eligible_alerts = defaultdict(list), Counter(), Counter()
    excluded, missing = Counter(), []
    for receipt in reports:
        for host, report in receipt.get('workers', {}).items():
            for key, values in report['valid_intervals'].items():
                intervals[key].extend(values)
            alerts.update(report['all_alerts'])
            eligible_alerts.update(report['eligible_alerts'])
            excluded.update(report['excluded_rows'])
        if receipt.get('failures'):
            missing.append({'segment': receipt['run_id'], 'workers': receipt['failures']})
    seconds = {k: sum(b-a for a,b in merge_intervals(intervals[k])) for k in expected}
    hours = sum(seconds.values()) / 3600
    rate = sum(eligible_alerts.values()) / hours if hours else None
    per_key = {k: eligible_alerts[k] * 3600 / v if v else None for k,v in seconds.items()}
    reached = elapsed >= protocol['minimum_wall_seconds'] and all(
        v >= protocol['target_valid_seconds_per_workload'] for v in seconds.values())
    return {'schema': 'sentinel-pulse-observation-summary-v1', 'elapsed_wall_seconds': elapsed,
            'valid_seconds_per_workload': seconds, 'all_alerts': dict(alerts),
            'eligible_alerts': dict(eligible_alerts), 'excluded_rows': dict(excluded),
            'missing_segment_audits': missing, 'eligible_alert_rate_per_workload_hour': rate,
            'eligible_alert_rates_per_key_hour': per_key, 'exposure_target_reached': reached,
            'quality_budget_met': rate is not None and rate <= protocol['maximum_alerts_per_valid_workload_hour']
                and all(v is not None and v <= protocol['maximum_alerts_per_hour_per_workload'] for v in per_key.values()),
            'confusion_matrix_measured': None, 'precision': None, 'recall': None,
            'normal_alerts_await_adjudication': True, 'automatic_promotion': False,
            'expected_confusion_matrix_not_measured': protocol['expected_confusion_matrix_not_measured']}


def atomic_json(path, value):
    temp = path.with_suffix('.tmp')
    with temp.open('w') as f:
        json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
        f.flush(); os.fsync(f.fileno())
    os.replace(temp, path)


def campaign(root, config, remote, protocol):
    protocol = validate_protocol(protocol)
    # One fleet owner because candidate systemd units are shared on workers.
    with coordinator.coordinator_lock(root.parent / 'observation-fleet'):
        return _campaign_owned(root, config, remote, protocol)


def _campaign_owned(root, config, remote, protocol):
    from .recovery_worker_probe import clean_source
    commit, files = clean_source(Path(config['source']))
    manifest_path = Path(config['model']) / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    binding = {'config': config, 'protocol': protocol, 'source_commit': commit,
               'source_files_sha256': digest(files), 'model_manifest_sha256': sha256_file(manifest_path),
               'decision_policy_sha256': sha256_file(Path(config['policy']))}
    if root.exists():
        registration = json.loads((root / 'START.json').read_text())
        if registration['binding'] != binding:
            raise ValueError('campaign binding drift; keep old campaign immutable')
        if (root / 'TERMINAL.json').exists():
            return json.loads((root / 'TERMINAL.json').read_text())
    else:
        root.mkdir(mode=0o750, parents=True)
        registration = {'schema': 'sentinel-pulse-observation-registration-v1',
                        'started_at_unix': time.time(), 'binding': binding}
        write_new(root / 'START.json', registration)
    expected = sorted(manifest['workloads'])
    receipts = [json.loads(l) for l in (root / 'segments.jsonl').read_text().splitlines()] if (root / 'segments.jsonl').exists() else []
    stopped = False
    def interrupt(_sig, _frame):
        nonlocal stopped
        stopped = True
    old = {s: signal.signal(s, interrupt) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        while not stopped:
            summary = summarize(receipts, expected, protocol, time.time()-registration['started_at_unix'])
            atomic_json(root / 'STATUS.json', summary)
            if summary['exposure_target_reached'] or summary['elapsed_wall_seconds'] >= protocol['maximum_wall_seconds']:
                result = {**summary, 'status': 'completed' if summary['exposure_target_reached'] else 'completed_with_insufficient_coverage',
                          'finished_at_unix': time.time()}
                write_new(root / 'TERMINAL.json', result)
                return result
            n = len(receipts) + 1
            run_id = root.name + '-s' + str(n).zfill(4)
            segment_root = root / 'segments' / run_id
            attempt = {'run_id': run_id, 'workers': {}, 'failures': {}}
            try:
                # Resume the same owned live child after coordinator interruption.
                if not (segment_root / 'TERMINAL.json').exists():
                    coordinator.run(segment_root, config, remote, run_id, protocol['segment_seconds'], True,
                                    resume=(segment_root / 'START.json').exists(), observation=True)
                marker = json.loads((segment_root / 'START.json').read_text())
                health_path = segment_root / 'dependency-health.jsonl'
                payload = {'marker': marker, 'health_journal': health_path.read_text() if health_path.exists() else ''}
                reports, failures = coordinator.parallel_calls({h: lambda h=h: remote.call(h, 'audit-segment', payload, timeout=900)
                                                               for h in sorted(coordinator.WORKERS)})
                attempt.update(workers=reports, failures=failures,
                               terminal=json.loads((segment_root / 'TERMINAL.json').read_text()))
                # Keep worker audit receipts even if the child quality verdict failed.
                for h,r in reports.items():
                    target = root / (run_id + '-' + h + '.json')
                    if target.exists():
                        if json.loads(target.read_text()) != r: raise ValueError('audit receipt drift')
                    else: write_new(target, r)
            except (ValueError, RuntimeError, OSError, KeyError) as error:
                attempt['failures']['coordinator'] = str(error)
            coordinator.append(root / 'segments.jsonl', attempt)
            receipts.append(attempt)
            # Failures preserve prior exposure; waiting and retry are journaled.
            if attempt['failures'] or attempt.get('terminal', {}).get('reason'):
                coordinator.append(root / 'recovery-events.jsonl', {'run_id': run_id, 'observed_at_unix': time.time(),
                    'action': 'retry_after_recovery', 'failures': attempt['failures'],
                    'reason': attempt.get('terminal', {}).get('reason'), 'prior_exposure_preserved': True})
                deadline = time.monotonic() + protocol['retry_seconds']
                while not stopped and time.monotonic() < deadline:
                    time.sleep(min(.5, max(0, deadline-time.monotonic())))
    finally:
        for s,h in old.items(): signal.signal(s,h)
    result = summarize(receipts, expected, protocol, time.time()-registration['started_at_unix'])
    atomic_json(root / 'STATUS.json', {**result, 'status': 'paused'})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('config', 'password-file', 'output-root', 'protocol'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--run-id', required=True)
    args = p.parse_args()
    if not coordinator.re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', args.run_id): raise ValueError('unsafe campaign ID')
    cfg = coordinator.validate_config(json.loads(args.config.read_text()))
    result = campaign(args.output_root / args.run_id, cfg, coordinator.Remote(cfg,args.password_file),
                      json.loads(args.protocol.read_text()))
    print(json.dumps(result, allow_nan=False))


if __name__ == '__main__': main()
