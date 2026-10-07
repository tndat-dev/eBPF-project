"""Integrity-checked interval metrics; protocol labels are not adjudication."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from .attack_trial import first_alert
from .integrity import sha256_file
from .observation_attack import result_report, rows, trial_key
from .run_500ms_blind_matrix import atomic_json
from .tetragon_evidence import find_execve_kprobe_event


def verify_seal(root):
    root = root.resolve()
    seal = json.loads((root / 'EVIDENCE_SEAL.json').read_text())
    required = {'START.json', 'TERMINAL.json'}
    if not required <= set(seal):
        raise ValueError('seal lacks registration/terminal')
    for name, expected in seal.items():
        path = root / name
        if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink():
            raise ValueError('unsafe sealed path')
        if not path.resolve().is_relative_to(root) or sha256_file(path) != expected:
            raise ValueError('sealed evidence drift: ' + name)
    actual = {str(p.relative_to(root)) for p in root.rglob('*')
              if p.is_file() and p.name != 'EVIDENCE_SEAL.json'}
    if actual != set(seal):
        raise ValueError('unsealed or missing evidence files')
    return sha256_file(root / 'EVIDENCE_SEAL.json')


def audit_attack(root):
    seal = verify_seal(root)
    start = json.loads((root / 'START.json').read_text())
    trials = rows(root / 'TRIALS.jsonl')
    report = result_report(start['schedule'], trials)
    terminal = json.loads((root / 'TERMINAL.json').read_text())
    for key in report:
        if terminal.get(key) != report[key]:
            raise ValueError('attack terminal metrics differ: ' + key)
    intents = {r['injection_id']: r for r in rows(root / 'INTENTS.jsonl')}
    kernels = {r['injection_id']: r for r in rows(root / 'kernel-events.jsonl')}
    if len(intents) != len(rows(root / 'INTENTS.jsonl')) or len(kernels) != len(rows(root / 'kernel-events.jsonl')):
        raise ValueError('duplicate dispatch/kernel receipt')
    for row in trials:
        if row['status'] != 'observed':
            continue
        intent = intents.get(row['injection_id'])
        kernel = kernels.get(row['injection_id'])
        if not intent or not kernel or trial_key(intent) != trial_key(row):
            raise ValueError('observed trial lacks dispatch/kernel receipt')
        if kernel['kernel_event_at'] != row['kernel_event_at']:
            raise ValueError('kernel timestamp differs')
        index = int(row['injection_id'].rsplit(':', 1)[1])
        raw = root / 'trials' / f'{index:04d}'
        reparsed = find_execve_kprobe_event((raw / 'tetragon.jsonl').read_text().splitlines(), intent,
                                           expected_binary=intent['binary_path'], maximum_delay_seconds=10)
        if reparsed != kernel:
            raise ValueError('kernel receipt differs from raw Tetragon stream')
        for field in ('pod_uid', 'node_name', 'workload_key', 'cgroup_id'):
            if str(row[field]) != str(intent[field]):
                raise ValueError('trial identity differs from dispatch')
        alert = first_alert(rows(raw / 'attributed-alerts.jsonl'),
                            intent, start['model_manifest_sha256'], start['decision_policy_sha256'])
        if bool(alert) != row['detected']:
            raise ValueError('detection differs from raw attributed alert')
        if alert and (not math.isfinite(row['kernel_to_alert_seconds'])
                      or row['kernel_to_alert_seconds'] < 0
                      or abs(float(alert['alerted_at']) - float(kernel['kernel_event_at'])
                             - row['kernel_to_alert_seconds']) > 1e-6):
            raise ValueError('latency differs from raw timestamps')
    return start, trials, dict(report, controller_evidence_seal_sha256=seal,
                               worker_raw_seals_rehashed_by_this_audit=False)


def control_plan(attack_plan):
    keys = sorted({r['workload_key'] for r in attack_plan})
    repeats = {k: sum(r['workload_key'] == k for r in attack_plan) for k in keys}
    return [dict(control_id=f'n{epoch:03d}:{index:02d}', epoch=epoch, workload_key=key)
            for epoch in range(1, max(repeats.values()) + 1)
            for index, key in enumerate(keys, 1) if epoch <= repeats[key]]


def confusion(trials, controls, plan):
    ids = [r['control_id'] for r in controls]
    allowed = {r['control_id']: r for r in plan}
    if len(set(ids)) != len(ids) or not set(ids) <= set(allowed):
        raise ValueError('duplicate/out-of-plan normal control')
    for row in controls:
        if row['workload_key'] != allowed[row['control_id']]['workload_key']:
            raise ValueError('control workload binding differs')
        if row['status'] == 'observed' and type(row.get('predicted_alert')) is not bool:
            raise ValueError('observed control lacks boolean prediction')
    observed_attack = [r for r in trials if r['status'] == 'observed']
    normal = [r for r in controls if r['status'] == 'observed'
              and r.get('label_status') == 'protocol_assumed_normal']
    tp = sum(r['detected'] is True for r in observed_attack)
    fn = len(observed_attack) - tp
    fp = sum(r['predicted_alert'] is True for r in normal)
    tn = len(normal) - fp
    return {
        'unit': '45-second target interval; prediction horizon first 15 seconds',
        'normal_label_basis': 'protocol assumption; healthy pre/post context; not independent adjudication',
        'provisional_protocol_confusion_matrix': {'TP': tp, 'FN': fn, 'FP': fp if normal else None,
                                                  'TN': tn if normal else None},
        'provisional_protocol_precision': tp / (tp + fp) if normal and tp + fp else None,
        'conditional_observed_attack_recall': tp / (tp + fn) if tp + fn else None,
        'provisional_protocol_false_positive_rate': fp / len(normal) if normal else None,
        'adjudicated_precision': None, 'adjudicated_confusion_matrix': None,
        'attack_unknown': len(trials) - len(observed_attack),
        'normal_unknown_or_uncertain': len(controls) - len(normal),
        'normal_receipts_missing': len(plan) - len(controls),
        'counted_alert_rows_in_control_receipts': sum(r.get('all_alert_rows_45s', 0) for r in controls),
        'zero_false_positive_gate': False, 'automatic_promotion': False,
        'precision_not_a_production_prevalence_estimate': True,
        'replica_and_shared_epoch_dependence_not_independent_samples': True,
        'expectations_not_measurements': {'precision': .95, 'recall': .95, 'false_positive_rate': .05},
    }


def finalize(attack_root, control_root, output):
    start, trials, attack = audit_attack(attack_root)
    control_seal = verify_seal(control_root)
    registration = json.loads((control_root / 'START.json').read_text())
    if registration['attack_start_sha256'] != sha256_file(attack_root / 'START.json'):
        raise ValueError('normal controls belong to another attack campaign')
    if registration['attack_evidence_seal_sha256'] != attack['controller_evidence_seal_sha256']:
        raise ValueError('registered attack seal differs')
    for field in ('model_manifest_sha256', 'decision_policy_sha256', 'source_commit', 'runtime_files'):
        if registration[field] != start[field]:
            raise ValueError('control candidate binding differs: ' + field)
    expected = control_plan(start['schedule'])
    if registration['plan'] != expected:
        raise ValueError('paired negative plan differs')
    controls = rows(control_root / 'CONTROLS.jsonl')
    # Independently reconstruct observed receipts from retained decision tails.
    # Do not rely solely on STATUS/TERMINAL counters written by the controller.
    from .normal_control import evaluate_control
    cached_epoch, context, tails = None, None, {}
    for row in controls:
        if row['status'] != 'observed':
            continue
        if cached_epoch != row['epoch']:
            cached_epoch = row['epoch']
            raw = control_root / 'epochs' / f'{cached_epoch:03d}'
            context = json.loads((raw / 'context.json').read_text())
            tails = {}
            for path in raw.glob('*.jsonl'):
                data = path.read_bytes()
                complete = data if data.endswith(b'\n') else data[:data.rfind(b'\n') + 1]
                tails[path.stem] = [json.loads(line) for line in complete.splitlines()]
        target = context['targets'][row['control_id']]
        decisions = next((r for r in tails.values() if any(d.get('node_name') == target['node_name'] for d in r)), [])
        item = next(r for r in context['items'] if r['control_id'] == row['control_id'])
        rebuilt = evaluate_control(item, target, decisions, context['interval_start'],
                                   start['model_manifest_sha256'], start['decision_policy_sha256'],
                                   context['pre_health']['healthy'] and context['post_health']['healthy'])
        if any(row.get(k) != v for k, v in rebuilt.items()):
            raise ValueError('control receipt differs from raw decisions')
    metrics = confusion(trials, controls, expected)
    report = dict(schema='sentinel-pulse-paired-evaluation-v1', attack=attack,
                  interval_metrics=metrics, control_evidence_seal_sha256=control_seal,
                  attack_root=str(attack_root), control_root=str(control_root),
                  model_unchanged=True, blind_outcomes_used_for_tuning=False)
    if output.resolve().is_relative_to(attack_root.resolve()) or output.resolve().is_relative_to(control_root.resolve()):
        raise ValueError('cannot write evaluation inside sealed evidence')
    output.mkdir(parents=True, exist_ok=True)
    atomic_json(output / 'RESULTS.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attack-root', type=Path, required=True)
    parser.add_argument('--control-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(finalize(args.attack_root, args.control_root, args.output), indent=2))


if __name__ == '__main__':
    main()
