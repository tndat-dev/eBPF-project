"""Apply the pre-registered selection rule for pulse-stable-candidate to the pulse-live-recalibrated evidence.

Rule, fixed before the numbers existed (19/10 10:52):

1. Calibration: use the refreshed calibration (pulse-live-recalibrated normal) if, for the run policy
   k1of1_a3, it lowers normal alert episodes per hour and costs at most 2 recall points.
2. Policy: among both grids under that calibration, keep policies with replay p95 <= 2.3 s
   (the fast scorer is expected to remove ~0.35 s), precision >= 0.95, recall >= 0.95 and
   control-positive rate <= 0.05; choose the fewest normal episodes per hour (then lower p95).
3. Otherwise choose the lowest p95 among policies with precision >= 0.95 and record that the
   expectations are not met.

Inputs are the files written by scripts/pulse_stable_candidate_selection.sh; nothing here is tuned afterwards.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

from ..common import atomic_json
from ..integrity import sha256_file

NODES = ('k8s-worker1.local', 'k8s-worker4.local', 'k8s-worker3.local')
GRIDS = ('default', 'looser')
REFERENCE = 'k1of1_a3'
P95_LIMIT, PRECISION, RECALL, CONTROL, RECALL_COST = 2.3, 0.95, 0.95, 0.05, 0.02


def normal_rates(directory: Path, prefix: str):
    episodes, hours = defaultdict(int), {}
    for grid in GRIDS:
        for node in NODES:
            data = json.loads((directory/f'normal-{prefix}-{grid}-{node}.json').read_text())
            hours[node] = data['total_scored_hours']
            for name, policy in data['policies'].items():
                episodes[name] += policy['total_episodes']
    total = sum(hours.values())
    return {name: count/total for name, count in episodes.items()}, total


def attack_metrics(directory: Path, prefix: str):
    merged = {}
    for grid in GRIDS:
        data = json.loads((directory/f'attack-{prefix}-{grid}.json').read_text())
        for name, policy in data['policies'].items():
            latency = policy.get('kernel_to_preview_seconds') or {}
            benign = policy.get('benign_exec_control') or {}
            merged[name] = dict(policy=policy['policy'], precision=policy['precision_expected'],
                                recall=policy['recall_observed'], control=policy['control_positive_rate'],
                                p95=latency.get('p95'), p99=latency.get('p99'),
                                benign_positive_rate=benign.get('positive_rate'))
    return merged


def table(directory: Path, prefix: str):
    rates, hours = normal_rates(directory, prefix)
    rows = attack_metrics(directory, prefix)
    for name, row in rows.items():
        row['episodes_per_hour'] = rates.get(name)
    return rows, hours


def select(directory: Path):
    asrun, asrun_hours = table(directory, 'asrun')
    refreshed, refreshed_hours = table(directory, 'refreshed')
    a, r = asrun[REFERENCE], refreshed[REFERENCE]
    use_refreshed = r['episodes_per_hour'] < a['episodes_per_hour'] and r['recall'] >= a['recall'] - RECALL_COST
    rows = refreshed if use_refreshed else asrun

    def ok(row):
        return all(row[k] is not None for k in ('p95', 'precision', 'recall', 'control', 'episodes_per_hour'))
    eligible = [(n, row) for n, row in rows.items() if ok(row) and row['p95'] <= P95_LIMIT
                and row['precision'] >= PRECISION and row['recall'] >= RECALL and row['control'] <= CONTROL]
    if eligible:
        name, row = min(eligible, key=lambda item: (item[1]['episodes_per_hour'], item[1]['p95']))
        meets = True
    else:
        fallback = [(n, row) for n, row in rows.items() if ok(row) and row['precision'] >= PRECISION]
        name, row = min(fallback, key=lambda item: item[1]['p95'])
        meets = False
    return dict(schema='pulse-r7-selection-v1', calibration='refreshed' if use_refreshed else 'as_run',
                calibration_check=dict(reference=REFERENCE, as_run=a, refreshed=r),
                policy=name, metrics=row, meets_registered_expectations=meets,
                rule=dict(p95_limit=P95_LIMIT, precision=PRECISION, recall=RECALL, control=CONTROL,
                          recall_cost=RECALL_COST),
                normal_hours=dict(as_run=asrun_hours, refreshed=refreshed_hours),
                eligible=[n for n, _ in eligible], tables=dict(as_run=asrun, refreshed=refreshed),
                inputs={p.name: sha256_file(p) for p in sorted(directory.glob('*.json'))},
                selected_at_unix=time.time())


HARD_P95_SECONDS = 2.0       # kernel -> preview target of the thesis
EPISODE_BUDGET = 0.1         # normal alert episodes per replica-hour (syscall protocol v2)


def known_gaps(m: dict) -> list:
    """Limits the selected policy still has on development data, written into the policy file."""
    gaps = []
    if m['p95'] > HARD_P95_SECONDS:
        gaps.append(f"kernel->preview p95 {m['p95']:.2f} s exceeds the {HARD_P95_SECONDS:g} s target")
    if m['episodes_per_hour'] > EPISODE_BUDGET:
        gaps.append(f"normal alert burden {m['episodes_per_hour']:.1f} episodes/replica-hour is "
                    f"~{m['episodes_per_hour']/EPISODE_BUDGET:.0f}x the {EPISODE_BUDGET:g}/h budget; not solved by thresholds")
    if m['benign_positive_rate'] > 0.5:
        gaps.append(f"benign new-process launches are flagged at {m['benign_positive_rate']:.0%}; "
                    'the detector separates new activity, not malicious activity')
    return gaps


def write_policy(selection: dict, template: Path, output: Path, candidate_hash: str, candidate_name: str):
    """A v2 preview policy file for the selected rule, bound to the pulse-stable-candidate candidate."""
    doc = json.loads(template.read_text())
    spec = selection['metrics']['policy']
    doc.update(policy_name=f"stable-candidate-{selection['policy'].replace('_', '-')}-{selection['calibration']}",
               candidate_name=candidate_name, candidate_manifest_sha256=candidate_hash,
               created_at=time.strftime('%Y-%m-%d'))
    doc['rule']['alpha_scale'] = float(spec['alpha_scale'])
    doc['rule']['temporal_confirmation'] = dict(k=int(spec['k']), n=int(spec['n']), max_gap_seconds=1.0)
    m = selection['metrics']
    doc['selection_basis'] = dict(
        data='development: pulse-live-recalibrated campaigns (420 pairs) and its normal tail',
        rule='pre-registered stable-candidate rule (SENTINEL_PULSE_STATUS); applied by sentinel_pulse.attack.select_policy',
        calibration=selection['calibration'], meets_registered_expectations=selection['meets_registered_expectations'],
        development_result=dict(precision_expected=m['precision'], recall_observed=m['recall'],
                                control_positive_rate=m['control'], benign_exec_positive_rate=m['benign_positive_rate'],
                                kernel_to_preview_p95_seconds=m['p95'],
                                normal_alert_episodes_per_replica_hour=m['episodes_per_hour']),
        known_gaps=known_gaps(m))
    doc['evaluation_requirements'] = ('fresh pulse-stable-candidate normal soak plus fresh attack campaign with benign-exec controls; '
                                      'fast scoring; report idle and benign controls separately; do not tune after outcomes')
    output.write_text(json.dumps(doc, indent=2) + '\n')
    return sha256_file(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--selection-dir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--from-selection', type=Path, help='write the policy file for an existing SELECTION.json')
    parser.add_argument('--template', type=Path, help='policy file to copy the registered fields from (pulse-live-recalibrated policy)')
    parser.add_argument('--candidate-hash'); parser.add_argument('--candidate-name')
    args = parser.parse_args()
    if args.from_selection:
        if not (args.template and args.candidate_hash and args.candidate_name):
            parser.error('--from-selection needs --template --candidate-hash --candidate-name')
        print(write_policy(json.loads(args.from_selection.read_text()), args.template, args.output,
                           args.candidate_hash, args.candidate_name))
        return
    if not args.selection_dir:
        parser.error('--selection-dir required')
    result = select(args.selection_dir)
    atomic_json(args.output, result)
    print(json.dumps({k: result[k] for k in ('calibration', 'policy', 'metrics', 'meets_registered_expectations', 'eligible')},
                     indent=2))


if __name__ == '__main__':
    main()
