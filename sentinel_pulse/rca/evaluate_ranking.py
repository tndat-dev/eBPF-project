"""Score RCA suspect ranking against attack campaigns' known injected process.

For each attack trial, the earliest RCA case on the same node/pod/container
whose trigger window ends inside the attack interval (+5 s) is matched, and
the rank of the fixture binary in that case's suspect list is recorded.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..common import atomic_json
from .ranking import ground_truth_rank, hit_rates
from .tree import event_time


def evaluate(case_dir: Path, campaigns: list[Path]):
    cases = []
    for path in case_dir.glob('*.json'):
        tree = json.loads(path.read_text())
        trigger = next(n['trigger'] for n in tree['nodes'] if n['kind'] == 'signal')
        cases.append((event_time(trigger['window_end']), trigger, tree))
    cases.sort(key=lambda c: c[0])
    rows = []
    for campaign in campaigns:
        for path in sorted(campaign.glob('trials/*/EVALUATION_INPUT.json')):
            attack = json.loads(path.read_text())['attack']
            begin = float(attack['start_at']); end = begin + float(attack.get('duration_seconds', 15)) + 5
            match = next((tree for at, trig, tree in cases if begin <= at <= end
                          and (trig['node_name'], trig['pod_uid'], trig['container_name'])
                          == (attack['node_name'], attack['pod_uid'], attack['container_name'])), None)
            rank = None if match is None else ground_truth_rank(match.get('suspects', []), binary=attack['binary_path'])
            rows.append(dict(trial=attack['trial_id'], scenario=attack.get('scenario'), workload=attack['workload_key'],
                             case_id=None if match is None else match['case_id'], rank=rank))
    with_case = [r['rank'] for r in rows if r['case_id']]
    return dict(schema='pulse-rca-ranking-evaluation-v1', trials=len(rows), trials_with_case=len(with_case),
                ranking=hit_rates(with_case), rows=rows,
                note='ground truth = fixture binary path; ranking is a triage heuristic, not causal proof')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--campaign', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.cases, args.campaign)
    atomic_json(args.output, result)
    print(json.dumps({k: v for k, v in result.items() if k != 'rows'}))


if __name__ == '__main__':
    main()
