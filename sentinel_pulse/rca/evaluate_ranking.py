"""Score RCA suspect ranking against attack campaigns' known injected process.

For each attack trial, the earliest RCA case on the same node/pod/container
whose trigger window ends inside the attack interval (+5 s) is matched, and
the rank of the fixture binary in that case's suspect list is recorded.

``--rerank-db`` recomputes the ranking offline with the current
``ranking.py`` from the subscriber's ``binaries`` table, using only binaries
first seen before each case was created (as the live service saw them).
``--without-privilege-drop-rule`` reranks as before RCA 5.10 (setuid/setgid at
process start scored like any other security operation), for the old-vs-new check.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3

from ..common import atomic_json
from . import ranking
from .ranking import ground_truth_rank, hit_rates, rank_suspects
from .tree import event_time


def load_binaries(db: Path):
    with sqlite3.connect(f'file:{db}?mode=ro', uri=True) as conn:
        return conn.execute('select workload, binary, first_seen from binaries').fetchall()


def rerank(tree, binaries, frozen_at, tie_break='name'):
    workload = next(n['trigger'] for n in tree['nodes'] if n['kind'] == 'signal')['workload_key']
    baseline = {b: t for w, b, t in binaries if w == workload and t <= tree['created_at']}
    return rank_suspects(tree, baseline, frozen_at, tie_break)[:20]


def evaluate(case_dir: Path, campaigns: list[Path], rerank_db: Path | None = None, frozen_at: float | None = None,
             privilege_drop_rule: bool = True, tie_break: str = 'name'):
    binaries = load_binaries(rerank_db) if rerank_db else None
    if not privilege_drop_rule and binaries is None:
        raise ValueError('the old ranking rule needs --rerank-db')
    cases = []
    saved = ranking.DROP_AT_START_SECONDS
    if not privilege_drop_rule:
        ranking.DROP_AT_START_SECONDS = -1.0   # 0 <= dt <= -1 never holds: the rule is off
    try:
        for path in case_dir.glob('*.json'):
            tree = json.loads(path.read_text())
            if binaries is not None:
                tree['suspects'] = rerank(tree, binaries, frozen_at, tie_break)
            trigger = next(n['trigger'] for n in tree['nodes'] if n['kind'] == 'signal')
            cases.append((event_time(trigger['window_end']), trigger, tree))
    finally:
        ranking.DROP_AT_START_SECONDS = saved
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
                ranking=hit_rates(with_case), rows=rows, reranked=binaries is not None,
                privilege_drop_rule=privilege_drop_rule if binaries is not None else 'as stored',
                tie_break=tie_break if binaries is not None else 'as stored',
                binary_baseline_frozen_at=frozen_at,
                note='ground truth = fixture binary path; ranking is a triage heuristic, not causal proof')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--campaign', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rerank-db', type=Path, help="subscriber context.sqlite3 (read-only)")
    parser.add_argument('--frozen-at', type=float, help='binary_baseline_frozen_at of the subscriber config')
    parser.add_argument('--without-privilege-drop-rule', action='store_true', help='rerank with the rule before RCA 5.10')
    parser.add_argument('--tie-break', choices=('name', 'recency'), default='name', help='equal scores: binary path or latest start first (RCA 5.19)')
    args = parser.parse_args()
    result = evaluate(args.cases, args.campaign, args.rerank_db, args.frozen_at,
                      privilege_drop_rule=not args.without_privilege_drop_rule, tie_break=args.tie_break)
    atomic_json(args.output, result)
    print(json.dumps({k: v for k, v in result.items() if k != 'rows'}))


if __name__ == '__main__':
    main()
