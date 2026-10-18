"""Prove that this checkout scores exactly like the frozen worker did.

Replays the feature records of sealed matched-worker segments through this
checkout's batch scorer and preview policy, frame by frame as the worker
did, and compares every score with the decision the frozen source recorded.
Exact equality (not a tolerance) is required before this checkout may be
registered as a new ``frozen_source``.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import time

from ..common import atomic_json
from ..detector.candidate_policy import load_preview_policy
from ..detector.idle_batch import SCORE_FIELDS, IdleBatchRuntime
from ..detector.idle_candidate import IdleCandidateScorer
from ..integrity import sha256_file

KEY = ('workload_key', 'pod_uid', 'container_name', 'workload_revision', 'cgroup_id', 'window_end')
COMPARED = (*SCORE_FIELDS, 'status', 'candidate_alert_preview')


def key_of(row):
    return tuple(str(row.get(name)) for name in KEY)


def frames(path: Path):
    """Group feature records by snapshot boundary, preserving file order."""
    current, boundary = [], None
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            if not line.endswith('\n'):
                break
            record = json.loads(line)
            if 'window_end' not in record:
                continue  # feature-schema header
            end = float(record['window_end'])
            if boundary is not None and end != boundary:
                yield boundary, current
                current = []
            boundary = end
            current.append(record)
    if current:
        yield boundary, current


def replay_segment(segment: Path, scorer, policy, limit=None):
    recorded = {}
    with (segment / 'decisions.jsonl').open(encoding='utf-8') as stream:
        for line in stream:
            if line.endswith('\n'):
                row = json.loads(line)
                if 'window_end' in row:
                    recorded[key_of(row)] = row
    runtime = IdleBatchRuntime(scorer, policy)
    counts = defaultdict(int)
    max_diff = defaultdict(float)
    mismatches = []
    last = None
    for boundary, records in frames(segment / 'features.jsonl'):
        if last is not None and not .35 <= boundary - last <= .8:
            runtime.history.histories.clear()  # worker clears on cadence gaps
            counts['cadence_resets'] += 1
        last = boundary
        for offset in range(0, len(records), 256):
            batch = records[offset:offset + 256]
            for record, decision in zip(batch, runtime.observe_many(batch)):
                decision.update({k: record[k] for k in KEY if k in record})
                old = recorded.get(key_of(decision))
                if old is None:
                    counts['missing_recorded_decision'] += 1
                    continue
                counts['compared'] += 1
                if old.get('status') != 'candidate-raw-score-only' and decision.get('status') != 'candidate-raw-score-only':
                    counts['both_unscored'] += 1
                    continue
                diff = [name for name in COMPARED if old.get(name) != decision.get(name)]
                for name in SCORE_FIELDS:
                    a, b = old.get(name), decision.get(name)
                    if isinstance(a, float) and isinstance(b, float) and math.isfinite(a) and math.isfinite(b):
                        max_diff[name] = max(max_diff[name], abs(a - b))
                if diff:
                    counts['mismatched'] += 1
                    if len(mismatches) < 20:
                        mismatches.append(dict(key=key_of(decision), fields=diff,
                                               recorded={n: old.get(n) for n in diff},
                                               replayed={n: decision.get(n) for n in diff}))
                else:
                    counts['exact_scored_match'] += 1
        if limit is not None and counts['compared'] >= limit:
            break
    return dict(segment=str(segment), counts=dict(counts), max_abs_difference=dict(max_diff),
                sample_mismatches=mismatches)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--segment', type=Path, action='append', required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--model-hash', required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-hash', required=True)
    parser.add_argument('--limit-per-segment', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('output exists; choose a new path')
    started = time.time()
    scorer = IdleCandidateScorer(args.candidate, args.model_hash)
    policy = load_preview_policy(args.policy, scorer)
    if policy.sha256 != args.policy_hash:
        raise SystemExit('policy hash differs')
    segments = [replay_segment(s, scorer, policy, args.limit_per_segment) for s in args.segment]
    scored = sum(s['counts'].get('exact_scored_match', 0) + s['counts'].get('mismatched', 0) for s in segments)
    mismatched = sum(s['counts'].get('mismatched', 0) for s in segments)
    package = Path(__file__).resolve().parents[1]
    result = dict(schema='pulse-scorer-equivalence-v1', model_hash=args.model_hash, policy_hash=args.policy_hash,
                  scored_rows_compared=scored, mismatched_rows=mismatched,
                  equivalent=scored > 0 and mismatched == 0, segments=segments,
                  source_sha256={str(p.relative_to(package)): sha256_file(p)
                                 for p in sorted(package.rglob('*.py'))},
                  started_at_unix=started, finished_at_unix=time.time())
    atomic_json(args.output, result)
    print(json.dumps({k: v for k, v in result.items() if k not in ('segments', 'source_sha256')}))
    return 0 if result['equivalent'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
