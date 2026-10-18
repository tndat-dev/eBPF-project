"""Development study: how temporal confirmation trades alert burden for recall.

``normal``  streams one worker's sealed 48 h soak decisions and counts, per
            policy, positive windows and alert episodes per scored hour.
``attack``  replays recorded attack/control pairs (R3, R5) through the same
            interval evaluator used for the published matrix.

Both inputs were already used to develop the current candidate, so results
are development evidence only. The chosen policy must be frozen and then
tested on fresh blind attacks and independent normal data.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

from ..common import atomic_json
from ..detector.confirmation import IDENTITY, SCORED, ConfirmationPolicy, ConfirmationState, apply, default_grid
from ..integrity import sha256_file
from .preview_evaluation import evaluate_interval, summarize

MODEL_HASH = '747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08'
POLICY_HASH = 'fd0be94a4ca7f2cd64b97bf5c7dc074763405f821ab346e8e19bb5975d10f401'
EPISODE_QUIET_SECONDS = 15.0


class EpisodeCounter:
    """Merge positive windows of one container separated by < quiet gap."""

    def __init__(self, quiet=EPISODE_QUIET_SECONDS):
        self.quiet = quiet
        self.last = {}
        self.episodes = defaultdict(int)
        self.windows = defaultdict(int)

    def add(self, workload, key, at):
        self.windows[workload] += 1
        previous = self.last.get(key)
        if previous is None or at - previous >= self.quiet:
            self.episodes[workload] += 1
        self.last[key] = at


def normal_burden(worker_root: Path, policies, model_hash=MODEL_HASH, policy_hash=POLICY_HASH):
    segments = sorted(p for p in (worker_root / 'segments').iterdir() if p.is_dir())
    states = {p.name: ConfirmationState(p) for p in policies}
    counters = {p.name: EpisodeCounter() for p in policies}
    scored_seconds = defaultdict(float)
    scored_windows = defaultdict(int)
    frozen_positive = defaultdict(int)
    mismatched_binding = 0
    for segment in segments:
        path = segment / 'decisions.jsonl'
        if not path.exists():
            continue
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                if '"joint_p"' not in line or not line.endswith('\n'):
                    continue
                row = json.loads(line)
                if row.get('status') != SCORED or row.get('policy_evaluated') is not True:
                    continue
                if row.get('candidate_manifest_sha256') != model_hash or row.get('policy_sha256') != policy_hash:
                    mismatched_binding += 1
                    continue
                workload = row['workload_key']
                key = tuple(str(row.get(name)) for name in IDENTITY)
                begin, end = float(row['window_start']), float(row['window_end'])
                scored_windows[workload] += 1
                scored_seconds[workload] += max(0.0, end - begin)
                frozen_positive[workload] += row.get('candidate_alert_preview') is True
                for name, state in states.items():
                    if state.update(row):
                        counters[name].add(workload, key, end)
    hours = {w: s / 3600 for w, s in scored_seconds.items()}
    results = {}
    for policy in policies:
        c = counters[policy.name]
        results[policy.name] = dict(
            policy=dict(k=policy.k, n=policy.n, alpha_scale=policy.alpha_scale),
            positive_windows=dict(c.windows), episodes=dict(c.episodes),
            total_positive_windows=sum(c.windows.values()), total_episodes=sum(c.episodes.values()),
            episodes_per_scored_hour=sum(c.episodes.values()) / sum(hours.values()) if hours else None)
    baseline = results.get('k1of1_a1')
    return dict(
        schema='pulse-confirmation-normal-burden-v1', worker_root=str(worker_root),
        node_name=worker_root.name, segments=len(segments), model_hash=model_hash, policy_hash=policy_hash,
        scored_windows=dict(scored_windows), scored_hours=hours, total_scored_hours=sum(hours.values()),
        frozen_positive_windows=dict(frozen_positive), mismatched_binding_rows=mismatched_binding,
        baseline_reproduces_frozen_previews=None if baseline is None
            else baseline['total_positive_windows'] == sum(frozen_positive.values()),
        episode_quiet_seconds=EPISODE_QUIET_SECONDS, labels='unadjudicated normal soak; positives are not confirmed FP',
        policies=results)


def attack_replay(campaign_roots, policies, model_hash=MODEL_HASH, policy_hash=POLICY_HASH):
    inputs, preserved = [], []
    for root in campaign_roots:
        results = json.loads((root / 'RESULTS.json').read_text())
        for key, pair in sorted(results['completed'].items(), key=lambda item: int(item[0])):
            path = root / 'trials' / f'{int(key):04d}' / 'EVALUATION_INPUT.json'
            if path.exists():
                inputs.append((root.name, int(key), path, json.loads(path.read_text())))
            else:
                # No saved rows: keep the recorded (unknown/infrastructure) outcomes.
                preserved.extend(pair)
    report = {}
    for policy in policies:
        outcomes = list(preserved)
        for _campaign, key, _path, data in inputs:
            rows = apply(data['decisions'], policy)
            for label in ('control', 'attack'):
                trial = data[label]
                if trial['trial_id'] != f'{key}:{label}':
                    raise ValueError('saved trial identity differs')
                outcomes.append(evaluate_interval(rows, trial, model_hash, policy_hash))
        report[policy.name] = dict(policy=dict(k=policy.k, n=policy.n, alpha_scale=policy.alpha_scale),
                                   minimum_added_delay_seconds=policy.minimum_added_delay_seconds,
                                   **summarize(outcomes))
    return dict(schema='pulse-confirmation-attack-replay-v1', campaigns=[str(r) for r in campaign_roots],
                replayed_pairs=len(inputs), preserved_outcomes_without_rows=len(preserved),
                evaluation_inputs_sha256={str(p): sha256_file(p) for _c, _k, p, _d in inputs},
                fresh_blind=False, evidence_class='development_replay_of_exposed_scenarios',
                policies=report)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    normal = sub.add_parser('normal')
    normal.add_argument('--worker-root', type=Path, required=True)
    normal.add_argument('--output', type=Path, required=True)
    attack = sub.add_parser('attack')
    attack.add_argument('--campaign', type=Path, action='append', required=True)
    attack.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('output exists; choose a new path')
    policies = default_grid()
    started = time.time()
    if args.command == 'normal':
        result = normal_burden(args.worker_root, policies)
    else:
        result = attack_replay(args.campaign, policies)
    result.update(source_sha256=sha256_file(Path(__file__)), grid=[p.name for p in policies],
                  started_at_unix=started, finished_at_unix=time.time(), automatic_promotion=False)
    atomic_json(args.output, result)
    print(json.dumps({k: v for k, v in result.items() if k not in ('policies', 'evaluation_inputs_sha256')})[:2000])


if __name__ == '__main__':
    main()
