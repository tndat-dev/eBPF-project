"""Development study: alert burden vs recall under confirmation and recalibration.

``calibrate``  collects per-workload normal tree/support scores from sealed
               soak decisions inside a registered time span.
``normal``     streams one worker's sealed soak decisions and counts, per
               policy, positive windows and alert episodes per scored hour.
``attack``     replays recorded attack/control pairs (pulse-attack-dev, pulse-attack-dev-rabbitmq) through the same
               interval evaluator used for the published matrix.

``normal`` and ``attack`` optionally recompute p-values against a calibration
file before applying each confirmation policy. All inputs were already used
while developing the current candidate, so results are development evidence
only. A chosen policy must be frozen and then tested on fresh blind attacks
and independent normal data.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

from ..common import atomic_json, open_sealed, sealed_path
from ..detector.confirmation import IDENTITY, SCORED, ConfirmationState, apply, default_grid, looser_grid
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


def in_spans(begin, end, spans):
    return any(end > a and begin < b for a, b in spans)


def scored_rows(worker_root: Path, model_hash=MODEL_HASH, policy_hash=POLICY_HASH,
                since=None, until=None, exclude=(), stats=None):
    """Yield bound, policy-evaluated scored rows of one worker in segment order."""
    stats = stats if stats is not None else defaultdict(int)
    for segment in sorted(p for p in (worker_root / 'segments').iterdir() if p.is_dir()):
        stats['segments'] += 1
        path = sealed_path(segment / 'decisions.jsonl')
        if not path.exists():
            continue
        with open_sealed(segment / 'decisions.jsonl') as stream:
            for line in stream:
                if '"joint_p"' not in line or not line.endswith('\n'):
                    continue
                row = json.loads(line)
                if row.get('status') != SCORED or row.get('policy_evaluated') is not True:
                    continue
                if row.get('candidate_manifest_sha256') != model_hash or row.get('policy_sha256') != policy_hash:
                    stats['mismatched_binding_rows'] += 1
                    continue
                begin, end = float(row['window_start']), float(row['window_end'])
                if (since is not None and begin < since) or (until is not None and end > until):
                    continue
                if in_spans(begin, end, exclude):
                    stats['excluded_rows'] += 1
                    continue
                yield row


def normal_burden(worker_root: Path, policies, model_hash=MODEL_HASH, policy_hash=POLICY_HASH,
                  since=None, until=None, exclude=(), recalibrator=None):
    states = {p.name: ConfirmationState(p) for p in policies}
    counters = {p.name: EpisodeCounter() for p in policies}
    scored_seconds = defaultdict(float)
    scored_windows = defaultdict(int)
    frozen_positive = defaultdict(int)
    stats = defaultdict(int)
    for row in scored_rows(worker_root, model_hash, policy_hash, since, until, exclude, stats):
        if recalibrator is not None:
            row = recalibrator.rewrite(row)
            if row is None:
                stats['uncalibrated_rows'] += 1
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
        node_name=worker_root.name, model_hash=model_hash, policy_hash=policy_hash,
        since_unix=since, until_unix=until, excluded_spans=[list(s) for s in exclude],
        recalibrated=recalibrator is not None, stats=dict(stats),
        scored_windows=dict(scored_windows), scored_hours=hours, total_scored_hours=sum(hours.values()),
        frozen_positive_windows=dict(frozen_positive),
        baseline_reproduces_frozen_previews=None if baseline is None or recalibrator is not None
            else baseline['total_positive_windows'] == sum(frozen_positive.values()),
        episode_quiet_seconds=EPISODE_QUIET_SECONDS, labels='unadjudicated normal soak; positives are not confirmed FP',
        policies=results)


def calibration_scores(worker_roots, since, until, exclude=(), model_hash=MODEL_HASH, policy_hash=POLICY_HASH):
    """Per-workload normal tree/support scores pooled over workers."""
    tree, support = defaultdict(list), defaultdict(list)
    stats = defaultdict(int)
    for root in worker_roots:
        for row in scored_rows(root, model_hash, policy_hash, since, until, exclude, stats):
            if row.get('eligible_for_normal_review') is not True:
                stats['ineligible_rows'] += 1
                continue
            tree[row['workload_key']].append(float(row['tree_score']))
            support[row['workload_key']].append(float(row['support_score']))
    return dict(tree), dict(support), dict(stats)


def save_calibration(path: Path, tree, support, metadata):
    import numpy as np
    arrays = {f'tree::{k}': np.asarray(v, dtype=np.float64) for k, v in tree.items()}
    arrays.update({f'support::{k}': np.asarray(v, dtype=np.float64) for k, v in support.items()})
    with path.open('xb') as stream:
        np.savez_compressed(stream, metadata=np.array(json.dumps(metadata, sort_keys=True)), **arrays)


def load_calibration(path: Path, minimum_examples=1200):
    import numpy as np
    from ..detector.recalibration import Recalibrator
    data = np.load(path, allow_pickle=False)
    tree = {k.split('::', 1)[1]: data[k] for k in data.files if k.startswith('tree::')}
    support = {k.split('::', 1)[1]: data[k] for k in data.files if k.startswith('support::')}
    return Recalibrator(tree, support, minimum_examples), json.loads(str(data['metadata']))


def attack_replay(campaign_roots, policies, model_hash=MODEL_HASH, policy_hash=POLICY_HASH, recalibrator=None):
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

    def prepared(rows):
        if recalibrator is None:
            return rows
        out = []
        for row in rows:
            if row.get('status') == SCORED and row.get('joint_p') is not None:
                # Missing calibration removes scored exposure, so the interval becomes unknown.
                row = recalibrator.rewrite(row) or dict(row, status='uncalibrated')
            out.append(row)
        return out
    report = {}
    for policy in policies:
        outcomes = list(preserved)
        for _campaign, key, _path, data in inputs:
            rows = apply(prepared(data['decisions']), policy)
            for label in ('control', 'benign', 'attack'):
                if label not in data:
                    continue
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
                recalibrated=recalibrator is not None, fresh_blind=False,
                evidence_class='development_replay_of_exposed_scenarios', policies=report)


def span(text):
    begin, end = (float(x) for x in text.split(':'))
    if not begin < end:
        raise argparse.ArgumentTypeError('span must be START:END unix seconds')
    return begin, end


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('normal', 'attack', 'calibrate'):
        p = sub.add_parser(name)
        p.add_argument('--output', type=Path, required=True)
        if name != 'attack':
            p.add_argument('--since', type=float)
            p.add_argument('--until', type=float)
            p.add_argument('--exclude', type=span, action='append', default=[])
        if name != 'calibrate':
            p.add_argument('--calibration', type=Path)
            p.add_argument('--grid', choices=('default', 'looser'), default='default')
        # defaults: the frozen 15/10 candidate; pulse-live-recalibrated rows carry ec72d9ea.../f6107351...
        p.add_argument('--model-hash', default=MODEL_HASH)
        p.add_argument('--policy-hash', default=POLICY_HASH)
    sub.choices['normal'].add_argument('--worker-root', type=Path, required=True)
    sub.choices['calibrate'].add_argument('--worker-root', type=Path, action='append', required=True)
    sub.choices['attack'].add_argument('--campaign', type=Path, action='append', required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('output exists; choose a new path')
    started = time.time()
    if args.command == 'calibrate':
        if args.since is None or args.until is None:
            raise SystemExit('calibration requires --since and --until')
        tree, support, stats = calibration_scores(args.worker_root, args.since, args.until, args.exclude,
                                                  args.model_hash, args.policy_hash)
        metadata = dict(schema='pulse-recalibration-scores-v1', worker_roots=[str(r) for r in args.worker_root],
                        since_unix=args.since, until_unix=args.until, excluded_spans=[list(s) for s in args.exclude],
                        sizes={k: len(v) for k, v in tree.items()}, stats=stats, model_hash=args.model_hash,
                        policy_hash=args.policy_hash, source_sha256=sha256_file(Path(__file__)),
                        started_at_unix=started, finished_at_unix=time.time())
        save_calibration(args.output, tree, support, metadata)
        print(json.dumps(metadata)[:2000])
        return
    recalibrator, calibration = None, None
    if args.calibration is not None:
        recalibrator, calibration = load_calibration(args.calibration)
    policies = looser_grid() if args.grid == 'looser' else default_grid()
    if args.command == 'normal':
        result = normal_burden(args.worker_root, policies, args.model_hash, args.policy_hash, since=args.since,
                               until=args.until, exclude=args.exclude, recalibrator=recalibrator)
    else:
        result = attack_replay(args.campaign, policies, args.model_hash, args.policy_hash, recalibrator=recalibrator)
    if args.calibration is not None:
        result.update(calibration_file=str(args.calibration), calibration_sha256=sha256_file(args.calibration),
                      calibration_metadata=calibration, usable_calibrated_workloads=sorted(recalibrator.usable))
    result.update(source_sha256=sha256_file(Path(__file__)), grid=[p.name for p in policies],
                  started_at_unix=started, finished_at_unix=time.time(), automatic_promotion=False)
    atomic_json(args.output, result)
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ('policies', 'evaluation_inputs_sha256', 'calibration_metadata')})[:2000])


if __name__ == '__main__':
    main()
