"""Compare R4 syscall arms at a matched normal alert budget after recalibration.

Under the frozen calibration every arm was dominated by the same drift, so
the arms could not be told apart (18.6-20.8 episodes/hour, within seed
noise). This applies the remedy that worked for Pulse to every arm alike:

1. per model (workload|arm|seed), recalibrate p-values on the earliest
   ``calibration_fraction`` of the sealed normal holdout (score dump);
2. count normal alert episodes on the rest of the holdout for a grid of
   alpha scales;
3. score the R3/R5 attack/control intervals (arm attack replay) with the
   same calibration and scales;
4. for each episode budget, give every arm its loosest scale within budget
   and report recall, control-positive rate and detection delay there.

Evidence class: development (R3/R5 scenarios were exposed while building the
Pulse candidate; the holdout is unadjudicated normal). Delay is
``first positive window_end - kernel_event_at``, a lower bound on
kernel->alert.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

import numpy as np

from ..common import atomic_json
from ..detector.support_model import pvalues
from ..integrity import sha256_file
from .arm_attack_replay import interval_outcome, load_trials
from .score_dump import load_study

EPISODE_QUIET_SECONDS = 15.0
WINDOW_SECONDS = 0.5
SCALES = (0.5, 1, 1.5, 2, 3, 4, 5, 7, 10, 15, 20, 30)
BUDGETS = (0.1, 1.0, 5.0, 18.0)
MINIMUM_CALIBRATION = 1200


def joint_p(tree, support, cal_tree, cal_support):
    return np.minimum(1.0, 2*np.minimum(pvalues(tree, cal_tree), pvalues(support, cal_support)))


def count_episodes(identity, window_end, positive, quiet=EPISODE_QUIET_SECONDS):
    """Positive windows of one container separated by < quiet merge into one episode."""
    if not positive.any():
        return 0
    order = np.lexsort((window_end[positive], identity[positive]))
    ids, ends = identity[positive][order], window_end[positive][order]
    new = np.ones(len(ids), dtype=bool)
    new[1:] = (ids[1:] != ids[:-1]) | (ends[1:]-ends[:-1] >= quiet)
    return int(new.sum())


def load_holdout(dump_root: Path, arm: str):
    """tag -> dict(identity, window_end, tree, support) for every model of one arm."""
    parts = defaultdict(lambda: defaultdict(list))
    global_ids = {}
    for npz in sorted(dump_root.glob('*/s*/scores.npz')):
        with np.load(npz, allow_pickle=False) as data:
            # identity indexes are local to each file; map them to one global numbering
            local = np.array([global_ids.setdefault(json.dumps(k), len(global_ids))
                              for k in json.loads(str(data['identities']))], dtype=np.int64)
            for name in data.files:
                if '::' not in name:
                    continue
                tag, field = name.rsplit('::', 1)
                if tag.split('|')[1] != arm:
                    continue
                values = data[name]
                parts[tag][field].append(local[values] if field == 'identity' else values)
    out = {}
    for tag, fields in parts.items():
        order_end = np.concatenate(fields['window_end'])
        order = np.argsort(order_end, kind='stable')
        out[tag] = dict(identity=np.concatenate(fields['identity'])[order], window_end=order_end[order],
                        tree=np.concatenate(fields['tree_score']).astype(np.float64)[order],
                        support=np.concatenate(fields['support_score']).astype(np.float64)[order])
    return out


def load_replay(replay: Path):
    """tag -> trial_id -> windows (with tree/support scores and the model alpha)."""
    out = defaultdict(dict)
    with (replay/'windows.jsonl').open() as stream:
        for line in stream:
            row = json.loads(line)
            out[row['tag']][row['trial_id']] = row['windows']
    return out


def evaluate_arm(arm, holdout, replay, trials, split_at, scales=SCALES):
    rows = defaultdict(lambda: dict(episodes=0, windows=0, positive=0, counts=defaultdict(int), delays=[]))
    calibrated_models, skipped = 0, []
    for tag, h in sorted(holdout.items()):
        cal = h['window_end'] < split_at
        ev = ~cal
        if min(cal.sum(), ev.sum()) < MINIMUM_CALIBRATION:
            skipped.append(tag); continue
        cal_tree, cal_support = np.sort(h['tree'][cal]), np.sort(h['support'][cal])
        p = joint_p(h['tree'][ev], h['support'][ev], cal_tree, cal_support)
        trial_windows = replay.get(tag, {})
        alpha = next((w[0]['alpha'] for w in trial_windows.values() if w), None)
        if alpha is None:
            skipped.append(tag); continue
        calibrated_models += 1
        seed = tag.split('|')[2]
        rescored = {}
        for trial_id, windows in trial_windows.items():
            if windows:
                jp = joint_p(np.array([w['tree_score'] for w in windows]), np.array([w['support_score'] for w in windows]),
                             cal_tree, cal_support)
                rescored[trial_id] = [dict(w, joint_p=float(j)) for w, j in zip(windows, jp)]
        workload = tag.split('|')[0]
        for scale in scales:
            r = rows[scale, seed]
            positive = p <= alpha*scale
            r['episodes'] += count_episodes(h['identity'][ev], h['window_end'][ev], positive)
            r['windows'] += int(ev.sum()); r['positive'] += int(positive.sum())
            for trial in trials:
                if trial['workload_key'] != workload:
                    continue
                result = interval_outcome(rescored.get(trial['trial_id'], []), trial, lambda w: alpha*scale)
                kind = 'benign' if trial.get('control_kind') == 'benign_exec' else trial['label']
                r['counts'][f"{kind}:{result['outcome']}"] += 1
                if result['delay'] is not None:
                    r['delays'].append(result['delay'])
    table = {}
    for scale in scales:
        per_seed = []
        delays = []
        for (s, seed), r in rows.items():
            if s != scale:
                continue
            c = r['counts']
            tp, fn = c['attack:TP'], c['attack:FN']
            fp, tn = c['expected_normal:FP_expected'], c['expected_normal:TN_expected']
            hours = r['windows']*WINDOW_SECONDS/3600
            per_seed.append(dict(seed=seed, episodes_per_replica_hour=r['episodes']/hours if hours else None,
                                 positive_window_rate=r['positive']/r['windows'] if r['windows'] else None,
                                 recall=tp/(tp+fn) if tp+fn else None,
                                 control_positive_rate=fp/(fp+tn) if fp+tn else None,
                                 precision_1to1=tp/(tp+fp) if tp+fp else None, TP=tp, FN=fn, FP=fp, TN=tn))
            delays += r['delays']
        mean = lambda k: float(np.mean([s[k] for s in per_seed if s[k] is not None])) if per_seed else None
        table[f'{scale:g}'] = dict(seeds=per_seed, episodes_per_replica_hour=mean('episodes_per_replica_hour'),
            positive_window_rate=mean('positive_window_rate'), recall=mean('recall'),
            control_positive_rate=mean('control_positive_rate'), precision_1to1=mean('precision_1to1'),
            delay_p50=float(np.percentile(delays, 50)) if delays else None,
            delay_p95=float(np.percentile(delays, 95)) if delays else None)
    return dict(scales=table, calibrated_models=calibrated_models, skipped_models=skipped)


def matched(arms, budgets=BUDGETS):
    out = {}
    for budget in budgets:
        out[f'{budget:g}'] = {}
        for arm, result in arms.items():
            within = [(float(s), v) for s, v in result['scales'].items()
                      if v['episodes_per_replica_hour'] is not None and v['episodes_per_replica_hour'] <= budget]
            if not within:
                out[f'{budget:g}'][arm] = None; continue
            scale, v = max(within, key=lambda sv: sv[0])
            out[f'{budget:g}'][arm] = dict(alpha_scale=scale, **{k: v[k] for k in (
                'episodes_per_replica_hour', 'recall', 'control_positive_rate', 'precision_1to1', 'delay_p50', 'delay_p95')})
    return out


def run(study: Path, dump_root: Path, replay: Path, campaigns, output: Path, calibration_fraction=0.2):
    registration, index, _ = load_study(study)
    begin, finish = registration['holdout_start_unix'], registration['planned_end_unix']
    split_at = begin + calibration_fraction*(finish-begin)
    trials = load_trials(campaigns)
    windows = load_replay(replay)
    arms = {}
    for arm in sorted(index['arms']):
        arms[arm] = evaluate_arm(arm, load_holdout(dump_root, arm), windows, trials, split_at)
        print(arm, {s: round(v['episodes_per_replica_hour'] or -1, 2) for s, v in arms[arm]['scales'].items()}, flush=True)
    result = dict(schema='pulse-r4-arm-budget-v1', study=str(study), dump_root=str(dump_root), replay=str(replay),
                  campaigns=[str(c) for c in campaigns], calibration_fraction=calibration_fraction,
                  calibration_span_unix=[begin, split_at], evaluation_span_unix=[split_at, finish],
                  episode_quiet_seconds=EPISODE_QUIET_SECONDS, scales=list(SCALES), budgets=list(BUDGETS),
                  evidence_class='development; unadjudicated normal holdout; R3/R5 scenarios previously exposed',
                  delay_definition='first positive window_end - kernel_event_at (lower bound on kernel->alert)',
                  arms=arms, matched_budget=matched(arms),
                  source_sha256=sha256_file(Path(__file__)), finished_at_unix=time.time())
    output.mkdir(parents=True, exist_ok=False)
    atomic_json(output/'RESULTS.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study', type=Path, required=True)
    parser.add_argument('--dump-root', type=Path, required=True)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--campaign', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--calibration-fraction', type=float, default=0.2)
    args = parser.parse_args()
    result = run(args.study.resolve(), args.dump_root, args.replay, args.campaign, args.output, args.calibration_fraction)
    for budget, arms in result['matched_budget'].items():
        print('== budget', budget, 'episodes/replica-hour')
        for arm, v in sorted(arms.items(), key=lambda kv: -(kv[1] or {}).get('recall', -1) if kv[1] else 1):
            print(arm, v)


if __name__ == '__main__':
    main()
