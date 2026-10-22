"""Compare syscall-arms syscall arms at a matched normal alert budget after recalibration.

Under the frozen calibration every arm was dominated by the same drift, so
the arms could not be told apart (18.6-20.8 episodes/hour, within seed
noise). This applies the remedy that worked for Pulse to every arm alike:

1. per model (workload|arm|seed), recalibrate p-values on the earliest
   ``calibration_fraction`` of the sealed normal holdout (score dump);
2. count normal alert episodes on the rest of the holdout for a grid of
   alpha scales;
3. score the pulse-attack-dev attack/control intervals (arm attack replay) with the
   same calibration and scales;
4. for each episode budget, give every arm its loosest scale within budget
   and report recall, control-positive rate and detection delay there.

``--confirm-k/--confirm-n`` apply Pulse's k-of-n temporal confirmation
(``detector/confirmation.py``) to every arm alike, both on the normal holdout and
on the attack/control windows: a window is positive only if it passes and at least
k of the last n windows of the same container passed, history restarting after a
gap. Default 1-of-1 is the single-window rule used before.

``--cusum-drift b`` applies Pulse's stable temporal rule instead (CUSUM on -ln p with drift b, alarm at S >= h,
S restarting after a gap, as ``detector/confirmation.CusumState``; 22/10, Pulse 5.19). The grid is then over the
CUSUM threshold h instead of the alpha scale, and the matched budget gives every arm its lowest h within budget.
Output keys stay the same (the grid value is reported as ``alpha_scale`` too) so arm_bootstrap / arm_scenarios
read it unchanged.

Evidence class: development (pulse-attack-dev scenarios were exposed while building the
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
from .arm_attack_replay import interval_outcome, load_trials, trial_key
from .score_dump import load_study

EPISODE_QUIET_SECONDS = 15.0
WINDOW_SECONDS = 0.5
SCALES = (0.5, 1, 1.5, 2, 3, 4, 5, 7, 10, 15, 20, 30)
BUDGETS = (0.1, 1.0, 5.0, 18.0)
CUSUM_THRESHOLDS = (1, 2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 25, 30, 40)
MINIMUM_CALIBRATION = 1200


def joint_p(tree, support, cal_tree, cal_support):
    return np.minimum(1.0, 2*np.minimum(pvalues(tree, cal_tree), pvalues(support, cal_support)))


PVALUES = ('joint', 'tree', 'support')


def combined_p(kind, tree, support, cal_tree, cal_support):
    """Pulse's joint p-value, or one branch alone (feature-group study: is each branch needed?)."""
    if kind == 'joint':
        return joint_p(tree, support, cal_tree, cal_support)
    if kind == 'tree':
        return pvalues(tree, cal_tree)
    if kind == 'support':
        return pvalues(support, cal_support)
    raise ValueError(f'unknown p-value kind {kind}')


def count_episodes(identity, window_end, positive, quiet=EPISODE_QUIET_SECONDS):
    """Positive windows of one container separated by < quiet merge into one episode."""
    if not positive.any():
        return 0
    order = np.lexsort((window_end[positive], identity[positive]))
    ids, ends = identity[positive][order], window_end[positive][order]
    new = np.ones(len(ids), dtype=bool)
    new[1:] = (ids[1:] != ids[:-1]) | (ends[1:]-ends[:-1] >= quiet)
    return int(new.sum())


MAX_GAP_SECONDS = 1.0        # as ConfirmationPolicy.max_gap_seconds


def confirm(identity, window_end, passed, k=1, n=1, max_gap=MAX_GAP_SECONDS):
    """Vectorised k-of-n confirmation, aligned with the inputs.

    Mirrors ``ConfirmationState``: windows of one container in time order; the history
    restarts when the next window starts more than ``max_gap`` after the previous one
    ended or overlaps it by more than 0.25 s. Window starts are taken as
    ``window_end - WINDOW_SECONDS`` (score dumps keep only window_end)."""
    passed = np.asarray(passed, dtype=bool)
    if k == 1 and n == 1:
        return passed.copy()
    order = np.lexsort((window_end, identity))
    ids, ends, ok = np.asarray(identity)[order], np.asarray(window_end, dtype=np.float64)[order], passed[order]
    starts = ends - WINDOW_SECONDS
    new_run = np.ones(len(ids), dtype=bool)
    if len(ids) > 1:
        new_run[1:] = (ids[1:] != ids[:-1]) | (starts[1:] - ends[:-1] > max_gap) | (starts[1:] < ends[:-1] - 0.25)
    run_start = np.maximum.accumulate(np.where(new_run, np.arange(len(ids)), 0))
    cs = np.concatenate(([0], np.cumsum(ok)))
    idx = np.arange(len(ids))
    lo = np.maximum(idx - n + 1, run_start)
    out_sorted = ok & (cs[idx + 1] - cs[lo] >= k)
    out = np.empty_like(out_sorted)
    out[order] = out_sorted
    return out


def cusum_scores(identity, window_end, x, drift, max_gap=MAX_GAP_SECONDS):
    """CUSUM statistic S per window, aligned with the inputs: S_t = max(0, S_{t-1} + x_t - drift) over the windows
    of one container in time order, restarting (S = 0 before the window) on the same gaps as ``confirm``.
    Vectorised Page recursion: S_t = C_t - min(0, min_{j<=t} C_j), C the within-run cumulative sum."""
    order = np.lexsort((window_end, identity))
    ids, ends = np.asarray(identity)[order], np.asarray(window_end, dtype=np.float64)[order]
    y = np.asarray(x, dtype=np.float64)[order] - drift
    starts = ends - WINDOW_SECONDS
    new_run = np.ones(len(ids), dtype=bool)
    if len(ids) > 1:
        new_run[1:] = (ids[1:] != ids[:-1]) | (starts[1:] - ends[:-1] > max_gap) | (starts[1:] < ends[:-1] - 0.25)
    out = np.empty(len(ids))
    if not len(ids):
        return out
    run = np.cumsum(new_run) - 1
    g = np.cumsum(y)
    first = np.flatnonzero(new_run)
    c = g - (g[first] - y[first])[run]
    k = 2*float(np.max(np.abs(c))) + 10.0
    m = np.minimum.accumulate(c - run*k) + run*k        # later runs sit far lower: the running min never crosses back
    out[order] = c - np.minimum(0.0, m)
    return out


def cusum_alarms(identity, window_end, x, drift, threshold, on_alarm='keep', max_gap=MAX_GAP_SECONDS):
    """Alarms aligned with the inputs, with CusumState semantics including ``on_alarm`` (keep / cap / restart,
    stable-selection-v1 amendment 1). keep uses the vectorised statistic; cap and restart a loop per call."""
    if on_alarm == 'keep':
        return cusum_scores(identity, window_end, x, drift, max_gap) >= threshold
    order = np.lexsort((window_end, identity))
    ids, ends = np.asarray(identity)[order], np.asarray(window_end, dtype=np.float64)[order]
    starts = ends - WINDOW_SECONDS
    new_run = np.ones(len(ids), dtype=bool)
    if len(ids) > 1:
        new_run[1:] = (ids[1:] != ids[:-1]) | (starts[1:] - ends[:-1] > max_gap) | (starts[1:] < ends[:-1] - 0.25)
    y = (np.asarray(x, dtype=np.float64)[order] - drift).tolist()
    alarm, s = np.zeros(len(ids), dtype=bool), 0.0
    for i, (yi, ni) in enumerate(zip(y, new_run.tolist())):
        if ni:
            s = 0.0
        s = max(0.0, s + yi)
        if s >= threshold:
            alarm[i] = True
            s = threshold if on_alarm == 'cap' else 0.0
    out = np.empty_like(alarm)
    out[order] = alarm
    return out


def cusum_windows(windows, drift, threshold, on_alarm='keep'):
    """Trial windows with ``joint_p`` 0 where CUSUM alarms and +inf elsewhere (compare against 0.5)."""
    if not windows:
        return windows
    ends = np.array([float(w['end']) for w in windows])
    x = -np.log(np.maximum(np.array([w['joint_p'] for w in windows], dtype=np.float64), 1e-12))
    alarm = cusum_alarms(np.zeros(len(windows), dtype=np.int64), ends, x, drift, threshold, on_alarm)
    return [dict(w, raw_joint_p=w['joint_p'], joint_p=0.0 if a else float('inf')) for w, a in zip(windows, alarm)]


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
    """tag -> trial key -> windows (with tree/support scores and the model alpha).

    Replays written before 19/10 18:00 keyed trials by bare trial_id, which repeats across
    campaigns; they are refused rather than silently mis-joined."""
    out = defaultdict(dict)
    with (replay/'windows.jsonl').open() as stream:
        for line in stream:
            row = json.loads(line)
            if 'trial_key' not in row:
                raise ValueError('replay keyed by bare trial_id (ambiguous across campaigns); re-run arm_attack_replay')
            out[row['tag']][row['trial_key']] = row['windows']
    return out


def evaluate_arm(arm, holdout, replay, trials, split_at, scales=SCALES, outcomes=None, confirmation=(1, 1),
                 pvalue='joint', cusum_drift=None, cusum_on_alarm='keep'):
    """``outcomes``, if a list, receives one row per (seed, scale, trial) for paired bootstrap.
    ``confirmation`` = (k, n) temporal confirmation applied to holdout and trial windows.
    ``cusum_drift``: CUSUM instead of k-of-n; ``scales`` are then CUSUM thresholds."""
    k, n = confirmation
    rows = defaultdict(lambda: dict(episodes=0, windows=0, positive=0, counts=defaultdict(int), delays=[]))
    calibrated_models, skipped = 0, []
    for tag, h in sorted(holdout.items()):
        cal = h['window_end'] < split_at
        ev = ~cal
        if min(cal.sum(), ev.sum()) < MINIMUM_CALIBRATION:
            skipped.append(tag); continue
        cal_tree, cal_support = np.sort(h['tree'][cal]), np.sort(h['support'][cal])
        p = combined_p(pvalue, h['tree'][ev], h['support'][ev], cal_tree, cal_support)
        trial_windows = replay.get(tag, {})
        alpha = next((w[0]['alpha'] for w in trial_windows.values() if w), None)
        if alpha is None:
            skipped.append(tag); continue
        calibrated_models += 1
        seed = tag.split('|')[2]
        rescored = {}
        for key, windows in trial_windows.items():
            if windows:
                jp = combined_p(pvalue, np.array([w['tree_score'] for w in windows]),
                                np.array([w['support_score'] for w in windows]), cal_tree, cal_support)
                rescored[key] = [dict(w, joint_p=float(j)) for w, j in zip(windows, jp)]
        workload = tag.split('|')[0]
        if cusum_drift is not None:
            x_ev = -np.log(np.maximum(p, 1e-12))
            stat = cusum_scores(h['identity'][ev], h['window_end'][ev], x_ev, cusum_drift) if cusum_on_alarm == 'keep' else None
        for scale in scales:
            r = rows[scale, seed]
            if cusum_drift is None:
                positive = confirm(h['identity'][ev], h['window_end'][ev], p <= alpha*scale, k, n)
                confirmed = {key: confirmed_windows(windows, alpha*scale, k, n) for key, windows in rescored.items()}
                threshold = alpha*scale
            else:
                positive = (stat >= scale if stat is not None else
                            cusum_alarms(h['identity'][ev], h['window_end'][ev], x_ev, cusum_drift, scale, cusum_on_alarm))
                confirmed = {key: cusum_windows(windows, cusum_drift, scale, cusum_on_alarm) for key, windows in rescored.items()}
                threshold = 0.5
            r['episodes'] += count_episodes(h['identity'][ev], h['window_end'][ev], positive)
            r['windows'] += int(ev.sum()); r['positive'] += int(positive.sum())
            for trial in trials:
                if trial['workload_key'] != workload:
                    continue
                result = interval_outcome(confirmed.get(trial_key(trial), []), trial, lambda w: threshold)
                kind = 'benign' if trial.get('control_kind') == 'benign_exec' else trial['label']
                r['counts'][f"{kind}:{result['outcome']}"] += 1
                if outcomes is not None:
                    outcomes.append(dict(arm=arm, seed=seed, scale=scale, trial_key=trial_key(trial),
                                         workload=workload, kind=kind, outcome=result['outcome'], delay=result['delay']))
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
            bfp, btn = c['benign:FP_expected'], c['benign:TN_expected']
            hours = r['windows']*WINDOW_SECONDS/3600
            per_seed.append(dict(seed=seed, episodes_per_replica_hour=r['episodes']/hours if hours else None,
                                 positive_window_rate=r['positive']/r['windows'] if r['windows'] else None,
                                 recall=tp/(tp+fn) if tp+fn else None,
                                 control_positive_rate=fp/(fp+tn) if fp+tn else None,
                                 precision_1to1=tp/(tp+fp) if tp+fp else None, TP=tp, FN=fn, FP=fp, TN=tn,
                                 benign_positive_rate=bfp/(bfp+btn) if bfp+btn else None))
            delays += r['delays']
        def mean(key):
            values = [s[key] for s in per_seed if s[key] is not None]
            return float(np.mean(values)) if values else None
        table[f'{scale:g}'] = dict(seeds=per_seed, episodes_per_replica_hour=mean('episodes_per_replica_hour'),
            positive_window_rate=mean('positive_window_rate'), recall=mean('recall'),
            control_positive_rate=mean('control_positive_rate'), precision_1to1=mean('precision_1to1'),
            benign_positive_rate=mean('benign_positive_rate'),
            delay_p50=float(np.percentile(delays, 50)) if delays else None,
            delay_p95=float(np.percentile(delays, 95)) if delays else None)
    return dict(scales=table, calibrated_models=calibrated_models, skipped_models=skipped)


def confirmed_windows(windows, threshold, k=1, n=1):
    """Trial windows (one container) with ``joint_p`` set to +inf where confirmation fails, so
    ``interval_outcome`` counts only confirmed positives; the raw value stays in ``raw_joint_p``."""
    if k == 1 and n == 1 or not windows:
        return windows
    ends = np.array([float(w['end']) for w in windows])
    jp = np.array([w['joint_p'] for w in windows])
    ok = confirm(np.zeros(len(windows), dtype=np.int64), ends, jp <= threshold, k, n)
    return [dict(w, raw_joint_p=w['joint_p'], joint_p=w['joint_p'] if c else float('inf')) for w, c in zip(windows, ok)]


def matched(arms, budgets=BUDGETS, loosest=max):
    """Per budget, every arm at its loosest grid value within budget: the largest alpha scale, or (``loosest=min``)
    the lowest CUSUM threshold."""
    out = {}
    for budget in budgets:
        out[f'{budget:g}'] = {}
        for arm, result in arms.items():
            within = [(float(s), v) for s, v in result['scales'].items()
                      if v['episodes_per_replica_hour'] is not None and v['episodes_per_replica_hour'] <= budget]
            if not within:
                out[f'{budget:g}'][arm] = None; continue
            scale, v = loosest(within, key=lambda sv: sv[0])
            out[f'{budget:g}'][arm] = dict(alpha_scale=scale, **{k: v[k] for k in (
                'episodes_per_replica_hour', 'recall', 'control_positive_rate', 'precision_1to1',
                'benign_positive_rate', 'delay_p50', 'delay_p95')})
    return out


def run(study: Path, dump_root: Path, replay: Path, campaigns, output: Path, calibration_fraction=0.2,
        confirmation=(1, 1), pvalue=('joint',), arms_filter=None, cusum_drift=None, cusum_on_alarm='keep'):
    if output.exists():
        raise ValueError('output exists; choose a new path')
    registration, index, _ = load_study(study)
    begin, finish = registration['holdout_start_unix'], registration['planned_end_unix']
    split_at = begin + calibration_fraction*(finish-begin)
    trials = load_trials(campaigns)
    windows = load_replay(replay)
    arms = {}
    kinds = (pvalue,) if isinstance(pvalue, str) else tuple(pvalue)
    for arm in sorted(index['arms']):
        if arms_filter and arm not in arms_filter:
            continue
        holdout = load_holdout(dump_root, arm)
        for kind in kinds:
            # a branch-only p-value is reported as its own arm, e.g. 'base29@tree', paired by trial with 'base29'
            name = arm if kind == 'joint' else f'{arm}@{kind}'
            rows = []
            arms[name] = evaluate_arm(name, holdout, windows, trials, split_at, outcomes=rows,
                                      confirmation=confirmation, pvalue=kind, cusum_drift=cusum_drift,
                                      cusum_on_alarm=cusum_on_alarm,
                                      scales=SCALES if cusum_drift is None else CUSUM_THRESHOLDS)
            output.mkdir(parents=True, exist_ok=True)
            with (output/'TRIAL_OUTCOMES.jsonl').open('a') as stream:
                stream.writelines(json.dumps(r) + '\n' for r in rows)
            print(name, {s: round(v['episodes_per_replica_hour'] or -1, 2) for s, v in arms[name]['scales'].items()}, flush=True)
    result = dict(schema='pulse-r4-arm-budget-v1', study=str(study), dump_root=str(dump_root), replay=str(replay),
                  campaigns=[str(c) for c in campaigns], calibration_fraction=calibration_fraction,
                  calibration_span_unix=[begin, split_at], evaluation_span_unix=[split_at, finish],
                  episode_quiet_seconds=EPISODE_QUIET_SECONDS, budgets=list(BUDGETS),
                  scales=list(SCALES if cusum_drift is None else CUSUM_THRESHOLDS),
                  grid='alpha_scale' if cusum_drift is None else 'cusum_threshold',
                  confirmation=dict(k=confirmation[0], n=confirmation[1], max_gap_seconds=MAX_GAP_SECONDS)
                  if cusum_drift is None else dict(kind='cusum', drift=cusum_drift, on_alarm=cusum_on_alarm,
                                                   max_gap_seconds=MAX_GAP_SECONDS),
                  pvalue=list(kinds), arms_evaluated=sorted(arms),
                  evidence_class='development; unadjudicated normal holdout; pulse-attack-dev scenarios previously exposed',
                  delay_definition='first positive window_end - kernel_event_at (lower bound on kernel->alert)',
                  arms=arms, matched_budget=matched(arms, loosest=max if cusum_drift is None else min),
                  source_sha256=sha256_file(Path(__file__)), finished_at_unix=time.time())
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
    parser.add_argument('--confirm-k', type=int, default=1)
    parser.add_argument('--confirm-n', type=int, default=1)
    parser.add_argument('--pvalue', choices=PVALUES, action='append',
                        help="joint (Pulse) and/or one branch alone; non-joint kinds become arms 'name@kind'")
    parser.add_argument('--arm', action='append', help='evaluate only these arms')
    parser.add_argument('--cusum-drift', type=float, help="Pulse's stable rule: CUSUM on -ln p with this drift (grid over h)")
    parser.add_argument('--cusum-on-alarm', choices=('keep', 'cap', 'restart'), default='keep',
                        help='what S does after an alarm (stable: cap; stable-selection-v1 amendment 1)')
    args = parser.parse_args()
    if not 1 <= args.confirm_k <= args.confirm_n:
        parser.error('need 1 <= k <= n')
    result = run(args.study.resolve(), args.dump_root, args.replay, args.campaign, args.output, args.calibration_fraction,
                 confirmation=(args.confirm_k, args.confirm_n), pvalue=tuple(args.pvalue or ('joint',)), arms_filter=args.arm,
                 cusum_drift=args.cusum_drift, cusum_on_alarm=args.cusum_on_alarm)
    for budget, arms in result['matched_budget'].items():
        print('== budget', budget, 'episodes/replica-hour')
        for arm, v in sorted(arms.items(), key=lambda kv: -(kv[1] or {}).get('recall', -1) if kv[1] else 1):
            print(arm, v)


if __name__ == '__main__':
    main()
