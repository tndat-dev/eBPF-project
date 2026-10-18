"""Does refreshing the conformal calibration keep the alert burden down over time?

One recalibration (c1, normal of 15/10 00:30-07:30 UTC) cut flagged normal
windows from 8.1% to 0.35%, but the burden still drifts upward as the normal
workload changes. This replays the 48 h soak offline under several
calibration schedules, with the frozen estimators unchanged:

- ``static``: the c1 span for the whole evaluation (the R6 candidate);
- ``rolling-W-B``: every B hours, calibrate on the preceding W hours;
- ``guarded``: as rolling, but windows that were positive at alpha x1 when
  scored are left out of later calibrations, so an attack (or any burst)
  cannot teach the calibration that it is normal.

Normal burden is measured on the evaluation span with campaign intervals
excluded. Attack/control trials (R3/R5) are rescored with the calibration
that was active when each trial started. Evidence class: development,
unadjudicated normal.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

import numpy as np

from ..common import atomic_json
from ..detector.confirmation import SCORED, ConfirmationPolicy, apply
from ..detector.recalibration import Recalibrator
from ..integrity import sha256_file
from ..syscall_study.arm_budget import joint_p
from .confirmation_study import MODEL_HASH, POLICY_HASH, scored_rows
from .preview_evaluation import evaluate_interval, summarize

MINIMUM = 1200
HOUR = 3600.0
SCALES = (1.0, 3.0)


def campaign_spans(campaign_roots, margin=20.0):
    """Every registered control/benign/attack interval, padded, as exclusion spans."""
    spans = []
    for root in campaign_roots:
        path = root/'INTERVALS.jsonl'
        if path.exists():
            for line in path.read_text().splitlines():
                start = float(json.loads(line)['start_at'])
                spans.append((start - margin, start + 15 + margin))
    return sorted(spans)


def masked(end, spans):
    out = np.zeros(len(end), dtype=bool)
    for a, b in spans:
        lo, hi = np.searchsorted(end, a), np.searchsorted(end, b)
        out[lo:hi] = True
    return out


def load_rows(worker_roots, model_hash=MODEL_HASH, policy_hash=POLICY_HASH):
    """workload -> arrays sorted by window_end; identity numbering is global."""
    ids, cols = {}, defaultdict(lambda: defaultdict(list))
    alpha = {}
    for root in worker_roots:
        for row in scored_rows(root, model_hash, policy_hash):
            w = row['workload_key']
            key = (row['node_name'], row['pod_uid'], row['container_name'], row['workload_revision'], row['cgroup_id'])
            c = cols[w]
            c['identity'].append(ids.setdefault(key, len(ids)))
            c['end'].append(float(row['window_end']))
            c['tree'].append(float(row['tree_score'])); c['support'].append(float(row['support_score']))
            c['eligible'].append(row.get('eligible_for_normal_review') is True)
            alpha[w] = float(row['candidate_policy_alpha'])
    out = {}
    for w, c in cols.items():
        end = np.asarray(c['end']); order = np.argsort(end, kind='stable')
        out[w] = dict(identity=np.asarray(c['identity'], dtype=np.int64)[order], end=end[order],
                      tree=np.asarray(c['tree'])[order], support=np.asarray(c['support'])[order],
                      eligible=np.asarray(c['eligible'])[order], alpha=alpha[w])
    return out


def calibration(a, lo, hi, usable_mask):
    i, j = np.searchsorted(a['end'], lo), np.searchsorted(a['end'], hi)
    keep = usable_mask[i:j]
    tree, support = a['tree'][i:j][keep], a['support'][i:j][keep]
    if min(len(tree), len(support)) < MINIMUM:
        return None
    return np.sort(tree), np.sort(support)


def schedule(kind, eval_start, eval_end, static_span, window_hours=None, refresh_hours=None):
    """[(block_start, block_end, cal_lo, cal_hi)]"""
    if kind == 'static':
        return [(eval_start, eval_end, *static_span)]
    blocks, t, step = [], eval_start, refresh_hours*HOUR
    while t < eval_end:
        blocks.append((t, min(t+step, eval_end), t - window_hours*HOUR, t))
        t += step
    return blocks


def run_strategy(rows, blocks, exclude, guarded, scales=SCALES, static_span=None):
    """Positive flags per scale for every evaluation row, plus the calibration used per block."""
    flags = {s: {} for s in scales}
    calibrations = []   # (block_start, block_end, {workload: (tree, support)})
    positive1 = {}
    for w, a in rows.items():
        excluded = masked(a['end'], exclude)
        base = a['eligible'] & ~excluded
        if guarded and static_span is not None:
            # windows before the first block were scored by the static calibration
            cal = calibration(a, *static_span, base)
            p1 = np.zeros(len(a['end']), dtype=bool)
            if cal is not None:
                pre = a['end'] < blocks[0][0]
                p1[pre] = joint_p(a['tree'][pre], a['support'][pre], *cal) <= a['alpha']
            positive1[w] = p1
        for s in scales:
            flags[s][w] = np.zeros(len(a['end']), dtype=bool)
        flags.setdefault('scored', {})[w] = np.zeros(len(a['end']), dtype=bool)
        a['_base'] = base
    for start, end, lo, hi in blocks:
        used = {}
        for w, a in rows.items():
            usable = a['_base'] & ~positive1[w] if guarded else a['_base']
            cal = calibration(a, lo, hi, usable)
            i, j = np.searchsorted(a['end'], start), np.searchsorted(a['end'], end)
            if cal is None or i == j:
                continue
            used[w] = cal
            p = joint_p(a['tree'][i:j], a['support'][i:j], *cal)
            flags['scored'][w][i:j] = True
            for s in scales:
                flags[s][w][i:j] = p <= a['alpha']*s
            if guarded:
                positive1[w][i:j] = p <= a['alpha']
        calibrations.append((start, end, used))
    return flags, calibrations


def episode_starts(identity, end, positive, quiet=15.0):
    """Boolean mask (aligned with the inputs) of positive windows that open a new episode."""
    out = np.zeros(len(end), dtype=bool)
    idx = np.flatnonzero(positive)
    if not len(idx):
        return out
    idx = idx[np.lexsort((end[idx], identity[idx]))]
    new = np.ones(len(idx), dtype=bool)
    new[1:] = (identity[idx][1:] != identity[idx][:-1]) | (end[idx][1:] - end[idx][:-1] >= quiet)
    out[idx[new]] = True
    return out


def normal_metrics(rows, flags, eval_start, eval_end, exclude, scales=SCALES):
    out = {}
    hours_blocks = np.arange(eval_start, eval_end, HOUR)
    for s in scales:
        episodes = windows = positives = 0
        uncalibrated = 0
        hourly = np.zeros(len(hours_blocks)); hourly_windows = np.zeros(len(hours_blocks))
        for w, a in rows.items():
            sel = (a['end'] >= eval_start) & (a['end'] < eval_end) & a['eligible'] & ~masked(a['end'], exclude)
            scored = sel & flags['scored'][w]
            uncalibrated += int((sel & ~flags['scored'][w]).sum())
            pos = flags[s][w] & scored
            starts = episode_starts(a['identity'], a['end'], pos)
            episodes += int(starts.sum())
            windows += int(scored.sum()); positives += int(pos.sum())
            # hourly curve: each episode is attributed to the hour it starts in
            bucket = np.clip(((a['end'] - eval_start)//HOUR).astype(int), 0, len(hours_blocks)-1)
            hourly += np.bincount(bucket[starts], minlength=len(hours_blocks))
            hourly_windows += np.bincount(bucket[scored], minlength=len(hours_blocks))
        hours = windows*0.5/HOUR
        out[f'{s:g}'] = dict(episodes_per_replica_hour=episodes/hours if hours else None,
            positive_window_rate=positives/windows if windows else None, scored_replica_hours=hours,
            uncalibrated_windows=uncalibrated,
            hourly_episodes_per_replica_hour=[float(e/(n*0.5/HOUR)) if n else None for e, n in zip(hourly, hourly_windows)])
    return out


def attack_metrics(campaign_roots, calibrations, scales=SCALES):
    inputs = []
    for root in campaign_roots:
        for path in sorted(root.glob('trials/*/EVALUATION_INPUT.json')):
            inputs.append(json.loads(path.read_text()))
    out = {}
    for s in scales:
        policy = ConfirmationPolicy(1, 1, s)
        outcomes = []
        for data in inputs:
            start = float(data['attack']['start_at'])
            used = next((u for a, b, u in calibrations if a <= start < b), None)
            if used is None:
                used = min(calibrations, key=lambda c: abs(c[0]-start))[2]
            recal = Recalibrator({w: c[0] for w, c in used.items()}, {w: c[1] for w, c in used.items()}, MINIMUM)
            rows = [recal.rewrite(r) or dict(r, status='uncalibrated')
                    if r.get('status') == SCORED and r.get('joint_p') is not None else r for r in data['decisions']]
            rows = apply(rows, policy)
            for label in ('control', 'benign', 'attack'):
                if label in data:
                    outcomes.append(evaluate_interval(rows, data[label], MODEL_HASH, POLICY_HASH))
        out[f'{s:g}'] = summarize(outcomes)
    return out


def run(worker_roots, campaign_roots, output, static_span, eval_start, eval_end=None, extra_exclude=(),
        strategies=('static', 'rolling-6-1', 'rolling-3-1', 'rolling-12-1', 'guarded-6-1')):
    started = time.time()
    rows = load_rows(worker_roots)
    eval_end = eval_end or max(float(a['end'][-1]) for a in rows.values())
    exclude = sorted(campaign_spans(campaign_roots) + list(extra_exclude))
    results = {}
    for name in strategies:
        kind, *params = name.split('-')
        window, refresh = (float(params[0]), float(params[1])) if params else (None, None)
        blocks = schedule('static' if kind == 'static' else 'rolling', eval_start, eval_end, static_span, window, refresh)
        flags, calibrations = run_strategy(rows, blocks, exclude, guarded=kind == 'guarded', static_span=static_span)
        results[name] = dict(normal=normal_metrics(rows, flags, eval_start, eval_end, exclude),
                             attack=attack_metrics(campaign_roots, calibrations), blocks=len(blocks))
        print(name, {s: round(v['episodes_per_replica_hour'] or -1, 2) for s, v in results[name]['normal'].items()},
              {s: (v['recall_observed'], v['control_positive_rate']) for s, v in results[name]['attack'].items()}, flush=True)
    result = dict(schema='pulse-rolling-recalibration-v1', worker_roots=[str(r) for r in worker_roots],
                  campaigns=[str(c) for c in campaign_roots], model_hash=MODEL_HASH, policy_hash=POLICY_HASH,
                  static_calibration_span_unix=list(static_span), evaluation_span_unix=[eval_start, eval_end],
                  excluded_spans=len(exclude), minimum_calibration_examples=MINIMUM, scales=list(SCALES),
                  evidence_class='development; unadjudicated normal; R3/R5 scenarios previously exposed',
                  strategies=results, estimators_changed=False,
                  source_sha256=sha256_file(Path(__file__)), started_at_unix=started, finished_at_unix=time.time())
    atomic_json(output, result)
    return result


def span(text):
    a, b = (float(x) for x in text.split(':'))
    return a, b


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--worker-root', type=Path, action='append', required=True)
    parser.add_argument('--campaign', type=Path, action='append', required=True)
    parser.add_argument('--static-span', type=span, required=True)
    parser.add_argument('--eval-start', type=float, required=True)
    parser.add_argument('--eval-end', type=float)
    parser.add_argument('--exclude', type=span, action='append', default=[])
    parser.add_argument('--strategy', action='append')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('output exists; choose a new path')
    kwargs = dict(strategies=tuple(args.strategy)) if args.strategy else {}
    run(args.worker_root, args.campaign, args.output, args.static_span, args.eval_start, args.eval_end,
        args.exclude, **kwargs)


if __name__ == '__main__':
    main()
