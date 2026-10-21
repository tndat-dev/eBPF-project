"""Does refreshing the conformal calibration keep the alert burden down over time?

One recalibration (c1, normal of 15/10 00:30-07:30 UTC) cut flagged normal
windows from 8.1% to 0.35%, but the burden still drifts upward as the normal
workload changes. This replays the 48 h soak offline under several
calibration schedules, with the frozen estimators unchanged:

- ``static``: the c1 span for the whole evaluation (the pulse-live-recalibrated candidate);
- ``rolling-W-B``: every B hours, calibrate on the preceding W hours;
- ``guarded``: as rolling, but windows that were positive at alpha x1 when
  scored are left out of later calibrations, so an attack (or any burst)
  cannot teach the calibration that it is normal.

Strategies from the literature (protocol calibration-strategies-v1, registered before any of them was run):

- ``weighted-W-H-B``: every B hours, calibrate on the preceding W hours with time-decayed weights
  w_i = 0.5 ** (age_i / H hours), the test point weight 1 (non-exchangeable conformal, Barber, Candès,
  Ramdas, Tibshirani, Ann. Stat. 2023): p = (1 + sum_{S_i >= s} w_i) / (1 + sum_i w_i). Weights depend only
  on time, never on scores, as the method requires;
- ``mondrian-W-B``: as rolling, but one calibration per (workload, node) cell (Mondrian conformal), falling
  back to the workload when a cell has fewer than MINIMUM examples;
- ``aci-<base>``: adaptive conformal inference (Gibbs & Candès, NeurIPS 2021) on top of ``static``,
  ``asrun`` or ``rolling-W-B`` p-values: per workload and alpha scale, alpha_{t+1} = alpha_t +
  gamma (alpha* - err_t) over the scored windows in time order (campaign windows included, as live),
  err_t = [p_t <= alpha_t], alpha* = model alpha x scale, gamma = ACI_GAMMA x alpha*;
- ``asrun``: the p-values recorded live (no recalibration), the reference on a run whose calibration came
  from an earlier capture.

Normal burden is measured on the evaluation span with campaign intervals
excluded. Attack/control trials (pulse-attack-dev) are rescored with the calibration
that was active when each trial started (ACI: the alpha of the trial's workload when the trial started).
Evidence class: development, unadjudicated normal.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

import numpy as np

from ..common import atomic_json
from ..detector.confirmation import SCORED, ConfirmationPolicy, CusumPolicy, CusumState, apply, cauchy_p
from ..detector.support_model import pvalues
from ..detector.recalibration import Recalibrator
from ..integrity import sha256_file
from ..syscall_study.arm_budget import confirm, joint_p
from .confirmation_study import MODEL_HASH, POLICY_HASH, scored_rows
from .preview_evaluation import evaluate_interval, summarize

MINIMUM = 1200
HOUR = 3600.0
SCALES = (1.0, 3.0)
ACI_GAMMA = 0.01   # step size relative to the target alpha (registered; Gibbs & Candes use 0.005 at alpha 0.1)


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
            c['node'].append(str(row['node_name'])); c['jp'].append(float(row['joint_p']))
            c['start'].append(float(row['window_start']))
            c['tp'].append(float(row['tree_p'])); c['sp'].append(float(row['support_p']))
            alpha[w] = float(row['candidate_policy_alpha'])
    out = {}
    for w, c in cols.items():
        end = np.asarray(c['end']); order = np.argsort(end, kind='stable')
        out[w] = dict(identity=np.asarray(c['identity'], dtype=np.int64)[order], end=end[order],
                      tree=np.asarray(c['tree'])[order], support=np.asarray(c['support'])[order],
                      eligible=np.asarray(c['eligible'])[order], alpha=alpha[w],
                      node=np.asarray(c['node'])[order], jp=np.asarray(c['jp'])[order],
                      start=np.asarray(c['start'])[order], tp=np.asarray(c['tp'])[order], sp=np.asarray(c['sp'])[order])
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


class Calibration:
    """Sorted normal tree/support scores of one workload (or cell), optionally with time-decay weights."""

    def __init__(self, tree, support, weights=None):
        ot, os_ = np.argsort(tree, kind='stable'), np.argsort(support, kind='stable')
        self.tree, self.support = np.asarray(tree)[ot], np.asarray(support)[os_]
        self.weighted = weights is not None
        if self.weighted:
            w = np.asarray(weights, dtype=np.float64)
            self.tree_tail = np.concatenate([np.cumsum(w[ot][::-1])[::-1], [0.0]])
            self.support_tail = np.concatenate([np.cumsum(w[os_][::-1])[::-1], [0.0]])
            self.size = float(w.sum())
        else:
            self.size = float(min(len(self.tree), len(self.support)))

    def joint_p(self, tree, support):
        if not self.weighted:
            return joint_p(np.asarray(tree, dtype=np.float64), np.asarray(support, dtype=np.float64), self.tree, self.support)
        pt = (1.0 + self.tree_tail[np.searchsorted(self.tree, tree, side='left')]) / (1.0 + self.tree_tail[0])
        ps = (1.0 + self.support_tail[np.searchsorted(self.support, support, side='left')]) / (1.0 + self.support_tail[0])
        return np.minimum(1.0, 2*np.minimum(pt, ps))

    def branch_p(self, tree, support):
        """(tree_p, support_p); min(1, 2 min(tree_p, support_p)) equals ``joint_p``."""
        tree, support = np.asarray(tree, dtype=np.float64), np.asarray(support, dtype=np.float64)
        if not self.weighted:
            return pvalues(tree, self.tree), pvalues(support, self.support)
        pt = (1.0 + self.tree_tail[np.searchsorted(self.tree, tree, side='left')]) / (1.0 + self.tree_tail[0])
        ps = (1.0 + self.support_tail[np.searchsorted(self.support, support, side='left')]) / (1.0 + self.support_tail[0])
        return pt, ps


def block_calibration(a, lo, hi, usable, block_start, half_life_hours=None, node=None):
    """Calibration from usable windows ending in [lo, hi) (one node if given); None below MINIMUM."""
    i, j = np.searchsorted(a['end'], lo), np.searchsorted(a['end'], hi)
    keep = usable[i:j] if node is None else usable[i:j] & (a['node'][i:j] == node)
    tree, support = a['tree'][i:j][keep], a['support'][i:j][keep]
    weights = None
    if half_life_hours is not None:
        weights = 0.5 ** ((block_start - a['end'][i:j][keep]) / (half_life_hours*HOUR))
    cal = Calibration(tree, support, weights)
    return cal if cal.size >= MINIMUM else None


def pvalue_strategy(rows, kind, blocks, exclude, half_life_hours=None):
    """p[w] for every row (nan where no usable calibration) and per-block rescorers {w: {node|None: Calibration}}.

    kind: 'asrun' (recorded p), 'calibrated' (static/rolling/weighted blocks), 'mondrian' (per node cell)."""
    p, rescorers, pb = {}, [], {}
    for w, a in rows.items():
        p[w] = a['jp'].astype(np.float64) if kind == 'asrun' else np.full(len(a['end']), np.nan)
        pb[w] = ((a['tp'].astype(np.float64), a['sp'].astype(np.float64)) if kind == 'asrun'
                 else (np.full(len(a['end']), np.nan), np.full(len(a['end']), np.nan)))
    if kind == 'asrun':
        return p, None, pb
    usable = {w: a['eligible'] & ~masked(a['end'], exclude) for w, a in rows.items()}
    for start, end, lo, hi in blocks:
        used = {}
        for w, a in rows.items():
            i, j = np.searchsorted(a['end'], start), np.searchsorted(a['end'], end)
            pooled = block_calibration(a, lo, hi, usable[w], start, half_life_hours)
            cells = {None: pooled} if pooled is not None else {}
            if kind == 'mondrian':
                for node in np.unique(a['node']):
                    cal = block_calibration(a, lo, hi, usable[w], start, half_life_hours, node=node)
                    if cal is not None:
                        cells[node] = cal
            if not cells:
                continue
            used[w] = cells
            if i == j:
                continue
            if kind == 'mondrian':
                for node in np.unique(a['node'][i:j]):
                    cal = cells.get(node, cells.get(None))
                    if cal is None:
                        continue
                    sel = np.flatnonzero(a['node'][i:j] == node) + i
                    p[w][sel] = cal.joint_p(a['tree'][sel], a['support'][sel])
                    pb[w][0][sel], pb[w][1][sel] = cal.branch_p(a['tree'][sel], a['support'][sel])
            elif None in cells:
                p[w][i:j] = cells[None].joint_p(a['tree'][i:j], a['support'][i:j])
                pb[w][0][i:j], pb[w][1][i:j] = cells[None].branch_p(a['tree'][i:j], a['support'][i:j])
        rescorers.append((start, end, used))
    return p, rescorers, pb


def aci_alpha(p, eligible, target, gamma):
    """Adaptive conformal inference (Gibbs & Candes 2021): alpha_{t+1} = alpha_t + gamma (target - err_t).
    Returns (positive flags, alpha before each window). Windows without a p-value keep alpha unchanged."""
    pv, ok = np.asarray(p, dtype=np.float64).tolist(), np.asarray(eligible, dtype=bool).tolist()
    alpha, flags = [0.0]*len(pv), [False]*len(pv)
    a_t = target
    for t, pt in enumerate(pv):
        alpha[t] = a_t
        if pt == pt and ok[t]:               # not nan
            err = pt <= a_t
            flags[t] = err
            a_t = min(1.0, a_t + gamma*(target - err))
    return np.asarray(flags, dtype=bool), np.asarray(alpha)


def parse_temporal(text):
    """'kofn' (default: the run's k-of-n on joint_p), 'cauchy' (k-of-n on the Cauchy combination) or
    'cusum-<drift>-<threshold>' (CUSUM on -ln joint_p, no k-of-n); same classes as the live policy (5.19)."""
    if text in (None, 'kofn'):
        return 'kofn', None
    if text == 'cauchy':
        return 'cauchy', None
    kind, *params = text.split('-')
    if kind == 'cusum' and len(params) == 2:
        return 'cusum', CusumPolicy(drift=float(params[0]), threshold=float(params[1]))
    raise ValueError('unknown temporal rule: ' + text)


def cauchy_array(pt, ps):
    return np.array([cauchy_p(a, b) if a == a and b == b else np.nan for a, b in zip(pt.tolist(), ps.tolist())])


def cusum_flags(a, p, policy):
    """CUSUM signal per row of one workload (rows in window_end order; nan p = unscored, skipped)."""
    state, out = CusumState(policy), np.zeros(len(p), dtype=bool)
    ident, start, end = a['identity'].tolist(), a['start'].tolist(), a['end'].tolist()
    for i, pi in enumerate(p.tolist()):
        if pi == pi:
            out[i] = state.update(dict(node_name=ident[i], window_start=start[i], window_end=end[i], joint_p=pi))
    return out


def run_strategy_ext(rows, name, eval_start, eval_end, static_span, exclude, scales=SCALES, temporal='kofn'):
    """flags (as run_strategy), rescorers and ACI alphas for the literature strategies."""
    tkind, tpolicy = parse_temporal(temporal)
    kind, *params = name.split('-')
    aci = kind == 'aci'
    if aci:
        kind, *params = params
        if tkind != 'kofn':
            raise ValueError('ACI is registered with k-of-n only')
    half_life = None
    if kind == 'asrun':
        blocks, pkind = [(eval_start, eval_end, None, None)], 'asrun'
    elif kind == 'static':
        blocks, pkind = schedule('static', eval_start, eval_end, static_span), 'calibrated'
    elif kind in ('rolling', 'weighted', 'mondrian'):
        window, refresh = float(params[0]), float(params[-1])
        half_life = float(params[1]) if kind == 'weighted' else None
        blocks = schedule('rolling', eval_start, eval_end, static_span, window, refresh)
        pkind = 'mondrian' if kind == 'mondrian' else 'calibrated'
    else:
        raise ValueError('unknown strategy: ' + name)
    p, rescorers, pb = pvalue_strategy(rows, pkind, blocks, exclude, half_life)
    flags = {s: {} for s in scales}; flags['scored'] = {}
    alphas = {s: {} for s in scales}
    for w, a in rows.items():
        scored = np.isfinite(p[w])
        if pkind == 'asrun':
            scored &= (a['end'] >= eval_start) & (a['end'] < eval_end)
        flags['scored'][w] = scored
        if tkind == 'cusum':
            f = cusum_flags(a, np.where(np.isfinite(p[w]), p[w], np.nan), tpolicy) & scored
            for s in scales:
                flags[s][w] = f
            continue
        pw = cauchy_array(*pb[w]) if tkind == 'cauchy' else p[w]
        for s in scales:
            target = a['alpha']*s
            if aci:
                f, al = aci_alpha(np.where(scored, p[w], np.nan), a['eligible'], target, ACI_GAMMA*target)
                flags[s][w] = f
                alphas[s][w] = (a['end'], al)
            else:
                flags[s][w] = scored & (np.nan_to_num(pw, nan=2.0) <= target)
    return flags, rescorers, (alphas if aci else None), len(blocks)


def rescore_trial_rows(decisions, rescorers, start, alphas=None, scale=1.0):
    """Decision rows of one trial rewritten with the calibration (and ACI alpha) active at ``start``."""
    used = None
    if rescorers is not None:
        used = next((u for a, b, u in rescorers if a <= start < b), None)
        if used is None:
            used = min(rescorers, key=lambda c: abs(c[0]-start))[2]
    out = []
    for r in decisions:
        if r.get('status') != SCORED or r.get('joint_p') is None:
            out.append(r); continue
        w = r['workload_key']
        if used is not None:
            cells = used.get(w)
            cal = None if cells is None else cells.get(str(r.get('node_name')), cells.get(None))
            if cal is None:
                out.append(dict(r, status='uncalibrated')); continue
            jp = float(cal.joint_p(np.array([float(r['tree_score'])]), np.array([float(r['support_score'])]))[0])
            tp, sp = (float(x[0]) for x in cal.branch_p(np.array([float(r['tree_score'])]), np.array([float(r['support_score'])])))
            r = dict(r, frozen_joint_p=r['joint_p'], joint_p=jp, tree_p=tp, support_p=sp)
        if alphas is not None and w in alphas:
            ends, al = alphas[w]
            k = max(0, np.searchsorted(ends, start) - 1)
            r = dict(r, candidate_policy_alpha=float(al[k]) / scale)   # apply() multiplies by the scale again
        out.append(r)
    return out


def apply_cusum(rows, policy):
    """Rows in window order with candidate_alert_preview from CUSUM (same CusumState as the live policy)."""
    state, out = CusumState(policy), []
    for row in sorted(rows, key=lambda r: (float(r.get('window_end', 0)), float(r.get('window_start', 0)))):
        if row.get('status') == SCORED and row.get('joint_p') is not None:
            row = dict(row, frozen_candidate_alert_preview=row.get('candidate_alert_preview'),
                       candidate_alert_preview=state.update(row), confirmation_policy=policy.name)
        out.append(row)
    return out


def attack_metrics_ext(inputs, rescorers, alphas, scales=SCALES, confirmation=(1, 1),
                       model_hash=MODEL_HASH, policy_hash=POLICY_HASH, temporal='kofn'):
    tkind, tpolicy = parse_temporal(temporal)
    out = {}
    for s in scales:
        policy = ConfirmationPolicy(confirmation[0], confirmation[1], s)
        outcomes = []
        for data in inputs:
            start = float(data['attack']['start_at'])
            rows = rescore_trial_rows(data['decisions'], rescorers, start, None if alphas is None else alphas[s], s)
            if tkind == 'cusum':
                rows = apply_cusum(rows, tpolicy)
            else:
                if tkind == 'cauchy':
                    rows = [dict(r, joint_p=cauchy_p(r['tree_p'], r['support_p']))
                            if r.get('status') == SCORED and r.get('joint_p') is not None else r for r in rows]
                rows = apply(rows, policy)
            for label in ('control', 'benign', 'attack'):
                if label in data:
                    outcomes.append(evaluate_interval(rows, data[label], model_hash, policy_hash))
        out[f'{s:g}'] = summarize(outcomes)
    return out


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


def normal_metrics(rows, flags, eval_start, eval_end, exclude, scales=SCALES, confirmation=(1, 1)):
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
            if confirmation != (1, 1):
                # k-of-n over each container's consecutive scored windows, as the live policy does
                pos = confirm(a['identity'], a['end'], pos, *confirmation)
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


def attack_metrics(campaign_roots, calibrations, scales=SCALES, confirmation=(1, 1), model_hash=MODEL_HASH,
                   policy_hash=POLICY_HASH):
    inputs = []
    for root in campaign_roots:
        for path in sorted(root.glob('trials/*/EVALUATION_INPUT.json')):
            inputs.append(json.loads(path.read_text()))
    out = {}
    for s in scales:
        policy = ConfirmationPolicy(confirmation[0], confirmation[1], s)
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
                    outcomes.append(evaluate_interval(rows, data[label], model_hash, policy_hash))
        out[f'{s:g}'] = summarize(outcomes)
    return out


LITERATURE = ('asrun', 'weighted', 'mondrian', 'aci')


def run(worker_roots, campaign_roots, output, static_span, eval_start, eval_end=None, extra_exclude=(),
        strategies=('static', 'rolling-6-1', 'rolling-3-1', 'rolling-12-1', 'guarded-6-1'), scales=SCALES,
        confirmation=(1, 1), model_hash=MODEL_HASH, policy_hash=POLICY_HASH, temporal='kofn'):
    started = time.time()
    tkind, _ = parse_temporal(temporal)
    if tkind != 'kofn' and any(n.split('-')[0] == 'guarded' for n in strategies):
        raise ValueError('cauchy/cusum combinations are not implemented for guarded')
    rows = load_rows(worker_roots, model_hash, policy_hash)
    eval_end = eval_end or max(float(a['end'][-1]) for a in rows.values())
    exclude = sorted(campaign_spans(campaign_roots) + list(extra_exclude))
    inputs = [json.loads(path.read_text()) for root in campaign_roots
              for path in sorted(root.glob('trials/*/EVALUATION_INPUT.json'))]
    results = {}
    for name in strategies:
        if name.split('-')[0] in LITERATURE or tkind != 'kofn':   # static/rolling go through the same path for combos
            flags, rescorers, alphas, nblocks = run_strategy_ext(rows, name, eval_start, eval_end, static_span, exclude, scales,
                                                                 temporal)
            confirm_normal = (1, 1) if tkind == 'cusum' else confirmation
            results[name] = dict(normal=normal_metrics(rows, flags, eval_start, eval_end, exclude, scales, confirm_normal),
                                 attack=attack_metrics_ext(inputs, rescorers, alphas, scales, confirmation, model_hash, policy_hash,
                                                           temporal),
                                 blocks=nblocks)
            if alphas is not None:
                results[name]['aci_alpha_over_target'] = {
                    f'{s:g}': {w: dict(zip(('p05', 'p50', 'p95', 'last'), [float(x) for x in (*np.percentile(al/(rows[w]['alpha']*s), [5, 50, 95]), al[-1]/(rows[w]['alpha']*s))]))
                               for w, (_, al) in alphas[s].items() if len(al)} for s in scales}
            print(name, {s: round(v['episodes_per_replica_hour'] or -1, 2) for s, v in results[name]['normal'].items()},
                  {s: (v['recall_observed'], v['control_positive_rate']) for s, v in results[name]['attack'].items()}, flush=True)
            continue
        kind, *params = name.split('-')
        window, refresh = (float(params[0]), float(params[1])) if params else (None, None)
        blocks = schedule('static' if kind == 'static' else 'rolling', eval_start, eval_end, static_span, window, refresh)
        flags, calibrations = run_strategy(rows, blocks, exclude, guarded=kind == 'guarded', scales=scales,
                                           static_span=static_span)
        results[name] = dict(normal=normal_metrics(rows, flags, eval_start, eval_end, exclude, scales, confirmation),
                             attack=attack_metrics(campaign_roots, calibrations, scales, confirmation, model_hash, policy_hash),
                             blocks=len(blocks))
        print(name, {s: round(v['episodes_per_replica_hour'] or -1, 2) for s, v in results[name]['normal'].items()},
              {s: (v['recall_observed'], v['control_positive_rate']) for s, v in results[name]['attack'].items()}, flush=True)
    result = dict(schema='pulse-rolling-recalibration-v1', worker_roots=[str(r) for r in worker_roots],
                  campaigns=[str(c) for c in campaign_roots], model_hash=model_hash, policy_hash=policy_hash,
                  aci_gamma_relative=ACI_GAMMA, temporal=temporal,
                  static_calibration_span_unix=list(static_span), evaluation_span_unix=[eval_start, eval_end],
                  excluded_spans=len(exclude), minimum_calibration_examples=MINIMUM, scales=list(scales),
                  confirmation=dict(k=confirmation[0], n=confirmation[1]),
                  evidence_class='development; unadjudicated normal; pulse-attack-dev scenarios previously exposed',
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
    parser.add_argument('--scale', type=float, action='append', help='alpha scales (default 1 and 3)')
    parser.add_argument('--confirm-k', type=int, default=1)
    parser.add_argument('--confirm-n', type=int, default=1)
    parser.add_argument('--temporal', default='kofn', help="kofn | cauchy | cusum-<drift>-<threshold> (combined replay, 5.19)")
    parser.add_argument('--model-hash', default=MODEL_HASH)
    parser.add_argument('--policy-hash', default=POLICY_HASH)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('output exists; choose a new path')
    kwargs = dict(strategies=tuple(args.strategy)) if args.strategy else {}
    if args.scale:
        kwargs['scales'] = tuple(args.scale)
    kwargs['confirmation'] = (args.confirm_k, args.confirm_n)
    kwargs.update(model_hash=args.model_hash, policy_hash=args.policy_hash, temporal=args.temporal)
    run(args.worker_root, args.campaign, args.output, args.static_span, args.eval_start, args.eval_end,
        args.exclude, **kwargs)


if __name__ == '__main__':
    main()
