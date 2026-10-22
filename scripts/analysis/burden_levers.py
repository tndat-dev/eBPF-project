#!/usr/bin/env python3
"""Burden-reduction levers on window tables (protocol burden-reduction-v1 + amendment 1).

Per development run (a window table from ``sentinel_pulse.attack.window_table`` and its campaign):

- p-values: refreshed calibration (``--calibration`` npz, as ideas_screen) per workload; ``mondrian`` variants
  use the same calibration windows split by launch class (``--calibration-table``: window table of the
  calibration span), falling back to the workload when a class has < 1200 windows;
- variants: ``joint`` = min(1, 2 min(tree_p, support_p)) (L1), ``and`` = max(tree_p, support_p) (L2),
  ``mjoint`` / ``mand`` = the same on Mondrian p-values (L3);
- discount modes (L5, L6): a window whose context brings no syscall ID new to the peers / own history carries
  no evidence (CUSUM increment 0, k-of-n window not passed);
- rules: CUSUM on -ln p (S reset after a > 1 s gap, as the live CusumState), and k2of2 at alpha x scale;
- normal: rows from the run's selection start, campaign spans excluded; episodes merge positives of one
  container < 15 s apart (as EpisodeCounter); incidents merge them < 60 s / 300 s apart (L4, descriptive);
- campaign: a trial is positive when an alarm window lies in [start, start + 15 s]; delay = first such
  window_end - kernel event (as ideas_screen); trials with < 20 rows in [start - 30 s, start + 15 s] skipped.

Selection (protocol, fixed before any number): feasible = recall >= 95 %, precision >= 95 %, control <= 5 %,
p95 within the tier (< 2 s, <= 3 s) on EVERY development run; minimise the max-over-runs burden; within 5 %
of it the lower max control, then the simpler lever; propose only if burden <= 0.9 x the reference
(L1 joint, no discount, CUSUM b3 h6) on every run.
"""
import argparse, glob, json, sys, time
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.attack.window_table import load  # noqa: E402
from sentinel_pulse.detector.confirmation import IDENTITY  # noqa: E402
from sentinel_pulse.detector.support_model import pvalues  # noqa: E402
from sentinel_pulse.syscall_study.baselines import campaign_span  # noqa: E402

CUSUM_B = (2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 6.0)
CUSUM_H = (1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 10.0, 12.0)
KOFN = {'joint': (3.0, 5.0, 7.0, 10.0, 15.0, 20.0), 'and': (1.0, 3.0, 5.0, 10.0, 20.0)}
VARIANTS = ('joint', 'and', 'mjoint', 'mand')
MODES = ('none', 'peer30', 'peer60', 'self60', 'self300', 'peer30_or_self300', 'peer30_and_self300')
MODE_RANK = dict(none=0, peer30=3, peer60=3, self60=4, self300=4, peer30_or_self300=5, peer30_and_self300=5)
VARIANT_RANK = {'joint': 0, 'and': 1, 'mjoint': 2, 'mand': 2}
EPISODE_QUIET, INCIDENT_G, INTERVAL, MIN_ROWS, MIN_CAL = 15.0, (60.0, 300.0), 15.0, 20, 1200
REFERENCE = 'joint|none|cusum_b3_h6'
TIERS = {'lt2s': (lambda p95: p95 < 2.0), 'le3s': (lambda p95: p95 <= 3.0)}


# ---------------------------------------------------------------- p-values

def load_calibration(path):
    z = np.load(path, allow_pickle=False)
    tree = {f.split('::', 1)[1]: np.sort(z[f].astype(np.float64)) for f in z.files if f.startswith('tree::')}
    support = {f.split('::', 1)[1]: np.sort(z[f].astype(np.float64)) for f in z.files if f.startswith('support::')}
    return tree, support


def calibration_classes(table_path, tree, support):
    """{(workload, launch): (sorted tree, sorted support)} from the calibration-span window table; checks that
    its windows reproduce the npz per workload (same count and same sorted scores) under some row filter."""
    arrays, meta = load(Path(table_path))
    names = meta['workloads']
    checks, chosen = {}, None
    for name, keep in (('all', np.ones(len(arrays['end']), bool)), ('eligible', arrays['eligible'].astype(bool))):
        ok = True
        for i, w in enumerate(names):
            if w not in tree:
                continue
            sel = keep & (arrays['workload'] == i)
            ok &= (np.array_equal(np.sort(arrays['tree_score'][sel]), tree[w])
                   and np.array_equal(np.sort(arrays['support_score'][sel]), support[w]))
        checks[name] = bool(ok)
        if ok and chosen is None:
            chosen = keep
    if chosen is None:
        raise ValueError(f'calibration table does not reproduce the calibration npz: {checks}')
    classes = {}
    for i, w in enumerate(names):
        for launch in (False, True):
            sel = chosen & (arrays['workload'] == i) & (arrays['launch'].astype(bool) == launch)
            if sel.sum() >= MIN_CAL:
                classes[w, launch] = (np.sort(arrays['tree_score'][sel]), np.sort(arrays['support_score'][sel]))
    return classes, checks


def pvalue_columns(a, names, tree, support, classes):
    """tree_p / support_p per row (workload calibration) and Mondrian ones; rows without calibration: nan."""
    n = len(a['end'])
    tp, sp, mtp, msp = (np.full(n, np.nan) for _ in range(4))
    launch = a['launch'].astype(bool)
    for i, w in enumerate(names):
        if w not in tree or min(len(tree[w]), len(support[w])) < MIN_CAL:
            continue
        sel = a['workload'] == i
        tp[sel] = pvalues(a['tree_score'][sel], tree[w]); sp[sel] = pvalues(a['support_score'][sel], support[w])
        mtp[sel], msp[sel] = tp[sel], sp[sel]
        for cls in (False, True):
            if (w, cls) in classes:
                s = sel & (launch == cls)
                ct, cs = classes[w, cls]
                mtp[s] = pvalues(a['tree_score'][s], ct); msp[s] = pvalues(a['support_score'][s], cs)
    return {'joint': np.minimum(1.0, 2 * np.minimum(tp, sp)), 'and': np.maximum(tp, sp),
            'mjoint': np.minimum(1.0, 2 * np.minimum(mtp, msp)), 'mand': np.maximum(mtp, msp)}


# ---------------------------------------------------------------- rules

def segments(ident, start, end):
    """True where a row starts a new history (first of its container, gap > 1 s or overlap > 0.25 s)."""
    new = np.ones(len(end), bool)
    same = ident[1:] == ident[:-1]
    gap = start[1:] - end[:-1]
    new[1:] = ~same | (gap > 1.0) | (start[1:] < end[:-1] - 0.25)
    return new


def cusum(y, new):
    """S_t = max(0, S_{t-1} + y_t), S = 0 before each new segment (Page's recursion, vectorised:
    S_t = C_t - min(0, min_{j<=t} C_j) with C the within-segment cumulative sum)."""
    g = np.cumsum(y)
    seg = np.cumsum(new) - 1
    starts = np.flatnonzero(new)
    base = g[starts] - y[starts]
    c = g - base[seg]
    k = 2 * float(np.max(np.abs(c))) + 10.0
    h = c - seg * k                          # later segments far lower: a running min never crosses back
    m = np.minimum.accumulate(h) + seg * k
    return c - np.minimum(0.0, m)


def kofn2(passed, new):
    out = passed.copy()
    out[0] = False
    out[1:] &= passed[:-1] & ~new[1:]
    out[new] = False
    return out


# ---------------------------------------------------------------- metrics

def episodes(ident, end, positive, quiet):
    idx = np.flatnonzero(positive)
    if not len(idx):
        return 0
    i, e = ident[idx], end[idx]
    return int(1 + np.count_nonzero((i[1:] != i[:-1]) | (e[1:] - e[:-1] >= quiet)))


class Trials:
    def __init__(self, campaigns, ident_index, ident, start, end):
        rows = []
        for campaign in campaigns:
            for path in sorted(glob.glob(str(campaign).rstrip('/') + '/trials/*/EVALUATION_INPUT.json')):
                d = json.loads(Path(path).read_text())
                for label in ('control', 'benign', 'attack'):
                    t = d.get(label)
                    if not t:
                        continue
                    key = tuple(str(t.get(k)) for k in IDENTITY)
                    rows.append((label, d['attack'].get('scenario'), float(t['start_at']),
                                 t.get('kernel_event_at'), ident_index.get(key)))
        self.label, self.scenario, self.lo, self.hi, self.kernel = [], [], [], [], []
        self.skipped = defaultdict(int)
        block = {}
        for k in np.unique(ident):
            block[int(k)] = (int(np.searchsorted(ident, k, 'left')), int(np.searchsorted(ident, k, 'right')))
        for label, scenario, ts, kernel, k in rows:
            if k is None or k not in block:
                self.skipped[label] += 1
                continue
            b0, b1 = block[k]
            s, e = start[b0:b1], end[b0:b1]
            if np.count_nonzero((e >= ts - 30) & (e <= ts + INTERVAL)) < MIN_ROWS:
                self.skipped[label] += 1
                continue
            sel = np.flatnonzero((s >= ts) & (e <= ts + INTERVAL))
            if not len(sel):
                self.skipped[label] += 1
                continue
            self.label.append(label); self.scenario.append(scenario)
            self.lo.append(b0 + sel[0]); self.hi.append(b0 + sel[-1] + 1)
            self.kernel.append(np.nan if kernel is None else float(kernel))
        self.label, self.scenario = np.array(self.label), np.array(self.scenario)
        self.lo, self.hi, self.kernel = np.array(self.lo), np.array(self.hi), np.array(self.kernel)

    def outcome(self, alarm, end):
        cs = np.concatenate([[0], np.cumsum(alarm)])
        hit = cs[self.hi] - cs[self.lo] > 0
        first = np.searchsorted(cs, cs[self.lo] + 1) - 1          # first alarm row at or after lo
        first = np.where(hit, first, 0)
        delay = np.where(hit, end[first] - self.kernel, np.nan)
        return hit, delay


def metrics(alarm, ctx, trials, by_scenario=False):
    a = ctx
    normal_pos = alarm & a['normal']
    hours = a['hours']
    out = dict(burden=episodes(a['ident'], a['end'], normal_pos, EPISODE_QUIET) / hours)
    for g in INCIDENT_G:
        out[f'incidents{g:g}'] = episodes(a['ident'], a['end'], normal_pos, g) / hours
    hit, delay = trials.outcome(alarm, a['end'])
    for label in ('attack', 'benign', 'control'):
        m = trials.label == label
        out[label] = float(hit[m].mean()) if m.any() else None
    att = trials.label == 'attack'
    tp, fp = int(hit[att].sum()), int(hit[trials.label == 'control'].sum())
    out['precision'] = tp / (tp + fp) if tp + fp else None
    d = delay[att & hit & (delay >= 0)]
    out['p50'] = float(np.percentile(d, 50)) if len(d) else None
    out['p95'] = float(np.percentile(d, 95)) if len(d) else None
    if by_scenario:
        out['recall_by_scenario'] = {str(s): float(hit[att & (trials.scenario == s)].mean())
                                     for s in sorted(set(trials.scenario[att]))}
    return out


# ---------------------------------------------------------------- driver

def discount_mask(a, mode):
    if mode == 'none':
        return np.zeros(len(a['end']), bool)
    peer, self_ = a['novel_peer30'] == 0, a['novel_self300'] == 0
    return {'peer30': peer, 'peer60': a['novel_peer60'] == 0, 'self60': a['novel_self60'] == 0, 'self300': self_,
            'peer30_or_self300': peer | self_, 'peer30_and_self300': peer & self_}[mode]


def rules(variant, p, alpha, mode_mask, new, only=None):
    """Yield (rule name, alarm array) for every rule (or just ``only``) on one p-value variant and mode."""
    x = -np.log(np.maximum(p, 1e-12))
    for b in CUSUM_B:
        names = [f'cusum_b{b:g}_h{h:g}' for h in CUSUM_H]
        if only is not None and only not in names:
            continue
        s = cusum(np.where(mode_mask, 0.0, x - b), new)
        for name, h in zip(names, CUSUM_H):
            if only is None or only == name:
                yield name, s >= h
    for scale in KOFN['and' if variant in ('and', 'mand') else 'joint']:
        name = f'k2of2_a{scale:g}'
        if only is None or only == name:
            yield name, kofn2((p <= alpha * scale) & ~mode_mask, new)


def prepare(table, run_since, campaigns, tree, support, classes):
    a, meta = load(Path(table))
    order = np.lexsort((a['end'], a['ident']))
    a = {k: v[order] for k, v in a.items()}
    names = meta['workloads']
    p = pvalue_columns(a, names, tree, support, classes)
    keep = ~np.isnan(p['joint'])
    a = {k: v[keep] for k, v in a.items()}; p = {k: v[keep] for k, v in p.items()}
    spans = [campaign_span(Path(c)) for c in campaigns]
    normal = a['end'] >= run_since
    for lo, hi in spans:
        normal &= ~((a['end'] > lo) & (a['start'] < hi))
    a['normal'] = normal
    a['hours'] = float(np.sum((a['end'] - a['start'])[normal])) / 3600
    a['new'] = segments(a['ident'], a['start'], a['end'])
    index = {tuple(i): k for k, i in enumerate(meta['identities'])}
    trials = Trials(campaigns, index, a['ident'], a['start'], a['end'])
    asrun_equal = float(np.mean(np.isclose(p['joint'], a['joint_p'], rtol=0, atol=1e-12)))
    info = dict(rows=int(len(a['end'])), dropped_without_calibration=int((~keep).sum()), replica_hours=a['hours'],
                campaign_spans=spans, trials={k: int(np.sum(trials.label == k)) for k in ('attack', 'benign', 'control')},
                trials_skipped=dict(trials.skipped), recomputed_joint_equals_asrun=asrun_equal,
                launch_share=float(a['launch'].mean()),
                discount_share={m: float(discount_mask(a, m)[a['normal']].mean()) for m in MODES})
    return a, p, trials, info


def evaluate_run(a, p, trials):
    results = {}
    for variant in VARIANTS:
        for mode in MODES:
            for rule, alarm in rules(variant, p[variant], a['alpha'], discount_mask(a, mode), a['new']):
                results[f'{variant}|{mode}|{rule}'] = metrics(alarm, a, trials)
    return results


def rank(name):
    variant, mode, _ = name.split('|')
    return (MODE_RANK[mode], VARIANT_RANK[variant])


def select(runs):
    """Protocol rule over {run: {candidate: metrics}}."""
    names = set.intersection(*(set(r) for r in runs.values()))
    ref = {run: r[REFERENCE] for run, r in runs.items()}
    out = {}
    for tier, ok_p95 in TIERS.items():
        feasible = []
        for n in names:
            ms = [runs[run][n] for run in runs]
            if all(m['attack'] is not None and m['attack'] >= 0.95 and m['precision'] is not None and m['precision'] >= 0.95
                   and m['control'] is not None and m['control'] <= 0.05 and m['p95'] is not None and ok_p95(m['p95'])
                   for m in ms):
                feasible.append((max(m['burden'] for m in ms), max(m['control'] for m in ms), rank(n), n))
        if not feasible:
            out[tier] = dict(choice=None, feasible=0)
            continue
        best = min(f[0] for f in feasible)
        near = [f for f in feasible if f[0] <= best * 1.05]
        choice = min(near, key=lambda f: (f[1], f[2], f[0], f[3]))[3]
        proposed = all(runs[run][choice]['burden'] <= 0.9 * ref[run]['burden'] for run in runs)
        out[tier] = dict(choice=choice, proposed=proposed, feasible=len(feasible),
                         lowest_feasible_burden=best,
                         per_run={run: runs[run][choice] for run in runs},
                         reference_per_run={run: ref[run] for run in runs})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run', action='append', required=True,
                    help='name=<n>,table=<npz>,since=<unix selection start>,campaign=<dir>[,campaign=<dir>]')
    ap.add_argument('--calibration', required=True)
    ap.add_argument('--calibration-table', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    tree, support = load_calibration(args.calibration)
    classes, checks = calibration_classes(args.calibration_table, tree, support)
    runs, infos, contexts = {}, {}, {}
    for spec in args.run:
        kv = defaultdict(list)
        for part in spec.split(','):
            k, v = part.split('=', 1); kv[k].append(v)
        name = kv['name'][0]
        a, p, trials, info = prepare(kv['table'][0], float(kv['since'][0]), kv['campaign'], tree, support, classes)
        t0 = time.time()
        runs[name] = evaluate_run(a, p, trials)
        info['evaluate_seconds'] = time.time() - t0
        infos[name] = info; contexts[name] = (a, p, trials)
        print(name, json.dumps({k: v for k, v in info.items() if k != 'campaign_spans'}), flush=True)
    chosen = select(runs)
    for tier, c in chosen.items():
        if c.get('choice'):
            variant, mode, rule = c['choice'].split('|')
            for name, (a, p, trials) in contexts.items():
                (_, alarm), = rules(variant, p[variant], a['alpha'], discount_mask(a, mode), a['new'], only=rule)
                c['per_run'][name] = metrics(alarm, a, trials, by_scenario=True)
    for name, (a, p, trials) in contexts.items():
        (_, alarm), = rules('joint', p['joint'], a['alpha'], discount_mask(a, 'none'), a['new'], only='cusum_b3_h6')
        infos[name]['reference_by_scenario'] = metrics(alarm, a, trials, by_scenario=True)['recall_by_scenario']
    result = dict(schema='pulse-burden-levers-v1', protocol=['sentinel_pulse/protocol/burden-reduction-v1.json',
                  'sentinel_pulse/protocol/burden-reduction-v1-amendment-1.json'], calibration=args.calibration,
                  calibration_table=args.calibration_table, calibration_reproduced=checks,
                  mondrian_classes={f'{w}|{"launch" if c else "other"}': len(v[0]) for (w, c), v in classes.items()},
                  runs=infos, reference=REFERENCE, selection=chosen, candidates=runs, computed_at_unix=time.time())
    Path(args.output).write_text(json.dumps(result, indent=1, default=str))
    for tier, c in chosen.items():
        print(tier, json.dumps({k: v for k, v in c.items() if k not in ('per_run', 'reference_per_run')}),
              {run: {k: c['per_run'][run].get(k) for k in ('burden', 'attack', 'control', 'benign', 'p95')}
               for run in c.get('per_run', {})})


if __name__ == '__main__':
    main()
