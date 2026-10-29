#!/usr/bin/env python3
"""Live rolling calibration R against the bundle calibration F on the same run (live-recalibration-confirmation-v1).

- ``R``  the run's live ML previews (window table column ``preview``), scored under the rolling calibration;
- ``F``  the same rows rescored with ``--calibration`` (the bundle's calibration file) and the registered policy
         recomputed on the table (``--ml-rule`` tier of ``--ml-results``), as rule_comparison.py / burden_blind_test.py;
- ``R_system`` / ``F_system``  each with the live tripwire as a parallel stream (rule_comparison.compare, arm B2).

Definitions are those of rule_comparison.py (trial hit inside [start, start + 15 s], earliest alert, episodes of one
(pod_uid, container) less than 15 s apart, workload clusters). The normal span starts at the first applied refresh
(earliest ``applied`` row of the workers' recalibration.jsonl) or at selection end, whichever is later; campaign
span excluded. Paired R - F differences: workload-clustered bootstrap (rate and burden) and trial bootstrap (p95),
rule_comparison.bootstrap. F_check: on the rows that end before the first applied refresh (calibration epoch 0) R and
F must agree in >= 99.9 % of windows, else F is not a reproduction of the live scorer and no decision is made.
"""
import argparse
from collections import defaultdict
import glob
import json
from pathlib import Path
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rule_comparison as rc  # noqa: E402

bl = rc.bl
BLOCK_HOURS = 6


def first_applied(workers_root):
    times = []
    for log in glob.glob(f'{workers_root}/*/recalibration.jsonl'):
        for line in Path(log).read_text().splitlines():
            e = json.loads(line)
            if e.get('event') == 'applied':
                times.append(float(e['at']))
    return min(times) if times else None


def ml_arm(a, trials, ml_alarm, normal_from, campaign_span, resolver_workloads=()):
    """Per-trial (hit, time), normal episodes per cluster, replica-hours per cluster: compare()'s ML stream."""
    fields = a['identity_fields']
    pu, cn, wk = fields.index('pod_uid'), fields.index('container_name'), fields.index('workload_key')
    key_of_ident = [(str(i[pu]), str(i[cn])) for i in a['identities']]
    workload_of_key = dict(resolver_workloads)
    workload_of_key.update({(str(i[pu]), str(i[cn])): str(i[wk]) for i in a['identities']})
    cluster_of = lambda key: workload_of_key.get(key) or f'unmapped:{key[0]}:{key[1]}'
    n = len(trials.label)
    ident_of_trial = a['ident'][trials.lo]
    t = dict(label=trials.label, scenario=trials.scenario, kernel=trials.kernel, start=trials.start, rate=trials.rate,
             cluster=np.array([cluster_of(key_of_ident[int(k)]) for k in ident_of_trial]))
    hit, at = np.zeros(n, bool), np.full(n, np.inf)
    for i, (lo, hi) in enumerate(zip(trials.lo, trials.hi)):
        rows = np.flatnonzero(ml_alarm[lo:hi])
        if len(rows):
            hit[i], at[i] = True, a['end'][lo + rows[0]]
    normal = a['normal'] & (a['start'] >= normal_from)
    lo_c, hi_c = campaign_span
    normal &= ~((a['end'] > lo_c) & (a['end'] < hi_c))
    hours = defaultdict(float)
    for k, dur in zip(a['ident'][normal], (a['end'] - a['start'])[normal]):
        hours[cluster_of(key_of_ident[int(k)])] += dur / 3600
    events = defaultdict(list)
    idx = np.flatnonzero(ml_alarm & normal)
    for k, e in zip(a['ident'][idx], a['end'][idx]):
        events[key_of_ident[int(k)]].append(float(e))
    return t, hit, np.where(hit, at, np.nan), rc.episodes_by_cluster(events, cluster_of), dict(hours), normal


def blocks(a, alarm, normal, start, hours=BLOCK_HOURS):
    """Episodes per replica-hour in consecutive blocks of ``hours`` from ``start`` (per window-table identity)."""
    out = []
    end = float(a['end'][normal].max()) if normal.any() else start
    t0 = start
    while t0 < end:
        m = normal & (a['end'] >= t0) & (a['end'] < t0 + hours * 3600)
        rh = float(((a['end'] - a['start'])[m]).sum()) / 3600
        out.append(dict(from_unix=t0, replica_hours=rh,
                        burden=bl.episodes(a['ident'], a['end'], alarm & m, rc.QUIET) / rh if rh else None))
        t0 += hours * 3600
    return out


def decide(r, f, diff):
    """calibration-strategies-v1: burden >= 10 % lower, recall not > 2 points lower, control not > 1 point higher,
    p95 not > 0.2 s slower (primary set)."""
    checks = dict(burden_10pct_lower=r['burden'] <= 0.9 * f['burden'],
                  recall_within_2pt=r['primary']['attack'] >= f['primary']['attack'] - 0.02,
                  control_within_1pt=r['primary']['control'] <= f['primary']['control'] + 0.01,
                  p95_within_0_2s=(r['primary']['p95'] is not None and f['primary']['p95'] is not None
                                   and r['primary']['p95'] <= f['primary']['p95'] + 0.2))
    return dict(checks=checks, R_beats_F=all(checks.values()), burden_diff=diff['burden_diff'])


def run(a, trials, R, F, normal_from, campaign_span, epoch0_end, tripwire=None, resolver=(None, {})):
    t, hR, atR, epR, hours, normal = ml_arm(a, trials, R, normal_from, campaign_span, resolver[1])
    _, hF, atF, epF, _, _ = ml_arm(a, trials, F, normal_from, campaign_span, resolver[1])
    primary = np.isin(t['rate'], rc.PRIMARY_RATES)
    every = np.ones(len(primary), bool)
    total = sum(hours.values())
    arm = lambda h, at, ep: dict(primary=rc.trial_metrics(t, h, at, primary), all_rates=rc.trial_metrics(t, h, at, every),
                                 burden=sum(ep.values()) / total if total else None)
    arms = dict(F=arm(hF, atF, epF), R=arm(hR, atR, epR))
    diff = rc.bootstrap(t, dict(A=hF, R=hR), dict(A=atF, R=atR), primary, dict(A=epF, R=epR), hours)['R']
    pre = a['end'] < epoch0_end if epoch0_end is not None else np.zeros(len(R), bool)
    f_check = dict(rows=int(pre.sum()), agreement=float((R[pre] == F[pre]).mean()) if pre.any() else None)
    f_check['passed'] = f_check['agreement'] is not None and f_check['agreement'] >= 0.999
    out = dict(arms=arms, R_minus_F=diff, F_check=f_check, normal=dict(from_unix=normal_from, replica_hours=total),
               blocks=dict(R=blocks(a, R, normal, normal_from), F=blocks(a, F, normal, normal_from)))
    out['decision'] = decide(arms['R'], arms['F'], diff) if f_check['passed'] else dict(R_beats_F=None, reason='F_check failed')
    if tripwire is not None:
        names, workloads = resolver
        for name, alarm in (('F_system', F), ('R_system', R)):
            c = rc.compare(a, trials, normal_from, alarm, None, tripwire, None, names or {}, workloads, campaign_span)
            out['arms'][name] = c['arms']['B2']
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--table', required=True); ap.add_argument('--since', type=float, required=True)
    ap.add_argument('--selection-end', type=float, required=True); ap.add_argument('--campaign', required=True)
    ap.add_argument('--calibration', required=True); ap.add_argument('--calibration-table', required=True)
    ap.add_argument('--ml-rule', required=True); ap.add_argument('--ml-results', required=True)
    ap.add_argument('--tripwire', required=True); ap.add_argument('--workers-root', required=True)
    ap.add_argument('--output', required=True)
    x = ap.parse_args()
    tree, support = bl.load_calibration(x.calibration)
    classes, _ = bl.calibration_classes(x.calibration_table, tree, support)
    a, p, trials, _ = bl.prepare(x.table, x.since, [x.campaign], tree, support, classes)
    config = json.loads(Path(x.ml_results).read_text())['selection'][x.ml_rule]['choice']
    variant, mode, rule = config.split('|')
    (_, F), = bl.rules(variant, p[variant], a['alpha'], bl.discount_mask(a, mode), a['new'], only=rule)
    R = a['preview'].astype(bool)
    applied = first_applied(x.workers_root)
    normal_from = max(x.selection_end, applied) if applied else x.selection_end
    out = run(a, trials, R, F, normal_from, bl.campaign_span(Path(x.campaign)), applied,
              json.loads(Path(x.tripwire).read_text()), rc.load_resolver(x.workers_root))
    out.update(schema='pulse-recal-comparison-v1', protocol='sentinel_pulse/protocol/live-recalibration-confirmation-v1.json',
               F_config=config, first_applied_refresh_unix=applied, computed_at_unix=time.time())
    Path(x.output).write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps(dict(decision=out['decision'], F_check=out['F_check'],
                          burden={k: v['burden'] for k, v in out['arms'].items()}), default=str))


if __name__ == '__main__':
    main()
