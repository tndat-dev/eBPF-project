#!/usr/bin/env python3
"""System without and with rules (RULE_INTEGRATION_STATUS R6; protocol rule-integration-v1 + amendments 1 and 2).

Arms on the same trials and the same normal span of one live run:

- ``A``      ML only: the live previews of the stable ML (window table column ``preview``);
- ``B1``     ML and Falco as parallel alert streams;
- ``B2``     ML and tripwire A1 as parallel alert streams;
- ``B3``     ML filtered for paging by the post-ML probe triage (rule_tier.py definitions, fail-open);
- ``B_all``  ML after triage + Falco + tripwire.

A trial is detected by an arm when any of its streams alerts inside [start, start + 15 s]; the alert time is the
earliest stream alert (for the triaged ML stream: the creation time of the deciding RCA case, else the preview).
Normal burden: alerts of one container (pod_uid, container name) merged across the arm's streams into episodes
when less than 15 s apart, per replica-hour of the ML window table on the normal span (selection end to capture
end, campaign excluded). Every B arm is compared with A: per-trial differences with a workload-clustered
bootstrap 95 % CI, burden difference with the same bootstrap, p95 difference with a bootstrap over attack trials.

Inputs come from falco_baseline.py (per trial, normal events), novel_syscalls.py --normal-span (per trial, normal
alerts), the RCA cases and the run's resolver metadata (pod name -> pod_uid for Falco events).
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
import burden_levers as bl  # noqa: E402

QUIET, INTERVAL, TRIAGE_MATCH, TRIAL_CASE_SPAN = 15.0, 15.0, 5.0, 20.0
ARMS = ('A', 'B1', 'B2', 'B3', 'B_all')
PRIMARY_RATES = (6, 12, 24)


# ------------------------------------------------------------------ inputs

def load_cases(cases_dir, spec_path):
    """{(pod_uid, container): sorted [(trigger window_end, probe-only, created_at)]} (rule_tier definitions)."""
    import alarm_taxonomy as at
    spec = json.loads(Path(spec_path).read_text())['workloads']
    out = defaultdict(list)
    for path in sorted(Path(cases_dir).glob('*.json')):
        try:
            case = json.loads(path.read_text())
            kind, trigger, _ = at.classify(case)
        except (ValueError, KeyError, StopIteration):
            continue
        execs, probes = at.probe_flags(case, set((spec.get(trigger.get('workload_key')) or {}).get('entry_binaries', ())))
        held = kind == 'exec_in_window' and execs > 0 and probes == execs
        out[(str(trigger.get('pod_uid')), str(trigger.get('container_name')))].append(
            (float(trigger['window_end']), held, float(case.get('created_at') or trigger['window_end'])))
    for v in out.values():
        v.sort()
    return dict(out)


def triage(cases, lo, hi):
    """(matched, held, decided_at) over the cases with window_end in [lo, hi]: held when there is one and all are
    probe-only; decided_at = creation time of the first such case."""
    sel = [c for c in cases or () if lo <= c[0] <= hi]
    if not sel:
        return False, False, None
    return True, all(c[1] for c in sel), min(c[2] for c in sel)


def load_resolver(workers_root):
    """From the resolver metadata the workers logged: pod name -> {pod_uid} and (pod_uid, container) -> workload key
    ('namespace/workload:container', as the window table)."""
    names, workloads = defaultdict(set), {}
    for path in sorted(glob.glob(str(workers_root).rstrip('/') + '/*/segments/s*/issues.jsonl')):
        with open(path) as f:
            for line in f:
                if '"resolver_metadata"' not in line:
                    continue
                for c in json.loads(line)['document']['cgroups'].values():
                    if c.get('pod_uid') and c.get('pod_name'):
                        names[c['pod_name']].add(str(c['pod_uid']))
                        if c.get('workload_name') and c.get('container_name') != 'pod-slice':
                            workloads[(str(c['pod_uid']), str(c['container_name']))] = \
                                f"{c.get('namespace')}/{c['workload_name']}:{c['container_name']}"
    return dict(names), workloads


def by_trial(rows, key='start'):
    out = {}
    for r in rows:
        k = (r.get('label') or r.get('kind'), round(float(r[key]), 3))
        if k in out:
            raise ValueError(f'two trials share (label, start) {k}')
        out[k] = r
    return out


# ------------------------------------------------------------------ core

def episodes_by_cluster(events, cluster_of):
    """events: {container key: [times]} -> {cluster: episodes} (merge < QUIET across streams)."""
    out = defaultdict(int)
    for key, times in events.items():
        times = sorted(times)
        if times:
            out[cluster_of(key)] += 1 + int(np.count_nonzero(np.diff(times) >= QUIET))
    return dict(out)


def arm_trials(t, streams):
    """Per-trial (hit, alert time) of one arm from its streams' (hit, time) arrays."""
    hit = np.zeros(len(t['label']), bool); at = np.full(len(t['label']), np.inf)
    for h, tm in streams:
        hit |= h; at = np.where(h, np.minimum(at, tm), at)
    return hit, np.where(hit, at, np.nan)


def trial_metrics(t, hit, at, keep):
    out = {}
    for label in ('attack', 'benign', 'control'):
        m = keep & (t['label'] == label)
        out[label] = float(hit[m].mean()) if m.any() else None
    att, ctl = keep & (t['label'] == 'attack'), keep & (t['label'] == 'control')
    tp, fp = int(hit[att].sum()), int(hit[ctl].sum())
    out.update(TP=tp, FN=int((att & ~hit).sum()), control_FP=fp, precision=tp / (tp + fp) if tp + fp else None)
    d = at[att & hit] - t['kernel'][att & hit]
    d = d[np.isfinite(d) & (d >= 0)]
    out.update(p50=float(np.percentile(d, 50)) if len(d) else None, p95=float(np.percentile(d, 95)) if len(d) else None)
    out['recall_by_scenario'] = {str(s): float(hit[att & (t['scenario'] == s)].mean()) for s in sorted(set(t['scenario'][att]))}
    return out


def bootstrap(t, hits, ats, keep, episodes, hours, reps=10000, seed=20261025):
    """Workload-clustered paired CIs of B - A for attack/control/benign rates and burden; trial bootstrap for p95."""
    rng = np.random.default_rng(seed)
    clusters = sorted(set(t['cluster'][keep]) | set(hours) | set().union(*episodes.values()))
    index = {c: i for i, c in enumerate(clusters)}
    ci = lambda x: [float(np.percentile(x, 2.5)), float(np.percentile(x, 97.5))] if len(x) else None
    counts = {}
    for label in ('attack', 'control', 'benign'):
        m = keep & (t['label'] == label)
        n = np.bincount([index[c] for c in t['cluster'][m]], minlength=len(clusters)).astype(float)
        counts[label] = (m, n, {arm: np.bincount([index[c] for c in t['cluster'][m]], weights=hits[arm][m].astype(float),
                                               minlength=len(clusters)) for arm in hits})
    hrs = np.array([hours.get(c, 0.0) for c in clusters])
    eps = {arm: np.array([episodes[arm].get(c, 0) for c in clusters], float) for arm in hits}
    draws = rng.integers(0, len(clusters), size=(reps, len(clusters)))
    w = np.stack([np.bincount(d, minlength=len(clusters)) for d in draws]).astype(float)
    out = {}
    for arm in hits:
        if arm == 'A':
            continue
        res = {}
        for label, (_, n, k) in counts.items():
            den = w @ n
            with np.errstate(invalid='ignore', divide='ignore'):
                diff = (w @ k[arm] - w @ k['A']) / den
            res[f'{label}_diff'] = dict(point=float((k[arm].sum() - k['A'].sum()) / n.sum()) if n.sum() else None,
                                        ci95=ci(diff[np.isfinite(diff)]))
        with np.errstate(invalid='ignore', divide='ignore'):
            bd = (w @ eps[arm] - w @ eps['A']) / (w @ hrs)
        res['burden_diff'] = dict(point=float((eps[arm].sum() - eps['A'].sum()) / hrs.sum()), ci95=ci(bd[np.isfinite(bd)]))
        att = np.flatnonzero(keep & (t['label'] == 'attack'))
        p95 = []
        for _ in range(reps):
            s = rng.choice(att, size=len(att))
            vals = []
            for a_ in ('A', arm):
                d = ats[a_][s] - t['kernel'][s]
                d = d[hits[a_][s] & np.isfinite(d) & (d >= 0)]
                vals.append(np.percentile(d, 95) if len(d) else np.nan)
            p95.append(vals[1] - vals[0])
        p95 = np.array(p95)
        res['p95_diff_seconds'] = dict(ci95=ci(p95[np.isfinite(p95)]))
        out[arm] = res
    return out


def compare(a, trials, normal_from, ml_alarm, falco, tripwire, cases, pod_uids_of_name, resolver_workloads, campaign_span):
    """All arms; ``a``/``trials`` from burden_levers.prepare, ``ml_alarm`` per table row. Bootstrap clusters are
    workload keys (as burden_blind_test.burden_ci); a container outside the window table gets its workload key from
    the resolver metadata, else its own key."""
    fields = a['identity_fields']
    pu, cn, wk = fields.index('pod_uid'), fields.index('container_name'), fields.index('workload_key')
    key_of_ident = [(str(i[pu]), str(i[cn])) for i in a['identities']]
    workload_of_key = dict(resolver_workloads)
    workload_of_key.update({(str(i[pu]), str(i[cn])): str(i[wk]) for i in a['identities']})
    cluster_of = lambda key: workload_of_key.get(key) or f'unmapped:{key[0]}:{key[1]}'
    pod_uid_of_name = {name: next(iter(uids)) for name, uids in pod_uids_of_name.items() if len(uids) == 1}
    ambiguous_names = sorted(name for name, uids in pod_uids_of_name.items() if len(uids) > 1)
    n = len(trials.label)
    ident_of_trial = a['ident'][trials.lo]
    t = dict(label=trials.label, scenario=trials.scenario, kernel=trials.kernel, start=trials.start, rate=trials.rate,
             cluster=np.array([cluster_of(key_of_ident[int(k)]) for k in ident_of_trial]))
    # ML stream per trial: first alarm row in the trial's rows
    ml_hit, ml_at = np.zeros(n, bool), np.full(n, np.inf)
    for i, (lo, hi) in enumerate(zip(trials.lo, trials.hi)):
        rows = np.flatnonzero(ml_alarm[lo:hi])
        if len(rows):
            ml_hit[i], ml_at[i] = True, a['end'][lo + rows[0]]
    # triage of ML-positive trials
    held_t, tri_at, failopen = np.zeros(n, bool), ml_at.copy(), 0
    for i in np.flatnonzero(ml_hit):
        matched, held, decided = triage(cases.get(key_of_ident[int(ident_of_trial[i])]), t['start'][i], t['start'][i] + TRIAL_CASE_SPAN)
        held_t[i] = held
        if matched and decided is not None:
            tri_at[i] = max(decided, ml_at[i])
        else:
            failopen += 1
    # rule streams per trial, matched on (label, start)
    fz, tw = by_trial(falco['trials']), by_trial(tripwire['trials'])
    f_hit, f_at, w_hit, w_at = np.zeros(n, bool), np.full(n, np.inf), np.zeros(n, bool), np.full(n, np.inf)
    unmatched = dict(falco=0, tripwire=0)
    for i in range(n):
        k = (str(t['label'][i]), round(float(t['start'][i]), 3))
        r = fz.get(k)
        if r is None:
            unmatched['falco'] += 1
        elif r['detected']:
            f_hit[i], f_at[i] = True, float(r['first_event'])
        r = tw.get(k)
        if r is None:
            unmatched['tripwire'] += 1
        elif r['novel']:
            w_hit[i], w_at[i] = True, float(r['first_novel_end'])
    streams = dict(A=[(ml_hit, ml_at)], B1=[(ml_hit, ml_at), (f_hit, f_at)], B2=[(ml_hit, ml_at), (w_hit, w_at)],
                   B3=[(ml_hit & ~held_t, tri_at)], B_all=[(ml_hit & ~held_t, tri_at), (f_hit, f_at), (w_hit, w_at)])
    hits, ats = {}, {}
    for arm, s in streams.items():
        hits[arm], ats[arm] = arm_trials(t, s)
    # normal span
    normal = a['normal'] & (a['start'] >= normal_from)
    hours = defaultdict(float)
    for k, dur in zip(a['ident'][normal], (a['end'] - a['start'])[normal]):
        hours[cluster_of(key_of_ident[int(k)])] += dur / 3600
    lo_c, hi_c = campaign_span
    in_normal = lambda x: x >= normal_from and x <= float(a['end'][normal].max()) and not lo_c < x < hi_c
    ml_ev, tri_ev = defaultdict(list), defaultdict(list)
    idx = np.flatnonzero(ml_alarm & normal)
    held_episodes = episodes_total = 0
    if len(idx):
        ident, end = a['ident'][idx], a['end'][idx]
        first = np.ones(len(idx), bool)
        first[1:] = (ident[1:] != ident[:-1]) | (end[1:] - end[:-1] >= QUIET)
        starts = np.flatnonzero(first); stops = np.append(starts[1:], len(idx))
        for s0, s1 in zip(starts, stops):
            key = key_of_ident[int(ident[s0])]
            times = end[s0:s1].tolist()
            ml_ev[key] += times
            episodes_total += 1
            _, held, _ = triage(cases.get(key), end[s0] - TRIAGE_MATCH, end[s1 - 1] + TRIAGE_MATCH)
            if held:
                held_episodes += 1
            else:
                tri_ev[key] += times
    life = {}                                   # pod_uid -> (first start, last end) in the window table (rows sorted by ident)
    cut = np.flatnonzero(np.diff(a['ident'])) + 1
    for b0, b1 in zip(np.r_[0, cut], np.r_[cut, len(a['ident'])]):
        uid = key_of_ident[int(a['ident'][b0])][0]
        lo, hi = life.get(uid, (np.inf, -np.inf))
        life[uid] = (min(lo, float(a['start'][b0])), max(hi, float(a['end'][b1 - 1])))
    f_ev, unmapped = defaultdict(list), set()
    for e in falco['normal_events']:
        when = float(e['time'])
        if not in_normal(when):
            continue
        name = e.get('pod')
        uid = pod_uid_of_name.get(name)
        if uid is None and name in pod_uids_of_name:     # same pod name, several pods (restart): the one alive then
            alive = [u for u in pod_uids_of_name[name] if u in life and life[u][0] - QUIET <= when <= life[u][1] + QUIET]
            uid = alive[0] if len(alive) == 1 else None
        if uid is None:
            unmapped.add(name)
        f_ev[(uid or str(name), str(e.get('container_name')))].append(when)
    w_ev = defaultdict(list)
    for e in tripwire['normal']['alerts']:
        if in_normal(float(e['end'])):
            w_ev[(str(e['pod_uid']), str(e['container_name']))].append(float(e['end']))
    union = lambda *ds: {k: sum((d.get(k, []) for d in ds), []) for k in set().union(*ds)}
    events = dict(A=ml_ev, B1=union(ml_ev, f_ev), B2=union(ml_ev, w_ev), B3=tri_ev, B_all=union(tri_ev, f_ev, w_ev))
    episodes = {arm: episodes_by_cluster(ev, cluster_of) for arm, ev in events.items()}
    in_table = set(key_of_ident)
    outside = lambda ev: sum(episodes_by_cluster({k: v for k, v in ev.items() if k not in in_table}, cluster_of).values())
    total_hours = sum(hours.values())
    primary = np.isin(t['rate'], PRIMARY_RATES)
    every = np.ones(n, bool)
    arms = {}
    for arm in ARMS:
        arms[arm] = dict(primary=trial_metrics(t, hits[arm], ats[arm], primary),
                         all_rates=trial_metrics(t, hits[arm], ats[arm], every),
                         burden=sum(episodes[arm].values()) / total_hours,
                         normal_episodes_by_workload=dict(sorted(episodes[arm].items(), key=lambda kv: -kv[1])))
    return dict(arms=arms,
                comparison_primary=bootstrap(t, hits, ats, primary, episodes, hours),
                streams=dict(falco_normal_events=sum(map(len, f_ev.values())), falco_unmapped_pods=sorted(unmapped),
                             falco_pod_names_with_several_pods=ambiguous_names,
                             falco_episodes_outside_window_table=outside(f_ev),
                             tripwire_normal_alert_windows=sum(map(len, w_ev.values())),
                             tripwire_episodes_outside_window_table=outside(w_ev),
                             ml_normal_episodes=episodes_total, ml_normal_episodes_held_back=held_episodes,
                             triage_failopen_trials=int(failopen), trials_unmatched=unmatched),
                normal=dict(from_unix=normal_from, replica_hours=total_hours),
                trials=dict(n=int(n), attack=int((t['label'] == 'attack').sum())))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--table', required=True)
    ap.add_argument('--since', type=float, required=True, help='selection start (as the ML burden)')
    ap.add_argument('--normal-from', type=float, required=True, help='selection end: start of the R6 normal span')
    ap.add_argument('--campaign', required=True)
    ap.add_argument('--calibration', required=True)
    ap.add_argument('--calibration-table', required=True)
    ap.add_argument('--cases', required=True)
    ap.add_argument('--probe-spec', required=True)
    ap.add_argument('--falco', required=True)
    ap.add_argument('--tripwire', required=True)
    ap.add_argument('--workers-root', required=True)
    ap.add_argument('--output', required=True)
    x = ap.parse_args()
    tree, support = bl.load_calibration(x.calibration)
    classes, _ = bl.calibration_classes(x.calibration_table, tree, support)
    a, _, trials, _ = bl.prepare(x.table, x.since, [x.campaign], tree, support, classes)
    names, workloads = load_resolver(x.workers_root)   # pod name -> {pod_uid}, (pod_uid, container) -> workload key
    result = compare(a, trials, x.normal_from, a['preview'].astype(bool), json.loads(Path(x.falco).read_text()),
                     json.loads(Path(x.tripwire).read_text()), load_cases(x.cases, x.probe_spec), names, workloads,
                     bl.campaign_span(Path(x.campaign)))
    result.update(schema='pulse-rule-comparison-v1',
                  protocol='sentinel_pulse/protocol/rule-integration-v1.json + amendments 1 and 2',
                  inputs=dict(table=x.table, falco=x.falco, tripwire=x.tripwire, cases=x.cases), computed_at_unix=time.time())
    Path(x.output).write_text(json.dumps(result, indent=1, default=str))
    print(json.dumps({arm: dict(burden=round(r['burden'], 3), **{k: r['primary'][k] for k in ('attack', 'control', 'benign', 'precision', 'p95')})
                      for arm, r in result['arms'].items()}, default=str))


if __name__ == '__main__':
    main()
