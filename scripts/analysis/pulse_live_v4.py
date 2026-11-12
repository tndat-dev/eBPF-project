#!/usr/bin/env python3
"""Stage 2 of pulse-live-v3-v1 (+ amendments) for lidds-ml-v4: the arms on the trials and the normal span of one live run.

Arms: system (what the run alerted on), V4 (token or tree or support), T (token), T_raw (token before the lidds-ml-v5 gate),
C (tree or support), tree, support. Admin commands that failed are left out.
A trial is detected when an alarm of the arm falls inside [start, start + 15 s] on its container; the alert time is the
earliest alarm, the latency is alert time - kernel event, both from the window end. The campaign's own status counts only
count-branch rows (preview_evaluation.py), so it is not used here. Normal burden: alarms of one container merged into
episodes when less than 15 s apart, per replica-hour, from selection end to capture end without the campaign span,
workload-clustered bootstrap 95 % CI. Rates: Wilson 95 % CI. Primary set: attack rates 6, 12, 24 per second.

--exclude-span START END (unix seconds, repeatable) leaves out a span in which the infrastructure stalled (owner rule: a
run completes its cycle and bad spans are excluded in the analysis): every interval of a pair whose attack, control,
benign or admin interval overlaps the span is dropped, and the span leaves the normal time. Run without it for the
registered analysis and with it for the sensitivity.

    python3 pulse_live_v4.py --run-root ROOT --output out.json [--reps 10000] [--exclude-span A B] [--protocol TEXT]
"""
import argparse
from array import array
from collections import defaultdict
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.common import open_sealed  # noqa: E402
from sentinel_pulse.rca.baseline_seed import campaign_span  # noqa: E402

ARMS = ('system', 'V4', 'T', 'T_raw', 'C', 'tree', 'support')
PRIMARY = (6, 12, 24)
HORIZON = 15.0
QUIET = 15.0
WINDOW_SECONDS = 0.5
EXPECT = dict(recall=.95, precision=.95, control=.05, latency_p95=3.0)
CAMPAIGN = 'pulse-development-matrix'


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [c - h, c + h]


def arms_of(row):
    """Arms that alarm on one decision row."""
    status = row.get('status')
    out = ['system'] if row.get('candidate_alert_preview') is True and status in ('token-score', 'candidate-raw-score-only') else []
    if status == 'token-score':
        if row.get('candidate_alert_preview') is True:
            out += ['V4', 'T']
        if row.get('token_alert_raw', row.get('candidate_alert_preview')) is True:
            out += ['T_raw']
        return tuple(out)
    if status != 'candidate-raw-score-only':
        return ()
    if row.get('v3_tree_alert') is True:
        out += ['tree']
    if row.get('v3_support_alert') is True:
        out += ['support']
    if row.get('v3_tree_alert') is True or row.get('v3_support_alert') is True:
        out += ['V4', 'C']
    return tuple(out)


def admin_failed(campaign, pair):
    """A command the image lacks is not a benign run (protocol lidds-ml-v5)."""
    path = campaign / 'trials' / f'{pair:04d}' / 'ADMIN.json'
    return not path.exists() or json.loads(path.read_text()).get('returncode') != 0


def load_trials(campaign):
    """The campaign's intervals with their label (attack, control, benign) and the attack's kernel event."""
    trials = []
    for line in (campaign / 'INTERVALS.jsonl').read_text().splitlines():
        if not line:
            continue
        row = json.loads(line)
        label = ('attack' if row['label'] == 'attack' else 'admin' if row.get('control_kind') == 'admin_exec'
                 else 'benign' if row.get('control_kind') else 'control')
        pair = int(str(row['trial_id']).split(':')[0])
        if label == 'admin' and admin_failed(campaign, pair):
            continue
        trials.append(dict(label=label, start=float(row['start_at']), key=(row['pod_uid'], row['container_name']),
                           pair=int(str(row['trial_id']).split(':')[0]), workload=row['workload_key'],
                           rate=row.get('rate_per_second'), scenario=row.get('scenario'), kernel=None,
                           command=row.get('admin_command')))
    for trial in trials:
        if trial['label'] == 'attack':
            path = campaign / 'trials' / f"{trial['pair']:04d}" / 'EVALUATION_INPUT.json'
            if path.exists():
                trial['kernel'] = json.loads(path.read_text())['attack'].get('kernel_event_at')
    return trials


def read_decisions(root, normal, spans):
    """One pass: alarm times per arm and container, replica-seconds per workload on the normal span, scoring latency."""
    alarms = {arm: defaultdict(list) for arm in ARMS}
    seconds, workload_of, latency = defaultdict(float), {}, dict(token=array('f'), counts=array('f'))
    for segment in sorted({path.parent for path in root.glob('workers/*/segments/*/decisions.jsonl*')}):
        with open_sealed(segment / 'decisions.jsonl') as stream:
            for line in stream:
                row = json.loads(line)
                status, end = row.get('status'), row.get('window_end')
                if status not in ('token-score', 'candidate-raw-score-only') or end is None:
                    continue
                key = (row['pod_uid'], row['container_name'])
                workload_of[key] = row['workload_key']
                for arm in arms_of(row):
                    alarms[arm][key].append(end)
                emitted = row.get('preview_emitted_at')
                if emitted is not None:
                    latency['token' if status == 'token-score' else 'counts'].append(emitted - end)
                if status == 'candidate-raw-score-only' and normal[0] <= end < normal[1] and not in_spans(end, spans):
                    seconds[row['workload_key']] += WINDOW_SECONDS
    return alarms, seconds, workload_of, latency


def in_spans(t, spans):
    return any(a <= t < b for a, b in spans)


def first_alarm(times, start):
    """Earliest alarm in [start, start + HORIZON]; times sorted."""
    i = np.searchsorted(times, start)
    return float(times[i]) if i < len(times) and times[i] <= start + HORIZON else None


def trial_table(trials, alarms):
    """{arm: [alert time or None per trial]}."""
    table = {}
    for arm in ARMS:
        sorted_times = {k: np.sort(np.asarray(v)) for k, v in alarms[arm].items()}
        empty = np.empty(0)
        table[arm] = [first_alarm(sorted_times.get(t['key'], empty), t['start']) for t in trials]
    return table


def rate_row(hits, n):
    return dict(hits=hits, n=n, rate=hits / n if n else None, ci95=wilson(hits, n))


def trial_metrics(trials, at, keep):
    """Rates of one arm on the trials kept (a predicate on the pair's rate, applied through its attack)."""
    pair_rate = {t['pair']: t['rate'] for t in trials if t['label'] == 'attack'}
    idx = [i for i, t in enumerate(trials) if keep(pair_rate.get(t['pair']))]
    out = {}
    for label in ('attack', 'control', 'benign', 'admin'):
        members = [i for i in idx if trials[i]['label'] == label]
        out[label] = rate_row(sum(at[i] is not None for i in members), len(members))
    tp, fp = out['attack']['hits'], out['control']['hits']
    out['precision'] = rate_row(tp, tp + fp)
    delays = [at[i] - trials[i]['kernel'] for i in idx if trials[i]['label'] == 'attack' and at[i] is not None
              and trials[i]['kernel'] is not None and at[i] >= trials[i]['kernel']]
    out['latency_p50'] = float(np.percentile(delays, 50)) if delays else None
    out['latency_p95'] = float(np.percentile(delays, 95)) if delays else None
    return out


def by_field(trials, at, field, label='attack'):
    out = {}
    for value in sorted({t[field] for t in trials if t['label'] == label}, key=str):
        members = [i for i, t in enumerate(trials) if t['label'] == label and t[field] == value]
        out[str(value)] = rate_row(sum(at[i] is not None for i in members), len(members))
    return out


def episodes_per_workload(alarms, workload_of, normal, spans):
    """Alarms of one container on the normal span merged when less than QUIET apart, counted per workload."""
    out = defaultdict(int)
    for key, times in alarms.items():
        kept = np.sort(np.asarray([t for t in times if normal[0] <= t < normal[1] and not in_spans(t, spans)]))
        if len(kept):
            out[workload_of[key]] += 1 + int(np.count_nonzero(np.diff(kept) >= QUIET))
    return dict(out)


def burden(episodes, seconds, reps, seed=20261109):
    """Episodes per replica-hour and its workload-clustered bootstrap 95 % CI."""
    names = sorted(seconds)
    if not names or not sum(seconds.values()):
        return dict(value=None, episodes=0, replica_hours=0.0, ci95=None)
    ep = np.asarray([episodes.get(n, 0) for n in names], float)
    hours = np.asarray([seconds[n] / 3600 for n in names])
    rng = np.random.default_rng(seed)
    pick = rng.integers(0, len(names), size=(reps, len(names)))
    values = ep[pick].sum(1) / np.maximum(hours[pick].sum(1), 1e-9)
    return dict(value=float(ep.sum() / hours.sum()), episodes=int(ep.sum()), replica_hours=float(hours.sum()),
                ci95=[float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))])


def quantiles(values):
    if not len(values):
        return None
    x = np.frombuffer(values, dtype=np.float32)
    return dict(n=int(len(x)), **{f'p{q}': float(np.percentile(x, q)) for q in (50, 95, 99)}, max=float(x.max()))


def expectations(primary):
    met = dict(recall=primary['attack']['rate'] is not None and primary['attack']['rate'] >= EXPECT['recall'],
               precision=primary['precision']['rate'] is not None and primary['precision']['rate'] >= EXPECT['precision'],
               control=primary['control']['rate'] is not None and primary['control']['rate'] <= EXPECT['control'],
               latency_p95=primary['latency_p95'] is not None and primary['latency_p95'] <= EXPECT['latency_p95'])
    return dict(met, all=all(met.values()))


def worker_report(root):
    out = {}
    for status in sorted(root.glob('workers/*/STATUS.json')):
        doc = json.loads(status.read_text())
        tokens = sum(p.stat().st_size for p in status.parent.glob('segments/*/tokens.jsonl*'))
        out[status.parent.name] = dict(issues=doc.get('issues'), segments=doc.get('segments'), frames=doc.get('frames'),
                                       token_windows=doc.get('token_windows'), token_alerts=doc.get('token_alerts'),
                                       tokens_bytes=tokens)
    return out


def drop_stalled(trials, stalls):
    """Trials without the pairs that have an interval [start, start + HORIZON] overlapping a stalled span."""
    bad = {t['pair'] for t in trials if any(t['start'] < b and t['start'] + HORIZON > a for a, b in stalls)}
    return [t for t in trials if t['pair'] not in bad], sorted(bad)


def analyse(root, reps, stalls=(), protocol='sentinel_pulse/protocol/pulse-live-v3-v1.json + amendments 1, 2'):
    cfg = json.loads((root / 'CONFIG.json').read_text())
    campaign = root / CAMPAIGN
    normal = (float(cfg['selection_end']), float(cfg['selection_start']) + float(cfg['seconds']))
    spans = [campaign_span(campaign)] if (campaign / 'TERMINAL.json').exists() else []
    complete = bool(spans)
    trials, dropped = drop_stalled(load_trials(campaign), stalls)
    spans = spans + [tuple(x) for x in stalls]
    alarms, seconds, workload_of, latency = read_decisions(root, normal, spans)
    table = trial_table(trials, alarms)
    arms = {}
    for arm in ARMS:
        at = table[arm]
        primary = trial_metrics(trials, at, lambda rate: rate in PRIMARY)
        arms[arm] = dict(primary=primary, all_rates=trial_metrics(trials, at, lambda rate: rate is not None),
                         recall_by_rate=by_field(trials, at, 'rate'), recall_by_scenario=by_field(trials, at, 'scenario'),
                         admin_by_command=by_field(trials, at, 'command', 'admin'),
                         expectations=expectations(primary),
                         burden=burden(episodes_per_workload(alarms[arm], workload_of, normal, spans), seconds, reps))
    return dict(schema='pulse-live-v4-arms-v1', run=cfg['run_id'], protocol=protocol,
                campaign_complete=complete, pairs=len({t['pair'] for t in trials}), normal_span=normal, excluded_spans=spans,
                stalled_spans=[list(x) for x in stalls], pairs_dropped_for_stall=dropped,
                arms=arms, scoring_latency=dict(token=quantiles(latency['token']), counts=quantiles(latency['counts'])),
                workers=worker_report(root))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--reps', type=int, default=10000)
    ap.add_argument('--exclude-span', type=float, nargs=2, action='append', default=[], metavar=('START', 'END'))
    ap.add_argument('--protocol', default='sentinel_pulse/protocol/pulse-live-v3-v1.json + amendments 1, 2')
    a = ap.parse_args()
    out = analyse(a.run_root, a.reps, [tuple(x) for x in a.exclude_span], a.protocol)
    a.output.write_text(json.dumps(out, indent=1))
    for arm, r in out['arms'].items():
        p = r['primary']
        print(arm, f"recall {p['attack']['hits']}/{p['attack']['n']}", f"precision {p['precision']['rate']}",
              f"control {p['control']['hits']}/{p['control']['n']}", f"benign {p['benign']['hits']}/{p['benign']['n']}",
              f"p95 {p['latency_p95']}", f"burden {r['burden']['value']}", f"met {r['expectations']['all']}")


if __name__ == '__main__':
    main()
