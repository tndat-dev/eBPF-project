#!/usr/bin/env python3
"""Parts A and B of protocol ml-final-study-v1 on a live run (pulse-live-v5-1110) with the token models it ran with.

A, live attribution: every attack trial starts with a kubectl exec, and the benign binary of the same trial is flagged
almost always, so the recall may measure the launch rather than the attack operation. Per attack trial:
- as run: some window of the attack interval [start, start + 15 s] of its container scores above the threshold;
- attack-specific: the same, with every gram that the container showed in the same trial's benign and admin intervals
  removed from the window before scoring (the launch reference);
- post-launch: some window ending at least 1.5 s after the interval start scores above the threshold, nothing removed.

B, operator activity in normal, leave one command out: for each admin command c, each workload model also learns the
admin-interval windows of the other commands on that workload's containers and scores the held-out command's intervals;
attack, benign and control intervals are scored by the model that learnt every command. Thresholds stay those of the fit.

Gate: the recomputed score of every interval window equals the logged token_score within 1e-9.

    python3 live_attribution.py --run-root RUN --models FIT/token/MODELS.json --output out.json [--jobs 6]
"""
import argparse
from collections import Counter, defaultdict
import json
from multiprocessing import Pool
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.common import open_sealed  # noqa: E402
from sentinel_pulse.detector.token_model import TOP, CountTokenLM, strip  # noqa: E402
import pulse_live_v4 as live  # noqa: E402

HORIZON, POST_LAUNCH = live.HORIZON, 1.5
CAMPAIGN = live.CAMPAIGN
PRIMARY = live.PRIMARY
GATE_TOLERANCE = 1e-9


# ------------------------------------------------------------------ reading

def spans_of(trials):
    """{(pod_uid, container): [(start, end), ...]} of every interval."""
    out = defaultdict(list)
    for t in trials:
        out[t['key']].append((t['start'], t['start'] + HORIZON))
    return {k: sorted(v) for k, v in out.items()}


def _field(line, name):
    i = line.find(f'"{name}":')
    if i < 0:
        return None
    j = i + len(name) + 3
    if line[j] == '"':
        return line[j + 1:line.index('"', j + 1)]
    k = j
    while line[k] not in ',}':
        k += 1
    return line[j:k]


def read_segment(job):
    """Interval windows of one tokens.jsonl: [(key, window_end, grams, logged score, threshold)]."""
    path, spans = job
    out = []
    pods = {k[0] for k in spans}
    with open_sealed(Path(path)) as stream:
        for line in stream:
            pod = _field(line, 'pod_uid')
            if pod not in pods:
                continue
            key = (pod, _field(line, 'container_name'))
            ranges = spans.get(key)
            if not ranges:
                continue
            end = float(_field(line, 'window_end'))
            if not any(a <= end <= b for a, b in ranges):
                continue
            row = json.loads(line)
            out.append((key, end, [tuple(int(x) for x in g) for g in row['grams']], row.get('token_score'),
                        row.get('token_threshold')))
    return out


def collect(root, trials, jobs):
    spans = spans_of(trials)
    lo, hi = min(t['start'] for t in trials), max(t['start'] for t in trials) + HORIZON
    files = []
    for path in sorted(root.glob('workers/*/segments/*/tokens.jsonl*')):
        status = path.parent / 'TERMINAL.json'
        if status.exists():
            doc = json.loads(status.read_text())
            b = doc.get('finished_at_unix')
            if b is not None and (b < lo - 60 or b - 7200 > hi):   # a segment spans at most ~30 min before it finishes
                continue
        files.append(str(path))
    windows = defaultdict(list)
    with Pool(jobs) as pool:
        for rows in pool.imap_unordered(read_segment, [(f, spans) for f in files], chunksize=1):
            for key, end, grams, score, thr in rows:
                windows[key].append((end, grams, score, thr))
    for key in windows:
        windows[key].sort(key=lambda w: w[0])
    return windows, len(files)


# ------------------------------------------------------------------ scoring

def score(lm, grams, drop=frozenset()):
    """Mean of the TOP highest -ln p with multiplicity over the grams not in drop (CountTokenLM.window_score)."""
    return lm.window_score([g for g in grams if tuple(g[:4]) not in drop], TOP) if drop else lm.window_score(grams, TOP)


def interval_windows(windows, trial):
    a, b = trial['start'], trial['start'] + HORIZON
    return [w for w in windows.get(trial['key'], ()) if a <= w[0] <= b]


def load_models(path):
    doc = json.loads(Path(path).read_text())
    return {k: (v['lm'], float(v['threshold'])) for k, v in doc.items()}


def augmented(lm_path, grams_list):
    """The model of lm_path that has also learnt the given windows' grams (counts as the probe sends them)."""
    lm = CountTokenLM.load(Path(lm_path))
    for grams in grams_list:
        for *g, c in grams:
            lm.learn(strip(g), int(c))
    return lm.finalize()


# ------------------------------------------------------------------ parts

def part_a(trials, windows, models, lms):
    by_pair = defaultdict(dict)
    for t in trials:
        by_pair[t['pair']][t['label']] = t
    gate = dict(windows=0, largest_difference=0.0, missing_score=0)
    rows = []
    for t in trials:
        if t['workload'] not in models:
            continue
        lm, thr = lms[t['workload']], models[t['workload']][1]
        for end, grams, logged, _ in interval_windows(windows, t):
            s = score(lm, grams)
            if logged is None:
                gate['missing_score'] += 1
            else:
                gate['windows'] += 1
                gate['largest_difference'] = max(gate['largest_difference'], abs(s - logged))
        if t['label'] != 'attack':
            continue
        ref = set()
        for label in ('benign', 'admin'):
            other = by_pair[t['pair']].get(label)
            if other is not None and other['key'] == t['key']:
                for _, grams, _, _ in interval_windows(windows, other):
                    ref.update(tuple(g[:4]) for g in grams)
        run = specific = post = None
        for end, grams, _, _ in interval_windows(windows, t):
            if run is None and score(lm, grams) > thr:
                run = end
            if specific is None and score(lm, grams, ref) > thr:
                specific = end
            if post is None and end >= t['start'] + POST_LAUNCH and score(lm, grams) > thr:
                post = end
        rows.append(dict(pair=t['pair'], workload=t['workload'], scenario=t['scenario'], rate=t['rate'],
                         start=t['start'], reference_grams=len(ref), as_run=run, attack_specific=specific, post_launch=post))
    gate['passed'] = gate['windows'] > 0 and gate['largest_difference'] <= GATE_TOLERANCE
    return gate, rows


def summary_a(rows):
    def rates(sub):
        n = len(sub)
        k = lambda f: sum(r[f] is not None for r in sub)
        both = sum(r['attack_specific'] is not None and r['post_launch'] is not None for r in sub)
        either = sum(r['attack_specific'] is not None or r['post_launch'] is not None for r in sub)
        lat = [r['attack_specific'] - r['start'] for r in sub if r['attack_specific'] is not None]
        return dict(trials=n, as_run=k('as_run'), attack_specific=k('attack_specific'), post_launch=k('post_launch'),
                    both=both, either=either, launch_only=sum(r['as_run'] is not None and r['attack_specific'] is None
                                                              and r['post_launch'] is None for r in sub),
                    attack_specific_wilson=live.wilson(k('attack_specific'), n),
                    attack_specific_latency_p50=float(np.percentile(lat, 50)) if lat else None,
                    attack_specific_latency_p95=float(np.percentile(lat, 95)) if lat else None)
    primary = [r for r in rows if r['rate'] in PRIMARY]
    return dict(all=rates(rows), primary=rates(primary),
                by_scenario={s: rates([r for r in primary if r['scenario'] == s]) for s in sorted({r['scenario'] for r in rows})},
                by_rate={str(v): rates([r for r in rows if r['rate'] == v]) for v in sorted({r['rate'] for r in rows})})


def flagged(lm, thr, windows, trial, drop=frozenset()):
    return any(score(lm, g, drop) > thr for _, g, _, _ in interval_windows(windows, trial))


def part_b(trials, windows, models, lms):
    admin = [t for t in trials if t['label'] == 'admin' and t['workload'] in models]
    commands = sorted({t['command'] for t in admin})
    grams_of = lambda w, keep: [g for t in admin if t['workload'] == w and keep(t['command'])
                                for _, g, _, _ in interval_windows(windows, t)]
    held = defaultdict(lambda: [0, 0])
    base = defaultdict(lambda: [0, 0])
    for c in commands:
        for w in sorted({t['workload'] for t in admin if t['command'] == c}):
            lm = augmented(models[w][0], grams_of(w, lambda x: x != c))
            for t in admin:
                if t['command'] == c and t['workload'] == w:
                    for table, model in ((held, lm), (base, lms[w])):
                        table[c][0] += flagged(model, models[w][1], windows, t)
                        table[c][1] += 1
    full = {w: augmented(models[w][0], grams_of(w, lambda x: True)) for w in sorted({t['workload'] for t in admin})}
    by_pair = defaultdict(dict)
    for t in trials:
        by_pair[t['pair']][t['label']] = t
    out = defaultdict(lambda: dict(v5=[0, 0], operator=[0, 0]))
    for t in trials:
        if t['label'] == 'admin' or t['workload'] not in models:
            continue
        thr = models[t['workload']][1]
        aug = full.get(t['workload'], lms[t['workload']])
        sets = [t['label']] + ([f"{t['label']}-primary"] if t['rate'] in PRIMARY else [])
        drop = frozenset()
        if t['label'] == 'attack':
            ref = set()
            for label in ('benign', 'admin'):
                other = by_pair[t['pair']].get(label)
                if other is not None and other['key'] == t['key']:
                    for _, grams, _, _ in interval_windows(windows, other):
                        ref.update(tuple(g[:4]) for g in grams)
            drop = frozenset(ref)
            sets += ['attack-specific'] + (['attack-specific-primary'] if t['rate'] in PRIMARY else [])
        for name in sets:
            d = drop if name.startswith('attack-specific') else frozenset()
            for arm, model in (('v5', lms[t['workload']]), ('operator', aug)):
                out[name][arm][0] += flagged(model, thr, windows, t, d)
                out[name][arm][1] += 1
    pr = lambda k_n: dict(k=k_n[0], n=k_n[1], rate=k_n[0] / k_n[1] if k_n[1] else None)
    held_all = [sum(held[c][0] for c in commands), sum(held[c][1] for c in commands)]
    base_all = [sum(base[c][0] for c in commands), sum(base[c][1] for c in commands)]
    return dict(commands=commands,
                held_out_admin={c: dict(operator=pr(held[c]), v5=pr(base[c])) for c in commands},
                held_out_admin_all=dict(operator=pr(held_all), v5=pr(base_all)),
                intervals={k: {arm: pr(v) for arm, v in arms.items()} for k, arms in sorted(out.items())})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=6)
    a = ap.parse_args()
    trials = live.load_trials(a.run_root / CAMPAIGN)
    models = load_models(a.models)
    windows, files = collect(a.run_root, trials, a.jobs)
    lms = {w: CountTokenLM.load(Path(models[w][0])) for w in sorted({t['workload'] for t in trials} & set(models))}
    gate, rows = part_a(trials, windows, models, lms)
    doc = dict(schema='ml-final-study-v1-live-attribution', protocol='sentinel_pulse/protocol/ml-final-study-v1.json',
               run=str(a.run_root), models=str(a.models), segments_read=files,
               interval_windows=sum(len(v) for v in windows.values()), gate=gate)
    if gate['passed']:
        doc['A'] = summary_a(rows)
        doc['A_trials'] = rows
        doc['B'] = part_b(trials, windows, models, lms)
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps(dict(gate=gate, A=doc.get('A', {}).get('primary'), B=doc.get('B', {}).get('held_out_admin_all'))))


if __name__ == '__main__':
    main()
