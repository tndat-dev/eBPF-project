#!/usr/bin/env python3
"""H1 of protocol pulse-live-v6-v1: the native stream alone, on a live run made with the lineage build.

Every tokens.jsonl window of the lineage build holds the whole window ("grams") and the part counted on session-lineage
threads ("session": processes that entered through a runtime exec, and their descendants). Native = grams minus session,
count by count. Per interval label (control, admin, benign, attack, lotl) and set (all rates, primary), an interval is
flagged when some window of it ends in [start, start + 15 s] with a native score above the workload's threshold; the
whole window under the same rule is reported next to it (what the alert path saw).

    python3 native_stream.py --run-root RUN --models FIT/token/MODELS.json --output out.json [--jobs 6]
"""
# H1 của pulse-live-v6-v1: chấm riêng phần NATIVE của mỗi cửa sổ (grams − session) bằng cùng mô hình và ngưỡng; tỉ lệ gắn cờ
# lệnh quản trị và binary vô hại phải ≤ 5%.
import argparse
from collections import defaultdict
import json
from multiprocessing import Pool
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.common import open_sealed  # noqa: E402
import live_attribution as la  # noqa: E402

LABELS = ('control', 'admin', 'benign', 'attack', 'lotl')


def native_of(grams, session):
    """Window grams minus the session part, count by count; rows with nothing left are dropped."""
    left = {tuple(int(v) for v in g[:4]): int(g[4]) for g in grams}
    for g in session or ():
        key = tuple(int(v) for v in g[:4])
        left[key] = left.get(key, 0) - int(g[4])
        if left[key] < 0:
            raise ValueError('session part exceeds the window')
    return [[*k, c] for k, c in left.items() if c > 0]


def read_segment(job):
    """Interval windows of one tokens.jsonl: [(key, window_end, grams, session)]."""
    path, spans = job
    pods = {k[0] for k in spans}
    out = []
    with open_sealed(Path(path)) as stream:
        for line in stream:
            pod = la._field(line, 'pod_uid')
            if pod not in pods:
                continue
            key = (pod, la._field(line, 'container_name'))
            ranges = spans.get(key)
            if not ranges:
                continue
            end = float(la._field(line, 'window_end'))
            if not any(a <= end <= b for a, b in ranges):
                continue
            row = json.loads(line)
            if 'session' not in row:
                raise ValueError(f'{path}: a window without the lineage part (not a lineage build)')
            out.append((key, end, row['grams'], row['session']))
    return out


def collect(root, trials, jobs):
    spans = la.spans_of(trials)
    files = [str(p) for p in sorted(root.glob('workers/*/segments/*/tokens.jsonl*'))]
    windows = defaultdict(list)
    with Pool(jobs) as pool:
        for rows in pool.imap_unordered(read_segment, [(f, spans) for f in files], chunksize=1):
            for key, end, grams, session in rows:
                windows[key].append((end, grams, session))
    return windows, len(files)


def evaluate(trials, windows, models, lms):
    out = defaultdict(lambda: dict(native=[0, 0], whole=[0, 0], session_events=0, events=0))
    pair_rate = {t['pair']: t.get('rate') for t in trials if t['label'] == 'attack'}       # control rows carry neither
    pair_pad = {t['pair']: t.get('pad') or 0 for t in trials if t['label'] == 'attack'}
    for t in trials:
        if t['workload'] not in models or t['label'] not in LABELS:
            continue
        lm, thr = lms[t['workload']], models[t['workload']][1]
        a, b = t['start'], t['start'] + la.HORIZON
        wins = [w for w in windows.get(t['key'], ()) if a <= w[0] <= b]
        native = any(lm.window_score(native_of(g, s)) > thr for _, g, s in wins)
        whole = any(lm.window_score(g) > thr for _, g, _ in wins)
        pad = pair_pad.get(t['pair'], 0)
        sets = [t['label']] + ([f"{t['label']}-primary"] if pair_rate.get(t['pair']) in la.PRIMARY else [])
        if pad:
            sets = [f"{t['label']}-pad{pad}"]
        for name in sets:
            row = out[name]
            row['native'][0] += native
            row['whole'][0] += whole
            row['native'][1] += 1
            row['whole'][1] += 1
            row['session_events'] += sum(sum(int(x[4]) for x in s) for _, _, s in wins)
            row['events'] += sum(sum(int(x[4]) for x in g) for _, g, _ in wins)
    rate = lambda kn: dict(k=kn[0], n=kn[1], rate=kn[0] / kn[1] if kn[1] else None, ci95=la.live.wilson(kn[0], kn[1]))
    return {k: dict(native=rate(v['native']), whole=rate(v['whole']),
                    session_share=v['session_events'] / v['events'] if v['events'] else None) for k, v in sorted(out.items())}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=6)
    a = ap.parse_args()
    trials = la.live.load_trials(a.run_root / la.CAMPAIGN)
    models = la.load_models(a.models)
    windows, files = collect(a.run_root, trials, a.jobs)
    lms = {w: la.load_lm(models[w][0]) for w in sorted({t['workload'] for t in trials} & set(models))}
    res = evaluate(trials, windows, models, lms)
    h1 = {k: res[k]['native']['rate'] for k in ('admin', 'benign') if k in res}
    doc = dict(schema='pulse-live-v6-native-stream', protocol='sentinel_pulse/protocol/pulse-live-v6-v1.json',
               run=str(a.run_root), models=str(a.models), segments_read=files, intervals=res,
               H1=dict(native_flag_rate=h1, met=bool(h1) and all(v is not None and v <= 0.05 for v in h1.values())))
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps(dict(H1=doc['H1'], **{k: (v['native']['k'], v['whole']['k'], v['native']['n']) for k, v in res.items()})))


if __name__ == '__main__':
    main()
