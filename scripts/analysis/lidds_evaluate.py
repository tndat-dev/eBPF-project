#!/usr/bin/env python3
"""Pulse's final system and STIDE on LID-DS 2021 (protocol sentinel_pulse/protocol/lidds-evaluation-v1.json).

Per scenario (one workload), from the windows of sentinel_pulse/lidds/convert.py:

- ML: PulseExtendedReferenceTree(history 3, alpha 0.001) fitted on the training recordings, calibrated on the
  validation recordings, PulseSupportEnsemble on the same; a window passes when joint_p <= 5 x 0.05/30 and alarms
  on two consecutive contiguous passes (the live rule without the evidence discount);
- tripwire A1: IDs of the training windows as reference, exec set E;
- system: ML or tripwire;
- STIDE: 7-grams of syscall names per thread in the training traces; a test window alarms when one of its threads
  completes an unseen 7-gram (raw traces from the scenario archive).

Metrics per recording (attack recording detected = an alarm window ending after the exploit; a normal test
recording with any alarm = false-alarm recording; alarms before the exploit count as false alarms), per scenario and
pooled, with a scenario bootstrap of the pooled differences.

    python3 lidds_evaluate.py --converted DIR --archives DIR --exec-set E.json --output lidds-evaluation.json [--scenario NAME ...]
"""
import argparse
from collections import defaultdict, deque
import gzip
import json
import math
from pathlib import Path
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.detector.extended_reference_experiment import PulseExtendedReferenceTree  # noqa: E402
from sentinel_pulse.detector.support_model import PulseSupportEnsemble  # noqa: E402
from sentinel_pulse.encoding import decode_vector  # noqa: E402
from sentinel_pulse.lidds import convert  # noqa: E402

HISTORY, TREE_ALPHA, SEED = 3, 0.001, 73021
ALPHA = 0.05 / 30
SCALE = 5.0
STIDE_N, QUIET, WINDOW = 7, 15.0, 0.5
SPLITS = ('training', 'validation', 'test-normal', 'test-normal_and_attack')


# ------------------------------------------------------------------ data

def recordings(path):
    """{recording: [rows sorted by window_end]} of one split file."""
    out = defaultdict(list)
    with gzip.open(path, 'rt') as f:
        for line in f:
            row = json.loads(line)
            out[row['lidds']['recording']].append(row)
    for rows in out.values():
        rows.sort(key=lambda r: r['window_end'])
    return dict(out)


def runs(rows):
    """Contiguous runs of eligible windows (as the live scorer's history: a gap or ineligible window resets)."""
    out, current, last_end = [], [], None
    for r in rows:
        contiguous = last_end is not None and .35 <= r['window_end'] - last_end <= .8
        if not r.get('eligible_for_normal_review') or not contiguous:
            if current:
                out.append(current)
            current = []
        if r.get('eligible_for_normal_review'):
            current.append(r)
        last_end = r['window_end']
    if current:
        out.append(current)
    return out


def contexts(run_rows):
    """(contexts, rows) for every window with HISTORY contiguous eligible windows before it."""
    vec = np.asarray([decode_vector(r) for r in run_rows], dtype=np.float32)
    if len(vec) <= HISTORY:
        return np.empty((0, (HISTORY + 1) * vec.shape[1] if len(vec) else 0), np.float32), []
    ctx = np.stack([vec[i - HISTORY:i + 1].reshape(-1) for i in range(HISTORY, len(vec))])
    return ctx, run_rows[HISTORY:]


# ------------------------------------------------------------------ arms

def fit_ml(train_recs, cal_recs):
    seqs = lambda recs: [[decode_vector(r) for r in run] for rows in recs.values() for run in runs(rows)]
    tree = PulseExtendedReferenceTree(history=HISTORY, alpha=TREE_ALPHA, random_state=SEED)
    report = tree.fit_sequences({'train': seqs(train_recs), 'calibration': seqs(cal_recs)})
    model = PulseSupportEnsemble(tree)
    cur = lambda recs: np.asarray([decode_vector(r) for rows in recs.values() for run in runs(rows) for r in run[HISTORY:]],
                                  dtype=np.float32)
    report['support'] = model.fit_support(cur(train_recs), cur(cal_recs))
    return model, report


def ml_alarms(model, rows):
    """{window_end: alarm} for one recording: joint_p <= SCALE * ALPHA, two consecutive contiguous passes."""
    out = {}
    for run in runs(rows):
        ctx, scored = contexts(run)
        if not scored:
            continue
        joint = model.predict_contexts(ctx)['joint_p']
        passed = joint <= SCALE * ALPHA
        prev_end, prev_pass = None, False
        for r, ok in zip(scored, passed):
            contiguous = prev_end is not None and .35 <= r['window_end'] - prev_end <= .8
            out[r['window_end']] = bool(ok and prev_pass and contiguous)
            prev_end, prev_pass = r['window_end'], bool(ok)
    return out


def tripwire_reference(train_recs):
    return {int(i) for rows in train_recs.values() for r in rows for i in r['full_counts_delta']}


def tripwire_alarms(reference, exec_set, rows):
    return {r['window_end']: bool({int(i) for i in r['full_counts_delta']} - reference - exec_set) for r in rows}


def stide_ngrams(lines, n=STIDE_N):
    """(window_end, thread n-gram) of every completed n-gram of a recording's entry sequence per thread."""
    threads = defaultdict(lambda: deque(maxlen=n))
    for line in lines:
        parts = line.split(' ', 7)
        if len(parts) < 7 or parts[6] != '>':
            continue
        q = threads[parts[4]]; q.append(parts[5])
        if len(q) == n:
            ts = int(parts[0]) / 1e9
            yield math.floor(ts / WINDOW) * WINDOW + WINDOW, tuple(q)


# ------------------------------------------------------------------ metrics

def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [c - h, c + h]


def recording_outcome(alarm_ends, exploit_at):
    """(detected, latency, false_alarm_episodes) of one recording from its alarm window ends."""
    ends = sorted(alarm_ends)
    after = [e for e in ends if exploit_at is not None and e > exploit_at]
    before = [e for e in ends if exploit_at is None or e <= exploit_at]
    episodes = (1 + sum(1 for a, b in zip(before, before[1:]) if b - a >= QUIET)) if before else 0
    return bool(after), (after[0] - exploit_at) if after else None, episodes


def summarize(outcomes):
    """outcomes: [(split, detected, latency, false_episodes, windows)] -> metrics."""
    att = [o for o in outcomes if o[0] == 'test-normal_and_attack']
    nor = [o for o in outcomes if o[0] == 'test-normal']
    det = sum(o[1] for o in att); fa = sum(o[3] > 0 for o in nor)
    lat = [o[2] for o in att if o[2] is not None]
    hours = sum(o[4] for o in nor) * WINDOW / 3600
    return dict(attack_recordings=len(att), detected=det, detection_rate=det / len(att) if att else None,
                detection_ci95=wilson(det, len(att)), normal_recordings=len(nor), false_alarm_recordings=fa,
                false_alarm_rate=fa / len(nor) if nor else None, false_alarm_ci95=wilson(fa, len(nor)),
                false_alarm_episodes_per_hour=sum(o[3] for o in nor) / hours if hours else None,
                false_alarms_before_exploit=sum(o[3] for o in att), normal_hours=hours,
                latency_p50=float(np.percentile(lat, 50)) if lat else None,
                latency_p95=float(np.percentile(lat, 95)) if lat else None)


def evaluate_scenario(scenario, converted, archive, exec_set):
    recs = {s: recordings(converted / f'{s}.jsonl.gz') for s in SPLITS if (converted / f'{s}.jsonl.gz').exists()}
    model, fit = fit_ml(recs['training'], recs['validation'])
    reference = tripwire_reference(recs['training'])
    arms = defaultdict(list)
    test = {s: recs.get(s, {}) for s in ('test-normal', 'test-normal_and_attack')}
    windows_of = {}
    for split, group in test.items():
        for name, rows in group.items():
            exploit = rows[0]['lidds']['exploit_at'] if rows else None
            ml = ml_alarms(model, rows); tw = tripwire_alarms(reference, exec_set, rows)
            windows_of[name] = (split, exploit, len(rows))
            for arm, alarms in (('ml', ml), ('tripwire', tw),
                                ('system', {e: ml.get(e, False) or tw.get(e, False) for e in set(ml) | set(tw)})):
                d, lat, fa = recording_outcome([e for e, a in alarms.items() if a], exploit)
                arms[arm].append((split, d, lat, fa, len(rows)))
    # STIDE on the raw traces of the same recordings
    db, stide = set(), defaultdict(set)
    for split, name, blob in convert.scenario_recordings(archive):
        key = split.replace('/', '-')
        if key == 'training':
            _, lines = convert.recording(blob)
            db.update(g for _, g in stide_ngrams(lines))
    for split, name, blob in convert.scenario_recordings(archive):
        key = split.replace('/', '-')
        if key in test and name in windows_of:
            _, lines = convert.recording(blob)
            stide[name] = {e for e, g in stide_ngrams(lines) if g not in db}
    for name, (split, exploit, n) in windows_of.items():
        d, lat, fa = recording_outcome(stide.get(name, set()), exploit)
        arms['stide'].append((split, d, lat, fa, n))
    return dict(scenario=scenario, fit=fit, tripwire_reference_ids=len(reference), stide_database_ngrams=len(db),
                recordings={s: len(v) for s, v in recs.items()},
                arms={arm: summarize(o) for arm, o in arms.items()}), arms


def pooled_bootstrap(per_scenario, reps=10000, seed=20261029):
    """Scenario-clustered CI of pooled detection and false-alarm-rate differences system-ml and system-stide."""
    rng = np.random.default_rng(seed)
    names = sorted(per_scenario)
    def counts(arm):
        a = np.array([[sum(o[1] for o in per_scenario[s][arm] if o[0] == 'test-normal_and_attack'),
                       sum(o[0] == 'test-normal_and_attack' for o in per_scenario[s][arm]),
                       sum(o[3] > 0 for o in per_scenario[s][arm] if o[0] == 'test-normal'),
                       sum(o[0] == 'test-normal' for o in per_scenario[s][arm])] for s in names], float)
        return a
    c = {arm: counts(arm) for arm in ('ml', 'tripwire', 'system', 'stide')}
    idx = rng.integers(0, len(names), size=(reps, len(names)))
    out = {}
    for a, b in (('system', 'ml'), ('system', 'stide'), ('ml', 'stide')):
        ra, rb = c[a][idx].sum(1), c[b][idx].sum(1)
        with np.errstate(invalid='ignore', divide='ignore'):
            det = ra[:, 0] / ra[:, 1] - rb[:, 0] / rb[:, 1]
            fa = ra[:, 2] / ra[:, 3] - rb[:, 2] / rb[:, 3]
        pa, pb = c[a].sum(0), c[b].sum(0)
        ci = lambda x: [float(np.nanpercentile(x, 2.5)), float(np.nanpercentile(x, 97.5))]
        out[f'{a}-{b}'] = dict(detection_diff=float(pa[0] / pa[1] - pb[0] / pb[1]), detection_ci95=ci(det),
                               false_alarm_diff=float(pa[2] / pa[3] - pb[2] / pb[3]), false_alarm_ci95=ci(fa))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--converted', type=Path, required=True, help='convert.py output (one directory per scenario)')
    ap.add_argument('--archives', type=Path, required=True, help='directory of the LID-DS 2021 scenario zips')
    ap.add_argument('--exec-set', type=Path, required=True)
    ap.add_argument('--scenario', action='append', help='limit to these scenarios')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    exec_set = {int(x) for x in json.loads(a.exec_set.read_text())}
    names = a.scenario or sorted(p.name for p in a.converted.iterdir() if (p / 'SUMMARY.json').exists())
    results, raw = {}, {}
    for name in names:
        t0 = time.time()
        try:
            results[name], raw[name] = evaluate_scenario(name, a.converted / name, a.archives / f'{name}.zip', exec_set)
        except ValueError as exc:                      # e.g. too few calibration contexts: unknown, never dropped silently
            results[name] = dict(scenario=name, unknown=str(exc)); continue
        results[name]['seconds'] = time.time() - t0
        print(name, json.dumps({arm: {k: v for k, v in m.items() if k in ('detection_rate', 'false_alarm_rate', 'latency_p95')}
                                for arm, m in results[name]['arms'].items()}), flush=True)
    pooled = {arm: summarize([o for s in raw for o in raw[s][arm]]) for arm in ('ml', 'tripwire', 'system', 'stide')}
    doc = dict(schema='pulse-lidds-evaluation-v1', protocol='sentinel_pulse/protocol/lidds-evaluation-v1.json',
               scenarios=results, pooled=pooled, pooled_differences=pooled_bootstrap(raw) if len(raw) > 1 else None,
               computed_at_unix=time.time())
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(pooled, default=float)[:2000])


if __name__ == '__main__':
    main()
