#!/usr/bin/env python3
"""Pulse with argument, return-value and sequence signals on LID-DS 2021 (protocol lidds-evaluation-v2).

Per scenario, from the alias conversion (convert.py with SYSDIG_ALIASES, lidds-evaluation-v1 amendment 1) and the
raw traces of the scenario archive:

- ``ml``, ``tripwire``, ``system``: the v1 arms on the alias conversion (the sensitivity analysis of amendment 1);
- step 1: ``ml_support_first`` (windows without three windows of history are scored by the support branch alone,
  p <= 5 x 0.05/30, same two-consecutive rule) and ``tripwire_no_exec_set`` (no exec set E: LID-DS has no exec
  probes); ``step1`` = their OR;
- step 2: ``path``, ``errno``, ``bytes`` (sentinel_pulse/lidds/signals.py; references from the training recordings,
  normal ranges from training and validation, limits = max score over the validation windows; one window suffices);
  ``step2`` = step1 OR path OR errno OR bytes;
- step 3: ``ngram`` (per-thread 7-grams unseen in training, limit = max over validation windows); ``step3`` = step2
  OR ngram, the v2 system.

Official numbers: every test/normal recording and 70 % of the test/normal_and_attack recordings of each scenario;
the other 30 % (seeded) are the development set, reported apart. Metrics as v1 plus detection within 3 s and
precision at 1:1 and at the dataset's base rate.

    python3 lidds_evaluate_v2.py --converted DIR --archives DIR --exec-set E.json --output part.json [--scenario NAME ...]
    python3 lidds_evaluate_v2.py --merge part1.json part2.json ... --output lidds-evaluation-v2.json

Every output keeps the outcome of every recording and arm (``recordings``), so parts run in parallel merge exactly.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys
import time
import zipfile
import zlib

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_evaluate as v1  # noqa: E402
from sentinel_pulse.detector.support_model import pvalues  # noqa: E402
from sentinel_pulse.encoding import decode_vector  # noqa: E402
from sentinel_pulse.lidds import convert, signals  # noqa: E402

SPLIT_SEED, DEV_SHARE, FAST_SECONDS = 20261030, 0.3, 3.0
ARMS = ('ml', 'tripwire', 'system', 'ml_support_first', 'tripwire_no_exec_set', 'step1',
        'path', 'errno', 'bytes', 'step2', 'ngram', 'step3')


def split_recordings(archive, wanted):
    """(split, name, inner zip bytes) of the recordings of the ``wanted`` splits only (others are not read)."""
    outer = zipfile.ZipFile(archive)
    for member in sorted(outer.namelist()):
        if not member.endswith('.zip') or member.startswith('__MACOSX'):
            continue
        parts = member.split('/')
        split = '/'.join(parts[1:-1]).replace('/', '-')
        if split in wanted:
            yield split, parts[-1][:-4], outer.read(member)


def raw_windows(blob):
    _, lines = convert.recording(blob)
    return signals.recording_signals(lines)


def ml_alarms_support_first(model, rows):
    """As v1.ml_alarms, but the first HISTORY windows of a run are scored by the support branch alone."""
    out = {}
    for run in v1.runs(rows):
        vec = np.asarray([decode_vector(r) for r in run], dtype=np.float32)
        p = np.ones(len(run))
        head = min(v1.HISTORY, len(run))
        if head:
            p[:head] = pvalues(model.support_scores(vec[:head]), model.support_calibration)
        if len(run) > v1.HISTORY:
            ctx, _ = v1.contexts(run)
            p[v1.HISTORY:] = model.predict_contexts(ctx)['joint_p']
        passed = p <= v1.SCALE * v1.ALPHA
        prev_end, prev_pass = None, False
        for r, ok in zip(run, passed):
            contiguous = prev_end is not None and .35 <= r['window_end'] - prev_end <= .8
            out[r['window_end']] = bool(ok and prev_pass and contiguous)
            prev_end, prev_pass = r['window_end'], bool(ok)
    return out


def union(*alarms):
    keys = set().union(*alarms)
    return {k: any(a.get(k, False) for a in alarms) for k in keys}


def development_set(scenario, attack_names):
    names = sorted(attack_names)
    rng = np.random.default_rng(SPLIT_SEED + zlib.crc32(scenario.encode()))
    order = rng.permutation(len(names))
    return {names[i] for i in order[:round(DEV_SHARE * len(names))]}


def summarize(outcomes):
    """v1.summarize + detection within FAST_SECONDS and precision at 1:1 and at the base rate of the subset."""
    out = v1.summarize([o[:5] for o in outcomes])
    att = [o for o in outcomes if o[0] == 'test-normal_and_attack']
    fast = sum(o[1] and o[2] is not None and o[2] <= FAST_SECONDS for o in att)
    out.update(detected_within_3s=fast, detection_within_3s_rate=fast / len(att) if att else None)
    dr, fa = out['detection_rate'], out['false_alarm_rate']
    out['precision_1to1'] = dr / (dr + fa) if dr is not None and fa is not None and dr + fa else None
    tp, fp = out['detected'], out['false_alarm_recordings']
    out['precision_base_rate'] = tp / (tp + fp) if tp + fp else None
    return out


def evaluate_scenario(scenario, converted, archive, exec_set):
    recs = {s: v1.recordings(converted / f'{s}.jsonl.gz') for s in v1.SPLITS if (converted / f'{s}.jsonl.gz').exists()}
    model, fit = v1.fit_ml(recs['training'], recs['validation'])
    reference_ids = v1.tripwire_reference(recs['training'])
    ref = signals.Reference()
    for _, _, blob in split_recordings(archive, {'training'}):
        ref.learn(raw_windows(blob))
    validation = []
    for _, _, blob in split_recordings(archive, {'validation'}):
        validation.extend(raw_windows(blob).values())
    for s in validation:                                   # normal ranges: training and validation
        ref.widen(s)
    limits = signals.thresholds(ref, validation)
    attack_names = list(recs.get('test-normal_and_attack', {}))
    dev = development_set(scenario, attack_names)
    outcomes = defaultdict(list)
    for split, name, blob in split_recordings(archive, {'test-normal', 'test-normal_and_attack'}):
        rows = recs.get(split, {}).get(name)
        if not rows:
            continue                                       # no scored window in the conversion: as v1
        exploit = rows[0]['lidds']['exploit_at']
        ml, tw = v1.ml_alarms(model, rows), v1.tripwire_alarms(reference_ids, exec_set, rows)
        mls, two = ml_alarms_support_first(model, rows), v1.tripwire_alarms(reference_ids, set(), rows)
        br = signals.branch_alarms(ref, limits, raw_windows(blob))
        a = dict(ml=ml, tripwire=tw, system=union(ml, tw), ml_support_first=mls, tripwire_no_exec_set=two,
                 step1=union(mls, two), **br)
        a['step2'] = union(a['step1'], br['path'], br['errno'], br['bytes'])
        a['step3'] = union(a['step2'], br['ngram'])
        subset = 'development' if name in dev else 'official'
        for arm in ARMS:
            d, lat, fa = v1.recording_outcome([e for e, x in a[arm].items() if x], exploit)
            outcomes[arm].append((split, d, lat, fa, len(rows), subset, name))
    pick = lambda arm, sub: [o for o in outcomes[arm] if o[0] == 'test-normal' or o[5] == sub]
    return dict(scenario=scenario, fit=fit, tripwire_reference_ids=len(reference_ids),
                reference=dict(prefixes=len(ref.prefixes), paths=len(ref.paths), error_pairs=len(ref.errors),
                               ngrams=len(ref.ngrams)),
                limits=dict(limits), development_recordings=sorted(dev),
                arms={arm: dict(official=summarize(pick(arm, 'official')), development=summarize(pick(arm, 'development')),
                                all=summarize(outcomes[arm])) for arm in ARMS}), outcomes


def pooled(raw, subset):
    pick = lambda arm: [o for s in raw.values() for o in s[arm] if o[0] == 'test-normal' or subset == 'all' or o[5] == subset]
    return {arm: summarize(pick(arm)) for arm in ARMS}


def bootstrap(raw, a, b, subset='official', reps=10000, seed=SPLIT_SEED):
    """Scenario-clustered 95 % CI of pooled detection and false-alarm-rate differences a - b."""
    names = sorted(raw)
    def counts(arm):
        rows = []
        for s in names:
            o = [x for x in raw[s][arm] if x[0] == 'test-normal' or x[5] == subset]
            att = [x for x in o if x[0] == 'test-normal_and_attack']; nor = [x for x in o if x[0] == 'test-normal']
            rows.append([sum(x[1] for x in att), len(att), sum(x[3] > 0 for x in nor), len(nor)])
        return np.array(rows, float)
    ca, cb = counts(a), counts(b)
    idx = np.random.default_rng(seed).integers(0, len(names), size=(reps, len(names)))
    ra, rb = ca[idx].sum(1), cb[idx].sum(1)
    with np.errstate(invalid='ignore', divide='ignore'):
        det = ra[:, 0] / ra[:, 1] - rb[:, 0] / rb[:, 1]
        fa = ra[:, 2] / ra[:, 3] - rb[:, 2] / rb[:, 3]
    pa, pb = ca.sum(0), cb.sum(0)
    ci = lambda x: [float(np.nanpercentile(x, 2.5)), float(np.nanpercentile(x, 97.5))]
    return dict(detection_diff=float(pa[0] / pa[1] - pb[0] / pb[1]), detection_ci95=ci(det),
                false_alarm_diff=float(pa[2] / pa[3] - pb[2] / pb[3]), false_alarm_ci95=ci(fa))


def criteria(per_scenario, pool):
    """H1 / H2 / H3 of lidds-evaluation-v2 on the official subset for the v2 system (step3)."""
    s3 = pool['step3']
    h1 = s3['detection_rate'] >= 0.90 and s3['false_alarm_rate'] <= 0.030
    worst_fa = max(r['arms']['step3']['official']['false_alarm_rate'] for r in per_scenario.values())
    h2 = s3['detection_rate'] >= 0.95 and worst_fa <= 0.05
    h3 = {}
    for name, r in per_scenario.items():
        base = r['arms']['system']['official']
        if base['detection_rate'] == 1.0:
            new = r['arms']['step3']['official']
            h3[name] = new['detection_rate'] >= 0.99 and new['false_alarm_rate'] <= base['false_alarm_rate'] + 0.01
    return dict(H1=h1, H2=h2, H2_worst_scenario_false_alarm_rate=worst_fa, H3=all(h3.values()) if h3 else None,
                H3_per_scenario=h3)


def document(results, raw):
    ok = {k: v for k, v in results.items() if 'arms' in v}
    pool = {sub: pooled(raw, sub) for sub in ('official', 'development', 'all')}
    return dict(schema='pulse-lidds-evaluation-v2', protocol='sentinel_pulse/protocol/lidds-evaluation-v2.json',
                scenarios=results, pooled=pool,
                differences={f'{a}-{b}': bootstrap(raw, a, b) for a, b in (('step3', 'system'), ('step1', 'system'),
                                                                         ('step2', 'step1'), ('step3', 'step2'))} if len(raw) > 1 else None,
                criteria=criteria(ok, pool['official']) if ok else None,
                recordings={s: {arm: [list(o) for o in v] for arm, v in arms.items()} for s, arms in raw.items()},
                computed_at_unix=time.time())


def merge(paths):
    results, raw = {}, {}
    for path in paths:
        d = json.loads(Path(path).read_text())
        for name, r in d['scenarios'].items():
            if name in results:
                raise ValueError(f'scenario {name} in two parts')
            results[name] = r
        for name, arms in d['recordings'].items():
            raw[name] = {arm: [tuple(o) for o in v] for arm, v in arms.items()}
    return document(results, raw)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--converted', type=Path, help='alias conversion (one directory per scenario)')
    ap.add_argument('--archives', type=Path)
    ap.add_argument('--exec-set', type=Path)
    ap.add_argument('--scenario', action='append')
    ap.add_argument('--merge', nargs='+', type=Path, help='combine part outputs instead of evaluating')
    ap.add_argument('--output', type=Path, required=True)
    x = ap.parse_args()
    if x.merge:
        doc = merge(x.merge)
        x.output.write_text(json.dumps(doc, indent=1, default=float))
        print(json.dumps(doc['criteria'], default=float)); return
    exec_set = {int(i) for i in json.loads(x.exec_set.read_text())}
    names = x.scenario or sorted(p.name for p in x.converted.iterdir() if (p / 'SUMMARY.json').exists())
    results, raw = {}, {}
    for name in names:
        t0 = time.time()
        try:
            results[name], raw[name] = evaluate_scenario(name, x.converted / name, x.archives / f'{name}.zip', exec_set)
        except ValueError as exc:
            results[name] = dict(scenario=name, unknown=str(exc)); continue
        results[name]['seconds'] = time.time() - t0
        print(name, json.dumps({a: round(results[name]['arms'][a]['official']['detection_rate'], 3) for a in ('system', 'step1', 'step2', 'step3')}),
              flush=True)
    doc = document(results, raw)
    x.output.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(doc['criteria'], default=float))


if __name__ == '__main__':
    main()
