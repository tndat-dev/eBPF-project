#!/usr/bin/env python3
"""LID-DS 2019 development study (protocol lidds2019-development-v1): a 30 % development part of the 2019 test recordings.

  split    development/holdout of every 2019 test recording (sha256 rule of the protocol), from the recording names of
           the registered run's token matrices; written once, before any cache or score.
  cache    fact-gram cache (lidds_token_cache.py layout) of one scenario: training, validation and the test recordings
           of one part (development by default; holdout only for the single holdout scoring).
  gate     the base spec (select1f, n 4, top 10, alpha' 0.00018, trim 1 %) on the development caches must give the same
           decisions as the registered lidds-ml-v5 matrices on the same recordings.
  study    every candidate on the development part (registered primary exploit time and the 1 s label tolerance of
           lidds2019-confirmation-v2 amendment 1), with its LID-DS 2021 development / CB-DS numbers from the
           token-design-study-v1 receipts (q1 add-one alphabets, q2 parameters); the protocol's must-rules and selection.

    python3 lidds2019_dev.py split --tokens DIR2019 --output split.json
    python3 lidds2019_dev.py cache --archives DIR --scenario S --split split.json --output caches/S.npz [--n 5]
    python3 lidds2019_dev.py gate  --caches caches --tokens DIR2019 --out OUT
    python3 lidds2019_dev.py study --caches caches --out OUT --receipts validation-evidence/results-20261112/token-design-study

  grid     combinations (n x top-k x alpha' x trim), each scored on the 2019 development part AND on LID-DS 2021
           development / CB-DS (fact caches of token-design-study-v1, scored here, not taken from receipts); the 2021
           base combination must reproduce the token-design-study gate (530/6, p95 1.52 s, CB-DS 891/3).
  latency  per development attack recording of the slow scenarios: exploit time, first alarm, highest window after the
           exploit and when it comes, windows above the threshold, recording end (base decision).

    python3 lidds2019_dev.py grid --caches caches --out OUT --caches-2021 DIR --lidds-alarms a.json.gz --cbds-alarms c.json.gz
    python3 lidds2019_dev.py latency --caches caches --out OUT
"""
# NGHIÊN CỨU DEVELOPMENT CỦA LID-DS 2019 (lidds2019-development-v1): tách 30 % bản ghi test làm development theo sha256, thử
# các ứng viên (tham số, bảng chữ) trên phần đó, giữ điều kiện LID-DS 2021 development và CB-DS, rồi mới chốt.
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds2019_token as l19  # noqa: E402
import lidds_ml_v2 as m  # noqa: E402
import lidds_token_cache as tc  # noqa: E402
import lidds_token_study as st  # noqa: E402
import lidds_v3_combine as v3  # noqa: E402

SALT = 'lidds2019-development:'
TOLERANCE = 1.0
DEV_FA_LIMIT = 0.01
MIN_GAIN = 0.02
PROTOCOL = 'sentinel_pulse/protocol/lidds2019-development-v1.json'


def part_of(name):
    """The protocol's split: development if sha256(SALT + name) mod 10 < 3, else holdout."""
    return 'development' if int(hashlib.sha256((SALT + name).encode()).hexdigest(), 16) % 10 < 3 else 'holdout'


def split(token_dir):
    out, counts = {}, {}
    for meta_path in sorted(Path(token_dir).glob('*.json')):
        recs = json.loads(meta_path.read_text())['recordings']
        test = {n: r['split'] for n, r in recs.items() if r['split'] not in ('training', 'validation')}
        out[meta_path.stem] = {n: part_of(n) for n in sorted(test)}
        counts[meta_path.stem] = Counter(f'{part}/{test[n]}' for n, part in out[meta_path.stem].items())
    return dict(schema='lidds2019-development-split-v1', protocol=PROTOCOL, rule=f"sha256('{SALT}' + name) % 10 < 3",
                counts=counts, scenarios=out)


def cache(archives, scenario, split_doc, output, n=5, part='development'):
    names = {k for k, v in split_doc['scenarios'][scenario].items() if v == part}
    t0 = time.time()
    output = Path(output)
    partial = output.with_suffix('.part')
    vocab, meta, events = tc.build(Path(archives) / f'{scenario}.zip', partial, lambda name, s: name in names, n)
    partial.rename(output)
    output.with_suffix('.json').write_text(json.dumps(dict(schema='lidds-token-cache-v1', scenario=scenario, n=n, vocab=vocab, part=part,
                                                          recordings=meta, events=events, seconds=time.time() - t0)))
    return dict(scenario=scenario, part=part, recordings=len(meta), facts=len(vocab), events=events, seconds=round(time.time() - t0))


def inventory(caches):
    """lidds_ml_v2 alarms document of the test recordings in the caches (primary exploit time)."""
    docs: dict = dict(scenarios={})
    for p in sorted(Path(caches).glob('*.json')):
        recs = json.loads(p.read_text())['recordings']
        docs['scenarios'][p.stem] = dict(alarms={n: dict(split=r['split'], exploit=r['exploit'], subset='development')
                                                 for n, r in recs.items() if r['split'] not in ('training', 'validation')})
    return docs


def evaluate(scenarios, docs):
    pooled, per = [], {}
    for s, scn in scenarios.items():
        rows = list(m.rows(scn, docs['scenarios'][s]['alarms'], ('T',), None, lambda n, r: True).values())
        per[s] = v3.metrics(rows)
        pooled.extend(rows)
    out = v3.metrics(pooled)
    out['detected_within_3s'] = sum(1 for x in pooled if x[0] == 'test-normal_and_attack' and x[2] is not None and x[2] <= 3.0)
    return out, per


class Fixed:
    """A scored scenario with a fixed alpha' (m.rows passes alpha=None)."""

    def __init__(self, scn, alpha):
        self.scn, self.alpha = scn, alpha

    def firings(self, branches, alpha, name):
        return self.scn.firings(branches, self.alpha, name)


def scored(out, sid, column, alpha, trim, docs):
    d = Path(out) / 'scores' / sid
    spec = json.loads((d / 'SPEC.json').read_text())
    scen = {s: Fixed(st.TokenScenario(d / f'{s}.npz', column, spec['columns'], trim), alpha) for s in sorted(docs['scenarios'])}
    primary, per = evaluate(scen, docs)
    tol, tol_per = evaluate(scen, l19.shifted(docs, TOLERANCE))
    keep = lambda r: dict(detected=r['detected'], attack_recordings=r['attack_recordings'], false_alarm_recordings=r['false_alarm_recordings'],
                          normal_recordings=r['normal_recordings'], recall=r['recall'], false_alarm_rate=r['false_alarm_rate'],
                          latency_p50=r['latency_p50'], latency_p95=r['latency_p95'], detected_within_3s=r.get('detected_within_3s'))
    return dict(primary=keep(primary), tolerance=keep(tol),
                scenarios={s: dict(primary=[per[s]['detected'], per[s]['attack_recordings'], per[s]['false_alarm_recordings'], per[s]['normal_recordings']],
                                   tolerance=[tol_per[s]['detected'], tol_per[s]['false_alarm_recordings'], tol_per[s]['latency_p95']])
                           for s in per})


def namespace(caches, out, jobs):
    return SimpleNamespace(caches=str(caches), out=str(out), jobs=jobs)


def gate(caches, token_dir, out, jobs):
    """Base spec on the development caches == registered lidds-ml-v5 matrices on the same recordings."""
    docs = inventory(caches)
    st.ensure(namespace(caches, out, jobs), {'base': st.base_spec(tops=list(st.GRID['top']))})
    new = scored(out, 'base', f'top{st.TOP}', st.ALPHA, st.TRIM, docs)
    ref_scen = {s: l19.TokenScenario(s, token_dir) for s in sorted(docs['scenarios'])}
    ref, _ = evaluate(ref_scen, docs)
    same = all(new['primary'][k] == ref[k] for k in ('detected', 'attack_recordings', 'false_alarm_recordings', 'normal_recordings'))
    doc = dict(schema='lidds2019-development-gate-v1', protocol=PROTOCOL, passed=same, base=new['primary'],
               registered_matrices={k: ref[k] for k in ('detected', 'attack_recordings', 'false_alarm_recordings', 'normal_recordings', 'latency_p95')})
    (Path(out) / 'gate.json').write_text(json.dumps(doc, indent=1, default=float))
    return doc


def from_receipts(receipts):
    """LID-DS 2021 development / CB-DS metrics of token-design-study-v1 by candidate id."""
    q1 = json.loads((Path(receipts) / 'q1.json').read_text())
    q2 = json.loads((Path(receipts) / 'q2.json').read_text())['grid']
    out = {'base': q2['n']['4']}
    out.update({f'n{k}': v for k, v in q2['n'].items() if k != '4'})
    out.update({f'top{k}': v for k, v in q2['top'].items() if k != '10'})
    out.update({f'alpha{float(k):g}': v for k, v in q2['alpha'].items() if float(k) != st.ALPHA})
    out.update({f'trim{float(k):g}': v for k, v in q2['trim'].items() if float(k) != st.TRIM})
    out.update(q1['add_one'])
    return out


def keeps_2021(r):
    return r is not None and st.keeps(r)


def candidates(caches):
    """{id: (spec id, spec, column, alpha, trim)}: parameters of q2 and every add-one alphabet change the 2019 data allows."""
    base = st.base_spec(tops=list(st.GRID['top']))
    c = {'base': ('base', base, f'top{st.TOP}', st.ALPHA, st.TRIM)}
    for n in (3, 5):
        c[f'n{n}'] = (f'n{n}', st.base_spec(n=n), f'top{st.TOP}', st.ALPHA, st.TRIM)
    for k in st.GRID['top']:
        if k != st.TOP:
            c[f'top{k}'] = ('base', base, f'top{k}', st.ALPHA, st.TRIM)
    for alpha in st.GRID['alpha']:
        if alpha != st.ALPHA:
            c[f'alpha{alpha:g}'] = ('base', base, f'top{st.TOP}', alpha, st.TRIM)
    for trim in st.GRID['trim']:
        if trim != st.TRIM:
            c[f'trim{trim:g}'] = ('base', base, f'top{st.TOP}', st.ALPHA, trim)
    a = SimpleNamespace(caches=str(caches))
    one = st.base_spec()
    for name in sorted(st.vocab_names(a, 'e') - set(one['err'])):
        c[f'add-err-{name}'] = (f'add-err-{name}', st.with_detail(one, 'err', name), f'top{st.TOP}', st.ALPHA, st.TRIM)
    for name in sorted((st.vocab_names(a, 's') & tc.EXTRA_SIZE) - set(one['size'])):
        c[f'add-size-{name}'] = (f'add-size-{name}', st.with_detail(one, 'size', name), f'top{st.TOP}', st.ALPHA, st.TRIM)
    return c


def study(caches, out, receipts, jobs):
    g = Path(out) / 'gate.json'
    if not g.exists() or not json.loads(g.read_text())['passed']:
        raise SystemExit('run the gate first')
    docs, ref21, cands = inventory(caches), from_receipts(receipts), candidates(caches)
    st.ensure(namespace(caches, out, jobs), {sid: spec for sid, spec, *_ in cands.values()})
    rows = {}
    for cid, (sid, _, column, alpha, trim) in cands.items():
        r = scored(out, sid, column, alpha, trim, docs)
        r21 = ref21.get(cid)
        r['lidds2021_development'] = None if r21 is None else {k: r21[k] for k in ('detected', 'false_alarm_recordings', 'latency_p95',
                                                                                      'cb_detected', 'cb_false_alarm_recordings')}
        r['must'] = dict(dev_false_alarms=r['tolerance']['false_alarm_rate'] <= DEV_FA_LIMIT, lidds2021_and_cbds=keeps_2021(r21))
        rows[cid] = r
    base = rows['base']['tolerance']['recall']
    ok = [c for c, r in rows.items() if all(r['must'].values())]
    best = max(ok, key=lambda c: (rows[c]['tolerance']['detected'], -rows[c]['tolerance']['false_alarm_recordings'],
                                  -(rows[c]['tolerance']['latency_p95'] or 0), c == 'base'), default=None)
    chosen = best if best and rows[best]['tolerance']['recall'] - base >= MIN_GAIN else 'base'
    doc = dict(schema='lidds2019-development-study-v1', protocol=PROTOCOL, part='development', tolerance_seconds=TOLERANCE,
               candidates=rows, pass_must=sorted(ok), best=best, selected=chosen,
               note='LID-DS 2021 development / CB-DS numbers come from the token-design-study-v1 receipts (q1 add_one, q2 grid); '
                    'a candidate without such numbers (None) cannot pass the must-rules until it is scored on LID-DS 2021')
    (Path(out) / 'study.json').write_text(json.dumps(doc, indent=1, default=float))
    return doc


GRID_N, GRID_TOP = (4, 5), (3, 5, 10)
GRID_ALPHA = (0.0005, 0.0003, st.ALPHA, 0.0001, 0.00005)
GRID_TRIM = (0.005, 0.01, 0.02)


def grid(caches, out, caches21, lidds_alarms, cbds_alarms, jobs):
    """Combinations scored on both datasets; the protocol's must-rules and selection on the combinations."""
    docs = inventory(caches)
    specs = {f'g-n{n}': st.base_spec(n=n, tops=list(GRID_TOP)) for n in GRID_N}
    st.ensure(namespace(caches, out, jobs), specs)
    a21 = SimpleNamespace(caches=str(caches21), out=str(Path(out) / 'lidds2021'), jobs=jobs,
                          docs=(m.load(lidds_alarms), m.load(cbds_alarms)))
    Path(a21.out).mkdir(parents=True, exist_ok=True)
    st.ensure(a21, specs)
    ref = st.Scored(a21, 'g-n4', 'top10', st.TRIM).metrics(st.ALPHA)
    gate21 = (ref['detected'], ref['false_alarm_recordings'], ref['cb_detected'], ref['cb_false_alarm_recordings']) == (530, 6, 891, 3) \
        and round(ref['latency_p95'], 2) == 1.52
    if not gate21:
        raise SystemExit(f'LID-DS 2021 base combination does not reproduce the token-design-study gate: {ref}')
    rows = {}
    for n in GRID_N:
        for k in GRID_TOP:
            for trim in GRID_TRIM:
                s21 = st.Scored(a21, f'g-n{n}', f'top{k}', trim)
                for alpha in GRID_ALPHA:
                    cid = f'n{n}-top{k}-trim{trim:g}-alpha{alpha:g}'
                    r = scored(out, f'g-n{n}', f'top{k}', alpha, trim, docs)
                    r21 = s21.metrics(alpha)
                    r['lidds2021_development'] = {k2: r21[k2] for k2 in ('detected', 'false_alarm_recordings', 'latency_p95',
                                                                          'cb_detected', 'cb_false_alarm_recordings')}
                    r['must'] = dict(dev_false_alarms=r['tolerance']['false_alarm_rate'] <= DEV_FA_LIMIT, lidds2021_and_cbds=st.keeps(r21))
                    rows[cid] = r
    base_id = f'n4-top10-trim{st.TRIM:g}-alpha{st.ALPHA:g}'
    base = rows[base_id]['tolerance']['recall']
    ok = [c for c, r in rows.items() if all(r['must'].values())]
    best = max(ok, key=lambda c: (rows[c]['tolerance']['detected'], -rows[c]['tolerance']['false_alarm_recordings'],
                                  -(rows[c]['tolerance']['latency_p95'] or 0), c == base_id), default=None)
    chosen = best if best and rows[best]['tolerance']['recall'] - base >= MIN_GAIN else base_id
    doc = dict(schema='lidds2019-development-grid-v1', protocol=PROTOCOL, part='development', tolerance_seconds=TOLERANCE,
               lidds2021_gate=dict(passed=gate21, base=ref), grid=dict(n=GRID_N, top=GRID_TOP, alpha=GRID_ALPHA, trim=GRID_TRIM),
               candidates=rows, base=base_id, pass_must=sorted(ok), best=best, selected=chosen)
    (Path(out) / 'grid.json').write_text(json.dumps(doc, indent=1, default=float))
    return doc


SLOW = ('Bruteforce_CWE-307', 'CVE-2012-2122', 'CVE-2014-0160', 'CVE-2017-7529', 'CVE-2018-3760', 'CVE-2019-5418', 'EPS_CWE-434',
        'PHP_CWE-434', 'SQL_Injection_CWE-89', 'ZipSlip')


def latency(caches, out, scenarios=SLOW):
    """Where the time goes in the slow scenarios (development part, base decision): one row per attack recording."""
    docs = inventory(caches)
    d = Path(out) / 'scores' / 'base'
    spec = json.loads((d / 'SPEC.json').read_text())
    res = {}
    for s in scenarios:
        scn = st.TokenScenario(d / f'{s}.npz', f'top{st.TOP}', spec['columns'], st.TRIM)
        thr = m.threshold(scn.fit, st.ALPHA)
        rows = []
        for name, r in sorted(docs['scenarios'][s]['alarms'].items()):
            if r['exploit'] is None:
                continue
            a = scn.a.get(name)
            if a is None or not len(a):
                rows.append(dict(name=name, windows=0))
                continue
            t, x = a[:, 0], a[:, scn.i]
            ex = r['exploit']
            after = t > ex - TOLERANCE
            fire = t[(x > thr) & after]
            i = int(x[after].argmax()) if after.any() else None
            u = a[:, spec['columns'].index('unseen_any')]
            novel = t[(u > 0) & after]
            rows.append(dict(name=name, exploit=ex, end=float(t.max()), first_alarm_after=float(fire[0] - ex) if len(fire) else None,
                             first_unseen_after=float(novel[0] - ex) if len(novel) else None,
                             alarms_before=int(((x > thr) & ~after).sum()), alarms_after=int(len(fire)),
                             max_after=float(x[after][i]) if i is not None else None,
                             max_after_at=float(t[after][i] - ex) if i is not None else None,
                             max_before=float(x[~after].max()) if (~after).any() else None))
        res[s] = dict(threshold=thr, recordings=rows)
    lat = [r['first_unseen_after'] for v in res.values() for r in v['recordings'] if r.get('first_unseen_after') is not None]
    doc = dict(schema='lidds2019-development-latency-v1', protocol=PROTOCOL, part='development', scenarios=res,
               note='first_unseen_after: first window (after exploit - 1 s) holding any gram or token unseen in learning, a lower '
                    'bound on the latency of any detector that fires on unseen sequences')
    doc['first_unseen_after_p50_p95'] = [float(np.percentile(lat, 50)), float(np.percentile(lat, 95))] if lat else None
    (Path(out) / 'latency.json').write_text(json.dumps(doc, indent=1, default=float))
    return doc


RATE_LEVELS = (2e-5, 1e-5, 5e-6, 1e-6, 1e-7, 1e-8)


def rate(caches, out, caches21, lidds_alarms, cbds_alarms, jobs):
    """Token model (lidds-ml-v5) OR the rate branch of ml-final-study-v1 part D at a grid of rate levels, on both datasets."""
    import lidds_token_rate as tr
    from multiprocessing import Pool
    docs19 = inventory(caches)
    o19, o21 = Path(out) / 'rate2019', Path(out) / 'rate2021'
    jobs_ = [(str(c), str(o19)) for c in sorted(Path(caches).glob('*.npz'), key=lambda p: -p.stat().st_size)]
    jobs_ += [(str(c), str(o21)) for c in sorted(Path(caches21).glob('*.npz'), key=lambda p: -p.stat().st_size)]
    with Pool(min(jobs, len(jobs_))) as pool:
        for name in pool.imap_unordered(tr.task, jobs_, chunksize=1):
            print('rate scored', name, flush=True)
    cols = st.columns_of(st.base_spec())
    load = lambda d, kind, s, col, cs: st.TokenScenario(d / kind / f'{s}.npz', col, cs)
    lidds, cbds = m.load(lidds_alarms), m.load(cbds_alarms)
    rows = {}
    for level in RATE_LEVELS:
        both19 = {s: tr.EitherSplit(load(o19, 'rate', s, 'rate', tr.COLUMNS), load(o19, 'model', s, 'top10', cols), a_rate=level)
                  for s in sorted(docs19['scenarios'])}
        primary, per = evaluate(both19, docs19)
        tol, tol_per = evaluate(both19, l19.shifted(docs19, TOLERANCE))
        r21 = {}
        for doc, part, key in ((lidds, 'development', 'lidds'), (cbds, 'all', 'cbds')):
            names = sorted(s for s in doc['scenarios'] if (o21 / 'rate' / f'{s}.npz').exists())
            sc = {s: tr.EitherSplit(load(o21, 'rate', s, 'rate', tr.COLUMNS), load(o21, 'model', s, 'top10', cols), a_rate=level) for s in names}
            pooled, _ = m.score(sc, doc, ('T',), st.ALPHA, part)
            r21[key] = pooled
        m21 = dict(detected=r21['lidds']['detected'], false_alarm_recordings=r21['lidds']['false_alarm_recordings'],
                   latency_p95=r21['lidds']['latency_p95'], cb_detected=r21['cbds']['detected'],
                   cb_false_alarm_recordings=r21['cbds']['false_alarm_recordings'])
        keep = lambda r: dict(detected=r['detected'], attack_recordings=r['attack_recordings'], false_alarm_recordings=r['false_alarm_recordings'],
                              false_alarm_rate=r['false_alarm_rate'], recall=r['recall'], latency_p50=r['latency_p50'], latency_p95=r['latency_p95'])
        rows[f'model-or-rate-{level:g}'] = dict(primary=keep(primary), tolerance=keep(tol), lidds2021_development=m21,
                                                scenarios={s: [tol_per[s]['detected'], tol_per[s]['attack_recordings'],
                                                               tol_per[s]['false_alarm_recordings'], tol_per[s]['latency_p95']] for s in tol_per},
                                                must=dict(dev_false_alarms=tol['false_alarm_rate'] <= DEV_FA_LIMIT, lidds2021_and_cbds=st.keeps(m21)))
    doc = dict(schema='lidds2019-development-rate-v1', protocol=PROTOCOL, part='development', model_alpha=st.ALPHA, candidates=rows)
    (Path(out) / 'rate.json').write_text(json.dumps(doc, indent=1, default=float))
    return doc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='step', required=True)
    p = sub.add_parser('split')
    p.add_argument('--tokens', required=True)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('cache')
    p.add_argument('--archives', required=True)
    p.add_argument('--scenario', required=True)
    p.add_argument('--split', type=Path, required=True)
    p.add_argument('--part', choices=('development', 'holdout'), default='development')
    p.add_argument('--n', type=int, default=5)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('grid')
    p.add_argument('--caches', required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--caches-2021', required=True)
    p.add_argument('--lidds-alarms', required=True)
    p.add_argument('--cbds-alarms', required=True)
    p.add_argument('--jobs', type=int, default=4)
    p = sub.add_parser('rate')
    p.add_argument('--caches', required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--caches-2021', required=True)
    p.add_argument('--lidds-alarms', required=True)
    p.add_argument('--cbds-alarms', required=True)
    p.add_argument('--jobs', type=int, default=4)
    p = sub.add_parser('latency')
    p.add_argument('--caches', required=True)
    p.add_argument('--out', type=Path, required=True)
    for name in ('gate', 'study'):
        p = sub.add_parser(name)
        p.add_argument('--caches', required=True)
        p.add_argument('--out', type=Path, required=True)
        p.add_argument('--jobs', type=int, default=4)
        if name == 'gate':
            p.add_argument('--tokens', required=True)
        else:
            p.add_argument('--receipts', required=True)
    a = ap.parse_args()
    if a.step == 'split':
        if a.output.exists():
            raise SystemExit(f'{a.output} exists: the split is written once')
        a.output.write_text(json.dumps(split(a.tokens), indent=1))
        print(json.dumps(json.loads(a.output.read_text())['counts']))
    elif a.step == 'cache':
        if a.part == 'holdout':
            raise SystemExit('the holdout part is cached only by the single holdout scoring of the protocol')
        print(json.dumps(cache(a.archives, a.scenario, json.loads(a.split.read_text()), a.output, a.n, a.part)))
    elif a.step == 'gate':
        a.out.mkdir(parents=True, exist_ok=True)
        print(json.dumps(gate(a.caches, a.tokens, a.out, a.jobs), default=float)[:2000])
    elif a.step == 'grid':
        d = grid(a.caches, a.out, a.caches_2021, a.lidds_alarms, a.cbds_alarms, a.jobs)
        print(json.dumps(dict(pass_must=len(d['pass_must']), best=d['best'], selected=d['selected'])))
    elif a.step == 'rate':
        d = rate(a.caches, a.out, a.caches_2021, a.lidds_alarms, a.cbds_alarms, a.jobs)
        print(json.dumps({c: (r['tolerance']['detected'], r['tolerance']['latency_p95'], r['must']) for c, r in d['candidates'].items()}, default=float))
    elif a.step == 'latency':
        d = latency(a.caches, a.out)
        print(json.dumps({s: sum(r.get('first_alarm_after') is not None for r in v['recordings']) for s, v in d['scenarios'].items()}))
    else:
        d = study(a.caches, a.out, a.receipts, a.jobs)
        print(json.dumps(dict(pass_must=d['pass_must'], best=d['best'], selected=d['selected'])))


if __name__ == '__main__':
    main()
