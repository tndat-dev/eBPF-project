#!/usr/bin/env python3
"""load-threshold-v1 (sentinel_pulse/protocol/load-threshold-v1.json): thresholds that depend on the window's event count.

Candidates L0 (t3) and LB-a for B in {2, 3, 4} and a in {alpha' per bin, alpha'/B per bin}
(sentinel_pulse/detector/load_threshold.py). Steps:

  datasets  development data only: LID-DS 2021 development + CB-DS and LID-DS 2019 development (1 s tolerance) from the
            existing t3 score caches (columns top3 and events); L0 must reproduce t3's development numbers first
  cluster   the held-out block maxima per event class of a cross-fit with --dump-load (the diurnal fit): block exceedance
            per traffic regime and pooled; L0 must reproduce the fit's own held-out exceedance
  select    the registered must-rules and choice over both; writes the chosen candidate and its worker specs
  confirm   the chosen candidate once on LID-DS 2021 official, the LID-DS 2019 70 % part and CB-DS

    python3 load_threshold_study.py datasets --out DEV --lidds-alarms A --cbds-alarms C --output datasets.json
    python3 load_threshold_study.py cluster --fit FIT_DIR --capture CAPTURE --output cluster.json
    python3 load_threshold_study.py select --datasets datasets.json --cluster cluster.json --fit FIT_DIR --output selection.json
    python3 load_threshold_study.py confirm --out DEV --selection selection.json --lidds-alarms A --cbds-alarms C --output confirm.json
"""
# load-threshold-v1: ngưỡng theo số sự kiện của chính cửa sổ; chấm ứng viên trên dataset (development) và trên cụm
# (cực đại giữ ra theo lớp sự kiện, theo chế độ tải), chọn theo luật đã đăng ký, rồi xác nhận một lần trên official.
import argparse
import glob
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.detector import load_threshold as lt  # noqa: E402

ALPHA, TRIM, TOP = 0.0003, 0.005, 3
BINS = (2, 3, 4)
BRANCH_ALPHA = 0.00015                      # S1's native branch (session-stream-v1 amendment 1)
DEV_MUST = dict(lidds2021=(529, 5, 1.57), cbds=(891, 3), lidds2019=(310, 9))


def candidates():
    out = {'L0': None}
    for b in BINS:
        out[f'L{b}-per-bin'] = (b, False)
        out[f'L{b}-split'] = (b, True)
    return out


def level(alpha, cand):
    b, split = cand
    return alpha / b if split else alpha


# ------------------------------------------------------------------ datasets

def load_scenario_class():
    import lidds_token_study as st
    import lidds_ml_v2 as m

    class LoadScenario(st.TokenScenario):
        """A dataset scenario whose windows are compared with the threshold of their event-count bin."""

        def __init__(self, path, column, columns, trim, cand, alpha):
            super().__init__(path, column, columns, trim)
            self.ei = columns.index('events')
            val = [a for k, a in self.a.items() if k.startswith('val/') and len(a)]
            self.edges = lt.edges_of(np.concatenate([a[:, self.ei] for a in val]), cand[0])
            per_bin = [[] for _ in range(len(self.edges) + 1)]
            for a in val:
                b = np.searchsorted(self.edges, a[:, self.ei], side='right')
                for k in range(len(per_bin)):
                    s = a[b == k, self.i]
                    if len(s):
                        per_bin[k].append(float(s.max()))
            self.thr = np.asarray(lt.fit_bins(per_bin, m.threshold(self.fit, alpha), level(alpha, cand), trim))

        def firings(self, branches, alpha, name):
            a = self.a.get(name)
            if a is None or not len(a):
                return []
            thr = self.thr[np.searchsorted(self.edges, a[:, self.ei], side='right')]
            return sorted(a[a[:, self.i] > thr, 0].tolist())

    return LoadScenario


def scored2021(out, sid, alarms, cand, part='development'):
    import lidds_ml_v2 as m
    import lidds_token_study as st
    a = SimpleNamespace(out=str(out), docs=(m.load(alarms[0]), m.load(alarms[1])))
    s = st.Scored(a, sid, f'top{TOP}', TRIM)
    if cand is not None:
        d = Path(out) / 'scores' / sid
        cols = json.loads((d / 'SPEC.json').read_text())['columns']
        LS = load_scenario_class()
        s.lid = {k: LS(d / f'{k}.npz', f'top{TOP}', cols, TRIM, cand, ALPHA) for k in s.lid}
        s.cb = {k: LS(d / f'{k}.npz', f'top{TOP}', cols, TRIM, cand, ALPHA) for k in s.cb}
    return s.metrics(ALPHA, part=part)


def scored2019(caches, scores_dir, cand, tolerance=True):
    import lidds2019_dev as d19
    import lidds2019_token as l19
    import lidds_token_study as st
    docs = d19.inventory(caches)
    cols = json.loads((Path(scores_dir) / 'SPEC.json').read_text())['columns']
    if cand is None:
        mk = lambda s: st.TokenScenario(Path(scores_dir) / f'{s}.npz', f'top{TOP}', cols, TRIM)
    else:
        LS = load_scenario_class()
        mk = lambda s: LS(Path(scores_dir) / f'{s}.npz', f'top{TOP}', cols, TRIM, cand, ALPHA)
    scen = {s: d19.Fixed(mk(s), ALPHA) for s in sorted(docs['scenarios'])}
    p, _ = d19.evaluate(scen, docs)
    t, tper = d19.evaluate(scen, l19.shifted(docs, d19.TOLERANCE))
    keep = lambda r: {k: r.get(k) for k in ('detected', 'attack_recordings', 'false_alarm_recordings', 'normal_recordings',
                                             'recall', 'false_alarm_rate', 'latency_p50', 'latency_p95', 'detected_within_3s')}
    return dict(primary=keep(p), tolerance=keep(t), scenarios={s: [v['detected'], v['false_alarm_recordings']] for s, v in tper.items()})


def datasets(a):
    out = Path(a.out)
    rows = {}
    for cid, cand in candidates().items():
        r21 = scored2021(out / 'lidds2021', 'g-n4', (a.lidds_alarms, a.cbds_alarms), cand)
        r19 = scored2019(out / 'caches', out / 'scores' / 'g-n4', cand)
        rows[cid] = dict(lidds2021=dict(detected=r21['detected'], false_alarm_recordings=r21['false_alarm_recordings'],
                                        latency_p95=r21['latency_p95']),
                         cbds=dict(detected=r21['cb_detected'], false_alarm_recordings=r21['cb_false_alarm_recordings']),
                         lidds2019=dict(detected=r19['tolerance']['detected'], false_alarm_recordings=r19['tolerance']['false_alarm_recordings'],
                                        latency_p95=r19['tolerance']['latency_p95']))
        print(cid, json.dumps(rows[cid], default=float), flush=True)
    r0 = rows['L0']
    gate = (r0['lidds2021']['detected'], r0['lidds2021']['false_alarm_recordings'], r0['cbds']['detected'],
            r0['cbds']['false_alarm_recordings'], r0['lidds2019']['detected'], r0['lidds2019']['false_alarm_recordings']) == (529, 5, 891, 3, 310, 9)
    if not gate:
        raise SystemExit(f'L0 does not reproduce t3 development: {r0}')
    for r in rows.values():
        r['must'] = dev_must(r)
    Path(a.output).write_text(json.dumps(dict(schema='load-threshold-v1-datasets', gate_t3=gate, candidates=rows), indent=1, default=float))


def dev_must(r):
    d, f, p = DEV_MUST['lidds2021']
    return bool(r['lidds2021']['detected'] >= d and r['lidds2021']['false_alarm_recordings'] <= f
                and r['lidds2021']['latency_p95'] <= p + 1e-9
                and r['cbds']['detected'] >= DEV_MUST['cbds'][0] and r['cbds']['false_alarm_recordings'] <= DEV_MUST['cbds'][1]
                and r['lidds2019']['detected'] >= DEV_MUST['lidds2019'][0]
                and r['lidds2019']['false_alarm_recordings'] <= DEV_MUST['lidds2019'][1])


# ------------------------------------------------------------------ cluster

def regime_of(t, schedule):
    for p in schedule:
        if p['start'] <= t < p['end']:
            return p['regime']
    return 'outside-capture'


def quantile_from_hist(hist, q):
    keys = sorted(hist)
    counts = np.cumsum([hist[k] for k in keys])
    target = q * counts[-1]
    return keys[int(np.searchsorted(counts, target, side='left'))]


def workload_bins(doc, cand, fallback, alpha):
    """(edges, thresholds, blocks [(block, {bin: max})]) of one workload's load dump for a candidate."""
    hist = {int(k): v for k, v in doc['events'].items()}
    blocks = []
    if cand is None:
        edges = []
    else:
        edges = sorted({lt.snap(quantile_from_hist(hist, k / cand[0])) for k in range(1, cand[0])})
    for *cell, classes in doc['blocks']:
        per = {}
        for c, v in classes.items():
            c = int(c)
            k = lt.bin_of(0 if c < 0 else 1 << c, edges)
            per[k] = max(per.get(k, 0.0), v)
        blocks.append((cell[2], per))
    if cand is None:
        return edges, [fallback], blocks
    per_bin = [[p[k] for _, p in blocks if k in p] for k in range(len(edges) + 1)]
    return edges, lt.fit_bins(per_bin, fallback, level(alpha, cand), TRIM), blocks


def cluster(a):
    fit = Path(a.fit)
    models = json.loads((fit / 'token' / 'MODELS.json').read_text())
    schedule = json.loads((Path(a.capture) / 'CONFIG.json').read_text())['traffic_schedule'][:-1]
    dumps = {json.loads(Path(p).read_text())['workload']: p for p in glob.glob(str(fit / 'load' / '*.load.json'))}
    rows = {}
    for cid, cand in candidates().items():
        per_regime = {}
        for w, spec in sorted(models.items()):
            doc = json.loads(Path(dumps[w]).read_text())
            edges, thr, blocks = workload_bins(doc, cand, float(spec['threshold']), ALPHA)
            block = doc['block']
            for b, per in blocks:
                r = per_regime.setdefault(regime_of(b * block, schedule), [0, 0])
                r[0] += 1
                r[1] += any(v > thr[k] for k, v in per.items())
        n, k = sum(v[0] for v in per_regime.values()), sum(v[1] for v in per_regime.values())
        rows[cid] = dict(pooled=dict(blocks=n, above=k, share=k / n),
                         regimes={r: dict(blocks=v[0], above=v[1], share=v[1] / v[0]) for r, v in sorted(per_regime.items())})
        print(cid, json.dumps(dict(pooled=round(100 * k / n, 3), **{r: round(100 * v[1] / v[0], 3) for r, v in sorted(per_regime.items())})), flush=True)
    Path(a.output).write_text(json.dumps(dict(schema='load-threshold-v1-cluster', fit=str(fit), candidates=rows), indent=1))


def cluster_must(row, ref):
    reg = row['regimes']
    steady = reg.get('steady', {}).get('share') or 0
    return bool(row['pooled']['share'] < ref['pooled']['share']
                and all(reg.get(r, {}).get('share', 0) <= 2 * steady for r in ('burst', 'peak')))


# ------------------------------------------------------------------ select and specs

def specs(fit, cand):
    """{workload: {edges, thresholds (whole window, alpha'), native_thresholds (S1's native branch, alpha'/2)}}."""
    fit = Path(fit)
    models = json.loads((fit / 'token' / 'MODELS.json').read_text())
    fits = json.loads((fit / 'token' / 'FIT.json').read_text())['workloads']
    dumps = {json.loads(Path(p).read_text())['workload']: p for p in glob.glob(str(fit / 'load' / '*.load.json'))}
    out = {}
    for w, spec in sorted(models.items()):
        doc = json.loads(Path(dumps[w]).read_text())
        native_fallback = lt.threshold(fits[w]['gumbel'], BRANCH_ALPHA)
        edges, whole, _ = workload_bins(doc, cand, float(spec['threshold']), ALPHA)
        _, native, _ = workload_bins(doc, cand, native_fallback, BRANCH_ALPHA)
        out[w] = dict(edges=edges, thresholds=whole, native_thresholds=native)
    return out


def select(a):
    ds = json.loads(Path(a.datasets).read_text())['candidates']
    cl = json.loads(Path(a.cluster).read_text())['candidates']
    ref = cl['L0']
    rows = {}
    for cid in candidates():
        if cid == 'L0':
            continue
        rows[cid] = dict(dev_must=ds[cid]['must'], cluster_must=cluster_must(cl[cid], ref),
                         cluster_pooled=cl[cid]['pooled']['share'], lidds2021_false_alarms=ds[cid]['lidds2021']['false_alarm_recordings'])
    ok = [c for c, r in rows.items() if r['dev_must'] and r['cluster_must']]
    chosen = min(ok, key=lambda c: (rows[c]['cluster_pooled'], rows[c]['lidds2021_false_alarms'])) if ok else 'L0'
    doc = dict(schema='load-threshold-v1-selection', candidates=rows, passing=sorted(ok), chosen=chosen,
               chosen_candidate=candidates()[chosen])
    if chosen != 'L0':
        doc['specs'] = specs(a.fit, candidates()[chosen])
    Path(a.output).write_text(json.dumps(doc, indent=1))
    print(json.dumps({k: v for k, v in doc.items() if k != 'specs'}, default=float))


# ------------------------------------------------------------------ confirm (once, chosen candidate only)

def confirm(a):
    sel = json.loads(Path(a.selection).read_text())
    target = Path(a.output)
    if target.exists():
        raise SystemExit(f'{target} exists: the chosen candidate is confirmed once')
    if sel['chosen'] == 'L0':
        raise SystemExit('no candidate was chosen: nothing to confirm')
    cand = tuple(sel['chosen_candidate'])
    out = Path(a.out)
    off = scored2021(out / 'official2021', 'official', (a.lidds_alarms, a.cbds_alarms), cand, part='official')
    hold = scored2019(out / 'holdout-caches', out / 'holdout' / 'scores' / 'holdout', cand)
    t = hold['tolerance']
    passes = bool(off['recall_ci95'][0] >= 0.95 and off['false_alarm_recordings'] <= 15 and off['latency_p95'] <= 3.0
                  and t['recall'] >= 0.95 and t['false_alarm_rate'] <= 0.01)
    doc = dict(schema='load-threshold-v1-confirm', chosen=sel['chosen'],
               lidds2021_official={k: off[k] for k in ('detected', 'attack_recordings', 'false_alarm_recordings', 'normal_recordings',
                                                       'latency_p50', 'latency_p95', 'detected_within_3s', 'recall_ci95', 'scenarios')},
               cbds=dict(detected=off['cb_detected'], false_alarm_recordings=off['cb_false_alarm_recordings']),
               lidds2019_part70=hold, passes_datasets=passes)
    target.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(dict(chosen=sel['chosen'], official=(off['detected'], off['false_alarm_recordings'], off['latency_p95']),
                          lidds2019=(t['detected'], t['false_alarm_recordings']), passes=passes), default=float))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    d = sub.add_parser('datasets'); d.add_argument('--out', required=True); d.add_argument('--lidds-alarms', required=True)
    d.add_argument('--cbds-alarms', required=True); d.add_argument('--output', required=True)
    c = sub.add_parser('cluster'); c.add_argument('--fit', required=True); c.add_argument('--capture', required=True)
    c.add_argument('--output', required=True)
    s = sub.add_parser('select'); s.add_argument('--datasets', required=True); s.add_argument('--cluster', required=True)
    s.add_argument('--fit', required=True); s.add_argument('--output', required=True)
    f = sub.add_parser('confirm'); f.add_argument('--out', required=True); f.add_argument('--selection', required=True)
    f.add_argument('--lidds-alarms', required=True); f.add_argument('--cbds-alarms', required=True); f.add_argument('--output', required=True)
    a = ap.parse_args()
    dict(datasets=datasets, cluster=cluster, select=select, confirm=confirm)[a.cmd](a)


if __name__ == '__main__':
    main()
