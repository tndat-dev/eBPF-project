#!/usr/bin/env python3
"""LID-DS 2019 with the final token model (protocol lidds2019-confirmation-v2), and the gate it registers.

The token matrices come from lidds_ml_token_crossfit.py, unchanged, run on each 2019 archive built by
sentinel_pulse/lidds/lidds2019.py (held-out training/validation maxima as val/<name>, test recordings by name, column
xfit; the .json beside each matrix holds every test recording's split and exploit time). The decision is lidds-ml-v5's
token branch: moment Gumbel without the top 1 % of the held-out maxima (lidds_ml_v4.trimmed_gumbel) at alpha' = 0.0002 x
0.9, one window above it fires; detection, latency and false alarms as lidds_ml_v2.rows and lidds_v3_combine.metrics.

  gate   recomputes the registered LID-DS 2021 official result of lidds-ml-v5 (token alone) from the 2021 matrices and
         alarms inventory through this code path: 1,238/1,271 detected, 26/7,938 false-alarm recordings, p95 1.47 s.
         Writes the gate receipt; exits 1 on any difference.
  score  needs a passed gate receipt; scores every 2019 test recording once (the output must not exist), with the
         primary exploit time (first event + exploit_start_time) and, apart, the LID-DS library's (first event +
         warmup - 2 s, read from the archives), pooled and per scenario, and the protocol's criterion C1.

    python3 lidds2019_token.py gate --tokens DIR2021 --alarms lidds-alarms.json.gz --output gate.json
    python3 lidds2019_token.py score --tokens DIR2019 --archives DIR2019 --gate gate.json --output lidds2019.json
"""
# LID-DS 2019 (lidds2019-confirmation-v2): gate tái lập official 2021 bằng chính code này, rồi chấm 2019 đúng một lần với
# hai quy ước thời điểm exploit.
import argparse
import io
import json
from pathlib import Path
import sys
import zipfile

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_v2 as m  # noqa: E402
import lidds_ml_v4 as v4  # noqa: E402
import lidds_v3_combine as v3  # noqa: E402
import lidds_evaluate_v2 as ev  # noqa: E402

LEVEL = v4.ALPHA * v4.SHARES['T']
REGISTERED_2021 = dict(detected=1238, attack_recordings=1271, false_alarm_recordings=26, normal_recordings=7938,
                       latency_p95=1.47)
C1 = dict(recall=0.95, false_alarm_rate=0.01, latency_p95=3.0)


class TokenScenario:
    """The token branch of one scenario: held-out maxima -> trimmed moment Gumbel; firings above it at LEVEL."""

    def __init__(self, name, token_dir):
        z = np.load(Path(token_dir) / f'{name}.npz')
        self.meta = json.loads((Path(token_dir) / f'{name}.json').read_text())
        cols = self.meta.get('columns', ['window_end', 'xfit'])
        self.end, self.col = cols.index('window_end'), cols.index('xfit')
        maxima = [z[k][:, self.col].max() for k in z.files if k.startswith('val/') and len(z[k])]
        self.z, self.fit = z, v4.trimmed_gumbel(maxima)
        self.threshold = m.threshold(self.fit, LEVEL)

    def firings(self, branches=None, alpha=None, name=None):
        if name not in self.z.files or not len(self.z[name]):
            return []
        a = self.z[name]
        return sorted(a[a[:, self.col] > self.threshold, self.end].tolist())


def score_part(scenarios, docs, part):
    pooled, per = [], {}
    for s, scn in scenarios.items():
        recs = docs['scenarios'][s]['alarms']
        rows = list(m.rows(scn, recs, None, None, m.part_filter(s, recs, part)).values())
        per[s] = v3.metrics(rows)
        pooled.extend(rows)
    out = v3.metrics(pooled)
    out['detected_within_3s'] = sum(1 for x in pooled if x[0] == 'test-normal_and_attack' and x[2] is not None and x[2] <= 3.0)
    return out, per


def gate(token_dir, alarms):
    docs = m.load(alarms)
    scenarios = {s: TokenScenario(s, token_dir) for s in sorted(docs['scenarios'])}
    pooled, per = score_part(scenarios, docs, 'official')
    got: dict = dict(detected=pooled['detected'], attack_recordings=pooled['attack_recordings'],
               false_alarm_recordings=pooled['false_alarm_recordings'], normal_recordings=pooled['normal_recordings'],
               latency_p95=round(pooled['latency_p95'], 2) if pooled['latency_p95'] is not None else None)
    return dict(schema='lidds2019-confirmation-v2-gate', protocol='sentinel_pulse/protocol/lidds2019-confirmation-v2.json',
                tokens=str(token_dir), alarms=str(alarms), registered=REGISTERED_2021, reproduced=got,
                passed=got == REGISTERED_2021, scenarios=per)


def library_times(archive):
    """{recording: exploit time under the LID-DS library's convention} from the inner metadata of one 2019 archive."""
    out = {}
    for split, name, blob in ev.split_recordings(archive, {'test-normal_and_attack'}):
        z = zipfile.ZipFile(io.BytesIO(blob))
        meta = json.loads(z.read(next(n for n in z.namelist() if n.endswith('.json'))))
        lib = (meta.get('time') or {}).get('exploit_library') or []
        out[name] = lib[0]['absolute'] if lib else None
    return out


def inventory(scenarios, archives=None):
    """lidds_ml_v2 alarms documents for the primary and (with archives) the library exploit times."""
    primary: dict = dict(scenarios={})
    library: dict = dict(scenarios={})
    for s, scn in scenarios.items():
        recs = scn.meta['recordings']
        primary['scenarios'][s] = dict(alarms={n: dict(split=r['split'], exploit=r['exploit'], subset='all') for n, r in recs.items()})
        if archives:
            lib = library_times(Path(archives) / f'{s}.zip')
            library['scenarios'][s] = dict(alarms={n: dict(split=r['split'], subset='all',
                                                           exploit=lib.get(n) if r['split'] == 'test-normal_and_attack' else None)
                                                   for n, r in recs.items()})
    return primary, (library if archives else None)


def c1(p):
    return dict(recall=p['recall'] is not None and p['recall'] >= C1['recall'],
                false_alarm_rate=p['false_alarm_rate'] is not None and p['false_alarm_rate'] <= C1['false_alarm_rate'],
                latency_p95=p['latency_p95'] is not None and p['latency_p95'] <= C1['latency_p95'])


def score(token_dir, archives, gate_receipt):
    g = json.loads(Path(gate_receipt).read_text())
    if not g.get('passed'):
        raise SystemExit('the gate has not passed: nothing of LID-DS 2019 is scored')
    names = sorted(p.stem for p in Path(token_dir).glob('*.npz'))
    scenarios = {s: TokenScenario(s, token_dir) for s in names}
    primary, library = inventory(scenarios, archives)
    p, per = score_part(scenarios, primary, 'all')
    out: dict = dict(schema='lidds2019-confirmation-v2', protocol='sentinel_pulse/protocol/lidds2019-confirmation-v2.json',
               gate=str(gate_receipt), tokens=str(token_dir), level=LEVEL,
               thresholds={s: scn.threshold for s, scn in scenarios.items()},
               primary=dict(pooled=p, scenarios=per), C1=dict(c1(p), all=all(c1(p).values())))
    if library:
        lp, lper = score_part(scenarios, library, 'all')
        out['library_exploit_time'] = dict(pooled=lp, scenarios=lper)
    out['C2_named'] = sorted(s for s, r in per.items() if (r['recall'] is not None and r['recall'] < 0.90)
                             or (r['false_alarm_rate'] is not None and r['false_alarm_rate'] > 0.03))
    return out


def shifted(docs, seconds):
    """Alarms documents with every exploit time moved `seconds` earlier (amendment 1: label resolution)."""
    out = dict(scenarios={})
    for sc, doc in docs['scenarios'].items():
        out['scenarios'][sc] = dict(alarms={n: dict(r, exploit=(r['exploit'] - seconds if r.get('exploit') is not None else None))
                                            for n, r in doc['alarms'].items()})
    return out


def tolerance(token_dir, archives, token_dir_2021, alarms_2021, seconds=1.0):
    """lidds2019-confirmation-v2 amendment 1: the registered decision with a tolerance equal to the label resolution."""
    names = sorted(p.stem for p in Path(token_dir).glob('*.npz'))
    scenarios = {s: TokenScenario(s, token_dir) for s in names}
    primary, _ = inventory(scenarios, archives)
    base, _ = score_part(scenarios, primary, 'all')
    tol, per = score_part(scenarios, shifted(primary, seconds), 'all')
    docs21 = m.load(alarms_2021)
    sc21 = {s: TokenScenario(s, token_dir_2021) for s in sorted(docs21['scenarios'])}
    base21, _ = score_part(sc21, docs21, 'official')
    tol21, _ = score_part(sc21, shifted(docs21, seconds), 'official')
    return dict(schema='lidds2019-confirmation-v2-amendment-1',
                protocol='sentinel_pulse/protocol/lidds2019-confirmation-v2-amendment-1.json', seconds=seconds,
                lidds2019=dict(registered=base, tolerance=tol, tolerance_scenarios=per, C1_descriptive=c1(tol)),
                lidds2021_official=dict(registered=base21, tolerance=tol21))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    g = sub.add_parser('gate')
    g.add_argument('--tokens', type=Path, required=True)
    g.add_argument('--alarms', type=Path, required=True)
    g.add_argument('--output', type=Path, required=True)
    s = sub.add_parser('score')
    s.add_argument('--tokens', type=Path, required=True)
    s.add_argument('--archives', type=Path)
    s.add_argument('--gate', type=Path, required=True)
    s.add_argument('--output', type=Path, required=True)
    t = sub.add_parser('tolerance')
    t.add_argument('--tokens', type=Path, required=True)
    t.add_argument('--archives', type=Path, required=True)
    t.add_argument('--tokens-2021', type=Path, required=True)
    t.add_argument('--alarms-2021', type=Path, required=True)
    t.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    if a.cmd == 'tolerance':
        out = tolerance(a.tokens, a.archives, a.tokens_2021, a.alarms_2021)
        a.output.write_text(json.dumps(out, indent=1, default=float))
        print(json.dumps({k: out[k] for k in ('lidds2019', 'lidds2021_official')}, default=float)[:2000])
        return
    if a.cmd == 'gate':
        out = gate(a.tokens, a.alarms)
        a.output.write_text(json.dumps(out, indent=1, default=float))
        print(json.dumps(dict(passed=out['passed'], reproduced=out['reproduced'])))
        raise SystemExit(0 if out['passed'] else 1)
    if a.output.exists():
        raise SystemExit(f'{a.output} exists: LID-DS 2019 is scored once')
    out = score(a.tokens, a.archives, a.gate)
    a.output.write_text(json.dumps(out, indent=1, default=float))
    print(json.dumps(dict(primary=out['primary']['pooled'], C1=out['C1']), default=float))


if __name__ == '__main__':
    main()
