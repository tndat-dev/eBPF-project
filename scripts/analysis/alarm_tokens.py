#!/usr/bin/env python3
"""What raises the alarms under heavy load (load-diurnal-v1 follow-up, descriptive): the token models score a capture;
for every window above its workload's threshold, the three most surprising events are decoded (system call, token
kind: name only / error code / size class / open mode and directory) and classed as a NEW TOKEN (the event's token
alone is improbable: -ln P0 > 12) or a NEW CONTEXT (a known token after an unusual history). Counted per traffic
regime of the capture's schedule and per workload.

    python3 alarm_tokens.py --run-root CAPTURE --models FIT/token/MODELS.json --output out.json [--jobs 3]
"""
# Chẩn đoán cảnh báo lúc tải cao: giải mã 3 sự kiện bất ngờ nhất của mỗi cửa sổ báo, theo chế độ tải.
import argparse
from collections import Counter, defaultdict
import json
import math
from multiprocessing import Pool
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.common import open_sealed  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM, strip  # noqa: E402

KINDS = {0: 'name', 1: 'err', 2: 'size', 3: 'open'}
NEW_TOKEN = 12.0
_LMS = {}


def decode(tok):
    nr, kind, detail = tok >> 23, (tok >> 21) & 3, tok & 0x1FFFFF
    if kind == 3:
        return nr, 'open', ('w' if detail & (1 << 20) else 'r')
    return nr, KINDS[kind], (detail if kind in (1, 2) else None)


def regime_of(t, schedule):
    for p in schedule:
        if p['start'] <= t < p['end']:
            return p['regime']
    return 'outside'


def read_file(job):
    path, models, schedule = job
    out = defaultdict(Counter)                      # (regime, field) -> Counter
    windows = Counter()
    with open_sealed(Path(path)) as stream:
        for line in stream:
            w = json.loads(line)
            key = w['workload_key']
            if key not in models:
                continue
            lm_path, thr, top = models[key]
            if lm_path not in _LMS:
                _LMS[lm_path] = CountTokenLM.load(Path(lm_path))
                _LMS[lm_path].default_top = int(top)
            lm = _LMS[lm_path]
            reg = regime_of(w['window_end'], schedule)
            windows[reg] += 1
            if lm.window_score(w['grams']) <= thr:
                continue
            events = sorted(((-math.log(lm.prob(strip(g[:4]))), g) for g in w['grams']), key=lambda x: -x[0])[:3]
            out[(reg, 'alarm_windows')]['n'] += 1
            out[(reg, 'workload')][key] += 1
            for nll, g in events:
                nr, kind, detail = decode(int(g[3]))
                novel = -math.log(max(lm.base(int(g[3])), 1e-300)) > NEW_TOKEN
                out[(reg, 'kind')][kind] += 1
                out[(reg, 'novelty')]['new_token' if novel else 'new_context'] += 1
                out[(reg, 'token')][f'{nr}:{kind}:{detail}'] += 1
    return {f'{r}|{f}': dict(c) for (r, f), c in out.items()}, dict(windows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=3)
    ap.add_argument('--unistd', type=Path, default=Path('/usr/include/x86_64-linux-gnu/asm/unistd_64.h'))
    a = ap.parse_args()
    doc = json.loads(a.models.read_text())
    models = {k: (v['lm'], float(v['threshold']), int(v.get('top', 10))) for k, v in doc.items()}
    schedule = json.loads((a.run_root / 'CONFIG.json').read_text())['traffic_schedule'][:-1]
    names = {int(n): s for s, n in re.findall(r'#define __NR_(\w+)\s+(\d+)', a.unistd.read_text())} if a.unistd.exists() else {}
    files = [str(p) for p in sorted(a.run_root.glob('workers/*/segments/*/tokens.jsonl*'))]
    total, windows = defaultdict(Counter), Counter()
    with Pool(a.jobs) as pool:
        for part, win in pool.imap_unordered(read_file, [(f, models, schedule) for f in files], chunksize=1):
            for k, c in part.items():
                total[k].update(c)
            windows.update(win)
    regimes = sorted({k.split('|')[0] for k in total})
    named = lambda t: (lambda nr, kind, det: f"{names.get(int(nr), nr)}:{kind}" + ('' if det == 'None' else f":{det}"))(*t.split(':'))
    res = {}
    for r in regimes:
        n = total[f'{r}|alarm_windows']['n']
        ev = sum(total[f'{r}|kind'].values())
        res[r] = dict(windows=windows[r], alarm_windows=n, alarm_share=n / windows[r] if windows[r] else None,
                      kind_share={k: v / ev for k, v in total[f'{r}|kind'].items()},
                      novelty_share={k: v / ev for k, v in total[f'{r}|novelty'].items()},
                      top_tokens=[(named(t), c) for t, c in total[f'{r}|token'].most_common(15)],
                      top_workloads=total[f'{r}|workload'].most_common(8))
    a.output.write_text(json.dumps(dict(schema='alarm-tokens-v1', run=str(a.run_root), models=str(a.models), regimes=res), indent=1))
    for r, v in res.items():
        print(r, v['alarm_windows'], round(100 * (v['alarm_share'] or 0), 4), {k: round(x, 2) for k, x in v['kind_share'].items()},
              {k: round(x, 2) for k, x in v['novelty_share'].items()}, v['top_tokens'][:6], flush=True)


if __name__ == '__main__':
    main()
