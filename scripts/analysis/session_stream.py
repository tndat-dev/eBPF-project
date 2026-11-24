#!/usr/bin/env python3
"""session-stream-v1 (sentinel_pulse/protocol/session-stream-v1.json): the session lineage scored by its own branch.

Candidates on one finished live run of the lineage build:
  S0  the deployed alert path: the whole window by the workload's t3 model and threshold;
  S1  the native part by the workload's t3 model at the branch level (alpha' of each branch from the t3 fit's Gumbel
      parameters, FIT.json), OR the session part by ONE pooled session model (token_branch_fit.py --part session
      --pool-key) and its threshold;
  S2  as S1, with a per-workload session model where token_branch_fit.py --part session (minimum 200 blocks) gave one.
  B2  (exec-identity-v1, --session-prog) as S1, with the session part split by program (session_prog of the
      exec-identity build): a program with its own model (token_branch_fit.py --part session --by-prog, key
      '<pool key>|prog:<hash>') is scored by it, the programs without one together by the pooled model.
With --alpha-scale (improvement-round-2 A6, {workload: factor}) the native branch of a workload is at
branch alpha x factor; the S0 thresholds are those of --models.
Intervals as native_stream.py --h0-pairs (pairs with an attack interval), flagged when a window ending in
[start, start + 15 s] alarms; burden on the normal tail after the campaign as burden_context.py (episodes: alarms of
one container merged when < 15 s apart, per replica-hour). For S3 (scripts/analysis/session_triage.py) every interval
whose S0 alarm windows hold session events also gets the features of those session events.

    python3 session_stream.py --run-root RUN --models T3/MODELS.json --fit T3/FIT.json \
        [--session-pooled POOL/MODELS.json --session-per PER/MODELS.json --branch-alpha 0.00015] \
        [--session-prog PROG/MODELS.json --alpha-scale a6-scale.json] \
        --output out.json [--jobs 6] [--features-only]
"""
# session-stream-v1: chấm riêng dòng session (exec probe, lệnh vận hành, tấn công qua exec) bằng nhánh của nó; so S0
# (đường cảnh báo hiện tại), S1 (mô hình session gộp), S2 (theo workload nếu đủ dữ liệu); xuất đặc trưng cho S3.
import argparse
from collections import Counter, defaultdict
import json
import math
from multiprocessing import Pool
import os
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.common import open_sealed  # noqa: E402
import burden_context as bc  # noqa: E402
import live_attribution as la  # noqa: E402
from native_stream import native_of  # noqa: E402
import rule_intent as ri  # noqa: E402

live = la.live
NR_SHIFT, KIND_SHIFT = 23, 21
LABELS = ('control', 'admin', 'benign', 'attack', 'lotl', 'eventgen')
SYSTEMS = ('S0', 'S1', 'S2')
M = {}                                   # models of a pool worker (initializer)


def gumbel_threshold(fit, alpha):
    return fit[0] - fit[1] * math.log(-math.log(1 - alpha))


def load(models_path, fit_path, pooled_path, per_path, branch_alpha, prog_path=None, scale_path=None):
    t3 = la.load_models(models_path)
    fits = json.loads(Path(fit_path).read_text())['workloads'] if fit_path else {}
    scale = json.loads(Path(scale_path).read_text()) if scale_path else {}
    native_thr = {w: gumbel_threshold(fits[w]['gumbel'], branch_alpha * min(1.0, scale.get(w, 1.0)))
                  for w in t3 if w in fits and fits[w].get('gumbel')}
    pooled = la.load_models(pooled_path) if pooled_path else {}
    per = la.load_models(per_path) if per_path else {}
    prog = {int(k.rsplit('|prog:', 1)[1]): v for k, v in la.load_models(prog_path).items()} if prog_path else {}
    return t3, native_thr, pooled, per, prog


def init(args):
    t3, native_thr, pooled, per, prog = load(*args)
    M.update(t3=t3, native_thr=native_thr, lm={w: la.load_lm(p) for w, (p, _) in t3.items()},
             pooled=next(iter(pooled.values()), None), per=per, pooled_lm=None, per_lm={}, prog=prog,
             prog_lm={h: la.load_lm(p) for h, (p, _) in prog.items()})
    if M['pooled']:
        M['pooled_lm'] = la.load_lm(M['pooled'][0])
    M['per_lm'] = {w: la.load_lm(p) for w, (p, _) in per.items()}


def by_program(w, pooled):
    """exec-identity-v1: alarm of the session part split by program; `pooled` is the pooled verdict on the whole
    session part (used when the window has no program split)."""
    if 'session_prog' not in w:
        return pooled
    rest = []
    for prog, grams in sorted(_groups(w['session_prog']).items()):
        if prog in M['prog_lm']:
            if M['prog_lm'][prog].window_score(grams) > M['prog'][prog][1]:
                return True
        else:
            rest += grams
    return bool(rest) and M['pooled_lm'].window_score(rest) > M['pooled'][1]


def _groups(session_prog):
    out = {}
    for g in session_prog:
        out.setdefault(int(g[5]), []).append(g[:5])
    return out


def features(session):
    """Share of each system call (top 9 bits) and of error tokens among the session events of a window part."""
    calls, events, errors = Counter(), 0, 0
    for g in session:
        tok, c = int(g[3]), int(g[4])
        calls[tok >> NR_SHIFT] += c
        events += c
        errors += c * (((tok >> KIND_SHIFT) & 3) == 1)
    return calls, events, errors


def score(w, features_only):
    """{system: alarm} of one window (S0 only when features_only)."""
    key = w['workload_key']
    lm, thr = M['lm'][key], M['t3'][key][1]
    out = dict(S0=lm.window_score(w['grams']) > thr)
    if features_only:
        return out
    session = w.get('session') or []
    native = native_of(w['grams'], session)
    nat = bool(native) and lm.window_score(native) > M['native_thr'][key]
    pooled = bool(session) and M['pooled_lm'].window_score(session) > M['pooled'][1]
    if key in M['per_lm']:
        own = bool(session) and M['per_lm'][key].window_score(session) > M['per'][key][1]
    else:
        own = pooled
    out.update(S1=nat or pooled, S2=nat or own)
    if M['prog']:
        out['B2'] = nat or by_program(w, pooled)
    return out


def read_segment(job):
    path, spans, tail, excluded, features_only = job
    pods = {k[0] for k in spans}
    lo, hi = tail
    intervals, alarms = [], []
    with open_sealed(Path(path)) as stream:
        for line in stream:
            if line.startswith('{"type":"prog_names"'):   # exec-identity-v1 program-name lines
                continue
            end = float(la._field(line, 'window_end'))
            pod = la._field(line, 'pod_uid')
            in_tail = lo <= end < hi and not live.in_spans(end, excluded)
            in_interval = False
            if pod in pods:
                key = (pod, la._field(line, 'container_name'))
                in_interval = any(a <= end <= b for a, b in spans.get(key, ()))
            if not (in_tail or in_interval):
                continue
            w = json.loads(line)
            if w['workload_key'] not in M['t3']:
                continue
            flags = score(w, features_only)
            key = (w['pod_uid'], w['container_name'])
            if in_interval:
                feat = features(w.get('session') or []) if flags['S0'] else None
                intervals.append((key, end, flags, feat))
            if in_tail and any(flags.values()):
                session = w.get('session') or []
                alarms.append((key, w['workload_key'], end, flags, bool(session), len(session) < len(w['grams'])))
    return intervals, alarms


def evaluate(trials, windows, features_only, systems=None):
    systems = ('S0',) if features_only else systems or SYSTEMS
    attack_pairs = {t['pair']: t for t in trials if t['label'] == 'attack'}
    counts = defaultdict(lambda: {s: [0, 0] for s in systems})
    rows = []
    for t in trials:
        if t['label'] not in LABELS or t['pair'] not in attack_pairs:
            continue
        pair = attack_pairs[t['pair']]
        a, b = t['start'], t['start'] + la.HORIZON
        wins = [w for w in windows.get(t['key'], ()) if a <= w[0] <= b]
        hit = {s: any(f[s] for _, f, _ in wins) for s in systems}
        pad = pair.get('pad') or 0
        sets = [f"{t['label']}-pad{pad}"] if pad else [t['label']] + ([f"{t['label']}-primary"] if pair['rate'] in la.PRIMARY else [])
        for name in sets:
            for s in systems:
                counts[name][s][0] += hit[s]
                counts[name][s][1] += 1
        calls, events, errors, n = Counter(), 0, 0, 0
        for _, f, feat in wins:
            if feat:
                calls.update(feat[0]); events += feat[1]; errors += feat[2]; n += 1
        family = (t.get('scenario') if t['label'] == 'attack' else t.get('command') if t['label'] in ('admin', 'eventgen')
                  else t['label'])
        rows.append(dict(pair=t['pair'], label=t['label'], family=family, workload=t['workload'], rate=pair['rate'], pad=pad,
                         s0=hit['S0'], hits=hit, alarm_windows=n, session_events=events, error_events=errors,
                         calls={str(k): v for k, v in calls.items()}))
    rate = lambda kn: dict(k=kn[0], n=kn[1], rate=kn[0] / kn[1] if kn[1] else None, ci95=live.wilson(kn[0], kn[1]))
    return {k: {s: rate(v) for s, v in row.items()} for k, row in sorted(counts.items())}, rows


def admin_by_command(rows, systems, routine):
    """exec-identity-v1: operator-command intervals flagged per command and per set (routine: learnt during the
    capture; held-out: the other commands), per system."""
    out = {}
    for r in rows:
        if r['label'] != 'admin':
            continue
        for name in (r['family'], 'routine' if r['family'] in routine else 'held-out'):
            row = out.setdefault(name, {s: [0, 0] for s in systems})
            for s in systems:
                row[s][0] += bool(r['hits'][s])
                row[s][1] += 1
    return out


def burden(alarms, seconds, systems=SYSTEMS):
    hours = sum(seconds.values()) / 3600
    out = {}
    for s in systems:
        times, workload_of = defaultdict(list), {}
        for key, workload, end, flags, *_ in alarms:
            if flags.get(s):
                times[key].append(end); workload_of[key] = workload
        per_w = Counter()
        for key, ts in times.items():
            per_w[workload_of[key]] += len(bc.episodes(sorted(ts)))
        total = sum(per_w.values())
        out[s] = dict(episodes=total, per_replica_hour=total / hours if hours else None, by_workload=dict(per_w.most_common()))
    return dict(replica_hours=hours, systems=out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--fit', type=Path, help="FIT.json of the t3 fit (Gumbel parameters per workload); S1 and S2 need it")
    ap.add_argument('--session-pooled', type=Path)
    ap.add_argument('--session-per', type=Path)
    ap.add_argument('--branch-alpha', type=float, default=0.00015)
    ap.add_argument('--session-prog', type=Path, help='exec-identity-v1 B2: MODELS.json of token_branch_fit.py --by-prog')
    ap.add_argument('--alpha-scale', type=Path, help='improvement-round-2 A6: {workload: factor} of the native alpha')
    ap.add_argument('--routine', default='find,grep,sleep,stat,wc', help='exec-identity-v1: the routine operator commands')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=4)
    ap.add_argument('--features-only', action='store_true', help='S0 and the S3 features only (no session models)')
    a = ap.parse_args()
    if not a.features_only and not (a.session_pooled and a.fit):
        ap.error('S1 and S2 need --session-pooled and --fit')
    trials = live.load_trials(a.run_root / la.CAMPAIGN)
    spans = la.spans_of(trials)
    if a.features_only:
        tail, excluded = (0.0, 0.0), []
    else:
        cfg = json.loads((a.run_root / 'CONFIG.json').read_text())
        excluded = [live.campaign_span(a.run_root / live.CAMPAIGN)]
        tail = (max(float(cfg['selection_end']), excluded[0][1]), float(cfg['selection_start']) + float(cfg['seconds']))
    files = [str(p) for p in sorted(a.run_root.glob('workers/*/segments/*/tokens.jsonl*'))]
    windows, alarms = defaultdict(list), []
    init_args = (a.models, a.fit, a.session_pooled, a.session_per, a.branch_alpha, a.session_prog, a.alpha_scale)
    systems = SYSTEMS + (('B2',) if a.session_prog else ())
    with Pool(a.jobs, initializer=init, initargs=(init_args,)) as pool:
        for inter, alarm in pool.imap_unordered(read_segment, [(f, spans, tail, excluded, a.features_only) for f in files],
                                                chunksize=1):
            for key, end, flags, feat in inter:
                windows[key].append((end, flags, feat))
            alarms += alarm
    intervals, rows = evaluate(trials, windows, a.features_only, systems)
    doc = dict(schema='session-stream-v1', protocol='sentinel_pulse/protocol/session-stream-v1.json', run=str(a.run_root),
               models=str(a.models), session_pooled=str(a.session_pooled) if a.session_pooled else None,
               session_per=str(a.session_per) if a.session_per else None, branch_alpha=a.branch_alpha,
               session_prog=str(a.session_prog) if a.session_prog else None,
               alpha_scale=str(a.alpha_scale) if a.alpha_scale else None,
               segments_read=len(files), intervals=intervals, interval_rows=rows)
    if not a.features_only:
        decisions = [str(p) for p in sorted(a.run_root.glob('workers/*/segments/*/decisions.jsonl*')) if os.stat(p).st_mtime >= tail[0]]
        seconds = defaultdict(float)
        with Pool(a.jobs) as pool:
            for _, sec, _ in pool.map(ri.read_tail_decisions, [(f, tail[0], tail[1], excluded) for f in decisions], chunksize=1):
                for w, v in sec.items():
                    seconds[w] += v
        doc['burden'] = burden(alarms, seconds, systems)
        doc['burden']['by_stream'] = {s: dict(Counter('session' if sess and not nat else 'mixed' if sess else 'native'
                                                      for *_, f, sess, nat in alarms if f.get(s))) for s in systems}
        doc['admin_by_command'] = admin_by_command(rows, systems, a.routine.split(','))
        ia = lambda k, s: intervals.get(k, {}).get(s, {})
        crit = {}
        for s in systems[1:]:
            b = doc['burden']['systems'][s]['per_replica_hour']
            crit[s] = dict(primary_attack=ia('attack-primary', s).get('rate'), lotl=ia('lotl', s).get('rate'),
                           eventgen=ia('eventgen', s).get('rate'), control=ia('control', s).get('rate'), burden=b)
            crit[s]['passes'] = bool(crit[s]['primary_attack'] is not None and crit[s]['primary_attack'] >= .95
                                     and (crit[s]['lotl'] or 0) >= .95 and (crit[s]['eventgen'] or 0) >= .95
                                     and crit[s]['control'] is not None and crit[s]['control'] <= .05 and b is not None and b <= .24)
        doc['criteria'] = crit
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps({k: {s: v[s]['k'] for s in v} | {'n': next(iter(v.values()))['n']} for k, v in intervals.items()}))
    if 'criteria' in doc:
        print(json.dumps(dict(criteria=doc['criteria'],
                              burden={s: v['per_replica_hour'] for s, v in doc['burden']['systems'].items()}), default=float))


if __name__ == '__main__':
    main()
