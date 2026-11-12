#!/usr/bin/env python3
"""Parts B2 and B3 of protocol ml-final-study-v1 (amendment 1) on a live run with the token models it ran with.

B2, known tools in the workload model: pairs are dealt to 5 folds (pair number modulo 5); for fold f each workload model
also learns the admin-interval windows of its containers in the other folds and scores the admin intervals of fold f.

B3, lineage proxy: a window's session proxy is its grams unseen (at their own length) by the v5 workload model, the
native proxy the rest. Native arm: the native proxy against the v5 workload model and threshold. Session arms: one
session model for the cluster (CountTokenLM, same score), learnt from the session proxy of admin intervals, threshold by
the registered rule on held-out interval maxima:
  known_tools            held-out admin intervals, model of the other folds
  unseen_tool            command c under the model and threshold of the other 9 commands
  unknown_program        benign-binary intervals under the model of all admin intervals
  learnt_program         benign-binary intervals of fold f under admin + benign of the other folds
  attack_tools_only      attack intervals under the model of all admin intervals
  attack_program_learnt  attack intervals of fold f under admin + benign of the other folds

    python3 session_model.py --run-root RUN --models FIT/token/MODELS.json --output out.json [--jobs 6]
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.detector.token_model import TOP, CountTokenLM, call_of, strip  # noqa: E402
import live_attribution as la  # noqa: E402
import token_branch_fit as fit  # noqa: E402

FOLDS = 5
ALPHA = 0.0002 * 0.9
PRIMARY = la.PRIMARY


def seen(lm, gram):
    """Has the workload model seen this gram at its own length (a lone token: seen as a token)?"""
    g = strip(gram)
    w = g[-1]
    if len(g) == 1:
        return lm.given.get(call_of(w), {}).get(w, 0) > 0
    return lm.count[len(g) - 1].get(g[:-1], {}).get(w, 0) > 0


def split(lm, grams):
    """(native proxy, session proxy) of one window's [t0, t1, t2, t3, count] rows."""
    native, session = [], []
    for g in grams:
        (native if seen(lm, g[:4]) else session).append(g)
    return native, session


def counts_of(windows):
    c = Counter()
    for grams in windows:
        for *g, n in grams:
            c[strip(g)] += int(n)
    return c


def model_of(counters):
    lm = CountTokenLM()
    for c in counters:
        for g, n in c.items():
            lm.learn(g, n)
    return lm.finalize()


def interval_max(lm, windows):
    """Largest window score of an interval's session windows under a session model; 0 when it has none."""
    return max((lm.window_score(g, TOP) for g in windows if g), default=0.0)


def threshold_of(maxima):
    return fit.threshold(fit.trimmed_gumbel(maxima), ALPHA)


def rate(hits, n):
    return dict(k=int(hits), n=int(n), rate=hits / n if n else None)


def part_b2(trials, windows, models, lms):
    admin = [t for t in trials if t['label'] == 'admin' and t['workload'] in models]
    held, base = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
    for w in sorted({t['workload'] for t in admin}):
        mine = [t for t in admin if t['workload'] == w]
        for f in range(FOLDS):
            test = [t for t in mine if t['pair'] % FOLDS == f]
            if not test:
                continue
            learn = [g for t in mine if t['pair'] % FOLDS != f for _, g, _, _ in la.interval_windows(windows, t)]
            lm = la.augmented(models[w][0], learn)
            for t in test:
                for table, m in ((held, lm), (base, lms[w])):
                    table[t['command']][0] += la.flagged(m, models[w][1], windows, t)
                    table[t['command']][1] += 1
    cmds = sorted(held)
    tot = lambda tb: rate(sum(tb[c][0] for c in cmds), sum(tb[c][1] for c in cmds))
    return dict(held_out_admin=dict(known=tot(held), v5=tot(base)),
                by_command={c: dict(known=rate(*held[c]), v5=rate(*base[c])) for c in cmds})


def part_b3(trials, windows, models, lms):
    use = [t for t in trials if t['workload'] in models]
    nat, ses = {}, {}
    for i, t in enumerate(use):
        lm = lms[t['workload']]
        parts = [split(lm, g) for _, g, _, _ in la.interval_windows(windows, t)]
        nat[i] = [p[0] for p in parts]
        ses[i] = [p[1] for p in parts]
    idx = lambda label: [i for i, t in enumerate(use) if t['label'] == label]
    fold = lambda i: use[i]['pair'] % FOLDS
    primary_pairs = {t['pair'] for t in use if t['label'] == 'attack' and t['rate'] in PRIMARY}
    is_primary = lambda i: use[i]['pair'] in primary_pairs

    # native arm: what the workload model alone would still alarm on
    native = {}
    for label in ('control', 'admin', 'benign', 'attack'):
        ids = idx(label)
        hit = lambda i: any(lms[use[i]['workload']].window_score(g, TOP) > models[use[i]['workload']][1] for g in nat[i] if g)
        native[label] = rate(sum(hit(i) for i in ids), len(ids))
        native[f'{label}-primary'] = rate(sum(hit(i) for i in ids if is_primary(i)), sum(is_primary(i) for i in ids))

    admin, benign, attack = idx('admin'), idx('benign'), idx('attack')
    c_admin = {f: counts_of(g for i in admin if fold(i) == f for g in ses[i]) for f in range(FOLDS)}
    c_benign = {f: counts_of(g for i in benign if fold(i) == f for g in ses[i]) for f in range(FOLDS)}
    others = lambda table, f: [table[j] for j in range(FOLDS) if j != f]

    # known tools: cross-fit over folds
    m_admin = {f: model_of(others(c_admin, f)) for f in range(FOLDS)}
    known_max = {i: interval_max(m_admin[fold(i)], ses[i]) for i in admin}
    tau_known = threshold_of(list(known_max.values()))
    full_admin = model_of(list(c_admin.values()))
    out = dict(native_arm=native, session_grams=dict(
        admin_intervals_with_any=sum(any(g for g in ses[i]) for i in admin), admin_intervals=len(admin),
        distinct_admin_grams=len(counts_of(g for i in admin for g in ses[i]))))
    out['known_tools'] = dict(threshold=tau_known, flagged=rate(sum(v > tau_known for v in known_max.values()), len(admin)),
                              by_command={c: rate(sum(known_max[i] > tau_known for i in admin if use[i]['command'] == c),
                                                  sum(use[i]['command'] == c for i in admin))
                                          for c in sorted({use[i]['command'] for i in admin})})

    # unseen tool: leave one command out, model and threshold from the other nine
    unseen = {}
    for c in sorted({use[i]['command'] for i in admin}):
        rest = [i for i in admin if use[i]['command'] != c]
        cf = {f: counts_of(g for i in rest if fold(i) == f for g in ses[i]) for f in range(FOLDS)}
        mf = {f: model_of(others(cf, f)) for f in range(FOLDS)}
        tau = threshold_of([interval_max(mf[fold(i)], ses[i]) for i in rest])
        m = model_of(list(cf.values()))
        mine = [i for i in admin if use[i]['command'] == c]
        unseen[c] = dict(threshold=tau, **rate(sum(interval_max(m, ses[i]) > tau for i in mine), len(mine)))
    out['unseen_tool'] = dict(by_command=unseen, all=rate(sum(v['k'] for v in unseen.values()), sum(v['n'] for v in unseen.values())))

    def both(ids, score):
        return dict(all=rate(sum(score(i) for i in ids), len(ids)),
                    primary=rate(sum(score(i) for i in ids if is_primary(i)), sum(is_primary(i) for i in ids)))

    out['unknown_program'] = both(benign, lambda i: interval_max(full_admin, ses[i]) > tau_known)
    out['attack_tools_only'] = both(attack, lambda i: interval_max(full_admin, ses[i]) > tau_known)

    # the program is learnt too: admin + benign of the other folds
    m_ab = {f: model_of(others(c_admin, f) + others(c_benign, f)) for f in range(FOLDS)}
    ab_max = {i: interval_max(m_ab[fold(i)], ses[i]) for i in admin + benign}
    tau_ab = threshold_of(list(ab_max.values()))
    out['learnt_program'] = dict(threshold=tau_ab, benign=both(benign, lambda i: ab_max[i] > tau_ab),
                                 admin=both(admin, lambda i: ab_max[i] > tau_ab))
    attack_max = {i: interval_max(m_ab[fold(i)], ses[i]) for i in attack}
    out['attack_program_learnt'] = both(attack, lambda i: attack_max[i] > tau_ab)
    out['attack_program_learnt']['by_scenario'] = {
        s: rate(sum(attack_max[i] > tau_ab for i in attack if use[i]['scenario'] == s and is_primary(i)),
                sum(use[i]['scenario'] == s and is_primary(i) for i in attack)) for s in sorted({use[i]['scenario'] for i in attack})}
    nat_hit = lambda i: any(lms[use[i]['workload']].window_score(g, TOP) > models[use[i]['workload']][1] for g in nat[i] if g)
    out['system_native_or_session'] = dict(
        attack=both(attack, lambda i: nat_hit(i) or attack_max[i] > tau_ab),
        benign=both(benign, lambda i: nat_hit(i) or ab_max[i] > tau_ab),
        admin=both(admin, lambda i: nat_hit(i) or ab_max[i] > tau_ab),
        control=both(idx('control'), nat_hit))
    # exploratory (not part of the registered decision): the score distributions behind the session arms
    q = lambda v: dict(n=len(v), **{f'p{p}': float(np.percentile(v, p)) for p in (5, 25, 50, 75, 95, 99)}, max=float(max(v))) if v else None
    auc = lambda pos, neg: float(np.mean([(a > b) + 0.5 * (a == b) for a in pos for b in neg])) if pos and neg else None
    adm, ben = [ab_max[i] for i in admin], [ab_max[i] for i in benign]
    att = [attack_max[i] for i in attack]
    att_p = [attack_max[i] for i in attack if is_primary(i)]
    out['exploratory'] = dict(
        note='held-out interval maxima under the admin + benign session model (cross-fit); no decision uses these',
        admin=q(adm), benign=q(ben), attack=q(att), attack_primary=q(att_p),
        auc_attack_vs_benign=auc(att, ben), auc_attack_vs_admin=auc(att, adm), auc_attack_primary_vs_benign=auc(att_p, ben),
        attack_primary_above_largest_benign=rate(sum(v > max(ben) for v in att_p), len(att_p)),
        attack_primary_above_p99_admin_and_benign=rate(sum(v > np.percentile(adm + ben, 99) for v in att_p), len(att_p)),
        flagged_at_p99=dict(admin=rate(sum(v > np.percentile(adm + ben, 99) for v in adm), len(adm)),
                            benign=rate(sum(v > np.percentile(adm + ben, 99) for v in ben), len(ben))),
        by_scenario_primary_above_largest_benign={
            sc: rate(sum(attack_max[i] > max(ben) for i in attack if use[i]['scenario'] == sc and is_primary(i)),
                     sum(use[i]['scenario'] == sc and is_primary(i) for i in attack)) for sc in sorted({use[i]['scenario'] for i in attack})},
        tools_only=dict(admin=q(list(known_max.values())), benign=q([interval_max(full_admin, ses[i]) for i in benign]),
                        attack_primary=q([interval_max(full_admin, ses[i]) for i in attack if is_primary(i)])))
    n = out['native_arm']
    out['decision'] = dict(
        native_at_most_5_percent=all((n[k]['rate'] or 0) <= 0.05 for k in ('control', 'admin', 'benign')),
        known_tools_at_most_20_percent=out['known_tools']['flagged']['rate'] <= 0.20,
        attack_program_learnt_primary_at_least_95_percent=out['attack_program_learnt']['primary']['rate'] >= 0.95)
    out['decision']['build_lineage_tag'] = all(out['decision'].values())
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=6)
    a = ap.parse_args()
    trials = la.live.load_trials(a.run_root / la.CAMPAIGN)
    models = la.load_models(a.models)
    windows, files = la.collect(a.run_root, trials, a.jobs)
    lms = {w: CountTokenLM.load(Path(models[w][0])) for w in sorted({t['workload'] for t in trials} & set(models))}
    doc = dict(schema='ml-final-study-v1-session-model', protocol='sentinel_pulse/protocol/ml-final-study-v1-amendment-1.json',
               run=str(a.run_root), models=str(a.models), segments_read=files,
               B2=part_b2(trials, windows, models, lms), B3=part_b3(trials, windows, models, lms))
    a.output.write_text(json.dumps(doc, indent=1))
    b3 = doc['B3']
    print(json.dumps(dict(B2=doc['B2']['held_out_admin'], native=b3['native_arm'], known=b3['known_tools']['flagged'],
                          unseen=b3['unseen_tool']['all'], unknown_program=b3['unknown_program'],
                          learnt_program=b3['learnt_program']['benign'], attack_tools_only=b3['attack_tools_only'],
                          attack_program_learnt=b3['attack_program_learnt'], decision=b3['decision'], exploratory=b3['exploratory'])))


if __name__ == '__main__':
    main()
