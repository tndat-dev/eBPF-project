#!/usr/bin/env python3
"""Part E of ml-final-study-v1 (rule layer after ML), benefit side on the pulse-live-v5-1110 campaign.

R1 (image-tool exec): an alert whose window had, around it, only runtime execs of binaries that belong to the
container image is downgraded to info. R2 (drift): an alert whose exec is a binary not in the image stays an alert,
labelled drift. The v5 campaign injects, per trial and workload: a control (no exec), a benign exec of the operator
binary /operator/sentinel-benign-exec-control (NOT an image binary), an admin command (cat / ls / sh ... which ARE
image binaries), and a blind attack /operator/sentinel-runtime-attack-blind (NOT an image binary). So on v5:

  - R1 downgrades admin alerts (admin runs image tools) and leaves attack alerts (the attack binary is not an image
    binary), which is the 'admin flagged with and without R1, attack recall with and without' the protocol asks for;
  - R2 labels the operator benign exec and the attack as drift (both non-image), so R1's drift companion keeps them
    as alerts.

This measures the BENEFIT side only. The campaign has no living-off-the-land attack (one that execs an image tool),
so R1's miss on such an attack is NOT measured here; part F of a live run adds those before R1 is adopted (protocol).

Reuses the token-branch loader and the exact flagged() of live_attribution.py, so the ML alarms are the v5 model's.
    python3 rule_e_benefit.py --run-root RUN --models FIT/token/MODELS.json --output out.json [--jobs 6]
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_attribution as la  # noqa: E402
import pulse_live_v4 as live  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM  # noqa: E402

# v5 exec identity per trial label: admin runs image binaries (cat/ls/sh/...); the operator benign exec and the
# blind attack are /operator/ binaries injected into the container, not part of the image.
IMAGE_TOOL = {'admin', 'lotl'}      # pulse-live-v6-v1: the living-off-the-land step runs sh, cat, ls of the image
NON_IMAGE = {'benign', 'attack'}

# the two systems the thesis compares (memory rule-framework-last: ML decided first, then with-vs-without rules):
#   ml_only      -- the token model alone is the alert path (the deployed v5 system), alert = model fired ('ml')
#   ml_plus_rule -- the Part E rule layer on top, alert = model fired AND not downgraded by R1 ('after_r1')
# positive class is attack (recall); the negative classes are benign operator activity (admin = in-image tool use,
# the class R1 targets), benign (a non-image operator exec -> drift, unchanged by the rule) and control (no exec).
POS = 'attack'
NEG = ('admin', 'benign', 'control')
SYSTEMS = (('ml_only', 'ml'), ('ml_plus_rule', 'after_r1'))


def two_system(agg, suffix=''):
    """ML-only vs ML+rule, split out: attack recall and false-alarm (by negative class and pooled), from agg."""
    get = lambda label, field: agg[label + suffix][field] if (label + suffix) in agg else 0
    tot = lambda label: agg[label + suffix]['n'] if (label + suffix) in agg else 0
    frac = lambda h, n: dict(hit=h, n=n, rate=(h / n if n else None))
    neg = [label for label in NEG if (label + suffix) in agg]
    out = {}
    for name, field in SYSTEMS:
        nh = sum(get(label, field) for label in neg)
        nt = sum(tot(label) for label in neg)
        out[name] = dict(attack_recall=frac(get(POS, field), tot(POS)),
                         lotl_recall=frac(get('lotl', field), tot('lotl')),     # H4: the harm side of R1
                         false_alarm_by_class={label: frac(get(label, field), tot(label)) for label in neg},
                         false_alarm_pooled=frac(nh, nt))
    return out


def tally(trials, models, is_flagged):
    """Per set (label, label-primary, label-padN): n, ML alarms, alarms left after R1, R2 drift labels; admin per command."""
    # per (label[, -primary]) counts: n, ml alarms, alarms after R1, R2 drift labels
    agg = defaultdict(lambda: dict(n=0, ml=0, after_r1=0, r2_drift=0))
    per_command = defaultdict(lambda: dict(n=0, ml=0, after_r1=0))   # admin commands, to show which tools R1 covers
    pair_pad = {t['pair']: t.get('pad') or 0 for t in trials if t['label'] == 'attack'}
    pair_rate = {t['pair']: t.get('rate') for t in trials if t['label'] == 'attack'}   # control rows carry no rate
    for t in trials:
        w = t['workload']
        if w not in models:
            continue
        label = t['label']
        pad = pair_pad.get(t['pair'], 0)
        alarmed = is_flagged(t)
        downgraded = alarmed and label in IMAGE_TOOL           # R1 downgrades image-tool-only alerts
        drift = alarmed and label in NON_IMAGE                 # R2 labels non-image execs drift (still an alert)
        names = ([label] + ([label + '-primary'] if pair_rate.get(t['pair']) in la.PRIMARY else []) if not pad
                 else [f'{label}-pad{pad}'])            # dilution pairs (pulse-live-v6-v1) are their own sets
        for name in names:
            d = agg[name]
            d['n'] += 1
            d['ml'] += int(alarmed)
            d['after_r1'] += int(alarmed and not downgraded)
            d['r2_drift'] += int(drift)
        if label == 'admin' and not pad:
            c = per_command[t['command']]
            c['n'] += 1
            c['ml'] += int(alarmed)
            c['after_r1'] += int(alarmed and not downgraded)

    return agg, per_command


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=6)
    a = ap.parse_args()

    trials = live.load_trials(a.run_root / la.CAMPAIGN)
    models = la.load_models(a.models)
    windows, files = la.collect(a.run_root, trials, a.jobs)
    lms = {w: CountTokenLM.load(Path(models[w][0])) for w in sorted({t['workload'] for t in trials} & set(models))}

    agg, per_command = tally(trials, models, lambda t: la.flagged(lms[t['workload']], models[t['workload']][1], windows, t))

    rate = lambda d: dict(d, ml_rate=d['ml'] / d['n'] if d['n'] else None,
                          after_r1_rate=d['after_r1'] / d['n'] if d['n'] else None)
    out = {k: rate(v) for k, v in sorted(agg.items())}
    comparison = dict(all_rates=two_system(agg), primary=two_system(agg, '-primary'))
    doc = dict(schema='ml-final-study-v1-rule-e-benefit', protocol='sentinel_pulse/protocol/ml-final-study-v1.json',
               rules=dict(R1='downgrade an alert whose window had only runtime execs of image binaries (admin on v5)',
                          R2='an alert whose exec is a non-image binary stays an alert, labelled drift (benign/attack on v5)'),
               run=str(a.run_root), models=str(a.models), segments_read=files,
               scope='benefit side (admin) and, on runs with a living-off-the-land step (pulse-live-v6-v1 H4), the harm '
                     'side: lotl_recall under ml_only vs ml_plus_rule',
               systems=dict(ml_only='token model alone is the alert path (deployed v5)',
                            ml_plus_rule='token model + Part E rule layer (R1 downgrade image-tool-only windows, R2 drift label)'),
               comparison=comparison, by_label=out, admin_by_command={c: rate(v) for c, v in sorted(per_command.items())})
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    for scope, c in (('all_rates', comparison['all_rates']), ('primary(1/3/6 per s)', comparison['primary'])):
        print('==', scope, '==')
        for name, _ in SYSTEMS:
            s = c[name]
            fa = s['false_alarm_by_class']
            print(' %-13s attack_recall %d/%d  admin_FA %d/%d  benign_drift %d/%d  control %d/%d  pooled_FA %d/%d' % (
                name, s['attack_recall']['hit'], s['attack_recall']['n'],
                fa['admin']['hit'], fa['admin']['n'], fa['benign']['hit'], fa['benign']['n'],
                fa.get('control', {}).get('hit', 0), fa.get('control', {}).get('n', 0),
                s['false_alarm_pooled']['hit'], s['false_alarm_pooled']['n']))


if __name__ == '__main__':
    main()
