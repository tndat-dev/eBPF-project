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
IMAGE_TOOL = {'admin'}
NON_IMAGE = {'benign', 'attack'}


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

    # per (label[, -primary]) counts: n, ml alarms, alarms after R1, R2 drift labels
    agg = defaultdict(lambda: dict(n=0, ml=0, after_r1=0, r2_drift=0))
    per_command = defaultdict(lambda: dict(n=0, ml=0, after_r1=0))   # admin commands, to show which tools R1 covers
    for t in trials:
        w = t['workload']
        if w not in models:
            continue
        label = t['label']
        alarmed = la.flagged(lms[w], models[w][1], windows, t)
        downgraded = alarmed and label in IMAGE_TOOL           # R1 downgrades image-tool-only alerts
        drift = alarmed and label in NON_IMAGE                 # R2 labels non-image execs drift (still an alert)
        names = [label] + ([label + '-primary'] if t.get('rate') in la.PRIMARY else [])
        for name in names:
            d = agg[name]
            d['n'] += 1
            d['ml'] += int(alarmed)
            d['after_r1'] += int(alarmed and not downgraded)
            d['r2_drift'] += int(drift)
        if label == 'admin':
            c = per_command[t['command']]
            c['n'] += 1
            c['ml'] += int(alarmed)
            c['after_r1'] += int(alarmed and not downgraded)

    rate = lambda d: dict(d, ml_rate=d['ml'] / d['n'] if d['n'] else None,
                          after_r1_rate=d['after_r1'] / d['n'] if d['n'] else None)
    out = {k: rate(v) for k, v in sorted(agg.items())}
    doc = dict(schema='ml-final-study-v1-rule-e-benefit', protocol='sentinel_pulse/protocol/ml-final-study-v1.json',
               rules=dict(R1='downgrade an alert whose window had only runtime execs of image binaries (admin on v5)',
                          R2='an alert whose exec is a non-image binary stays an alert, labelled drift (benign/attack on v5)'),
               run=str(a.run_root), models=str(a.models), segments_read=files,
               scope='benefit side only; R1 miss on living-off-the-land attacks needs part F of a live run',
               by_label=out, admin_by_command={c: rate(v) for c, v in sorted(per_command.items())})
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    head = {k: {'n': out[k]['n'], 'ml': out[k]['ml'], 'after_r1': out[k]['after_r1'], 'r2_drift': out[k]['r2_drift']}
            for k in out if '-primary' not in k}
    print(json.dumps(dict(by_label=head), indent=1))


if __name__ == '__main__':
    main()
