#!/usr/bin/env python3
"""exec-intent-v1 P0: where in time the flags of benign launches and attacks fall, from stored campaign decisions.

For every trial (EVALUATION_INPUT.json: decision rows as run, policy as run) and each 15 s segment (benign launch,
attack): the windows after the launch, indexed 0..29 (0.5 s each). Reported per segment type:

- positive rate by window index;
- the segment flag rate if the first k windows after the launch were not allowed to raise a preview, for
  k = 0 (as run), 2, 4, 6, 8 (1-4 s): the upper bound of what discounting the startup phase alone could buy,
  and what it costs in attack recall (a later first preview also adds latency, reported as the median delay);
- per scenario for the attacks.

Descriptive and post hoc; no policy is chosen from it (exec-intent-v1 P0).
    python3 exec_phase_decomposition.py --campaign DIR [--campaign DIR ...] --output P0.json
"""
import argparse
from collections import defaultdict
import glob
import json
import statistics

SKIPS = (0, 2, 4, 6, 8)


def segment_windows(rows, start):
    w = sorted((r for r in rows if start <= r['window_start'] and r['window_end'] <= start + 15), key=lambda r: r['window_end'])
    return [(int((r['window_end'] - start) // 0.5) - 1, bool(r.get('candidate_alert_preview')), r['window_end'] - start) for r in w]


def analyse(campaigns, min_windows=20):
    pos_by_index = {lab: defaultdict(lambda: [0, 0]) for lab in ('benign', 'attack')}
    flagged = {lab: {k: [0, 0] for k in SKIPS} for lab in ('benign', 'attack')}
    delay = {k: [] for k in SKIPS}
    by_scenario = defaultdict(lambda: {k: [0, 0] for k in SKIPS})
    for campaign in campaigns:
        for path in sorted(glob.glob(campaign + '/trials/*/EVALUATION_INPUT.json')):
            d = json.load(open(path))
            rows = [r for r in d['decisions'] if r.get('status') == 'candidate-raw-score-only']
            for lab in ('benign', 'attack'):
                seg = d.get(lab)
                if not seg:
                    continue
                w = segment_windows(rows, float(seg['start_at']))
                if len(w) < min_windows:
                    continue
                for i, pos, _ in w:
                    if 0 <= i < 30:
                        pos_by_index[lab][i][0] += pos; pos_by_index[lab][i][1] += 1
                for k in SKIPS:
                    hits = [t for i, pos, t in w if pos and i >= k]
                    flagged[lab][k][0] += bool(hits); flagged[lab][k][1] += 1
                    if lab == 'attack':
                        sc = by_scenario[d['attack']['scenario']][k]; sc[0] += bool(hits); sc[1] += 1
                        if hits:
                            delay[k].append(min(hits))
    rate = lambda c: c[0] / c[1] if c[1] else None
    return dict(
        positive_rate_by_window_index={lab: [rate(v[i]) for i in range(30)] for lab, v in pos_by_index.items()},
        flag_rate_if_first_k_windows_skipped={lab: {str(k): dict(rate=rate(c), flagged=c[0], segments=c[1]) for k, c in v.items()}
                                              for lab, v in flagged.items()},
        attack_first_preview_after_launch_median_s={str(k): statistics.median(v) if v else None for k, v in delay.items()},
        attack_recall_by_scenario={sc: {str(k): rate(c) for k, c in v.items()} for sc, v in sorted(by_scenario.items())})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--campaign', action='append', required=True)
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    res = dict(schema='pulse-exec-phase-decomposition-v1', protocol='sentinel_pulse/protocol/exec-intent-v1.json (P0)',
               campaigns=a.campaign, note='descriptive, post hoc; skipping windows is an upper bound of a startup discount',
               **analyse(a.campaign))
    open(a.output, 'w').write(json.dumps(res, indent=1))
    for lab, v in res['flag_rate_if_first_k_windows_skipped'].items():
        print(lab, {k: round(x['rate'], 3) for k, x in v.items()})
    print('attack first preview median s', res['attack_first_preview_after_launch_median_s'])


if __name__ == '__main__':
    main()
