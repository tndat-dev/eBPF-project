#!/usr/bin/env python3
"""Why does the rank-1 suspect of a normal RCA case rank first? (RCA 5.12: effect of the carried-over baseline)

For every RCA case outside the campaign span (first interval - 60 s to campaign end + 60 s), takes the rank-1
suspect and counts its reasons. ``novel_binary`` / ``unknown_binary`` on a normal case means a benign binary the
baseline did not know; the carried-over baseline (rca/baseline_seed.py) should lower that share without changing
attack top-1 (rca evaluate_ranking). Reports the share overall and the binaries behind it.
"""
import argparse, json, time
from collections import Counter
from pathlib import Path


def campaign_span(campaign: Path, margin=60.0):
    starts = [float(json.loads(l)['start_at']) for l in (campaign / 'INTERVALS.jsonl').read_text().splitlines() if l]
    return min(starts) - margin, float(json.loads((campaign / 'TERMINAL.json').read_text())['finished_at_unix']) + margin


def trigger_end(case):
    trigger = next(n['trigger'] for n in case['nodes'] if n['kind'] == 'signal')
    return float(trigger['window_end'])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cases', type=Path, required=True)
    ap.add_argument('--campaign', type=Path, required=True)
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    lo, hi = campaign_span(a.campaign)
    reasons, novel_binaries, stats = Counter(), Counter(), Counter()
    for path in sorted(a.cases.glob('*.json')):
        try:
            case = json.loads(path.read_text())
            end = trigger_end(case)
        except (ValueError, KeyError, StopIteration):
            stats['unreadable'] += 1; continue
        if lo <= end <= hi:
            stats['campaign_span'] += 1; continue
        stats['normal_cases'] += 1
        top = (case.get('suspects') or [None])[0]
        if not top:
            stats['without_suspect'] += 1; continue
        why = set(top.get('reasons') or ())
        for r in why:
            reasons[r] += 1
        if why & {'novel_binary', 'unknown_binary'}:
            stats['top_novel_or_unknown'] += 1
            novel_binaries[top.get('binary')] += 1
    n = stats['normal_cases'] - stats['without_suspect']
    result = dict(schema='rca-suspect-reasons-v1', cases=str(a.cases), campaign=str(a.campaign), stats=dict(stats),
                  share_top_novel_or_unknown=stats['top_novel_or_unknown'] / n if n else None,
                  top_reasons={k: v / n for k, v in reasons.most_common()} if n else {},
                  binaries_behind_novel_or_unknown=novel_binaries.most_common(15), computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(result, indent=1))
    print(json.dumps({k: result[k] for k in ('stats', 'share_top_novel_or_unknown')}), result['binaries_behind_novel_or_unknown'][:6])


if __name__ == '__main__':
    main()
