#!/usr/bin/env python3
"""Apply ``rules_per_component`` of protocol feature-group-evaluation-v1 to arm_budget + arm_bootstrap outputs.

Components are the registered arms (drop_*, bins_only, history1/2) and the p-value variants base29@tree /
base29@support, each compared with base29 (the bootstrap's paired differences). One ``--set NAME=RESULTS,BOOTSTRAP``
per attack set; the rule names pulse-live-recalibrated for the separation clause. Rules (verbatim intent):

- needed: recall CI entirely below 0 on every set, OR separation CI entirely below 0 on pulse-live-recalibrated,
  OR p95 delay worse by >= 0.2 s on every set;
- removable: recall one-sided lower bound > -0.03 on every set AND separation lower bound > -0.03 AND p95 not
  worse by > 0.2 s on any set;
- inconclusive: neither. Applied at budget 1; at budget 5 when base29 has no matched scale at 1.

With fewer sets than v1 registered (two), the verdict is marked provisional.
"""
import argparse
import json
from pathlib import Path

COMPONENTS = ('drop_log_counts', 'drop_ratios', 'drop_aggregates', 'drop_syscall_bins', 'drop_transition_bins',
              'drop_rolling', 'drop_all_bins', 'bins_only', 'history1', 'history2', 'base29@tree', 'base29@support')


def budget_for(results, boot):
    for b in ('1', '5'):
        if results['matched_budget'].get(b, {}).get('base29') and 'base29' in boot['budgets'].get(b, {}):
            return b
    return None


def verdict(sets, live='pulse-live-recalibrated'):
    out = {}
    for comp in COMPONENTS:
        rows = {}
        for name, (results, boot) in sets.items():
            b = budget_for(results, boot)
            arm = boot['budgets'].get(b, {}).get(comp) if b else None
            mine, ref = results['matched_budget'][b].get(comp) if b else None, results['matched_budget'][b]['base29'] if b else None
            if not arm or not mine:
                rows[name] = dict(budget=b, available=False); continue
            p95 = (mine['delay_p95'] - ref['delay_p95']) if mine.get('delay_p95') is not None and ref.get('delay_p95') is not None else None
            rows[name] = dict(budget=b, available=True, recall_diff=arm['recall_diff'], separation_diff=arm['separation_diff'],
                              p95_diff_seconds=p95)
        avail = [r for r in rows.values() if r.get('available')]
        if not avail:
            out[comp] = dict(verdict='not_evaluated', sets=rows); continue
        live_row = rows.get(live) if rows.get(live, {}).get('available') else None
        needed = (all(r['recall_diff']['ci95'][1] < 0 for r in avail)
                  or (live_row is not None and live_row['separation_diff']['ci95'][1] < 0)
                  or all(r['p95_diff_seconds'] is not None and r['p95_diff_seconds'] >= 0.2 for r in avail))
        removable = (all(r['recall_diff']['lower95_one_sided'] > -0.03 for r in avail)
                     and all(r['separation_diff']['lower95_one_sided'] > -0.03 for r in avail)
                     and all(r['p95_diff_seconds'] is None or r['p95_diff_seconds'] <= 0.2 for r in avail))
        v = 'needed' if needed else ('removable' if removable else 'inconclusive')
        out[comp] = dict(verdict=v, provisional=len(avail) < 2, sets=rows)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--set', action='append', required=True, help='NAME=RESULTS.json,BOOTSTRAP.json')
    p.add_argument('--output', required=True)
    a = p.parse_args()
    sets = {}
    for item in a.set:
        name, files = item.split('=', 1)
        r, b = files.split(',')
        sets[name] = (json.loads(Path(r).read_text()), json.loads(Path(b).read_text()))
    v = verdict(sets)
    Path(a.output).write_text(json.dumps(dict(schema='pulse-feature-group-verdict-v1',
                                              protocol='sentinel_pulse/protocol/feature-group-evaluation-v1.json',
                                              sets=list(sets), components=v), indent=1))
    for comp, r in v.items():
        cells = []
        for name, s in r['sets'].items():
            if s.get('available'):
                cells.append(f"{name}@{s['budget']}: rec {s['recall_diff']['point']:+.3f} [{s['recall_diff']['ci95'][0]:+.3f},{s['recall_diff']['ci95'][1]:+.3f}]"
                             f" sep {s['separation_diff']['point']:+.3f} [{s['separation_diff']['ci95'][0]:+.3f},{s['separation_diff']['ci95'][1]:+.3f}]"
                             f" p95 {s['p95_diff_seconds'] if s['p95_diff_seconds'] is None else round(s['p95_diff_seconds'], 2)}")
        print(f"{comp:22s} {r['verdict']:13s}{' (provisional)' if r.get('provisional') else ''} | " + ' | '.join(cells))


if __name__ == '__main__':
    main()
