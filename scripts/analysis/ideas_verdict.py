#!/usr/bin/env python3
"""Verdict of the blind check registered in Pulse 5.11a (21/10 11:32) for the frozen screen methods.

Inputs: ``ideas_screen.py`` on the new campaign (interval rates, p95) and ``ideas_burden.py`` on the new
run's whole normal (episodes per replica-hour). A method is "better" than the running rule (joint + k2of2,
alpha x10) when, as registered:

  (a) burden <= 0.9 x reference, attack rate >= reference - 0.01, idle-control rate <= reference and
      p95 <= reference + 0.2 s; or
  (b) p95 <= reference - 0.2 s and burden <= reference.

Otherwise "not better". No parameter is chosen here; the parameters were frozen before the run existed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

FROZEN = {'cauchy': ('cauchy_a10', 'cauchy_k2of2_a10'), 'cusum': ('cusum_b3_h6', 'cusum_b3_h6')}
REFERENCE = ('joint_a10', 'joint_k2of2_a10')


def verdict(ref: dict, alt: dict) -> dict:
    """``ref`` / ``alt``: dict(attack, control, p95, burden)."""
    a = (alt['burden'] <= 0.9 * ref['burden'] and alt['attack'] >= ref['attack'] - 0.01
         and alt['control'] <= ref['control'] and alt['p95'] <= ref['p95'] + 0.2)
    b = alt['p95'] <= ref['p95'] - 0.2 and alt['burden'] <= ref['burden']
    return dict(better=bool(a or b), clause_a=bool(a), clause_b=bool(b))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--screen', required=True); p.add_argument('--burden', required=True); p.add_argument('--output', required=True)
    a = p.parse_args()
    screen, burden = json.loads(Path(a.screen).read_text()), json.loads(Path(a.burden).read_text())
    if screen['chosen'] != {'joint': REFERENCE[0], **{m: n for m, (n, _) in FROZEN.items()}}:
        raise SystemExit(f"development selection changed: {screen['chosen']} (frozen 21/10: cauchy_a10, cusum_b3_h6)")

    def row(names):
        s, b = screen['test_grid'][names[0]], burden['methods'][names[1]]
        return dict(attack=s['attack'], benign=s['benign'], control=s['control'], p50=s['p50'], p95=s['p95'],
                    burden=b['episodes_per_replica_hour'])
    ref = row(REFERENCE)
    out = dict(schema='pulse-ideas-verdict-v1', registered='SENTINEL_PULSE_STATUS 5.11a, 21/10 11:32', reference=ref,
               methods={m: dict(row(names), **verdict(ref, row(names))) for m, names in FROZEN.items()},
               screen=a.screen, burden=a.burden, scored_replica_hours=burden['scored_replica_hours'])
    Path(a.output).write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
