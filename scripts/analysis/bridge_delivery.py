#!/usr/bin/env python3
"""Did every alert episode of the bridge reach Alertmanager, and how fast; JSON receipt.

Episodes (episodes.jsonl, event start) against the alerts Alertmanager sent back on the push path (deliveries.jsonl):
delivered or not, inside and outside --stall spans, and the time from the decision (preview_emitted_at) to the receipt.
Standard library only.

    python3 bridge_delivery.py --bridge DIR --output out.json [--stall A B]
"""
import argparse
import json
from pathlib import Path


def quantiles(values):
    v = sorted(values)
    if not v:
        return None
    q = lambda p: v[int(p * (len(v) - 1))]
    return dict(n=len(v), p50=q(.5), p95=q(.95), p99=q(.99), max=v[-1])


def analyse(episodes, deliveries, stalls=()):
    starts = {e['episode']: e for e in episodes if e['event'] == 'start'}
    got = {d['episode']: d['received_at'] for d in deliveries if d['path'] == 'push'}
    stalled = lambda e: any(a <= e['preview_emitted_at'] <= b for a, b in stalls)
    out = {}
    for name, keep in (('outside_stall', lambda e: not stalled(e)), ('inside_stall', stalled)):
        members = {k: e for k, e in starts.items() if keep(e)}
        delays = [got[k] - e['preview_emitted_at'] for k, e in members.items() if k in got]
        out[name] = dict(episodes=len(members), delivered=len(delays), not_delivered=len(members) - len(delays),
                         decision_to_receipt_seconds=quantiles(delays))
    return dict(schema='bridge-delivery-v1', episodes=len(starts), stalled_spans=[list(s) for s in stalls], **out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bridge', type=Path, required=True)
    ap.add_argument('--stall', type=float, nargs=2, action='append', default=[])
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    rows = lambda name: [json.loads(line) for line in (a.bridge / name).read_text().splitlines() if line]
    out = analyse(rows('episodes.jsonl'), rows('deliveries.jsonl'), [tuple(s) for s in a.stall])
    a.output.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
