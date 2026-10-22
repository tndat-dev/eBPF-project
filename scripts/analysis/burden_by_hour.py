#!/usr/bin/env python3
"""Normal alert burden over the run, hour by hour (descriptive; TODO "phân rã theo thời gian").

On a window table (continuous streams, refreshed calibration) counts, per hour since the selection start, the
episodes per replica-hour of k2of2 alpha x10, CUSUM b3/h6 keep and CUSUM b3/h6 cap, on normal rows only (campaign
spans excluded). An episode is attributed to the hour of its first window. Also reports the same split for the
first 90 minutes (selection phase) against the rest, which is where the whole-normal and after-selection burdens
of 5.13b and 5.19 differ.
"""
import argparse, json, sys, time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import burden_levers as bl  # noqa: E402


def episode_starts(ident, end, positive, quiet=bl.EPISODE_QUIET):
    idx = np.flatnonzero(positive)
    if not len(idx):
        return idx
    i, e = ident[idx], end[idx]
    first = np.ones(len(idx), bool)
    first[1:] = (i[1:] != i[:-1]) | (e[1:] - e[:-1] >= quiet)
    return idx[first]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run', required=True, help='name=<n>,table=<npz>,since=<unix>,campaign=<dir>')
    ap.add_argument('--calibration', required=True)
    ap.add_argument('--selection-seconds', type=float, default=5400.0)
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    kv = {}
    for part in a.run.split(','):
        k, v = part.split('=', 1); kv.setdefault(k, []).append(v)
    tree, support = bl.load_calibration(a.calibration)
    since = float(kv['since'][0])
    arr, p, _, info = bl.prepare(kv['table'][0], since, kv['campaign'], tree, support, {})
    x = -np.log(np.maximum(p['joint'], 1e-12))
    rules = {'k2of2_a10': bl.kofn2(p['joint'] <= arr['alpha'] * 10, arr['new']),
             'cusum_b3_h6_keep': bl.cusum_alarms(x - 3.0, arr['new'], 6.0, 'keep'),
             'cusum_b3_h6_cap': bl.cusum_alarms(x - 3.0, arr['new'], 6.0, 'cap')}
    normal = arr['normal']
    hour = np.floor((arr['end'] - since) / 3600).astype(int)
    seconds = arr['end'] - arr['start']
    hours_of = {int(h): float(seconds[normal & (hour == h)].sum()) / 3600 for h in np.unique(hour[normal])}
    sel = arr['end'] < since + a.selection_seconds
    split_hours = dict(selection=float(seconds[normal & sel].sum()) / 3600, rest=float(seconds[normal & ~sel].sum()) / 3600)
    out = {}
    for name, alarm in rules.items():
        starts = episode_starts(arr['ident'], arr['end'], alarm & normal)
        per_hour = {}
        for h, rh in hours_of.items():
            n = int(np.sum(hour[starts] == h))
            per_hour[h] = dict(episodes=n, replica_hours=rh, per_replica_hour=n / rh if rh else None)
        n_sel = int(np.sum(sel[starts]))
        out[name] = dict(per_hour=per_hour,
                         selection_phase=dict(episodes=n_sel, per_replica_hour=n_sel / split_hours['selection'] if split_hours['selection'] else None),
                         after_selection=dict(episodes=int(len(starts) - n_sel),
                                              per_replica_hour=(len(starts) - n_sel) / split_hours['rest'] if split_hours['rest'] else None),
                         whole=dict(episodes=int(len(starts)), per_replica_hour=len(starts) / info['replica_hours']))
    result = dict(schema='pulse-burden-by-hour-v1', run=a.run, split_replica_hours=split_hours, rules=out,
                  computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(result, indent=1))
    print(json.dumps({n: {k: v[k] for k in ('selection_phase', 'after_selection', 'whole')} for n, v in out.items()}))


if __name__ == '__main__':
    main()
