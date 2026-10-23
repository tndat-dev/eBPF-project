#!/usr/bin/env python3
"""Do the replicas of one workload look alike to Pulse? Per-replica p-values from a run's window table (Pulse 5.25).

On the confirmation run the kafka broker on worker1 was alarming 67.7 % of the time, while the two other brokers,
running the same exec probes, stayed at the level of the rest of the cluster. Calibration is pooled per workload,
so a replica that differs systematically from its peers would get low p-values all the time. This reads the window
table of the run (``sentinel_pulse.attack.window_table``, built by the final stage) and reports, per replica of the
workload:

- scored windows and the share with an exec in the context (``launch``);
- quantiles of tree_p, support_p and joint_p;
- the share of windows flagged by the per-window rule (joint_p <= alpha), split by launch / no launch;
- among flagged windows, which branch gave the smaller p-value (tree or support).

``--exclude START,END`` (unix seconds, repeatable) leaves spans out, e.g. the campaign. Descriptive only: no
threshold, no selection.

    python3 scripts/analysis/replica_compare.py --table table-pulse-stable-confirm.npz \\
        --workload production/aims-kafka-dual-role:kafka --exclude 1792702400,1792733344 --output kafka-replicas.json
"""
import argparse
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.attack.window_table import load  # noqa: E402


def quantiles(v):
    return {f'p{int(q * 100):02d}': float(np.quantile(v, q)) for q in (.05, .25, .5, .75)} if len(v) else None


def share(mask, within=None):
    within = np.ones_like(mask, dtype=bool) if within is None else within
    n = int(within.sum())
    return dict(n=n, share=float(mask[within].mean()) if n else None)


def compare(arrays, meta, workload, exclude=()):
    fields = meta['identity_fields']
    w = meta['workloads'].index(workload)
    keep = arrays['workload'] == w
    for a, b in exclude:
        keep &= ~((arrays['end'] >= a) & (arrays['start'] <= b))
    out = {}
    for i in np.unique(arrays['ident'][keep]):
        ident = dict(zip(fields, meta['identities'][i]))
        m = keep & (arrays['ident'] == i)
        tree, support, joint = arrays['tree_p'][m], arrays['support_p'][m], arrays['joint_p'][m]
        launch = arrays['launch'][m].astype(bool)
        flagged = joint <= arrays['alpha'][m]
        name = f"{ident['node_name']}/{ident['pod_uid'][:8]}"
        out[name] = dict(
            identity=ident, windows=int(m.sum()), launch_share=float(launch.mean()) if m.any() else None,
            tree_p=quantiles(tree), support_p=quantiles(support), joint_p=quantiles(joint),
            flagged=share(flagged), flagged_launch=share(flagged, launch), flagged_no_launch=share(flagged, ~launch),
            preview_share=float(arrays['preview'][m].mean()) if m.any() else None,
            flagged_smaller_branch=dict(tree=int((flagged & (tree < support)).sum()),
                                        support=int((flagged & (support <= tree)).sum())))
    return dict(schema='pulse-replica-compare-v1', workload=workload, excluded=[list(e) for e in exclude],
                table_built_at_unix=meta.get('built_at_unix'), replicas=out)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--table', type=Path, required=True)
    p.add_argument('--workload', required=True)
    p.add_argument('--exclude', action='append', default=[], metavar='START,END')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    arrays, meta = load(a.table)
    result = compare(arrays, meta, a.workload, [tuple(float(x) for x in e.split(',')) for e in a.exclude])
    a.output.write_text(json.dumps(result, indent=1))
    for name, r in result['replicas'].items():
        print(name, r['windows'], 'flagged', r['flagged']['share'], 'launch', r['flagged_launch']['share'],
              'no launch', r['flagged_no_launch']['share'], r['flagged_smaller_branch'])


if __name__ == '__main__':
    main()
