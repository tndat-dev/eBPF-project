#!/usr/bin/env python3
"""session-stream-v1: SESSION.json of the worker's session branch (sentinel_pulse/detector/token_model.TokenBranch).

native_thresholds: each workload's t3 Gumbel fit (FIT.json of token_branch_fit.py) at the branch level; pooled: the one
entry of the pooled session fit (--part session --pool-key); per: the entries of the per-workload session fit, if any.

    python3 session_branch_config.py --fit T3/FIT.json --pooled POOL/MODELS.json [--per PER/MODELS.json] \
        [--branch-alpha 0.00015] --output SESSION.json
"""
import argparse
import json
import math
from pathlib import Path


def build(fit, pooled, per, branch_alpha):
    native = {w: v['gumbel'][0] - v['gumbel'][1] * math.log(-math.log(1 - branch_alpha))
              for w, v in fit['workloads'].items() if v.get('gumbel')}
    if len(pooled) != 1:
        raise ValueError('the pooled session fit must hold exactly one model')
    return dict(schema='session-stream-v1-branch', branch_alpha=branch_alpha, native_thresholds=native,
                pooled=next(iter(pooled.values())), per=per or {})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--fit', type=Path, required=True)
    ap.add_argument('--pooled', type=Path, required=True)
    ap.add_argument('--per', type=Path)
    ap.add_argument('--branch-alpha', type=float, default=0.00015)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    doc = build(json.loads(a.fit.read_text()), json.loads(a.pooled.read_text()),
                json.loads(a.per.read_text()) if a.per else None, a.branch_alpha)
    a.output.write_text(json.dumps(doc, indent=1, sort_keys=True) + '\n')
    print(a.output, len(doc['native_thresholds']), 'native thresholds,', len(doc['per']), 'per-workload session models')


if __name__ == '__main__':
    main()
