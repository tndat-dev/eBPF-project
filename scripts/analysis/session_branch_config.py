#!/usr/bin/env python3
"""session-stream-v1: SESSION.json of the worker's session branch (sentinel_pulse/detector/token_model.TokenBranch).

native_thresholds: each workload's t3 Gumbel fit (FIT.json of token_branch_fit.py) at the branch level; pooled: the one
entry of the pooled session fit (--part session --pool-key); per: the entries of the per-workload session fit, if any.
improvement-round-2 A6 (--alpha-scale {workload: factor}, improvement_round2.py a6): a workload's native threshold is
at branch alpha x min(1, factor).

    python3 session_branch_config.py --fit T3/FIT.json --pooled POOL/MODELS.json [--per PER/MODELS.json] \
        [--branch-alpha 0.00015] [--alpha-scale a6-scale.json] --output SESSION.json
"""
import argparse
import json
import math
from pathlib import Path


def build(fit, pooled, per, branch_alpha, scale=None):
    scale = scale or {}
    level = lambda w: branch_alpha * min(1.0, float(scale.get(w, 1.0)))
    native = {w: v['gumbel'][0] - v['gumbel'][1] * math.log(-math.log(1 - level(w)))
              for w, v in fit['workloads'].items() if v.get('gumbel')}
    if len(pooled) != 1:
        raise ValueError('the pooled session fit must hold exactly one model')
    doc = dict(schema='session-stream-v1-branch', branch_alpha=branch_alpha, native_thresholds=native,
               pooled=next(iter(pooled.values())), per=per or {})
    if scale:
        doc['alpha_scale'] = {w: float(v) for w, v in sorted(scale.items())}
    return doc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--fit', type=Path, required=True)
    ap.add_argument('--pooled', type=Path, required=True)
    ap.add_argument('--per', type=Path)
    ap.add_argument('--branch-alpha', type=float, default=0.00015)
    ap.add_argument('--alpha-scale', type=Path, help='improvement-round-2 A6: {workload: factor}')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    doc = build(json.loads(a.fit.read_text()), json.loads(a.pooled.read_text()),
                json.loads(a.per.read_text()) if a.per else None, a.branch_alpha,
                json.loads(a.alpha_scale.read_text()) if a.alpha_scale else None)
    a.output.write_text(json.dumps(doc, indent=1, sort_keys=True) + '\n')
    print(a.output, len(doc['native_thresholds']), 'native thresholds,', len(doc['per']), 'per-workload session models')


if __name__ == '__main__':
    main()
