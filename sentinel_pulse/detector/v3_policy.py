"""Count branches of lidds-ml-v3 on the cluster: the frozen candidate's tree and support scores, each against its own
per-workload threshold (moment-Gumbel on per-container time-block maxima of a normal validation span, alpha / 3,
scripts/analysis/count_branch_fit.py). One window above either threshold fires, as in lidds-ml-v3; the token branch
(token_model.TokenBranch) fires on its own windows, so the system alarm is any of the three.

The tree score enters as its logit (lidds_ml_v2 transform 'tree_plain': clip to [1e-4, 1 - 1e-4]), the support
score as it is.
"""
from __future__ import annotations

import json
import math
from pathlib import Path


def tree_logit(p: float) -> float:
    c = min(max(float(p), 1e-4), 1 - 1e-4)
    return math.log(c / (1 - c))


class CountBranches:
    def __init__(self, path: Path, sha256: str, sha256_file):
        if sha256_file(path) != sha256:
            raise ValueError('count-branch thresholds changed')
        doc = json.loads(Path(path).read_text())
        if doc.get('schema') != 'pulse-v3-count-thresholds-v1':
            raise ValueError('not a v3 count-threshold document')
        self.thresholds = {k: (float(v['tree']), float(v['support'])) for k, v in doc['workloads'].items()}
        # shadow (protocol lidds-ml-v5): the branches are computed and logged for the report, but do not alert
        self.shadow = doc.get('shadow') is True
        if not all(math.isfinite(t) and math.isfinite(s) for t, s in self.thresholds.values()):
            raise ValueError('non-finite count threshold')

    def apply(self, decision: dict):
        """Fields to add to a scored decision, or None (no score or no threshold for its workload)."""
        if decision.get('status') != 'candidate-raw-score-only':
            return None
        got = self.thresholds.get(decision.get('workload_key'))
        if got is None:
            return None
        tree = tree_logit(decision['tree_score']) > got[0]
        support = float(decision['support_score']) > got[1]
        return dict(v3_tree_alert=bool(tree), v3_support_alert=bool(support),
                    policy_alert_preview=decision.get('candidate_alert_preview'),
                    candidate_alert_preview=bool(tree or support) and not self.shadow, branch='counts')
