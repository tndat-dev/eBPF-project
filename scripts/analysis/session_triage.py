#!/usr/bin/env python3
"""session-stream-v1 S3: a learnt triage of the session alarms of the deployed model (label only, never a suppression).

Input: the interval_rows of session_stream.py (one per campaign interval of the H0 pairs; for each interval that the
deployed model flags, the session events of its alarm windows: calls by system-call number, error tokens, windows).
Rows used: flagged intervals with session events. Positives: fixture attacks, the living-off-the-land step, event-
generator actions; negatives: operator commands and the harmless binary. Features: share of each system call among
the session events, share of error tokens, log(1 + alarm windows). Model: L2 logistic regression (C = 1, balanced
classes). Operating point: the score that passes 5 % of the training negatives.

Leave-one-family-out on the training run (family: fixture scenario, 'lotl', each event-generator action, each operator
command, 'benign'), then one model on every family of the training run tested on another run (--test).

    python3 session_triage.py --train FINAL/session-stream.json [--test V6/session-features.json] --output out.json
"""
# S3: phân loại học được cho cảnh báo của dòng session (chỉ gắn nhãn, không bỏ cảnh báo); kiểm bằng bỏ-một-họ và chéo lượt.
import argparse
import json
import math
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression

POSITIVE, NEGATIVE = ('attack', 'lotl', 'eventgen'), ('admin', 'benign')
PASS_NEGATIVES = 0.05


def rows_of(path):
    doc = json.loads(Path(path).read_text())
    return [r for r in doc['interval_rows'] if r['s0'] and r['session_events'] > 0 and not r['pad']
            and r['label'] in POSITIVE + NEGATIVE]


def matrix(rows, calls):
    x = np.zeros((len(rows), len(calls) + 2))
    for i, r in enumerate(rows):
        for c, v in r['calls'].items():
            if c in calls:
                x[i, calls[c]] = v / r['session_events']
        x[i, -2] = r['error_events'] / r['session_events']
        x[i, -1] = math.log1p(r['alarm_windows'])
    return x


def fit(rows):
    calls = {c: i for i, c in enumerate(sorted({c for r in rows for c in r['calls']}, key=int))}
    y = np.array([r['label'] in POSITIVE for r in rows], int)
    model = LogisticRegression(C=1.0, class_weight='balanced', max_iter=5000).fit(matrix(rows, calls), y)
    neg = model.decision_function(matrix([r for r in rows if r['label'] in NEGATIVE], calls))
    cut = float(np.quantile(neg, 1 - PASS_NEGATIVES))
    return model, calls, cut


def passed(model, calls, cut, rows):
    return (model.decision_function(matrix(rows, calls)) > cut) if rows else np.zeros(0, bool)


def lofo(rows):
    out = {}
    for fam in sorted({(r['label'], r['family']) for r in rows}):
        held = [r for r in rows if (r['label'], r['family']) == fam]
        model, calls, cut = fit([r for r in rows if (r['label'], r['family']) != fam])
        p = passed(model, calls, cut, held)
        out[f'{fam[0]}:{fam[1]}'] = dict(label=fam[0], n=len(held), passed=int(p.sum()), share=float(p.mean()))
    return out


def summary(per_family):
    pos = [v for v in per_family.values() if v['label'] in POSITIVE]
    neg = [v for v in per_family.values() if v['label'] in NEGATIVE]
    neg_share = sum(v['passed'] for v in neg) / max(1, sum(v['n'] for v in neg))
    return dict(min_attack_family=min(v['share'] for v in pos), negatives_passed=neg_share,
                passes=min(v['share'] for v in pos) >= 0.90 and neg_share <= 0.20)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--train', type=Path, required=True)
    ap.add_argument('--test', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    rows = rows_of(a.train)
    per = lofo(rows)
    doc = dict(schema='session-stream-v1-s3', train=str(a.train), rows=len(rows), lofo=per, lofo_summary=summary(per))
    if a.test:
        model, calls, cut = fit(rows)
        test = rows_of(a.test)
        res = {}
        for group, labels in (('attacks', ('attack', 'lotl')), ('benign', NEGATIVE)):
            sub = [r for r in test if r['label'] in labels]
            p = passed(model, calls, cut, sub)
            res[group] = dict(n=len(sub), passed=int(p.sum()), share=float(p.mean()) if len(sub) else None)
        res['passes'] = bool((res['attacks']['share'] or 0) >= 0.95 and (res['benign']['share'] or 1) <= 0.20)
        doc.update(test=str(a.test), cross_run=res)
    doc['adopt_as_label'] = bool(doc['lofo_summary']['passes'] and doc.get('cross_run', {}).get('passes', False))
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps(dict(lofo=doc['lofo_summary'], cross_run=doc.get('cross_run'), adopt=doc['adopt_as_label'])))


if __name__ == '__main__':
    main()
