#!/usr/bin/env python3
"""Why an attack trial got no RCA case of its own, and how late exec events reach the RCA; JSON receipt.

The RCA groups the alerts of one container within 300 s into one case and opens a follow-up case only when the exec
log shows a binary that is new for that span. With ``follow_up_audit`` the service writes one line per follow-up
decision: verdict (allowed, binary_not_new, no_exec, too_soon), the alert's window end, and the exec log's latest
entry of that container with the time the exec happened (``at``) and the time the RCA received it (``received``).

For every attack trial (start at or after --since): the audit lines of its container whose window ends inside
[start, start + 20 s], and for each whether the exec log already held the attack binary. A trial is

    own_case             a follow-up was allowed (or the trial opened a first case: no audit line, a case exists)
    exec_missing         every decision was taken while the latest exec was not the attack binary: its exec event had
                         not reached the RCA (late event) or was never observed
    exec_known_refused   the attack binary was the latest exec and the follow-up was still refused (too_soon, not new)
    no_decision          no audit line in the window and no case: the alert never asked for a case

Exec lag = received - at of the latest exec of every audit line, inside and outside --stall spans.

    python3 rca_follow_up.py --audit follow_up_audit.jsonl --cases DIR --campaign DIR --since T --output out.json [--stall A B]
"""
import argparse
from collections import Counter, defaultdict
import glob
import json
from pathlib import Path

WINDOW = 20.0


def quantiles(values):
    v = sorted(values)
    if not v:
        return None
    q = lambda p: v[int(p * (len(v) - 1))]
    return dict(n=len(v), p50=q(.5), p95=q(.95), p99=q(.99), max=v[-1], over_2s=sum(x > 2 for x in v), over_10s=sum(x > 10 for x in v))


def in_spans(t, spans):
    return any(a <= t <= b for a, b in spans)


def case_windows(cases_dir):
    """{identity: [trigger window ends]} of the stored cases."""
    out = defaultdict(list)
    for path in glob.glob(str(Path(cases_dir) / '*.json')):
        doc = json.loads(Path(path).read_text())
        trig = next(n['trigger'] for n in doc['nodes'] if n['kind'] == 'signal')
        out[(trig['node_name'], trig['pod_uid'], trig['container_name'])].append(float(trig['window_end']))
    return out


def classify(lines, binary, has_case):
    if any(d['verdict'] == 'allowed' for d in lines) or (not lines and has_case):
        return 'own_case'
    if not lines:
        return 'no_decision'
    known = [d for d in lines if (d.get('latest_exec') or {}).get('binary') == binary]
    return 'exec_known_refused' if known else 'exec_missing'


def analyse(audit, cases, trials, since, stalls=()):
    by_identity = defaultdict(list)
    for d in audit:
        by_identity[tuple(json.loads(d['identity']))].append(d)
    classes, verdicts, attack_lag, rows = Counter(), Counter(), [], []
    for t in trials:
        start = float(t['start_at'])
        if start < since:
            continue
        ident = (t['node_name'], t['pod_uid'], t['container_name'])
        lines = [d for d in by_identity.get(ident, []) if start <= d['window_end'] <= start + WINDOW]
        has_case = any(start <= w <= start + WINDOW for w in cases.get(ident, []))
        cls = classify(lines, t['binary_path'], has_case)
        classes[cls] += 1
        stalled = in_spans(start, stalls)
        if cls != 'own_case':
            verdicts.update(d['verdict'] for d in lines)
            rows.append(dict(start=start, identity=list(ident), cls=cls, stalled=stalled,
                             decisions=[dict(verdict=d['verdict'], window_end=d['window_end'], latest=(d.get('latest_exec') or {}).get('binary'))
                                        for d in lines]))
        for d in lines:
            e = d.get('latest_exec') or {}
            if e.get('binary') == t['binary_path'] and e.get('received') is not None:
                attack_lag.append(e['received'] - e['at'])
                break
    lag_in, lag_out = [], []
    for d in audit:
        e = d.get('latest_exec') or {}
        if e.get('received') is not None and e.get('at') is not None:
            (lag_in if in_spans(e['received'], stalls) or in_spans(e['at'], stalls) else lag_out).append(e['received'] - e['at'])
    return dict(schema='rca-follow-up-audit-v1', since=since, stalled_spans=[list(s) for s in stalls], attack_trials=sum(classes.values()),
                classes=dict(classes), verdicts_of_trials_without_own_case=dict(verdicts),
                without_own_case_in_stall=sum(r['stalled'] for r in rows),
                audit_lines=len(audit), audit_verdicts=dict(Counter(d['verdict'] for d in audit)),
                exec_lag_seconds=dict(outside_stall=quantiles(lag_out), inside_stall=quantiles(lag_in), attack_binary=quantiles(attack_lag)),
                trials_without_own_case=rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--audit', type=Path, required=True)
    ap.add_argument('--cases', type=Path, required=True)
    ap.add_argument('--campaign', type=Path, required=True)
    ap.add_argument('--since', type=float, default=0.0)
    ap.add_argument('--stall', type=float, nargs=2, action='append', default=[])
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    audit = [json.loads(line) for line in a.audit.read_text().splitlines() if line]
    trials = [json.loads(p.read_text())['attack'] for p in sorted(a.campaign.glob('trials/*/EVALUATION_INPUT.json'))]
    out = analyse(audit, case_windows(a.cases), [t for t in trials if t.get('start_at') is not None], a.since, [tuple(s) for s in a.stall])
    a.output.write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != 'trials_without_own_case'}, indent=1))


if __name__ == '__main__':
    main()
