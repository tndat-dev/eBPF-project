#!/usr/bin/env python3
"""Why attack trials do or do not get their own RCA case; JSON receipt.

For each attack trial starting at or after --since: a case on the same node/pod/container whose
trigger window ends within [start, start+20 s] counts as the attack's case; otherwise the trial is
classified as grouped by an earlier case (cooldown), expired by retention, or without a case.
Also reports the rank of the fixture binary among stored suspects, flow presence and
preview->case latency. Ranking with a corrected baseline is rca.evaluate_ranking --rerank-db.
"""
import argparse, glob, json, statistics, time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cases', required=True); p.add_argument('--campaign', required=True)
p.add_argument('--since', type=float, default=0.0); p.add_argument('--output', required=True)
a = p.parse_args()
cases = []
for path in glob.glob(a.cases + '/*.json'):
    t = json.load(open(path)); trig = next(n['trigger'] for n in t['nodes'] if n['kind'] == 'signal')
    cases.append((float(trig['window_end']), (trig['node_name'], trig['pod_uid'], trig['container_name']), t, trig))
cases.sort(key=lambda c: c[0])
first = cases[0][0] if cases else float('inf')
classes, ranks, latency, flow, follow = {}, [], [], 0, 0
for path in sorted(glob.glob(a.campaign + '/trials/*/EVALUATION_INPUT.json')):
    d = json.load(open(path)); at = d['attack']; start = float(at['start_at'])
    if start < a.since: continue
    ident = (at['node_name'], at['pod_uid'], at['container_name'])
    match = next(((w, t, trig) for w, i, t, trig in cases if i == ident and start <= w <= start + 20), None)
    if match:
        w, t, trig = match; key = 'attack_case'
        ranks.append(next((s['rank'] for s in t.get('suspects', []) if s.get('binary') == at['binary_path']), None))
        flow += bool(t.get('matched_flow_events')); follow += bool(trig.get('follow_up_of'))
        latency.append(t['created_at'] - float(trig.get('preview_emitted_at') or w))
    elif start - 300 < first:
        key = 'case_expired_by_retention'
    elif d.get('benign') and any(i == ident and float(d['benign']['start_at']) <= w < start for w, i, _, _ in cases):
        key = 'grouped_after_benign_case'
    elif any(i == ident and start - 300 <= w < start for w, i, _, _ in cases):
        key = 'grouped_after_other_case'
    else:
        key = 'no_case'
    classes[key] = classes.get(key, 0) + 1
n = len(ranks)
result = dict(schema='rca-campaign-coverage-v1', cases_dir=a.cases, campaign=a.campaign, since_unix=a.since,
              trials=sum(classes.values()), classes=classes, attack_cases=n, follow_up_attack_cases=follow,
              stored_rank_top1=sum(r == 1 for r in ranks) / n if n else None,
              stored_rank_top5=sum(r is not None and r <= 5 for r in ranks) / n if n else None,
              cases_with_flow=flow,
              preview_to_case_seconds=dict(p50=statistics.median(latency), p95=sorted(latency)[max(0, int(.95*len(latency))-1)]) if latency else None,
              computed_at_unix=time.time())
json.dump(result, open(a.output, 'w'), indent=2); print(json.dumps(result))
