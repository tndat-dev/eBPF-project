#!/usr/bin/env python3
"""pulse-live-final-v1 'reported': burden episodes of the normal tail labelled by stream and by Kubernetes events (D10).

Episodes as burden_context.py (token arm T alarms per container, merged when < 15 s apart, normal span outside the
selection prefix and the campaign). Stream of an episode: session when every alarm window in it has session events and
no native ones, native when none has session events, mixed otherwise. Kubernetes label: an operational event of the same
workload (pod or controller name prefix) recorded in [start - 300 s, end + 60 s]; reasons kept: rollout, scaling,
restart, probe and operator updates (not secret-store validation, policy reports or RabbitMQ object declarations).
"""
import argparse, collections, datetime, json, sys
from pathlib import Path
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
import pulse_live_v4 as live
import burden_context as bc

OPS = {'ScalingReplicaSet', 'SuccessfulRescale', 'Killing', 'Scheduled', 'Pulled', 'Created', 'Started', 'Unhealthy',
       'SuccessfulCreate', 'SuccessfulDelete', 'SuccessfulUpdate', 'BackOff', 'Failed', 'Evicted', 'Preempted'}
BEFORE, AFTER = 300.0, 60.0


def ts(r):
    v = r.get('last') or r.get('first')
    return datetime.datetime.fromisoformat(v.replace('Z', '+00:00')).timestamp() if v else r['recorded_at']


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--run-root', type=Path, required=True); ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); root = a.run_root
    cfg = json.loads((root / 'CONFIG.json').read_text())
    normal = (float(cfg['selection_end']), float(cfg['selection_start']) + float(cfg['seconds']))
    spans = [live.campaign_span(root / live.CAMPAIGN)]
    keep = lambda t: normal[0] <= t < normal[1] and not live.in_spans(t, spans)
    alarms, workload_of = collections.defaultdict(list), {}
    for seg in sorted({p.parent for p in root.glob('workers/*/segments/*/decisions.jsonl*')}):
        with live.open_sealed(seg / 'decisions.jsonl') as f:
            for line in f:
                row = json.loads(line)
                end = row.get('window_end')
                if 'T' not in live.arms_of(row) or end is None or not keep(end):
                    continue
                key = (row['pod_uid'], row['container_name']); workload_of[key] = row['workload_key']
                ev, se = row.get('events') or 0, row.get('session_events') or 0
                alarms[key].append((end, se > 0, ev - se > 0))
    events = [r for r in map(json.loads, open(root / 'k8s-events.jsonl')) if r['namespace'] == 'production' and r['reason'] in OPS]
    last_recorded = max(json.loads(l)['recorded_at'] for l in open(root / 'k8s-events.jsonl'))
    eps = []
    for key, rows in alarms.items():
        rows.sort(); times = [r[0] for r in rows]
        for start, end in bc.episodes(times):
            inside = [r for r in rows if start <= r[0] <= end]
            sess, nat = any(r[1] for r in inside), any(r[2] for r in inside)
            stream = 'mixed' if sess and nat else 'session' if sess else 'native'
            w = workload_of[key]; base = w.split('/')[1].split(':')[0]
            near = sorted({e['reason'] for e in events if (e['name'].startswith(base) or base.startswith(e['name']))
                           and start - BEFORE <= ts(e) <= end + AFTER})
            eps.append(dict(workload=w, start=start, end=end, stream=stream, k8s=near, recorded=start <= last_recorded))
    by_stream = collections.Counter(e['stream'] for e in eps)
    labelled = [e for e in eps if e['k8s']]
    doc = dict(schema='pulse-live-final-v1-burden-labels', run=cfg['run_id'], window_before=BEFORE, window_after=AFTER,
               reasons=sorted(OPS), k8s_recorded_until=last_recorded, episodes=len(eps),
               by_stream=dict(by_stream), k8s_labelled=len(labelled),
               k8s_by_reason=dict(collections.Counter(r for e in labelled for r in e['k8s'])),
               k8s_by_workload=dict(collections.Counter(e['workload'] for e in labelled)),
               after_k8s_record_end=sum(not e['recorded'] for e in eps),
               stream_of_labelled=dict(collections.Counter(e['stream'] for e in labelled)),
               episodes_list=sorted(eps, key=lambda e: e['start']))
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps({k: v for k, v in doc.items() if k != 'episodes_list'}))


if __name__ == '__main__':
    main()
