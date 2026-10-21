#!/usr/bin/env python3
"""Normal alert burden broken down by workload (and node) from confirmation_study ``normal`` outputs.

Input: the per-node ``normal-<calibration>-<grid>-<node>.json`` files of one evaluation span (they carry
episodes, positive windows and scored replica-hours per workload for every policy). Output, per policy and
calibration: episodes per replica-hour for each workload (nodes pooled and per node), the share of all
episodes from the top workloads, and positive windows per episode (how long a normal "alert" lasts).
Labels are unadjudicated normal: positives are not confirmed false positives.
"""
import argparse, collections, glob, json, re, time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--inputs', required=True, help='directory with normal-<cal>-<grid>-<node>.json')
p.add_argument('--policy', action='append', default=None, help='policy names (default: k1of1_a3, k2of2_a5, k2of2_a10)')
p.add_argument('--output', required=True)
a = p.parse_args()
policies = a.policy or ['k1of1_a3', 'k2of2_a5', 'k2of2_a10']

# (calibration, policy) -> workload -> node -> [episodes, positive windows, replica-hours]
cells = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0, 0.0])))
sources = {}
for path in sorted(glob.glob(f'{a.inputs}/normal-*.json')):
    # normal-<calibration>-<grid>-<node>.json (job chọn 20/10) or normal-<calibration>-<node>.json (final stage 21/10)
    m = re.match(r'normal-(asrun|refreshed)-(?:(default|looser|latency3s)-)?(k8s-.+)\.json', Path(path).name)
    if not m:
        continue
    cal, grid, node = m.groups()
    d = json.loads(Path(path).read_text())
    sources[Path(path).name] = dict(since=d['since_unix'], until=d['until_unix'], total_scored_hours=d['total_scored_hours'])
    for name in policies:
        pol = d['policies'].get(name)
        if pol is None:
            continue
        key = (cal, name)
        if key in cells and any(node in v for v in cells[key].values()):
            continue          # the same policy appears in both grids; count it once per node
        for w, hours in d['scored_hours'].items():
            c = cells[key][w][node.split('.')[0]]
            c[0] += pol['episodes'].get(w, 0); c[1] += pol['positive_windows'].get(w, 0); c[2] += hours

report = {}
for (cal, name), by_w in sorted(cells.items()):
    rows, total_ep, total_h = [], 0, 0.0
    for w, by_node in by_w.items():
        ep = sum(v[0] for v in by_node.values()); pw = sum(v[1] for v in by_node.values()); h = sum(v[2] for v in by_node.values())
        total_ep += ep; total_h += h
        rows.append(dict(workload=w, episodes=ep, replica_hours=round(h, 2), episodes_per_replica_hour=ep / h if h else None,
                         positive_windows_per_episode=pw / ep if ep else None,
                         per_node={n: dict(episodes=v[0], replica_hours=round(v[2], 2),
                                           episodes_per_replica_hour=v[0] / v[2] if v[2] else None)
                                   for n, v in sorted(by_node.items())}))
    rows.sort(key=lambda r: -r['episodes'])
    share = lambda k: sum(r['episodes'] for r in rows[:k]) / total_ep if total_ep else None
    report.setdefault(cal, {})[name] = dict(total_episodes=total_ep, total_replica_hours=round(total_h, 2),
        episodes_per_replica_hour=total_ep / total_h if total_h else None,
        share_of_episodes_top3=share(3), share_of_episodes_top5=share(5),
        workloads_with_zero_episodes=[r['workload'] for r in rows if r['episodes'] == 0], workloads=rows)

out = dict(schema='pulse-burden-by-workload-v1', inputs=a.inputs, sources=sources, policies=policies,
           labels='unadjudicated normal; positives are not confirmed false positives', calibrations=report,
           computed_at_unix=time.time())
Path(a.output).write_text(json.dumps(out, indent=2))
for cal, pols in report.items():
    for name, r in pols.items():
        print(f"== {cal} {name}: {r['episodes_per_replica_hour']:.2f} ep/replica-h, top3 {r['share_of_episodes_top3']:.0%}, top5 {r['share_of_episodes_top5']:.0%}")
        for row in r['workloads'][:8]:
            nodes = ' '.join(f"{n.replace('k8s-','')}={v['episodes_per_replica_hour']:.1f}" for n, v in row['per_node'].items()
                             if v['episodes_per_replica_hour'] is not None)
            print(f"   {row['workload'].replace('production/',''):48s} {row['episodes']:5d} ep {row['episodes_per_replica_hour']:6.2f}/rh "
                  f"{(row['positive_windows_per_episode'] or 0):5.1f} win/ep  [{nodes}]")
