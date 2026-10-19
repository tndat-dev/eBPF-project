#!/usr/bin/env python3
"""Hypothesis check: does "a syscall ID never seen in this workload's normal" separate attacks from
a benign new process?

Normal reference: union of syscall IDs (full_counts_delta keys) per workload over an attack-free
span of the capture. For every campaign interval (attack / benign-launch / idle control) the IDs
seen in its 15 s that are absent from the reference are listed. Reports, per scenario and label,
the share of intervals with at least one novel ID and the most frequent novel IDs. Development
evidence: the same R6 capture supplies reference and intervals (disjoint time spans).
"""
import argparse, collections, glob, json, time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--workers-root', required=True)
p.add_argument('--campaign', action='append', required=True)
p.add_argument('--reference-span', required=True, help='START:END unix seconds (attack-free)')
p.add_argument('--output', required=True)
a = p.parse_args()
ref_lo, ref_hi = (float(x) for x in a.reference_span.split(':'))

trials = []
for campaign in a.campaign:
    for path in sorted(glob.glob(campaign + '/trials/*/EVALUATION_INPUT.json')):
        d = json.loads(Path(path).read_text())
        for label in ('control', 'benign', 'attack'):
            if label in d:
                t = d[label]
                trials.append(dict(label=label, scenario=d['attack']['scenario'], workload=t['workload_key'],
                                   ident=(t['node_name'], str(t['pod_uid']), str(t['cgroup_id'])),
                                   start=float(t['start_at']), end=float(t['start_at']) + 15))
by_ident = collections.defaultdict(list)
for t in trials:
    by_ident[t['ident']].append(t)
t_lo = min(t['start'] for t in trials); t_hi = max(t['end'] for t in trials)

reference = collections.defaultdict(set)
seen = collections.defaultdict(set)          # trial index -> IDs
index = {id(t): i for i, t in enumerate(trials)}
rows = 0
for seg in sorted(glob.glob(a.workers_root + '/*/segments/s*/features.jsonl')):
    if not (Path(seg).parent/'TERMINAL.json').exists():
        continue
    with open(seg) as stream:
        for line in stream:
            if '"full_counts_delta"' not in line:
                continue
            row = json.loads(line); end = float(row['window_end']); rows += 1
            if ref_lo <= row['window_start'] and end <= ref_hi:
                reference[row['workload_key']].update(row['full_counts_delta'])
            elif t_lo <= end <= t_hi:
                for t in by_ident.get((row['node_name'], str(row['pod_uid']), str(row['cgroup_id'])), ()):
                    if t['start'] <= row['window_start'] and end <= t['end']:
                        seen[index[id(t)]].update(row['full_counts_delta'])

stats = collections.defaultdict(lambda: collections.Counter()); novel_ids = collections.defaultdict(collections.Counter)
missing_reference = set()
for i, t in enumerate(trials):
    if i not in seen:
        stats[(t['scenario'], t['label'])]['no_windows'] += 1; continue
    ref = reference.get(t['workload'])
    if not ref:
        missing_reference.add(t['workload']); stats[(t['scenario'], t['label'])]['no_reference'] += 1; continue
    novel = seen[i] - ref
    stats[(t['scenario'], t['label'])]['novel' if novel else 'none'] += 1
    novel_ids[(t['scenario'], t['label'])].update(novel)
table = {}
for (scenario, label), c in sorted(stats.items()):
    n = c['novel'] + c['none']
    table.setdefault(scenario, {})[label] = dict(intervals=n, with_novel_id=c['novel'], share=c['novel'] / n if n else None,
                                                 skipped=dict(no_windows=c['no_windows'], no_reference=c['no_reference']),
                                                 top_novel_ids=novel_ids[(scenario, label)].most_common(6))
overall = collections.Counter()
for (scenario, label), c in stats.items():
    overall[label + ':novel'] += c['novel']; overall[label + ':none'] += c['none']
result = dict(schema='pulse-novel-syscall-hypothesis-v1', workers_root=a.workers_root, campaigns=a.campaign,
              reference_span_unix=[ref_lo, ref_hi], feature_rows_read=rows,
              reference_ids_per_workload={w: len(v) for w, v in sorted(reference.items())},
              workloads_without_reference=sorted(missing_reference),
              by_scenario=table,
              overall={label: overall[label + ':novel'] / max(1, overall[label + ':novel'] + overall[label + ':none'])
                       for label in ('attack', 'benign', 'control')},
              note='development; syscall IDs are x86-64 numbers; a novel ID is absent from the workload reference set',
              computed_at_unix=time.time())
json.dump(result, open(a.output, 'w'), indent=2)
print(json.dumps(dict(overall=result['overall'], by_scenario={s: {l: v['share'] for l, v in d.items()} for s, d in table.items()})))
