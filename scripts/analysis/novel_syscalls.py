#!/usr/bin/env python3
"""Hypothesis check: does "a syscall ID never seen in this workload's normal" separate attacks from
a benign new process?

Normal reference: union of syscall IDs (full_counts_delta keys) per workload over an attack-free
span of the capture. For every campaign interval (attack / benign-launch / idle control) the IDs
seen in its 15 s that are absent from the reference are listed. Reports, per scenario and label,
the share of intervals with at least one novel ID and the most frequent novel IDs. Development
evidence: the same pulse-live-recalibrated capture supplies reference and intervals (disjoint time spans).

``--exec-set`` (section 5.7c, exec-aware novelty): a JSON list of syscall IDs produced by the exec
mechanism itself; those IDs never count as novel. The output lists every novel ID per label
(``novel_ids_by_label``), from which the frozen exec set is the benign-launch union.
Segment files may be plain or seal-verified gzip (``features.jsonl.gz``).
"""
import argparse, collections, glob, gzip, json, time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--workers-root', required=True)
p.add_argument('--campaign', action='append', required=True)
p.add_argument('--reference-span', required=True, help='START:END unix seconds (attack-free)')
p.add_argument('--exec-set', help='JSON list of syscall IDs from the exec mechanism; never novel')
p.add_argument('--output', required=True)
a = p.parse_args()
ref_lo, ref_hi = (float(x) for x in a.reference_span.split(':'))
exec_set = {str(x) for x in json.loads(Path(a.exec_set).read_text())} if a.exec_set else set()

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
for terminal in sorted(glob.glob(a.workers_root + '/*/segments/s*/TERMINAL.json')):
    seg = Path(terminal).parent/'features.jsonl'
    opener = (lambda: open(seg)) if seg.exists() else (lambda: gzip.open(str(seg) + '.gz', 'rt'))
    if not seg.exists() and not Path(str(seg) + '.gz').exists():
        continue
    with opener() as stream:
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
all_novel = collections.defaultdict(collections.Counter)
for i, t in enumerate(trials):
    if i not in seen:
        stats[(t['scenario'], t['label'])]['no_windows'] += 1; continue
    ref = reference.get(t['workload'])
    if not ref:
        missing_reference.add(t['workload']); stats[(t['scenario'], t['label'])]['no_reference'] += 1; continue
    novel = seen[i] - ref - exec_set
    all_novel[t['label']].update(novel)
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
              exec_set=sorted(exec_set, key=int),
              novel_ids_by_label={label: dict(c.most_common()) for label, c in sorted(all_novel.items())},
              overall={label: overall[label + ':novel'] / max(1, overall[label + ':novel'] + overall[label + ':none'])
                       for label in ('attack', 'benign', 'control')},
              note='development; syscall IDs are x86-64 numbers; a novel ID is absent from the workload reference set',
              computed_at_unix=time.time())
json.dump(result, open(a.output, 'w'), indent=2)
print(json.dumps(dict(overall=result['overall'], by_scenario={s: {l: v['share'] for l, v in d.items()} for s, d in table.items()})))
