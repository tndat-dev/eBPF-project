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

Tripwire latency (Pulse 5.16): for attack intervals with a novel ID, the delay from the kernel event to the
end of the first window carrying one (same unit as the preview delay). ``--secondary-reference-span`` adds,
from the same pass, the result against a second reference (e.g. only the pre-attack selection span, the
reference a live tripwire could have had).
Segment files may be plain or seal-verified gzip (``features.jsonl.gz``).
"""
import argparse, collections, glob, gzip, json, time
from pathlib import Path

import numpy as np


def first_novel_delay(windows, reference, exec_set, kernel):
    """``windows``: [(window_end, ids)] of one interval. Returns (has_novel, delay or None, before_kernel)."""
    ends = [end for end, ids in sorted(windows, key=lambda w: w[0]) if set(ids) - reference - exec_set]
    if not ends:
        return False, None, False
    if kernel is None:
        return True, None, False
    return True, (ends[0] - kernel if ends[0] >= kernel else None), ends[0] < kernel


def evaluate(trials, windows, reference, exec_set):
    stats = collections.defaultdict(collections.Counter); novel_ids = collections.defaultdict(collections.Counter)
    missing_reference = set(); all_novel = collections.defaultdict(collections.Counter)
    delays = collections.defaultdict(list); before_kernel = collections.Counter()
    for i, t in enumerate(trials):
        if i not in windows:
            stats[(t['scenario'], t['label'])]['no_windows'] += 1; continue
        ref = reference.get(t['workload'])
        if not ref:
            missing_reference.add(t['workload']); stats[(t['scenario'], t['label'])]['no_reference'] += 1; continue
        novel = set().union(*(ids for _, ids in windows[i])) - ref - exec_set
        all_novel[t['label']].update(novel)
        stats[(t['scenario'], t['label'])]['novel' if novel else 'none'] += 1
        novel_ids[(t['scenario'], t['label'])].update(novel)
        if t['label'] == 'attack' and novel:
            _, delay, early = first_novel_delay(windows[i], ref, exec_set, t['kernel'])
            if delay is not None:
                delays[t['scenario']].append(delay)
            before_kernel[t['scenario']] += early
    pct = lambda d, q: float(np.percentile(d, q)) if d else None
    table = {}
    for (scenario, label), c in sorted(stats.items()):
        n = c['novel'] + c['none']
        table.setdefault(scenario, {})[label] = dict(intervals=n, with_novel_id=c['novel'], share=c['novel'] / n if n else None,
                                                     skipped=dict(no_windows=c['no_windows'], no_reference=c['no_reference']),
                                                     top_novel_ids=novel_ids[(scenario, label)].most_common(6))
        if label == 'attack':
            d = delays[scenario]
            table[scenario][label].update(delay_p50=pct(d, 50), delay_p95=pct(d, 95), delays=len(d),
                                          first_novel_before_kernel=before_kernel[scenario])
    overall = collections.Counter()
    for (scenario, label), c in stats.items():
        overall[label + ':novel'] += c['novel']; overall[label + ':none'] += c['none']
    every = [x for d in delays.values() for x in d]
    return dict(reference_ids_per_workload={w: len(v) for w, v in sorted(reference.items())},
                workloads_without_reference=sorted(missing_reference), by_scenario=table,
                novel_ids_by_label={label: dict(c.most_common()) for label, c in sorted(all_novel.items())},
                overall={label: overall[label + ':novel'] / max(1, overall[label + ':novel'] + overall[label + ':none'])
                         for label in ('attack', 'benign', 'control')},
                attack_delay=dict(p50=pct(every, 50), p95=pct(every, 95), n=len(every),
                                  definition='end of first window with a novel ID - kernel_event_at'))


def span(text):
    lo, hi = (float(x) for x in text.split(':'))
    return lo, hi


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workers-root', required=True)
    p.add_argument('--campaign', action='append', required=True)
    p.add_argument('--reference-span', type=span, required=True, help='START:END unix seconds (attack-free)')
    p.add_argument('--secondary-reference-span', type=span, help='a second reference span evaluated in the same pass')
    p.add_argument('--exec-set', help='JSON list of syscall IDs from the exec mechanism; never novel')
    p.add_argument('--output', required=True)
    a = p.parse_args()
    exec_set = {str(x) for x in json.loads(Path(a.exec_set).read_text())} if a.exec_set else set()
    spans = {'primary': a.reference_span, **({'secondary': a.secondary_reference_span} if a.secondary_reference_span else {})}

    trials = []
    for campaign in a.campaign:
        for path in sorted(glob.glob(campaign + '/trials/*/EVALUATION_INPUT.json')):
            d = json.loads(Path(path).read_text())
            for label in ('control', 'benign', 'attack'):
                if label in d:
                    t = d[label]
                    trials.append(dict(label=label, scenario=d['attack']['scenario'], workload=t['workload_key'],
                                       ident=(t['node_name'], str(t['pod_uid']), str(t['cgroup_id'])),
                                       start=float(t['start_at']), end=float(t['start_at']) + 15,
                                       kernel=float(t['kernel_event_at']) if t.get('kernel_event_at') is not None else None))
    by_ident = collections.defaultdict(list)
    for i, t in enumerate(trials):
        by_ident[t['ident']].append(i)
    t_lo = min(t['start'] for t in trials); t_hi = max(t['end'] for t in trials)

    references = {name: collections.defaultdict(set) for name in spans}
    windows = collections.defaultdict(list)          # trial index -> [(window_end, IDs)]
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
                for name, (lo, hi) in spans.items():
                    if lo <= row['window_start'] and end <= hi:
                        references[name][row['workload_key']].update(row['full_counts_delta'])
                if t_lo <= end <= t_hi:
                    for i in by_ident.get((row['node_name'], str(row['pod_uid']), str(row['cgroup_id'])), ()):
                        if trials[i]['start'] <= row['window_start'] and end <= trials[i]['end']:
                            windows[i].append((end, tuple(row['full_counts_delta'])))

    primary = evaluate(trials, windows, references['primary'], exec_set)
    result = dict(schema='pulse-novel-syscall-hypothesis-v1', workers_root=a.workers_root, campaigns=a.campaign,
                  reference_span_unix=list(a.reference_span), feature_rows_read=rows, **primary,
                  exec_set=sorted(exec_set, key=int),
                  note='development; syscall IDs are x86-64 numbers; a novel ID is absent from the workload reference set',
                  computed_at_unix=time.time())
    if 'secondary' in spans:
        result['secondary'] = dict(reference_span_unix=list(spans['secondary']),
                                   **evaluate(trials, windows, references['secondary'], exec_set))
    json.dump(result, open(a.output, 'w'), indent=2)
    print(json.dumps(dict(overall=result['overall'], attack_delay=result['attack_delay'],
                          by_scenario={s: {l: v['share'] for l, v in d.items()} for s, d in result['by_scenario'].items()},
                          secondary=result.get('secondary', {}).get('overall'))))


if __name__ == '__main__':
    main()
