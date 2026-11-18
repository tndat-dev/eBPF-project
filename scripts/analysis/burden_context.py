#!/usr/bin/env python3
"""improvement-round-v1 D10 (incident grouping) and D11 (replica consensus) on finished live runs, token arm T.

Episodes are the alarms of one container on the normal span (outside the selection and the campaign) merged when less
than 15 s apart, as pulse_live_v4.episodes_per_workload. Then:

- D11: an episode is "multi-replica" when another replica of the same workload alarms within DELTA seconds of it (the
  workload changed as a whole: an aged model, a rollout); otherwise "single-replica" (the attack-candidate channel). The
  campaign attacks hit one replica, so their alarm should stay single-replica: the share of attack trials whose first
  alarm has a concurrent alarm on another replica is reported (the harm).
- D10: episodes of one workload less than GAP seconds apart form an incident; incidents per day and per replica-day.

Kubernetes events of the past runs are gone (one-hour TTL), so the operational labelling of D10 is not measured here.

    python3 burden_context.py --run-root RUN --output out.json
"""
# GÁNH CẢNH BÁO THEO NGỮ CẢNH (vòng cải thiện D10, D11): gom đợt thành sự cố; tách đợt chỉ một replica (ứng viên tấn công)
# với đợt nhiều replica cùng lúc (cả workload đổi: mô hình cũ, rollout). Đo cả mặt hại: tấn công có bị coi là nhiều replica.
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pulse_live_v4 as live  # noqa: E402

DELTA = 5.0
GAP = 600.0


def episodes(times, quiet=live.QUIET):
    """[(start, end)] of sorted alarm times merged when less than `quiet` apart."""
    out = []
    for t in times:
        if out and t - out[-1][1] < quiet:
            out[-1][1] = t
        else:
            out.append([t, t])
    return [tuple(e) for e in out]


def concurrent(other_times, start, end, delta=DELTA):
    """Does a sorted array of alarm times hold one in [start - delta, end + delta]?"""
    i = np.searchsorted(other_times, start - delta)
    return bool(i < len(other_times) and other_times[i] <= end + delta)


def consensus(alarms, workload_of, keep):
    """{workload: [single, multi]} over the episodes whose times pass keep(t), plus the episode list."""
    by_workload = defaultdict(list)
    for key in alarms:
        by_workload[workload_of[key]].append(key)
    arrays = {k: np.sort(np.asarray(v)) for k, v in alarms.items()}
    counts, eps = defaultdict(lambda: [0, 0]), []
    for key, times in arrays.items():
        w = workload_of[key]
        for start, end in episodes([t for t in times if keep(t)]):
            multi = any(concurrent(arrays[o], start, end) for o in by_workload[w] if o != key)
            counts[w][multi] += 1
            eps.append((w, start, end, multi))
    return dict(counts), eps


def incidents(eps, gap=GAP):
    """Episodes of one workload less than `gap` apart form one incident; -> {workload: incidents}."""
    out = defaultdict(int)
    by_w = defaultdict(list)
    for w, start, end, _ in eps:
        by_w[w].append((start, end))
    for w, xs in by_w.items():
        xs.sort()
        last = None
        for start, end in xs:
            if last is None or start - last >= gap:
                out[w] += 1
            last = end if last is None else max(last, end)
    return dict(out)


def attack_harm(trials, alarms, workload_of):
    """Attack trials (base pairs) whose first alarm in the trial has a concurrent alarm on another replica."""
    arrays = {k: np.sort(np.asarray(v)) for k, v in alarms.items()}
    by_workload = defaultdict(list)
    for key in arrays:
        by_workload[workload_of[key]].append(key)
    hit = multi = 0
    for t in trials:
        if t['label'] not in ('attack', 'lotl') or t.get('pad'):
            continue
        first = live.first_alarm(arrays.get(t['key'], np.empty(0)), t['start'])
        if first is None:
            continue
        hit += 1
        multi += any(concurrent(arrays[o], first, first) for o in by_workload[t['workload']] if o != t['key'])
    return dict(detected=hit, multi_replica=multi, share=multi / hit if hit else None)


def analyse(root):
    cfg = json.loads((root / 'CONFIG.json').read_text())
    campaign = root / live.CAMPAIGN
    normal = (float(cfg['selection_end']), float(cfg['selection_start']) + float(cfg['seconds']))
    spans = [live.campaign_span(campaign)] if (campaign / 'TERMINAL.json').exists() else []
    trials = live.load_trials(campaign)
    alarms, seconds, workload_of, _ = live.read_decisions(root, normal, spans)
    token = alarms['T']
    keep = lambda t: normal[0] <= t < normal[1] and not live.in_spans(t, spans)
    counts, eps = consensus(token, workload_of, keep)
    hours = sum(seconds.values()) / 3600
    single = sum(c[0] for c in counts.values())
    multi = sum(c[1] for c in counts.values())
    inc = incidents(eps)
    normal_hours = (normal[1] - normal[0] - sum(b - a for a, b in spans)) / 3600
    return dict(schema='improvement-round-v1-burden-context', run=cfg['run_id'],
                protocol='sentinel_pulse/protocol/improvement-round-v1-amendment-1.json (D10, D11)',
                delta_seconds=DELTA, incident_gap_seconds=GAP, replica_hours=hours, normal_hours=normal_hours,
                episodes=dict(all=single + multi, single_replica=single, multi_replica=multi,
                              per_replica_hour=dict(all=(single + multi) / hours if hours else None,
                                                    single_replica=single / hours if hours else None)),
                by_workload={w: dict(single=c[0], multi=c[1], incidents=inc.get(w, 0)) for w, c in sorted(counts.items())},
                incidents=dict(total=sum(inc.values()), per_day=sum(inc.values()) / (normal_hours / 24) if normal_hours else None),
                attack_harm=attack_harm(trials, token, workload_of))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, action='append', required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    doc = {str(r.name): analyse(r) for r in a.run_root}
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    for run, d in doc.items():
        print(run, json.dumps(dict(episodes=d['episodes'], incidents=d['incidents'], attack_harm=d['attack_harm']), default=float))


if __name__ == '__main__':
    main()
