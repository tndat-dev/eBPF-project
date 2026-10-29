#!/usr/bin/env python3
"""Why an attack trial got no RCA case of its own after the benign launch's case (RCA 5.15, 5.17).

For every attack trial that rca_coverage.py would class ``grouped_after_benign_case`` (no case whose trigger
window ends in [start, start + 20 s], a case of the same container since the benign launch), the alert bridge's
episodes of that container (node, pod UID, container) tell which step stopped it:

- ``episode_carried_over``: an episode that started before the attack was still open at the attack start, so no new
  alert (and, with RCA built from delivered alerts, no new trigger) was sent;
- ``no_new_episode``: no episode was open and none started inside [start, start + 20 s];
- ``trigger_refused_too_soon``: an episode started inside the interval, less than ``--min-seconds`` after the
  previous case of the container (RCA follow_up_min_seconds);
- ``trigger_refused_exec_check``: an episode started and the gap was long enough, so the follow-up was refused by the
  exec-log checks (binary not new / no exec since the previous case).

Standard library only (runs on the system Python of .234; RCA cases are root-owned).
"""
import argparse
from collections import Counter, defaultdict
import glob
import json
from pathlib import Path
import time

HORIZON, COOLDOWN = 20.0, 300.0


def load_cases(cases_dir):
    out = defaultdict(list)
    for path in glob.glob(str(cases_dir).rstrip('/') + '/*.json'):
        t = json.load(open(path))
        trig = next(n['trigger'] for n in t['nodes'] if n['kind'] == 'signal')
        out[(trig['node_name'], trig['pod_uid'], trig['container_name'])].append((float(trig['window_end']), float(t['created_at'])))
    for v in out.values():
        v.sort()
    return out


def load_episodes(path):
    starts, ends = defaultdict(list), {}
    for line in open(path):
        e = json.loads(line)
        if e['event'] == 'start':
            starts[(e['node'], e['pod_uid'], e['container'])].append(e)
        elif e['event'] == 'end':
            ends[e['episode']] = float(e['ended_at'])
    return starts, ends


def classify(trials, cases, starts, ends, min_seconds=10.0):
    out, causes = [], Counter()
    for at, benign in trials:
        start = float(at['start_at']); ident = (at['node_name'], at['pod_uid'], at['container_name'])
        mine = cases.get(ident, [])
        if any(start <= w <= start + HORIZON for w, _ in mine):
            continue                                                      # the attack has its own case
        if not (benign and any(float(benign['start_at']) <= w < start for w, _ in mine)):
            continue                                                      # not grouped after the benign case
        eps = starts.get(ident, [])
        open_at_start = [e for e in eps if float(e['bridge_received_at']) < start <= ends.get(e['episode'], float('inf'))]
        inside = [e for e in eps if start <= float(e['bridge_received_at']) <= start + HORIZON]
        if inside:
            trigger_at = float(inside[0]['bridge_received_at'])
            previous = max((c for _, c in mine if c <= trigger_at), default=None)
            cause = 'trigger_refused_too_soon' if previous is not None and trigger_at - previous < min_seconds else 'trigger_refused_exec_check'
        elif open_at_start:
            cause = 'episode_carried_over'
        else:
            cause = 'no_new_episode'
        causes[cause] += 1
        out.append(dict(trial_id=at.get('trial_id'), scenario=at.get('scenario'), workload=at.get('workload_key'), cause=cause,
                        seconds_benign_to_attack=start - float(benign['start_at'])))
    return causes, out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cases', required=True); ap.add_argument('--campaign', required=True)
    ap.add_argument('--episodes', required=True, help="alert bridge episodes.jsonl of the run")
    ap.add_argument('--since', type=float, default=0.0); ap.add_argument('--min-seconds', type=float, default=10.0)
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    trials = []
    for path in sorted(glob.glob(a.campaign.rstrip('/') + '/trials/*/EVALUATION_INPUT.json')):
        d = json.load(open(path))
        if float(d['attack']['start_at']) >= a.since:
            trials.append((d['attack'], d.get('benign')))
    starts, ends = load_episodes(a.episodes)
    causes, rows = classify(trials, load_cases(a.cases), starts, ends, a.min_seconds)
    doc = dict(schema='rca-grouping-causes-v1', cases=a.cases, campaign=a.campaign, episodes=a.episodes, since_unix=a.since,
               grouped_after_benign=sum(causes.values()), causes=dict(causes), trials=rows, computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(doc, indent=1)); print(json.dumps(dict(causes)))


if __name__ == '__main__':
    main()
