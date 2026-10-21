#!/usr/bin/env python3
"""Rule-based baseline: Falco (as deployed on the cluster, default rules, no tuning) on Pulse's campaign trials.

Falco 0.44.1 runs as a DaemonSet on every node with stdout output (text). Its pod logs, including rotated files,
were copied off the nodes after the campaign. Definitions fixed before the first run (Pulse 5.15d):

- an event belongs to a trial container when its ``container_id`` (12 hex chars) is the prefix of the trial's
  containerd ID; control, benign launch and attack of one trial share the container;
- a trial is *detected* when at least one Falco event of that container has its event time in
  [start_at, start_at + 15 s] (same unit as Pulse's interval outcome); events are attributed by rule output text;
- delay = first event time - kernel_event_at (attacks only), comparable to Pulse's kernel -> preview delay;
- normal burden: events of ``production`` containers inside [--normal-since, --normal-until] and outside the campaign
  span (first interval - 60 s to the campaign end + 60 s), merged per container into episodes when less than 15 s
  apart; per hour of that window, and per replica-hour if ``--replica-hours`` (Pulse's scored replica-hours for the
  same window) is given. ``--normal-until`` must not exceed the time the logs were copied off the nodes.

Falco's event time is printed without a date; the date comes from the kubelet log timestamp of the same line.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import re
import time

LINE = re.compile(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}\.\d+)Z stdout F (\d{2}):(\d{2}):(\d{2})\.(\d+): (\w+) (.*?) \| (.*)$')
FIELD = re.compile(r'(container_id|k8s_ns_name|k8s_pod_name|container_name)=(\S+)')
QUIET = 15.0


def parse(line):
    """(unix seconds, priority, rule text, fields) or None."""
    m = LINE.match(line)
    if not m:
        return None
    day, logged, hh, mm, ss, frac, priority, rule, rest = m.groups()
    base = datetime.fromisoformat(f'{day}T{hh}:{mm}:{ss}+00:00').timestamp() + float('0.' + frac)
    logged_at = datetime.fromisoformat(f'{day}T{logged[:15]}+00:00').timestamp()
    if base - logged_at > 12 * 3600:      # event just before midnight, logged after it
        base -= 86400
    fields = dict(FIELD.findall(rest))
    return base, priority, rule.strip(), fields


def load_events(log_dirs):
    events = []
    for d in log_dirs:
        for path in sorted(Path(d).rglob('*.log*')):
            opener = gzip.open if path.suffix == '.gz' else open
            with opener(path, 'rt', errors='replace') as f:
                for line in f:
                    e = parse(line.rstrip('\n'))
                    if e is not None:
                        events.append(e)
    events.sort(key=lambda e: e[0])
    # rotated copies can overlap the live file: keep each (time, container, rule) once
    seen, out = set(), []
    for e in events:
        key = (round(e[0], 6), e[3].get('container_id'), e[2])
        if key not in seen:
            seen.add(key); out.append(e)
    return out


def trials(campaign: Path):
    out = []
    for path in sorted(campaign.glob('trials/*/EVALUATION_INPUT.json')):
        d = json.loads(path.read_text())
        cid = str(d['attack'].get('container_id') or '').split('//')[-1][:12]
        for label in ('control', 'benign', 'attack'):
            if label in d:
                t = d[label]
                kind = 'benign' if label == 'benign' else ('attack' if label == 'attack' else 'control')
                out.append(dict(kind=kind, start=float(t['start_at']), container=cid, scenario=d['attack'].get('scenario'),
                                kernel=float(t['kernel_event_at']) if t.get('kernel_event_at') is not None else None))
    return out


def campaign_span(campaign: Path, margin=60.0):
    starts = [float(json.loads(l)['start_at']) for l in (campaign/'INTERVALS.jsonl').read_text().splitlines() if l]
    return min(starts) - margin, float(json.loads((campaign/'TERMINAL.json').read_text())['finished_at_unix']) + margin


def pct(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(q * len(v)))] if v else None


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--logs', action='append', required=True, help='directory of Falco pod logs (one per node)')
    p.add_argument('--campaign', type=Path, required=True)
    p.add_argument('--replica-hours', type=float)
    p.add_argument('--normal-since', type=float, required=True, help='unix start of the normal window (e.g. selection start)')
    p.add_argument('--normal-until', type=float, required=True, help='unix end (<= when the logs were copied)')
    p.add_argument('--output', required=True)
    a = p.parse_args()
    events = load_events(a.logs)
    by_container = defaultdict(list)
    for e in events:
        by_container[e[3].get('container_id')].append(e)
    rows = trials(a.campaign)
    outcome = defaultdict(Counter); by_rule = defaultdict(Counter); by_scenario = defaultdict(Counter); delays = []
    for t in rows:
        hits = [e for e in by_container.get(t['container'], ()) if t['start'] <= e[0] <= t['start'] + 15.0]
        outcome[t['kind']]['detected' if hits else 'missed'] += 1
        for rule in {e[2] for e in hits}:
            by_rule[t['kind']][rule] += 1
        if t['kind'] == 'attack':
            by_scenario[t['scenario']]['detected' if hits else 'missed'] += 1
            if hits and t['kernel'] is not None:
                first = min(e[0] for e in hits)
                if first >= t['kernel']:
                    delays.append(first - t['kernel'])
    lo, hi = campaign_span(a.campaign)
    since, until = a.normal_since, a.normal_until
    normal = [e for e in events if e[3].get('k8s_ns_name') == 'production' and since <= e[0] <= until
              and not lo <= e[0] <= hi]
    covered = (until - since - max(0.0, min(hi, until) - max(lo, since))) / 3600
    episodes, rule_episodes, pod_episodes, last = 0, Counter(), Counter(), {}
    for e in normal:
        key = e[3].get('container_id')
        if key not in last or e[0] - last[key] >= QUIET:
            episodes += 1; rule_episodes[e[2]] += 1; pod_episodes[e[3].get('k8s_pod_name')] += 1
        last[key] = e[0]
    drift_containers = {e[3].get('container_id') for e in events if 'not part of base image' in e[2] and lo <= e[0] <= hi}
    trial_containers = {t['container'] for t in rows}
    rate = lambda k: outcome[k]['detected'] / sum(outcome[k].values()) if sum(outcome[k].values()) else None
    result = dict(schema='pulse-falco-baseline-v1', logs=a.logs, campaign=str(a.campaign), events=len(events),
                  falco_version='0.44.1 (DaemonSet image falcosecurity/falco:0.44.1), default rules as deployed',
                  trial_detection={k: dict(v, rate=rate(k)) for k, v in outcome.items()},
                  attack_by_scenario={s: dict(v, rate=v['detected'] / sum(v.values())) for s, v in sorted(by_scenario.items())},
                  rules_on_trials={k: dict(v.most_common()) for k, v in by_rule.items()},
                  attack_delay=dict(p50=pct(delays, .5), p95=pct(delays, .95), n=len(delays),
                                    definition='first Falco event time in the interval - kernel_event_at'),
                  drift_rule_coverage=dict(trial_containers=len(trial_containers),
                                           containers_with_drift_alert=len(drift_containers & trial_containers),
                                           note='the drift rule sees only executables in the overlayfs upper layer'),
                  normal=dict(window_unix=[since, until], events=len(normal), episodes=episodes,
                              episodes_by_rule=dict(rule_episodes.most_common()), top_pods=pod_episodes.most_common(5),
                              covered_hours=covered,
                              episodes_per_hour=episodes / covered if covered > 0 else None,
                              episodes_per_replica_hour=episodes / a.replica_hours if a.replica_hours else None),
                  computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result[k] for k in ('trial_detection', 'attack_by_scenario', 'attack_delay')}, indent=1))
    print(json.dumps(result['normal'], indent=1)[:800])


if __name__ == '__main__':
    main()
