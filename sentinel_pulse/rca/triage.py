"""Probe-aware triage annotation for RCA cases (Pulse 5.18; ideas from NoDoze, NDSS 2019, and Alahmadi et al.,
USENIX Security 2022).

Kubernetes exec probes (``exec: python -c ...``, ``sh -c redis-cli ...``) start a new process in the container
every few seconds. Pulse flags new processes, so many normal alerts coincide with a probe. This module labels a
case; it never suppresses, delays or changes the ML preview or the case itself:

- ``exec_in_window``: an exec in [window_start - 2.5 s, window_end + 0.5 s] of the trigger;
- ``probe_execs`` / ``execs``: execs of the case whose in-container ancestor chain starts at a process whose
  parent is the container runtime and whose binary basename is a declared exec-probe entry of that container;
- ``probe_only``: exec in window and every exec of the case is a probe exec.

Same definitions as ``scripts/analysis/alarm_taxonomy.py`` (tests compare both). Binaries, not argument vectors,
are matched: an operator running the probe's interpreter by hand would also be labelled probe-only.
"""
from __future__ import annotations

from datetime import datetime

from .ranking import is_container_runtime

LOOKBACK = 2.5
AFTER = 0.5


def iso_seconds(text):
    if text is None:
        return None
    if isinstance(text, (int, float)):
        return float(text)
    head, _, frac = str(text).rstrip('Z').partition('.')
    return datetime.fromisoformat(head + '+00:00').timestamp() + (float('0.' + frac) if frac else 0.0)


def probe_entries(pod: dict) -> dict:
    """{container name: {basename of command[0] of each exec probe}} from one pod object (kubectl JSON)."""
    out = {}
    for c in pod.get('spec', {}).get('containers', []):
        for kind in ('livenessProbe', 'readinessProbe', 'startupProbe'):
            command = ((c.get(kind) or {}).get('exec') or {}).get('command') or []
            if command:
                out.setdefault(c['name'], set()).add(str(command[0]).rsplit('/', 1)[-1])
    return out


def _execs(case):
    nodes = {n['id']: n for n in case['nodes']}
    for edge in case['edges']:
        target, source = nodes.get(edge['target']), nodes.get(edge['source'])
        if target and target.get('kind') == 'runtime_event' and target.get('operation') == 'exec':
            yield iso_seconds(target.get('observed_at')), source


def triage(case: dict, entries: set) -> dict:
    trigger = next(n['trigger'] for n in case['nodes'] if n['kind'] == 'signal')
    we = iso_seconds(trigger.get('window_end'))
    ws = iso_seconds(trigger.get('window_start'))
    if we is None:
        return dict(method='probe_aware_triage_v1', effect='annotation_only_preview_and_case_unchanged',
                    probe_only=False, unavailable='trigger_without_window_end')
    ws = we - 0.5 if ws is None else ws
    by_exec = {n.get('exec_id'): n for n in case['nodes'] if n['kind'] in ('process', 'process_parent')}
    execs = probes = 0
    in_window = False
    for at, source in _execs(case):
        if at is not None and ws - LOOKBACK <= at <= we + AFTER:
            in_window = True
        if source is None:
            continue
        execs += 1
        node, seen = source, set()
        while node is not None and node.get('exec_id') not in seen:
            seen.add(node.get('exec_id'))
            parent = by_exec.get(node.get('parent_exec_id'))
            if parent is None or not parent.get('container_name'):
                if (parent is not None and is_container_runtime(parent.get('binary'))
                        and str(node.get('binary', '')).rsplit('/', 1)[-1] in entries):
                    probes += 1
                break
            node = parent
    return dict(exec_in_window=in_window, execs=execs, probe_execs=probes,
                probe_only=bool(in_window and execs and probes == execs),
                declared_probe_entries=sorted(entries), method='probe_aware_triage_v1',
                effect='annotation_only_preview_and_case_unchanged')
