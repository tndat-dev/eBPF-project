"""Rank the processes of an RCA evidence graph as investigation suspects.

A Pulse signal says *which container* behaved abnormally, not *which
process*. This turns the graph into an ordered suspect list with explicit,
auditable reasons. Scores are heuristics for triage order, not probabilities
or proof of causality.

Reasons and weights:
- binary first seen in this workload after the registered baseline freeze
  (``novel_binary``, 4) or never recorded at all (``unknown_binary``, 2)
- exec observed inside the case window (``started_in_window``, 2)
- credential / namespace / mount / ptrace operations (``security_operation``, 3 each, max 9)
  except a privilege *drop* at launch: setuid/setgid/setre*/setres* to a non-zero id within
  ``DROP_AT_START_SECONDS`` of the process's own start (``privilege_drop_at_start``, 0). Every probe or
  ``kubectl exec`` into a non-root container does this (found 21/10: redis liveness probes outranked
  the injected binary in 21 of 273 cases). Raising to uid/gid 0, or a change later in life, still counts.
- failed syscalls (``failed_syscall``, 1 each, max 3)
- parent of another suspect process in the window (``spawned_children``, 1)

Container-runtime processes (containerd shim, runc, crun, conmon) are host-side
context for every ``kubectl exec`` and container start; they are never
candidates and do not earn ``spawned_children``.
"""
from __future__ import annotations

from collections import defaultdict
import re

SECURITY = {'credential', 'namespace', 'mount', 'ptrace'}
ID_SETTERS = {'setuid', 'setgid', 'setreuid', 'setregid', 'setresuid', 'setresgid'}
DROP_AT_START_SECONDS = 1.0


def _seconds(stamp):
    from datetime import datetime
    if stamp is None:
        return None
    try:
        text = str(stamp).replace('Z', '+00:00')
        head, _, frac = text.partition('.')
        if frac:  # Python's fromisoformat takes at most microseconds
            digits = ''.join(ch for ch in frac if ch.isdigit())
            zone = frac[len(digits):]
            text = f'{head}.{digits[:6]}{zone}'
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def is_privilege_drop_at_start(event: dict, process: dict) -> bool:
    """setuid/setgid-style call to a non-zero id shortly after the process itself started."""
    if event.get('category') != 'credential' or event.get('operation') not in ID_SETTERS:
        return False
    ids = []
    for key, value in (event.get('details') or {}).items():
        if key in ('uid', 'gid', 'ruid', 'euid', 'suid', 'rgid', 'egid', 'sgid'):
            try:
                ids.append(int(value))
            except (TypeError, ValueError):
                return False
    ids = [v for v in ids if v not in (-1, 4294967295)]   # -1 = "leave unchanged" for setres*/setre*
    if not ids or 0 in ids:                              # no target, or a raise to root: keep as security
        return False
    began, at = _seconds(process.get('start_time')), _seconds(event.get('observed_at'))
    return began is not None and at is not None and 0 <= at - began <= DROP_AT_START_SECONDS
CONTAINER_RUNTIME = re.compile(r'(^|/)(containerd-shim[^/]*|runc|crun|conmon)$')


def is_container_runtime(binary) -> bool:
    return bool(binary) and CONTAINER_RUNTIME.search(str(binary)) is not None


def workload_of(namespace, pod_name, container):
    """Map a pod to the ``namespace/controller:container`` key Pulse uses.

    Deployment pods end in ``-<replicaset hash>-<5 chars>``, StatefulSet pods
    in ``-<ordinal>``; anything else keeps its full name.
    """
    name = str(pod_name or '')
    m = re.fullmatch(r'(.+)-[0-9a-z]{6,10}-[0-9a-z]{5}', name)
    if m:
        name = m.group(1)
    else:
        name = re.sub(r'-\d+$', '', name)
    return f'{namespace}/{name}:{container}'


def rank_suspects(tree: dict, baseline: dict | None = None, frozen_at: float | None = None) -> list[dict]:
    """``baseline`` maps binary path -> first time seen in this workload."""
    nodes = {n['id']: n for n in tree['nodes']}
    processes = {nid: n for nid, n in nodes.items() if n['kind'] in ('process', 'process_parent')
                 and not is_container_runtime(n.get('binary'))}
    reasons = defaultdict(list)
    children = defaultdict(set)
    for edge in tree['edges']:
        src, dst, relation = edge['source'], edge['target'], edge['relation']
        if relation == 'parent_of' and src in processes and dst in processes:
            children[src].add(dst)
        if src not in processes or dst not in nodes:
            continue
        target = nodes[dst]
        if target['kind'] != 'runtime_event':
            continue
        if target['operation'] == 'exec':
            reasons[src].append(('started_in_window', 2))
        if target['category'] in SECURITY:
            if is_privilege_drop_at_start(target, processes[src]):
                reasons[src].append(('privilege_drop_at_start', 0))
            else:
                reasons[src].append(('security_operation', 3))
        if (target.get('outcome') or {}).get('status') == 'failure':
            reasons[src].append(('failed_syscall', 1))
    ranked = []
    for pid, node in processes.items():
        found = reasons[pid]
        score = sum(w for r, w in found if r == 'started_in_window')
        score += min(9, sum(w for r, w in found if r == 'security_operation'))
        score += min(3, sum(w for r, w in found if r == 'failed_syscall'))
        binary = node.get('binary')
        why = sorted({r for r, _ in found})
        if baseline is not None and binary:
            first = baseline.get(binary)
            if first is None:
                score += 2; why.append('unknown_binary')
            elif frozen_at is not None and first > frozen_at:
                score += 4; why.append('novel_binary')
        if any(reasons[c] for c in children[pid]):
            score += 1; why.append('spawned_children')
        ranked.append(dict(process=pid, exec_id=node.get('exec_id'), binary=binary, pid=node.get('pid'),
                           score=score, reasons=sorted(why)))
    ranked.sort(key=lambda r: (-r['score'], str(r['binary']), str(r['exec_id'])))
    for i, row in enumerate(ranked, 1):
        row['rank'] = i
    return ranked


def ground_truth_rank(ranked: list[dict], exec_id: str | None = None, binary: str | None = None):
    """Rank of the known injected process (by exec ID, else binary path); None if absent."""
    for row in ranked:
        if (exec_id and row['exec_id'] == exec_id) or (not exec_id and binary and row['binary'] == binary):
            return row['rank']
    return None


def hit_rates(ranks: list[int | None], ks=(1, 3, 5)) -> dict:
    """Top-k hit rate over cases with a ground truth; absent counts as a miss."""
    n = len(ranks)
    return dict(cases=n, **{f'top{k}': (sum(r is not None and r <= k for r in ranks) / n if n else None) for k in ks},
                absent=sum(r is None for r in ranks))
