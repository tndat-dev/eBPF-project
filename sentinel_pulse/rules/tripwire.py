"""Tripwire A1 in the live worker (RULE_INTEGRATION_STATUS R3, R6; final system = ML + tripwire, owner 25/10).

Definition, as the offline ``scripts/analysis/novel_syscalls.py`` (protocol tripwire-a1-blind-v1, amendment 2 of
rule-integration-v1):

- the reference of a workload is the union of the syscall IDs of every window of that workload, on every node, whose
  [window_start, window_end] lies inside the reference span (the run's selection span);
- a later window alerts when it carries an ID that is neither in its workload's reference nor in the frozen exec set E.

Live, a worker sees its own windows directly and the other workers' windows as ID masks from the peer exchange
(``pipeline/peer_exchange.py``, the same messages the evidence discount uses; only workloads with a model are
exchanged). A peer window arrives a little after it ends, so the reference is treated as complete ``grace_seconds``
after the span ends: windows ending before that are not judged (``tripwire_status = reference_pending``). Peer
windows of the reference span that still arrive after that are counted (``late_reference_windows``); the offline
recomputation after the run measures the effect.

The tripwire only adds fields to a decision row (``tripwire_status``, ``tripwire_alert``, ``tripwire_novel_ids``);
``candidate_alert_preview`` and every other ML field stay as the ML wrote them.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..integrity import sha256_file


def load_exec_set(path: Path, sha256: str | None = None) -> set[int]:
    if sha256 is not None and sha256_file(path) != sha256:
        raise ValueError('tripwire exec set differs from the registered file')
    ids = {int(x) for x in json.loads(Path(path).read_text())}
    if not ids or any(not 0 <= i < 1024 for i in ids):
        raise ValueError('invalid tripwire exec set')
    return ids


def ids_of(mask: int) -> list[int]:
    out, i = [], 0
    while mask:
        if mask & 1:
            out.append(i)
        mask >>= 1; i += 1
    return out


class Tripwire:
    def __init__(self, workloads, exec_ids, reference_span, grace_seconds: float = 60.0):
        self.workloads = set(workloads)
        self.exec_mask = sum(1 << i for i in exec_ids)
        self.lo, self.hi = float(reference_span[0]), float(reference_span[1])
        if not self.lo < self.hi:
            raise ValueError('empty tripwire reference span')
        self.ready_at = self.hi + float(grace_seconds)
        self.reference = {}
        self.stats = dict(reference_windows=0, remote_reference_windows=0, late_reference_windows=0,
                          judged=0, alerts=0, no_reference=0, pending=0)

    def observe(self, workload: str, start: float, end: float, mask: int, now: float, remote: bool = False):
        """Add one window (local or a peer's) to the reference when it lies inside the reference span."""
        if workload not in self.workloads or not (self.lo <= start and end <= self.hi):
            return
        self.reference[workload] = self.reference.get(workload, 0) | mask
        self.stats['reference_windows'] += 1
        self.stats['remote_reference_windows'] += remote
        if now >= self.ready_at:
            self.stats['late_reference_windows'] += 1

    def judge(self, workload: str, end: float, mask: int) -> dict | None:
        """Fields for the decision row of one local window (None for a workload without a model)."""
        if workload not in self.workloads:
            return None
        if end < self.ready_at:
            self.stats['pending'] += 1
            return dict(tripwire_status='reference_pending')
        ref = self.reference.get(workload)
        if ref is None:
            self.stats['no_reference'] += 1
            return dict(tripwire_status='no_reference')
        novel = mask & ~ref & ~self.exec_mask
        self.stats['judged'] += 1
        self.stats['alerts'] += bool(novel)
        return dict(tripwire_status='judged', tripwire_alert=bool(novel), tripwire_novel_ids=ids_of(novel))
