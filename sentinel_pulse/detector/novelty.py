"""Syscall-ID novelty of a container window against its peers (other replicas of the same workload) and its own
history: one definition shared by the offline window table (``sentinel_pulse.attack.window_table``, protocol
burden-reduction-v1) and the live preview path (``PeerNovelty``; Pulse 5.22 choice adopted blind in 5.25).

``Signals`` moved here unchanged from ``window_table`` on 24/10 so the live worker can import it without the
offline analysis stack.
"""
from __future__ import annotations

from collections import defaultdict, deque
import math

EXEC_IDS = (59, 322)
EXEC_MASK = sum(1 << i for i in EXEC_IDS)
CONTEXT = 4
BUCKET = 2.0
PEER_T = (30.0, 60.0)
SELF_T = (60.0, 300.0)


def id_mask(counts: dict) -> int:
    mask = 0
    for key, value in counts.items():
        if value:
            mask |= 1 << int(key)
    return mask


class Signals:
    """Context and novelty signals over a stream of windows in (approximate) window_end order."""

    def __init__(self, bucket=BUCKET, peer=PEER_T, self_=SELF_T, context=CONTEXT):
        self.bucket, self.peer, self.self_, self.context = bucket, tuple(sorted(peer)), tuple(sorted(self_)), context
        self.horizon = max(self.peer + self.self_) + 2 * bucket
        self.ctx = {}                      # ident -> deque of (start, mask)
        self.prev_end = {}
        self.first = {}
        self.buckets = defaultdict(dict)   # ident -> {bucket index: mask}, presence even when the mask is 0
        self.order = defaultdict(deque)    # ident -> bucket indices in insertion order (pruning)
        self.members = defaultdict(dict)   # workload -> {ident: last window_end}

    def observe(self, ident, workload, start, end, mask, want=True):
        ctx = self.ctx.get(ident)
        if ctx is None or abs(start - self.prev_end[ident]) > 1e-3:
            ctx = self.ctx[ident] = deque(maxlen=self.context)
        ctx.append((start, mask))
        self.prev_end[ident] = end
        self.first.setdefault(ident, end)
        result = None
        if want:
            union = 0
            for _, m in ctx:
                union |= m
            result = dict(launch=bool(union & EXEC_MASK), **self._peer(ident, workload, end, union),
                          **self._self(ident, end, ctx[0][0], union))
        self._add(ident, workload, end, mask)
        return result

    def _peer(self, ident, workload, end, union):
        out, b = {}, self.bucket
        newest = math.floor(end / b)
        peers = self.members[workload]
        for t in self.peer:
            oldest = math.ceil((end - t) / b)
            seen, present = 0, False
            for other, last in list(peers.items()):
                if other == ident:
                    continue
                if last < end - self.horizon:
                    del peers[other]
                    continue
                buckets = self.buckets[other]
                for k in range(oldest, newest + 1):
                    m = buckets.get(k)
                    if m is not None:
                        present = True
                        seen |= m
            out[f'novel_peer{t:g}'] = (union & ~seen).bit_count() if present else -1
        return out

    def _self(self, ident, end, ctx_start, union):
        out, b = {}, self.bucket
        buckets = self.buckets[ident]
        top = math.floor(ctx_start / b) - 1          # last whole bucket before the context starts
        seen, k = 0, top
        for t in self.self_:
            oldest = math.ceil((end - t) / b)
            while k >= oldest:
                seen |= buckets.get(k, 0)
                k -= 1
            out[f'novel_self{t:g}'] = (union & ~seen).bit_count() if self.first[ident] <= end - t else -1
        return out

    def _add(self, ident, workload, end, mask):
        k = math.floor(end / self.bucket)
        buckets, order = self.buckets[ident], self.order[ident]
        if k not in buckets:
            buckets[k] = 0
            order.append(k)
            cutoff = math.floor((end - self.horizon) / self.bucket)
            while order and order[0] < cutoff:
                del buckets[order.popleft()]
        buckets[k] |= mask
        self.members[workload][ident] = end


IDENTITY = ('workload_key', 'node_name', 'pod_uid', 'container_name', 'workload_revision', 'cgroup_id')


class PeerNovelty:
    """Live peer novelty for one worker: local windows are observed as they are scored, the peers' windows as they
    arrive from the other workers (``remote``). Same ``Signals`` as the offline table, with only the peer span.

    A local window gets ``novel_peer`` = the number of syscall IDs of its context (current + up to 3 previous
    contiguous windows) that no other replica of its workload showed within ``seconds`` (2 s buckets, up to the
    window's own end), or -1 when no other replica had a window in that span. Offline the stream of every worker is
    merged by window_end; live a peer window arrives a little after it ends, so the newest peer bucket can be
    incomplete when a local window is decided. That is the only difference; it is measured on the run.
    """

    def __init__(self, workloads, seconds: float = 30.0, bucket: float = BUCKET, context: int = CONTEXT):
        self.workloads = set(workloads)
        self.seconds = float(seconds)
        self.signals = Signals(bucket=bucket, peer=(self.seconds,), self_=(), context=context)
        self.name = f'novel_peer{self.seconds:g}'
        self.outbox = []

    @staticmethod
    def identity(record) -> tuple:
        return tuple(str(record.get(k)) for k in IDENTITY)

    def local(self, record, want: bool = True):
        """Observe one local feature record; returns novel_peer (None for a workload without a model or when
        ``want`` is false) and queues the window for the peers."""
        workload = str(record.get('workload_key'))
        if workload not in self.workloads:
            return None
        ident, mask = self.identity(record), id_mask(record['full_counts_delta'])
        start, end = float(record['window_start']), float(record['window_end'])
        result = self.signals.observe(ident, workload, start, end, mask, want)
        self.outbox.append(dict(i=list(ident), s=start, e=end, m=format(mask, 'x')))
        return None if result is None else result[self.name]

    def remote(self, message):
        """Observe one window of another worker (a message produced by its ``local``)."""
        ident = tuple(message['i'])
        if ident[0] not in self.workloads:
            return
        self.signals.observe(ident, ident[0], float(message['s']), float(message['e']), int(message['m'], 16), False)

    def drain_outbox(self):
        out, self.outbox = self.outbox, []
        return out
