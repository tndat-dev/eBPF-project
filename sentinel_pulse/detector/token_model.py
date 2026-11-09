"""Token branch of lidds-ml-v3 on the probe's integer tokens (sentinel_pulse/ebpf/pulse_token_ids.h).

The same model as scripts/analysis/lidds_ml_tokens.py TokenLM: per-thread 4-grams, Witten-Bell backoff over shorter
contexts down to the base P(name) x P(token | name), both add-half, an unseen call graded by the mean unseen-token
probability of the known calls. Two differences, neither in the arithmetic:

- tokens are the probe's 32-bit integers and a token's call (the "name") is its syscall number, ``tok >> 23``;
- it learns from gram counts (the probe sends one count per distinct (cgroup, window, gram)), so a gram seen c times
  adds c, exactly what c separate ``TokenLM.learn`` calls add (tests/test_token_model.py checks the equality).

A window's score is the mean of its TOP highest per-event -log p, events counted with their multiplicity. Grams whose
leading slots are TOK_NONE (thread start) are the shorter grams of the offline model.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import gzip
import json
import math
from pathlib import Path

N, TOP = 4, 10
TOK_NONE = 0xFFFFFFFF
NR_SHIFT = 23
KIND_SHIFT = 21


def call_of(tok: int) -> int:
    return tok >> NR_SHIFT


def strip(gram) -> tuple:
    """Drop the empty history slots in front: (NONE, NONE, a, b) -> (a, b)."""
    g = tuple(int(t) for t in gram)
    start = 0
    while start < len(g) - 1 and g[start] == TOK_NONE:
        start += 1
    if TOK_NONE in g[start:]:
        raise ValueError('empty slot inside a gram')
    return g[start:]


class CountTokenLM:
    def __init__(self, n: int = N):
        self.n = n
        self.count = [defaultdict(Counter) for _ in range(n)]
        self.names = Counter()
        self.given = defaultdict(Counter)
        self.total = 0
        self.finalized = False

    def learn(self, gram, weight: int = 1):
        if weight <= 0:
            raise ValueError('gram count must be positive')
        g = tuple(gram[-self.n:])
        w = g[-1]
        for k in range(1, min(self.n, len(g))):
            self.count[k][g[-1 - k:-1]][w] += weight
        name = call_of(w)
        self.names[name] += weight
        self.given[name][w] += weight
        self.total += weight

    def learn_window(self, grams):
        """grams: [[t0, t1, t2, t3, count], ...] as the probe sends them."""
        for *gram, c in grams:
            self.learn(strip(gram), int(c))

    def finalize(self):
        self.stats = [{h: (sum(c.values()), len(c)) for h, c in level.items()} for level in self.count]
        self.memo = {}
        unseen = [0.5 / (sum(c.values()) + 0.5 * (len(c) + 1)) for c in self.given.values()]
        self.unseen_given = sum(unseen) / len(unseen) if unseen else 1.0
        self.given_total = {name: sum(c.values()) for name, c in self.given.items()}
        self.finalized = True
        return self

    def base(self, w: int) -> float:
        name = call_of(w)
        p_name = (self.names.get(name, 0) + 0.5) / (self.total + 0.5 * (len(self.names) + 1))
        given = self.given.get(name)
        if not given:
            return p_name * self.unseen_given
        return p_name * (given.get(w, 0) + 0.5) / (self.given_total[name] + 0.5 * (len(given) + 1))

    def prob(self, g) -> float:
        g = tuple(g[-self.n:])
        hit = self.memo.get(g)
        if hit is not None:
            return hit
        w = g[-1]
        p = self.base(w)
        for k in range(1, min(self.n, len(g))):
            h = g[-1 - k:-1]
            st = self.stats[k].get(h)
            if not st:
                continue
            tot, types = st
            p = (self.count[k][h].get(w, 0) + types * p) / (tot + types)
        if len(self.memo) < 2_000_000:
            self.memo[g] = p
        return p

    def window_score(self, grams, top: int = TOP) -> float:
        """Mean of the top highest -log p of a window's events; 0 for an empty window (as the offline scorer)."""
        values = sorted(((-math.log(self.prob(strip(gram))), int(c)) for *gram, c in grams), reverse=True)
        taken, total = 0, 0.0
        for nll, c in values:
            use = min(c, top - taken)
            total += nll * use
            taken += use
            if taken == top:
                break
        return total / taken if taken else 0.0

    # persistence: counts only; finalize() rebuilds the rest
    def to_json(self) -> dict:
        return dict(schema='sentinel-pulse-token-lm-v1', n=self.n, total=self.total,
                    names=[[k, v] for k, v in self.names.items()],
                    given=[[name, [[w, c] for w, c in ws.items()]] for name, ws in self.given.items()],
                    count=[[[list(h), [[w, c] for w, c in ws.items()]] for h, ws in level.items()] for level in self.count])

    @classmethod
    def from_json(cls, doc: dict) -> 'CountTokenLM':
        if doc.get('schema') != 'sentinel-pulse-token-lm-v1':
            raise ValueError('not a token LM document')
        lm = cls(doc['n'])
        lm.total = doc['total']
        lm.names = Counter({k: v for k, v in doc['names']})
        for name, ws in doc['given']:
            lm.given[name] = Counter({w: c for w, c in ws})
        for k, level in enumerate(doc['count']):
            for h, ws in level:
                lm.count[k][tuple(h)] = Counter({w: c for w, c in ws})
        return lm.finalize()

    def save(self, path: Path):
        with gzip.open(path, 'wt') as handle:
            json.dump(self.to_json(), handle, separators=(',', ':'))

    @classmethod
    def load(cls, path: Path) -> 'CountTokenLM':
        with gzip.open(path, 'rt') as handle:
            return cls.from_json(json.load(handle))


NR_EXECVE = 59


def has_execve(grams) -> bool:
    """A process image changed in this window: some event of the window is an execve (its last token slot)."""
    return any(call_of(int(gram[3])) == NR_EXECVE for gram in grams if int(gram[3]) != TOK_NONE)


class TokenBranch:
    """Online token branch for the worker. spec (worker cfg tokens.models): {workload_key: {"lm": path,
    "lm_sha256": hex, "threshold": float}}; a workload without a model gets no token score. One window above its
    workload's threshold is a token alert (the lidds-ml-v3 rule: one window fires).

    gate (worker cfg tokens.gate, protocol lidds-ml-v5), optional: {"pool": {"lm": path, "lm_sha256": hex},
    "exec_hold_seconds": float}, with "pool_threshold" per workload in spec. The alert then also needs the window to be
    surprising to the model of all workloads together (score above pool_threshold) and to lie more than
    exec_hold_seconds after the container's last execve. With "phase_threshold" (amendment 1) a window within those
    seconds is not held but compared with that threshold instead."""

    def __init__(self, spec: dict, sha256_file, gate: dict | None = None):
        self.models, self.thresholds = {}, {}
        self.pool, self.pool_thresholds, self.hold, self.last_exec = None, {}, 0.0, {}
        self.phase_threshold = None
        if gate:
            path = Path(gate['pool']['lm'])
            if sha256_file(path) != gate['pool']['lm_sha256']:
                raise ValueError('token pool model changed')
            self.pool = CountTokenLM.load(path)
            self.hold = float(gate['exec_hold_seconds'])
            if gate.get('phase_threshold') is not None:
                self.phase_threshold = float(gate['phase_threshold'])
                if not math.isfinite(self.phase_threshold):
                    raise ValueError('token phase threshold is not finite')
            self.pool_thresholds = {key: float(item['pool_threshold']) for key, item in spec.items()}
            if not all(math.isfinite(t) for t in self.pool_thresholds.values()):
                raise ValueError('token pool threshold is not finite')
        for key, item in spec.items():
            path = Path(item['lm'])
            if sha256_file(path) != item['lm_sha256']:
                raise ValueError(f'token model of {key} changed')
            self.models[key] = CountTokenLM.load(path)
            self.thresholds[key] = float(item['threshold'])
            if not math.isfinite(self.thresholds[key]):
                raise ValueError(f'token threshold of {key} is not finite')

    def score(self, window: dict):
        lm = self.models.get(window['workload_key'])
        if lm is None:
            return None
        s = lm.window_score(window['grams'])
        raw = bool(s > self.thresholds[window['workload_key']])
        out = dict(token_score=s, token_threshold=self.thresholds[window['workload_key']], token_alert=raw)
        if self.pool is None:
            return out
        key = (window['pod_uid'], window['container_name'])
        if has_execve(window['grams']):
            self.last_exec[key] = window['window_end']
        held = window['window_end'] - self.last_exec.get(key, -math.inf) <= self.hold
        pool_score = self.pool.window_score(window['grams'])
        threshold = self.pool_thresholds[window['workload_key']]
        passes = (pool_score > self.phase_threshold) if held and self.phase_threshold is not None else (
            pool_score > threshold and not held)
        out.update(token_alert=bool(raw and passes), token_alert_raw=raw,
                   token_pool_score=pool_score, token_pool_threshold=threshold, token_exec_held=held)
        return out
