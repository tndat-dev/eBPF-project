"""Per-run window table for the burden-reduction study (protocol burden-reduction-v1 + amendment 1).

One pass over a run's sealed segments (all workers merged in window_end order) joins every scored, bound
decision row with its feature row and keeps, per scored window: identity, scores, as-run p-values, alpha, and
the context signals the levers need:

- ``launch``: execve (59) or execveat (322) in the context;
- ``novel_peer_T``: syscall IDs of the context that no OTHER replica of the same workload showed in the last
  T seconds (-1: no other replica had a window in that span);
- ``novel_self_T``: syscall IDs of the context that the container did not show in its own windows from T
  seconds ago up to the start of the context (-1: the container has less than T seconds of history);
- ``preview``: the live policy's ``candidate_alert_preview`` of the window (what the run actually alerted on).

Context = current + up to 3 previous windows of the container, chained while each window starts where the
previous one ended (as the model's history). Every feature row counts as behaviour (idle and unscored windows
too); only scored windows are written. History spans are taken in whole 2 s buckets of window_end (a bucket
counts when it lies inside the span), so a span is at most 2 s shorter at each edge than T.
"""
from __future__ import annotations

import argparse
from array import array
from collections import defaultdict
import heapq
import json
from pathlib import Path
import time

import numpy as np

from ..common import open_sealed
from ..detector.confirmation import IDENTITY, SCORED
from ..syscall_study.matched_holdout import bounds

from ..detector.novelty import (BUCKET, CONTEXT, EXEC_IDS, EXEC_MASK, PEER_T, SELF_T,  # noqa: F401  (re-export)
                               Signals, id_mask)
FLOATS = ('start', 'end', 'tree_score', 'support_score', 'tree_p', 'support_p', 'joint_p', 'alpha')
SIGNALS = tuple(f'novel_peer{t:g}' for t in PEER_T) + tuple(f'novel_self{t:g}' for t in SELF_T)


VECTOR_FIELD = '"vector_f32_zlib_b64":"'
WORKLOAD_FIELD = '"workload_key":"'


def light_row(line, workloads):
    """A feature line parsed without its (unused) vector; None when its workload is not one being scored.
    Containers outside the scored workloads are about two thirds of the lines and never matter here."""
    a = line.find(WORKLOAD_FIELD)
    if a < 0:
        return None
    a += len(WORKLOAD_FIELD)
    if line[a:line.find('"', a)] not in workloads:
        return None
    v = line.find(VECTOR_FIELD)
    if v >= 0:
        line = line[:v] + '"_":0' + line[line.find('"', v + len(VECTOR_FIELD)) + 1:]
    return json.loads(line)


def worker_rows(root: Path, model_hash, policy_hash, begin, until, stats):
    """(window_end, window_start, identity, workload, ID mask, decision or None) of one worker, segment order."""
    for segment in sorted(p for p in (root / 'segments').iterdir() if p.is_dir()):
        first, last = bounds(segment / 'features.jsonl')
        if first is None or (until is not None and first > until) or (begin is not None and last < begin):
            continue
        decisions, workloads = {}, set()
        with open_sealed(segment / 'decisions.jsonl') as stream:
            for line in stream:
                if '"joint_p"' not in line:
                    continue
                r = json.loads(line)
                if r.get('status') != SCORED or r.get('policy_evaluated') is not True:
                    continue
                if r.get('candidate_manifest_sha256') != model_hash or r.get('policy_sha256') != policy_hash:
                    stats['mismatched_binding_rows'] += 1
                    continue
                workloads.add(r['workload_key'])
                key = (tuple(str(r.get(k)) for k in IDENTITY), float(r['window_end']))
                decisions[key] = (float(r['tree_score']), float(r['support_score']), float(r['tree_p']),
                                  float(r['support_p']), float(r['joint_p']), float(r['candidate_policy_alpha']),
                                  bool(r.get('eligible_for_normal_review')), bool(r.get('candidate_alert_preview')))
        with open_sealed(segment / 'features.jsonl') as stream:
            for line in stream:
                if '"full_counts_delta"' not in line:
                    continue
                r = light_row(line, workloads)
                if r is None:
                    continue
                end = float(r['window_end'])
                if (begin is not None and end < begin) or (until is not None and end > until):
                    continue
                ident = tuple(str(r.get(k)) for k in IDENTITY)
                stats['feature_rows'] += 1
                yield end, float(r['window_start']), ident, r['workload_key'], id_mask(r['full_counts_delta']), \
                    decisions.pop((ident, end), None)
        stats['decisions_without_features'] += len(decisions)
        stats['segments'] += 1


def build(roots, model_hash, policy_hash, since=None, until=None):
    stats = defaultdict(int)
    signals = Signals()
    begin = None if since is None else since - signals.horizon
    streams = [worker_rows(Path(r), model_hash, policy_hash, begin, until, stats) for r in roots]
    idents, workloads = {}, {}
    cols = {name: array('d') for name in FLOATS}
    cols.update(ident=array('i'), workload=array('h'), eligible=array('b'), launch=array('b'), preview=array('b'))
    cols.update({name: array('h') for name in SIGNALS})
    for end, start, ident, workload, mask, dec in heapq.merge(*streams, key=lambda row: row[0]):
        want = dec is not None and (since is None or start >= since)   # same span rule as scored_rows
        s = signals.observe(ident, workload, start, end, mask, want)
        if not want:
            continue
        stats['scored_rows'] += 1
        cols['ident'].append(idents.setdefault(ident, len(idents)))
        cols['workload'].append(workloads.setdefault(workload, len(workloads)))
        for name, value in zip(FLOATS, (start, end, *dec[:6])):
            cols[name].append(value)
        cols['eligible'].append(dec[6]); cols['launch'].append(s['launch']); cols['preview'].append(dec[7])
        for name in SIGNALS:
            cols[name].append(s[name])
    arrays = {name: np.frombuffer(col, dtype=col.typecode).copy() for name, col in cols.items()}
    meta = dict(schema='pulse-window-table-v1', roots=[str(r) for r in roots], model_hash=model_hash,
                policy_hash=policy_hash, since_unix=since, until_unix=until, bucket_seconds=signals.bucket,
                peer_seconds=list(signals.peer), self_seconds=list(signals.self_), context_windows=signals.context,
                identity_fields=list(IDENTITY), identities=[list(i) for i in sorted(idents, key=idents.get)],
                workloads=sorted(workloads, key=workloads.get), stats=dict(stats), built_at_unix=time.time())
    return arrays, meta


def save(path: Path, arrays, meta):
    partial = path.with_name(path.name + '.partial.npz')
    with partial.open('wb') as stream:
        np.savez(stream, meta=np.array(json.dumps(meta)), **arrays)
    partial.replace(path)


def load(path: Path):
    z = np.load(path, allow_pickle=False)
    return {k: z[k] for k in z.files if k != 'meta'}, json.loads(str(z['meta']))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--worker-root', type=Path, action='append', required=True)
    p.add_argument('--model-hash', required=True)
    p.add_argument('--policy-hash', required=True)
    p.add_argument('--since', type=float)
    p.add_argument('--until', type=float)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    arrays, meta = build(a.worker_root, a.model_hash, a.policy_hash, a.since, a.until)
    save(a.output, arrays, meta)
    print(json.dumps(dict(rows=int(len(arrays['end'])), identities=len(meta['identities']), stats=meta['stats'])))


if __name__ == '__main__':
    main()
