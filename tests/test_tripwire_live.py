"""Tripwire A1 in the live worker (sentinel_pulse/rules/tripwire.py) against the offline definition (novel_syscalls)."""
import json

import numpy as np
import pytest

from sentinel_pulse.detector.novelty import PeerNovelty, id_mask
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.rca.tree import trigger_kind
from sentinel_pulse.rules.tripwire import Tripwire, ids_of, load_exec_set

EXEC = {59, 322}
SPAN = (100.0, 160.0)


def _rows(seed=7, seconds=150):
    """Two nodes; workload W has replicas on both, X only on node A; a rare ID appears after the reference span."""
    rng = np.random.default_rng(seed)
    containers = [('A', 'p1', 'W'), ('B', 'p2', 'W'), ('A', 'p3', 'X')]
    rows = []
    for k in range(int(seconds / .5)):
        for node, pod, workload in containers:
            end = 100.5 + .5 * k + (.25 if node == 'B' else 0)
            ids = set(rng.choice([0, 1, 3, 9, 13, 202], size=rng.integers(1, 4), replace=False).tolist())
            if node == 'B' and end < 130:
                ids.add(101)                       # only the peer shows 101 inside the reference span
            if end > 225 and rng.random() < .05:
                ids.add(int(rng.choice([101, 308, 59, 56])))   # 101 is known (peer), 59 is exec, 308/56 are new
            rows.append(dict(workload_key=f'production/{workload}', node_name=node, pod_uid=pod, container_name='app',
                             workload_revision='r', cgroup_id=pod, window_start=end - .5, window_end=end,
                             full_counts_delta={str(i): 1 for i in ids}))
    return sorted(rows, key=lambda r: r['window_end'])


def _offline(rows, modelled):
    """novel_syscalls.py: reference = union of IDs per workload over windows inside the span; alert = ID outside
    the reference and the exec set."""
    ref = {}
    for r in rows:
        if SPAN[0] <= r['window_start'] and r['window_end'] <= SPAN[1]:
            ref.setdefault(r['workload_key'], set()).update(int(i) for i in r['full_counts_delta'])
    out = {}
    for r in rows:
        if r['workload_key'] in modelled and r['window_end'] >= SPAN[1] + 60:
            novel = {int(i) for i in r['full_counts_delta']} - ref.get(r['workload_key'], set()) - EXEC
            out[(r['node_name'], r['pod_uid'], r['window_end'])] = sorted(novel)
    return out


def test_two_workers_exchanging_masks_match_the_offline_tripwire():
    rows = _rows()
    modelled = {'production/W', 'production/X'}
    novelty = {n: PeerNovelty(modelled, 30.0) for n in 'AB'}
    trip = {n: Tripwire(modelled, EXEC, SPAN, grace_seconds=60.0) for n in 'AB'}
    sent = {'A': [], 'B': []}
    live = {}
    for r in rows:                                   # one frame per window end, as in the worker loop
        me, other = r['node_name'], 'B' if r['node_name'] == 'A' else 'A'
        now = r['window_end']
        for m in sent[other]:
            novelty[me].remote(m)
            trip[me].observe(m['i'][0], float(m['s']), float(m['e']), int(m['m'], 16), now, remote=True)
        sent[other] = []
        mask = id_mask(r['full_counts_delta'])
        trip[me].observe(r['workload_key'], r['window_start'], r['window_end'], mask, now)
        novelty[me].local(r)
        sent[me].extend(novelty[me].drain_outbox())
        fields = trip[me].judge(r['workload_key'], r['window_end'], mask)
        if fields and fields['tripwire_status'] == 'judged':
            live[(r['node_name'], r['pod_uid'], r['window_end'])] = fields['tripwire_novel_ids']
            assert fields['tripwire_alert'] == bool(fields['tripwire_novel_ids'])
    offline = _offline(rows, modelled)
    assert live == offline
    assert any(v for v in live.values()) and any(56 in v or 308 in v for v in live.values())
    assert not any(59 in v for v in live.values())                    # exec ID never alerts
    w = [v for (node, pod, _), v in live.items() if pod in ('p1', 'p2')]
    assert not any(101 in v for v in w)                              # known to W through its replica on B
    assert any(101 in v for (node, pod, _), v in live.items() if pod == 'p3')   # new for X (no peer showed it)
    assert trip['A'].stats['remote_reference_windows'] > 0 and trip['A'].stats['late_reference_windows'] == 0


def test_windows_before_the_reference_is_complete_are_not_judged():
    trip = Tripwire({'w'}, EXEC, SPAN, grace_seconds=60.0)
    trip.observe('w', 100.0, 100.5, 0b11, now=100.5)
    assert trip.judge('w', 150.0, 0b100) == dict(tripwire_status='reference_pending')
    assert trip.judge('w', 219.9, 0b100) == dict(tripwire_status='reference_pending')
    assert trip.judge('w', 220.0, 0b100) == dict(tripwire_status='judged', tripwire_alert=True, tripwire_novel_ids=[2])
    assert trip.judge('other', 300.0, 0b100) is None
    trip2 = Tripwire({'w', 'v'}, EXEC, SPAN)
    assert trip2.judge('v', 300.0, 1) == dict(tripwire_status='no_reference')
    trip.observe('w', 120.0, 120.5, 0b1000, now=230.0)               # a peer window of the span arriving late
    assert trip.stats['late_reference_windows'] == 1
    assert ids_of(0b1010001) == [0, 4, 6]


def test_exec_set_is_pinned_by_hash(tmp_path):
    f = tmp_path / 'E.json'
    f.write_text(json.dumps(['59', '322']))
    assert load_exec_set(f, sha256_file(f)) == {59, 322}
    with pytest.raises(ValueError, match='registered'):
        load_exec_set(f, '0' * 64)
    f.write_text('[]')
    with pytest.raises(ValueError, match='invalid'):
        load_exec_set(f)


def _row(**extra):
    base = dict(candidate_manifest_sha256='m', policy_sha256='p', status='candidate-raw-score-only', policy_evaluated=True,
                node_name='n', pod_uid='u', container_name='c', workload_key='production/w:c', window_end=100.0,
                candidate_alert_preview=False)
    base.update(extra)
    return base


def test_trigger_kind_accepts_tripwire_rows_and_keeps_preview_first():
    assert trigger_kind(_row(), 'm', 'p') is None
    assert trigger_kind(_row(candidate_alert_preview=True, tripwire_alert=True, tripwire_status='judged'), 'm', 'p') == \
        'candidate_alert_preview'
    assert trigger_kind(_row(tripwire_alert=True, tripwire_status='judged'), 'm', 'p') == 'tripwire_alert'
    warming = _row(status='warming', policy_evaluated=False, tripwire_alert=True, tripwire_status='judged')
    assert trigger_kind(warming, 'm', 'p') == 'tripwire_alert'       # the tripwire does not need a warm ML history
    assert trigger_kind(dict(warming, candidate_alert_preview=True), 'm', 'p') == 'tripwire_alert'
    assert trigger_kind(_row(tripwire_alert=True, tripwire_status='reference_pending'), 'm', 'p') is None
    assert trigger_kind(_row(tripwire_alert=True, tripwire_status='judged'), 'm', 'other') is None
