"""Evidence discount by peer novelty in the live path (Pulse 5.22 lever L5, adopted blind in 5.25)."""
import importlib.util
import json
import time
from pathlib import Path

import numpy as np
import pytest

from test_recalibrated_candidate import KEY, _candidate, _policy, _stream

from sentinel_pulse.attack import window_table
from sentinel_pulse.detector import novelty
from sentinel_pulse.detector.candidate_policy import load_preview_policy
from sentinel_pulse.detector.idle_candidate import IdleCandidateScorer
from sentinel_pulse.pipeline.peer_exchange import PeerExchange

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('burden_levers', ROOT/'scripts'/'analysis'/'burden_levers.py')
bl = importlib.util.module_from_spec(spec); spec.loader.exec_module(bl)


def test_offline_table_and_live_path_share_one_definition():
    assert window_table.Signals is novelty.Signals and window_table.id_mask is novelty.id_mask


def _windows(seed=3, seconds=120):
    """Two nodes, one workload with two replicas on node A and one on node B, plus a workload without a model.
    Node A frames end on the half second, node B frames 0.25 s later (no ties in the merged stream)."""
    rng = np.random.default_rng(seed)
    containers = [('A', 'p1', 'W'), ('A', 'p2', 'W'), ('B', 'p3', 'W'), ('A', 'p4', 'X')]
    rows = []
    for k in range(int(seconds / .5)):
        for node, pod, workload in containers:
            end = 100 + .5 * k + (.25 if node == 'B' else 0)
            counts = {str(i): 1 for i in rng.choice([0, 1, 3, 9, 13, 202], size=rng.integers(1, 4), replace=False)}
            if rng.random() < .03:                       # a rare ID that the other replicas never show
                counts[str(int(rng.choice([59, 101, 308])))] = 1
            rows.append(dict(workload_key=f'production/{workload}', node_name=node, pod_uid=pod,
                             container_name='app', workload_revision='r', cgroup_id=pod,
                             window_start=end - .5, window_end=end, full_counts_delta=counts))
    return sorted(rows, key=lambda r: r['window_end'])        # stable: node order within one end


def test_two_workers_exchanging_masks_reproduce_the_offline_values():
    rows = _windows()
    modelled = {'production/W'}
    offline = novelty.Signals(peer=(30.0,), self_=())
    expected = []
    for r in rows:
        if r['workload_key'] not in modelled:
            continue
        res = offline.observe(novelty.PeerNovelty.identity(r), r['workload_key'], r['window_start'], r['window_end'],
                              novelty.id_mask(r['full_counts_delta']), True)
        expected.append(res['novel_peer30'])
    live = {'A': novelty.PeerNovelty(modelled, 30.0), 'B': novelty.PeerNovelty(modelled, 30.0)}
    sent = {'A': [], 'B': []}
    got = []
    for r in rows:                                     # each frame: deliver what the other worker already sent
        me, other = r['node_name'], 'B' if r['node_name'] == 'A' else 'A'
        for message in sent[other]:
            live[me].remote(message)
        sent[other] = []
        value = live[me].local(r)
        sent[me].extend(live[me].drain_outbox())
        if value is not None:
            got.append(value)
    assert got == expected
    assert 0 in got and any(v > 0 for v in got)        # both discounted and kept windows occur


def test_a_workload_without_a_model_or_without_other_replicas():
    live = novelty.PeerNovelty({'production/W'}, 30.0)
    row = dict(workload_key='production/X', node_name='A', pod_uid='p', container_name='c', workload_revision='r',
               cgroup_id='1', window_start=1.0, window_end=1.5, full_counts_delta={'0': 1})
    assert live.local(row) is None and live.drain_outbox() == []
    assert live.local(dict(row, workload_key='production/W')) == -1          # no other replica seen: keep
    assert len(live.drain_outbox()) == 1


def _discount_policy(tmp_path, digest, discount=None, **rule):
    path = _policy(tmp_path, digest, k=2, n=2, scale=5.0)
    data = json.loads(path.read_text())
    data['rule']['evidence_discount'] = discount or {'kind': 'peer_novelty', 'seconds': 30}
    data['rule'].update(rule)
    path.write_text(json.dumps(data))
    return path


def test_policy_with_discount_matches_the_offline_k2of2_lever(tmp_path):
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    policy = load_preview_policy(_discount_policy(tmp_path, digest), scorer)
    alpha = scorer.models[KEY].alpha
    rows = _stream()
    rng = np.random.default_rng(11)
    novel = rng.choice([-1, 0, 0, 1, 2], size=len(rows))
    live = []
    for r, n in zip(rows, novel):
        score = dict(status='candidate-raw-score-only', workload_key=KEY, joint_p=r['joint_p'], tree_p=r['tree_p'],
                     support_p=r['support_p'], raw_model_anomaly=r['joint_p'] <= alpha)
        ctx = dict(workload_key=KEY, pod_uid='u', container_name='app', workload_revision='r', cgroup_id='1',
                   window_start=r['start'], window_end=r['end'], novel_peer=int(n))
        out = policy.evaluate(score, ctx)
        assert out['evidence_discounted'] == (n == 0) and out['novel_peer'] == n
        live.append(out['candidate_alert_preview'])
    start = np.array([r['start'] for r in rows]); end = np.array([r['end'] for r in rows])
    joint = np.array([r['joint_p'] for r in rows])
    offline = bl.kofn2((joint <= alpha * 5.0) & ~(novel == 0), bl.segments(np.zeros(len(rows)), start, end))
    assert live == offline.tolist()
    assert any(live) and (np.array(live) != bl.kofn2(joint <= alpha * 5.0,
                                                     bl.segments(np.zeros(len(rows)), start, end))).any()


def test_discount_form_is_strict_and_needs_the_novelty(tmp_path):
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    for bad in ({'kind': 'peer_novelty'}, {'kind': 'self_novelty', 'seconds': 30},
                {'kind': 'peer_novelty', 'seconds': 30, 'extra': 1}, {'kind': 'peer_novelty', 'seconds': 0}):
        with pytest.raises(ValueError, match='evidence_discount'):
            load_preview_policy(_discount_policy(tmp_path, digest, bad), scorer)
    policy = load_preview_policy(_discount_policy(tmp_path, digest), scorer)
    score = dict(status='candidate-raw-score-only', workload_key=KEY, joint_p=.5, raw_model_anomaly=False)
    ctx = dict(workload_key=KEY, pod_uid='u', container_name='app', workload_revision='r', cgroup_id='1',
               window_start=1.0, window_end=1.5)
    with pytest.raises(ValueError, match='peer novelty'):
        policy.evaluate(score, ctx)


def test_exchange_delivers_published_windows_to_a_subscriber():
    a = PeerExchange(('127.0.0.1', 0), []).start()
    b = PeerExchange(('127.0.0.1', 0), [a.listen], retry_seconds=.2).start()
    try:
        deadline = time.time() + 5
        while not a.stats()['subscribers'] and time.time() < deadline:
            time.sleep(.02)
        messages = [dict(i=['production/W', 'A', 'p', 'app', 'r', '1'], s=1.0, e=1.5, m='3')] * 3
        a.publish(messages)
        got = []
        while len(got) < 3 and time.time() < deadline:
            got += b.drain(); time.sleep(.02)
        assert got == messages
        assert a.stats()['published'] == 3 and b.stats()['received'] == 3
        assert b.stats()['peers_connected'] == {f'127.0.0.1:{a.listen[1]}': True}
    finally:
        a.close(); b.close()
