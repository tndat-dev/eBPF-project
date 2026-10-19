import hashlib
import importlib.util
import json
from pathlib import Path

from sentinel_pulse.attack.confirmation_study import scored_rows
from sentinel_pulse.common import open_sealed, sealed_sha256
from sentinel_pulse.syscall_study.matched_holdout import bounds

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('compressor', ROOT/'scripts/compress_raw_frames.py')
compressor = importlib.util.module_from_spec(spec); spec.loader.exec_module(compressor)


def _segment(tmp_path):
    seg = tmp_path/'workers'/'w1'/'segments'/'s00001'
    seg.mkdir(parents=True)
    features = [json.dumps(dict(window_start=10.0 + i, window_end=10.5 + i, workload_key='w')) for i in range(50)]
    decisions = [json.dumps(dict(status='candidate-raw-score-only', policy_evaluated=True, joint_p=0.5,
                                 candidate_manifest_sha256='m', policy_sha256='p', window_start=10.0 + i,
                                 window_end=10.5 + i, workload_key='w', node_name='w1', pod_uid='u',
                                 container_name='c', workload_revision='r', cgroup_id=1)) for i in range(50)]
    (seg/'features.jsonl').write_text('\n'.join(features) + '\n')
    (seg/'decisions.jsonl').write_text('\n'.join(decisions) + '\n')
    seals = {n: hashlib.sha256((seg/n).read_bytes()).hexdigest() for n in ('features.jsonl', 'decisions.jsonl')}
    (seg/'TERMINAL.json').write_text(json.dumps(dict(seals=seals)))
    return seg, seals


def test_compressed_segment_reads_back_identically(tmp_path):
    seg, seals = _segment(tmp_path)
    plain_bounds = bounds(seg/'features.jsonl')
    plain_rows = list(scored_rows(tmp_path/'workers'/'w1', 'm', 'p'))
    plain_text = (seg/'decisions.jsonl').read_text()
    results = compressor.compress(seg, ['features.jsonl', 'decisions.jsonl'])
    assert [r['status'] for r in results] == ['compressed', 'compressed']
    assert not (seg/'features.jsonl').exists() and (seg/'features.jsonl.gz').exists()
    assert sealed_sha256(seg/'features.jsonl') == seals['features.jsonl']
    assert bounds(seg/'features.jsonl') == plain_bounds == (10.0, 59.5)
    with open_sealed(seg/'decisions.jsonl') as stream:
        assert stream.read() == plain_text
    assert list(scored_rows(tmp_path/'workers'/'w1', 'm', 'p')) == plain_rows


def test_seal_mismatch_keeps_the_original(tmp_path):
    seg, _ = _segment(tmp_path)
    (seg/'TERMINAL.json').write_text(json.dumps(dict(seals={'features.jsonl': '0'*64})))
    results = compressor.compress(seg, ['features.jsonl'])
    assert results[0]['status'] == 'seal_mismatch_kept_original'
    assert (seg/'features.jsonl').exists() and not (seg/'features.jsonl.gz').exists()
