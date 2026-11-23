"""Cross-fitted token branch on the cluster (lidds-ml-v4): folds by time chunks, final model on every window, held-out scores."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import token_branch_fit as f  # noqa: E402
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM  # noqa: E402

COMMON = [[TOK_NONE, TOK_NONE, 1 << 23, 2 << 23, 50], [TOK_NONE, 1 << 23, 2 << 23, 3 << 23, 50]]
RARE = [[3 << 23, 4 << 23, 5 << 23, 6 << 23, 20]]
START, CHUNK = 1000.0, 100.0


def write(path, rare_chunk=0, chunks=10):
    rows = []
    with open(path, 'w') as out:
        for c in range(chunks):
            for t in range(10):
                end = START + c * CHUNK + t * CHUNK / 10
                grams = COMMON + (RARE if c == rare_chunk else [])
                row = dict(window_end=end, workload_key='w', pod_uid='p', container_name='c', grams=grams)
                rows.append(row)
                out.write(json.dumps(row) + '\n')
    return rows


def test_folds_are_contiguous_chunks_dealt_in_turn():
    assert f.fold_of(START, START, CHUNK, 5) == 0
    assert f.fold_of(START + CHUNK - 1, START, CHUNK, 5) == 0
    assert f.fold_of(START + CHUNK, START, CHUNK, 5) == 1
    assert f.fold_of(START + 5 * CHUNK, START, CHUNK, 5) == 0


def test_final_model_equals_learning_every_window(tmp_path):
    rows = write(tmp_path / 'w.jsonl')
    final, _, windows = f.crossfit_one(str(tmp_path / 'w.jsonl'), START, START + 10 * CHUNK, 60.0, 5, CHUNK)
    direct = CountTokenLM()
    for row in rows:
        direct.learn_window(row['grams'])
    direct.finalize()
    assert windows == len(rows)
    assert final.to_json()['total'] == direct.to_json()['total']
    assert final.count[3] == direct.count[3] and final.given == direct.given and final.names == direct.names


def test_held_out_blocks_are_scored_without_their_own_fold(tmp_path):
    """A gram only in chunk 0 (fold 0) is unknown to the model that scores fold 0, and known to the final model."""
    rows = write(tmp_path / 'w.jsonl')
    final, maxima, _ = f.crossfit_one(str(tmp_path / 'w.jsonl'), START, START + 10 * CHUNK, 60.0, 5, CHUNK)
    rare_cell = ('p', 'c', int(rows[0]['window_end'] // 60))
    common_cell = ('p', 'c', int((START + 3 * CHUNK) // 60))
    assert maxima[rare_cell] > maxima[common_cell]
    assert maxima[rare_cell] > final.window_score(rows[0]['grams'])
    assert not list(tmp_path.glob('*.f[0-9]'))


def test_trim_drops_at_least_the_largest_maximum():
    x = list(range(1, 100)) + [100000.0]
    assert f.trimmed_gumbel(x) == f.gumbel(list(range(1, 100)))


def test_split_adds_the_extra_run_without_its_trials(tmp_path):
    def run(name, rows):
        seg = tmp_path / name / 'workers' / 'n' / 'segments' / 's00001'
        seg.mkdir(parents=True)
        (seg / 'tokens.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
        return tmp_path / name
    row = lambda end, pod='p': dict(window_end=end, workload_key='w', pod_uid=pod, container_name='c', grams=COMMON)
    capture = run('capture', [row(10.0), row(99.0), row(100.0)])
    live = run('live', [row(150.0), row(994.9), row(995.0), row(1010.0), row(1024.9), row(1025.0), row(1010.0, 'other'), row(2000.0)])
    camp = live / 'pulse-development-matrix'
    camp.mkdir()
    (camp / 'INTERVALS.jsonl').write_text(json.dumps(dict(pod_uid='p', container_name='c', start_at=1000.0)) + '\n')
    spans = f.trial_spans(camp)
    assert spans == {('p', 'c'): [(995.0, 1025.0)]}
    work = tmp_path / 'work'
    work.mkdir()
    names = f.split([(capture, 0.0, 100.0, None), (live, 200.0, 2000.0, spans)], work)
    kept = [(json.loads(l)['window_end'], json.loads(l)['pod_uid']) for l in names['w'].read_text().splitlines()]
    assert kept == [(10.0, 'p'), (99.0, 'p'), (994.9, 'p'), (1025.0, 'p'), (1010.0, 'other')]


def test_dump_maxima_writes_the_blocks_the_threshold_uses(tmp_path):
    write(tmp_path / 'w.jsonl')
    out, dump = tmp_path / 'out', tmp_path / 'dump'
    out.mkdir()
    dump.mkdir()
    job = ('w', str(tmp_path / 'w.jsonl'), (START, START + 500), (START + 500, START + 10 * CHUNK), 0.0002, 60.0, 2,
           str(out), 5, CHUNK, 0.9, str(dump))
    key, row, entry = f.fit_crossfit(job)
    doc = json.loads(next(dump.glob('*.maxima.json')).read_text())
    blocks = [b[-1] for b in doc['blocks']]
    assert doc['workload'] == 'w' and len(blocks) == row['validation_blocks']
    assert abs(f.threshold(f.trimmed_gumbel(blocks), 0.0002 * 0.9) - entry['threshold']) < 1e-12
    _, row2, entry2 = f.fit_crossfit(job[:-1])                 # without the dump: same threshold, nothing written
    assert entry2['threshold'] == entry['threshold']


def test_crossfit_span_takes_an_extra_normal_before_or_after_the_capture():
    import pytest
    assert f.crossfit_span((100, 180), (180, 220), (300, 400)) == ([100, 180], [180, 400])    # v5: later live run
    assert f.crossfit_span((100, 180), (180, 220), (10, 90)) == ([10, 180], [180, 220])       # v6: earlier live run
    with pytest.raises(ValueError):
        f.crossfit_span((100, 180), (180, 220), (150, 300))


def test_an_earlier_extra_normal_is_learnt_and_held_out(tmp_path):
    path = tmp_path / 'w.jsonl'
    rows = [dict(window_end=e, workload_key='w', pod_uid='p', container_name='c', grams=COMMON) for e in (50.0, 1050.0)]
    path.write_text(''.join(json.dumps(r) + '\n' for r in rows))
    train, validation = f.crossfit_span((1000.0, 1040.0), (1040.0, 1100.0), (0.0, 100.0))
    _, maxima, windows = f.crossfit_one(str(path), train[0], validation[1], 60.0, 5, 30.0)
    assert windows == 2 and ('p', 'c', 0) in maxima


def test_top_and_trim_reach_the_threshold_and_the_spec(tmp_path):
    """lidds-ml-v5-t3: the held-out maxima use the window score at top-k, the Gumbel drops `trim`, MODELS.json gets "top"."""
    write(tmp_path / 'w.jsonl')
    out = tmp_path / 'out'
    out.mkdir()
    base = ('w', str(tmp_path / 'w.jsonl'), (START, START + 500), (START + 500, START + 10 * CHUNK), 0.0003, 60.0, 2,
            str(out), 5, CHUNK, 1.0, None)
    _, row, entry = f.fit_crossfit(base + (3, 0.005))
    _, maxima, _ = f.crossfit_one(str(tmp_path / 'w.jsonl'), START, START + 10 * CHUNK, 60.0, 5, CHUNK, 3)
    assert entry['top'] == 3
    assert abs(f.threshold(f.trimmed_gumbel(list(maxima.values()), 0.005), 0.0003) - entry['threshold']) < 1e-12
    _, _, default = f.fit_crossfit(base)
    assert 'top' not in default


def test_split_keeps_one_lineage_part_and_pools_workloads(tmp_path):
    # session-stream-v1: --part session keeps the session grams (empty parts dropped), --part native the rest;
    # --pool-key writes every workload into one file
    run = tmp_path / 'run'
    seg = run / 'workers' / 'n' / 'segments' / 's00001'
    seg.mkdir(parents=True)
    rows = [dict(window_end=10.0, workload_key='a', pod_uid='p', container_name='c', grams=COMMON + RARE, session=RARE),
            dict(window_end=11.0, workload_key='b', pod_uid='q', container_name='c', grams=COMMON, session=[])]
    (seg / 'tokens.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    work = tmp_path / 'work'; work.mkdir()
    names = f.split([(run, 0.0, 100.0, None)], work, 'session', 'pool/session')
    assert list(names) == ['pool/session']
    kept = [json.loads(l) for l in open(names['pool/session'])]
    assert [r['grams'] for r in kept] == [RARE] and 'session' not in kept[0]
    work2 = tmp_path / 'work2'; work2.mkdir()
    names = f.split([(run, 0.0, 100.0, None)], work2, 'native')
    native = {k: [json.loads(l)['grams'] for l in open(v)] for k, v in names.items()}
    assert sorted(map(tuple, map(tuple, native['a'][0]))) == sorted(map(tuple, COMMON)) and native['b'] == [COMMON]


def test_split_skips_segments_that_start_after_the_span(tmp_path, monkeypatch):
    run = tmp_path / 'run'
    for name, ends in (('s00001', (10.0, 20.0)), ('s00002', (150.0, 160.0))):
        seg = run / 'workers' / 'n' / 'segments' / name
        seg.mkdir(parents=True)
        (seg / 'tokens.jsonl').write_text(''.join(json.dumps(dict(window_end=e, workload_key='w', pod_uid='p',
                                                                   container_name='c', grams=COMMON)) + '\n' for e in ends))
    work = tmp_path / 'work'; work.mkdir()
    names = f.split([(run, 0.0, 100.0, None)], work)
    assert [json.loads(l)['window_end'] for l in open(names['w'])] == [10.0, 20.0]


def test_dump_load_keeps_block_maxima_per_event_class_and_the_event_counts(tmp_path):
    write(tmp_path / 'w.jsonl')
    out, dump, load = tmp_path / 'out', tmp_path / 'dump', tmp_path / 'load'
    for d in (out, dump, load):
        d.mkdir()
    job = ('w', str(tmp_path / 'w.jsonl'), (START, START + 500), (START + 500, START + 10 * CHUNK), 0.0002, 60.0, 2,
           str(out), 5, CHUNK, 0.9, str(dump), 10, 0.01, str(load))
    _, row, _ = f.fit_crossfit(job)
    doc = json.loads(next(load.glob('*.load.json')).read_text())
    maxima = {tuple(b[:3]): b[-1] for b in json.loads(next(dump.glob('*.maxima.json')).read_text())['blocks']}
    assert len(doc['blocks']) == row['validation_blocks'] and sum(doc['events'].values()) == 100
    for *cell, classes in doc['blocks']:                     # the classes' maximum is the block maximum
        assert abs(max(classes.values()) - maxima[tuple(cell)]) < 1e-12
    assert set(doc['events']) == {'100', '120'}               # COMMON = 100 events; + RARE = 120
