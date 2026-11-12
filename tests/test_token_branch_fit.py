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
