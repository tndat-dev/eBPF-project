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


def test_phase_maxima_read_only_benign_launches_within_the_phase():
    import token_phase_threshold as tp
    tok = lambda nr: nr << 23
    pool = CountTokenLM()
    pool.learn_window([[TOK_NONE, TOK_NONE, tok(1), tok(2), 50]])
    pool.finalize()
    base = dict(pod_uid='p', container_name='c')
    odd = [TOK_NONE, TOK_NONE, tok(7), tok(8), 5]
    launch = [odd, [TOK_NONE, TOK_NONE, tok(7), tok(59), 1]]
    windows = [dict(base, window_end=100.5, grams=launch),      # execve inside the benign launch
               dict(base, window_end=103.0, grams=odd),         # the launch, after the phase
               dict(base, window_end=200.5, grams=launch)]      # execve outside any benign launch
    maxima = tp.launch_maxima(windows, {('p', 'c'): [100.0]}, pool, 1.0)
    assert list(maxima) == [('p', 'c', 100.0)]
    assert maxima[('p', 'c', 100.0)] == pool.window_score(launch)
