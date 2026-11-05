import importlib.util
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import test_lidds_evaluate_v2 as base  # noqa: E402
spec = importlib.util.spec_from_file_location('mltok', ROOT / 'scripts' / 'analysis' / 'lidds_ml_tokens.py')
tk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tk)


def test_tokens_carry_error_size_and_directory():
    assert tk.token('openat', 'fd=-2(ENOENT) name=/x flags=1(O_RDONLY)') == 'openat!ENOENT'
    assert tk.token('openat', 'fd=4(<f>/etc/passwd) name=/etc/passwd flags=1(O_RDONLY)') == 'openat:r:/etc'
    assert tk.token('openat', 'fd=4(<f>/srv/a/b) name=/srv/a/b flags=577(O_TRUNC|O_CREAT|O_WRONLY)') == 'openat:w:/srv'
    assert tk.token('read', 'res=70000 data=AA') == 'read#7'       # log2 bucket capped at 15, halved
    assert tk.token('read', 'res=100 data=AA') == 'read#3'
    assert tk.token('futex', 'res=0') == 'futex'


def test_unseen_token_is_graded_by_its_syscall_and_never_zero():
    lm = tk.TokenLM(n=3)
    grams = [('read#3', 'write#3', 'read#3'), ('write#3', 'read#3', 'write#3'), ('read#3', 'read#4', 'write#3')] * 200
    lm.learn(grams); lm.finalize()
    known_call = lm.prob(('read#3', 'write#3', 'read#8'))       # read is common, this size is new
    unknown_call = lm.prob(('read#3', 'write#3', 'ptrace'))     # the call itself is new
    seen = lm.prob(('read#3', 'write#3', 'read#3'))
    assert seen > known_call > unknown_call > 0


def test_recording_windows_score_events_and_count_unseen_grams():
    lines = [f'{1000000000 + i * 1000} 0 1 p 7 read < res=100 data=AA' for i in range(50)]
    lines += ['1600000000 0 1 p 7 openat < fd=4(<f>/etc/passwd) name=/etc/passwd flags=1(O_RDONLY)']
    per = tk.window_tokens(lines, n=3)
    lm = tk.TokenLM(n=3)
    first = sorted(per)[0]
    lm.learn(per[first]); lm.finalize()
    rows = tk.window_scores(per, lm)
    assert rows.shape[1] == len(tk.COLUMNS) and rows.shape[0] == len(per)
    assert rows[-1, tk.COLUMNS.index('top10')] > rows[0, tk.COLUMNS.index('top10')]
    assert rows[-1, tk.COLUMNS.index('unseen_grams')] >= 1 and rows[0, tk.COLUMNS.index('unseen_grams')] == 0


def test_end_to_end_writes_validation_and_test_matrices(tmp_path):
    archive = base._archive(tmp_path)
    out, meta = tk.evaluate(archive)
    assert sum(k.startswith('val/') for k in out) == 45 and len(meta) == 16
    assert all(v.shape[1] == len(tk.COLUMNS) for v in out.values())
    attack = [n for n, r in meta.items() if r['exploit']][0]
    before = out[attack][out[attack][:, 0] <= meta[attack]['exploit'], 1].max()
    after = out[attack][out[attack][:, 0] > meta[attack]['exploit'], 1].max()
    assert after > before                                       # the /etc write and the 64 KiB send stand out


def test_base_name_only_reads_the_head_of_a_token():
    assert tk.base_name('openat:r:/a|b@c') == 'openat'
    assert tk.base_name('nginx|read@4t#3') == 'read'
    assert tk.base_name('futex') == 'futex'
    assert tk.base_name('connect!ENOENT') == 'connect'

