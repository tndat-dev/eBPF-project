import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import test_lidds_evaluate_v2 as base  # noqa: E402
import lidds_ml_tokens as tk  # noqa: E402
spec = importlib.util.spec_from_file_location('ta', ROOT / 'scripts' / 'analysis' / 'lidds_ml_token_alphabets.py')
ta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ta)
LINES = ['1000000000 0 1 p 7 openat > dirfd=-100 name=/etc/x flags=1(O_RDONLY) mode=0',
         '1000000100 0 1 p 7 openat < fd=4(<f>/etc/x) dirfd=-100 name=/etc/x flags=1(O_RDONLY) mode=0',
         '1000000200 0 1 p 7 openat > dirfd=-100 name=/etc/y flags=1(O_RDONLY) mode=0',
         '1000000300 0 1 p 7 openat < fd=-2(ENOENT) dirfd=-100 name=/etc/y flags=1(O_RDONLY) mode=0',
         '1000000400 0 1 p 7 read > fd=4(<f>/etc/x) size=4096',
         '1000000500 0 1 p 7 read < res=100 data=A',
         '1000000600 0 1 p 7 mmap > addr=0 length=10',
         '1000000700 0 1 p 7 mmap < res=-12(ENOMEM)']


def last_tokens(alphabet):
    per = ta.alphabet_windows(LINES, (alphabet,))[alphabet]
    return [g[-1] for v in per.values() for g in v]


def test_full_matches_the_token_of_the_registered_model():
    exits = [ln.split(' ', 7) for ln in LINES if ' < ' in ln]
    assert last_tokens('full') == [tk.token(p[5], p[7]) for p in exits]


def test_each_alphabet_holds_only_what_its_probe_collects():
    assert last_tokens('name') == ['openat', 'openat', 'read', 'mmap']
    assert last_tokens('open_only') == ['openat:r:/etc', 'openat', 'read', 'mmap']
    assert last_tokens('open_err') == ['openat:r:/etc', 'openat!ENOENT', 'read', 'mmap']
    assert last_tokens('open_err_req') == ['openat:r:/etc', 'openat!ENOENT', 'read#6', 'mmap']
    assert last_tokens('noerr') == ['openat:r:/etc', 'openat', 'read#3', 'mmap']
    assert last_tokens('nosize') == ['openat:r:/etc', 'openat!ENOENT', 'read', 'mmap!ENOMEM']
    assert last_tokens('noopen') == ['openat', 'openat!ENOENT', 'read#3', 'mmap!ENOMEM']
    assert last_tokens('req')[2] == 'read#6'


def test_end_to_end_skips_recordings_not_wanted(tmp_path):
    archive = base._archive(tmp_path)
    out, meta = ta.evaluate(archive, ('full', 'name'), wanted=lambda name, split: split == 'test-normal')
    assert all(m['split'] == 'test-normal' for m in meta.values()) and sum(k.startswith('val/') for k in out) == 45
    assert out[next(iter(meta))].shape[1] == 3


def test_full_scores_equal_the_token_model(tmp_path):
    archive = base._archive(tmp_path)
    out, meta = ta.evaluate(archive, ('full',))
    ref, _ = tk.evaluate(archive)
    i = tk.COLUMNS.index('top10'); e = tk.COLUMNS.index('window_end')
    for k, a in ref.items():
        assert {float(w): round(float(x), 9) for w, x in zip(a[:, e], a[:, i]) if x} == {float(w): round(float(x), 9) for w, x in out[k] if x}
