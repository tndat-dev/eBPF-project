import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import test_lidds_evaluate_v2 as base  # noqa: E402
spec = importlib.util.spec_from_file_location('ti', ROOT / 'scripts' / 'analysis' / 'lidds_ml_token_inventory.py')
ti = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ti)


def test_kind_and_novel_counts_windows_after_the_exploit():
    assert [ti.kind(t) for t in ('openat!ENOENT', 'openat:r:/etc', 'read#3', 'mmap')] == ['err', 'open', 'size', 'name']
    per = {1.0: [('a', 'b', 'c', 'read#3')], 2.0: [('a', 'b', 'c', 'openat!ENOENT'), ('b', 'c', 'd', 'mmap')]}
    seen_t, seen_g = {'read#3', 'mmap'}, {('a', 'b', 'c', 'read#3')}
    assert ti.novel(per, seen_t, seen_g) == {('openat', 'err'): 1, ('mmap', 'name'): 1}
    assert ti.novel(per, seen_t, seen_g, after=2.0) == {}


def test_end_to_end_keeps_only_wanted_recordings(tmp_path):
    out, nt, ng = ti.evaluate(base._archive(tmp_path), lambda name, split: split == 'test-normal_and_attack')
    assert out and all(r['split'] == 'test-normal_and_attack' for r in out.values()) and nt > 0
