import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import test_lidds_evaluate_v2 as base  # noqa: E402
spec = importlib.util.spec_from_file_location('tv', ROOT / 'scripts' / 'analysis' / 'lidds_ml_token_variants.py')
tv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tv)


def test_variant_tokens():
    args = 'fd=4(<f>/etc/ssl/x) name=/etc/ssl/x flags=1(O_RDONLY)'
    assert tv.vtoken('openat', args, None, 'nginx', tv.VARIANTS['base']) == 'openat:r:/etc'
    assert tv.vtoken('openat', args, None, 'nginx', tv.VARIANTS['path2']) == 'openat:r:/etc/ssl'
    assert tv.vtoken('read', 'res=70000 data=A', None, 'nginx', tv.VARIANTS['size1']) == 'read#15'
    assert tv.vtoken('read', 'res=100 data=A', '4t', 'nginx', tv.VARIANTS['fd']) == 'read@4t#3'
    assert tv.vtoken('read', 'res=100 data=A', None, 'nginx', tv.VARIANTS['proc']) == 'nginx|read#3'


def test_fd_type_comes_from_the_entry_line():
    lines = ['1000000000 0 1 p 7 read > fd=23(<4t>1.1.1.1:5->2.2.2.2:6) size=10',
             '1000000100 0 1 p 7 read < res=100 data=A',
             '1000000200 0 1 p 7 read > fd=5(<f>/x) size=10',
             '1000000300 0 1 p 7 read < res=100 data=A']
    per = tv.variant_windows(lines, tv.VARIANTS['fd'])
    grams = [g for v in per.values() for g in v]
    assert grams[0][-1] == 'read@4t#3' and grams[1][-1] == 'read@f#3'


def test_end_to_end_scores_each_variant(tmp_path):
    archive = base._archive(tmp_path)
    out, meta = tv.evaluate(archive, ('base', 'fd'))
    assert sum(k.startswith('val/') for k in out) == 45 and len(meta) == 16
    k = next(n for n in meta)
    assert out[k].shape[1] == 3                  # window_end, base, fd
