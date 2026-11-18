"""lidds2019_dev.py: the registered split rule and the fixed-level scenario wrapper."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'analysis'))
import lidds2019_dev as dev  # noqa: E402


def test_split_rule_is_the_registered_one():
    import hashlib
    for name in ('a_1', 'b_2', 'c_3', 'normal_99'):
        want = 'development' if int(hashlib.sha256(('lidds2019-development:' + name).encode()).hexdigest(), 16) % 10 < 3 else 'holdout'
        assert dev.part_of(name) == want


def test_split_share_is_about_thirty_percent():
    names = [f'rec_{i}' for i in range(5000)]
    share = sum(dev.part_of(n) == 'development' for n in names) / len(names)
    assert 0.27 < share < 0.33


def test_split_reads_test_recordings_only(tmp_path):
    recs = {'t1': dict(split='training'), 'v1': dict(split='validation'), 'n1': dict(split='test-normal'),
            'a1': dict(split='test-normal_and_attack')}
    (tmp_path / 'S.json').write_text(json.dumps(dict(recordings=recs)))
    doc = dev.split(tmp_path)
    assert set(doc['scenarios']['S']) == {'n1', 'a1'}
    assert sum(doc['counts']['S'].values()) == 2


def test_fixed_passes_its_level():
    class Scn:
        def firings(self, branches, alpha, name):
            return [alpha]
    assert dev.Fixed(Scn(), 0.5).firings(None, None, 'x') == [0.5]
