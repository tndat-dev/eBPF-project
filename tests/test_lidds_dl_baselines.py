import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
spec = importlib.util.spec_from_file_location('dl', ROOT / 'scripts' / 'analysis' / 'lidds_dl_baselines.py')
dl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dl)


class Syscall:
    def __init__(self, t, alarm):
        self.t, self.alarm = t, alarm

    def timestamp_unix_in_ns(self):
        return int(self.t * 1e9)


class Recording:
    def __init__(self, name, exploit, calls):
        self.name, self._exploit, self._calls = name, exploit, calls

    def metadata(self):
        if self._exploit is None:
            return dict(exploit=False, time=dict(exploit=[]))
        return dict(exploit=True, time=dict(exploit=[dict(absolute=self._exploit)]))

    def syscalls(self):
        return iter(self._calls)


class Preprocessor:
    def __init__(self):
        self.resets = 0

    def new_recording(self):
        self.resets += 1


class Ids:
    def __init__(self):
        self._data_preprocessor = Preprocessor()

    def _detect_syscall(self, syscall):
        return syscall.alarm


def test_outcome_splits_alarms_at_the_exploit_and_counts_episodes():
    attack = Recording('a', 100.0, [Syscall(90, True), Syscall(99, True), Syscall(100, False), Syscall(101.5, True),
                                    Syscall(102, True)])
    normal = Recording('n', None, [Syscall(10, True), Syscall(11, True), Syscall(20, True), Syscall(21, False)])
    clean = Recording('c', None, [Syscall(1, False)])
    dl.STATE.update(ids=Ids(), tests=[attack, normal, clean])
    a, n, c = (dl.outcome(i) for i in range(3))
    assert a[:5] == ['test-normal_and_attack', True, 1.5, 2, 5]       # 90 and 99 are 9 s apart: two episodes
    assert n[:5] == ['test-normal', False, None, 2, 4] and n[6] == 'n'
    assert c[3] == 0 and dl.STATE['ids']._data_preprocessor.resets == 3


def test_merge_uses_the_v2_subsets_and_reports_both_parts(tmp_path):
    rows = [['test-normal_and_attack', True, 0.5, 0, 9, 'development', 'a0'],
            ['test-normal_and_attack', False, None, 0, 9, 'official', 'a1'],
            ['test-normal_and_attack', True, 1.0, 0, 9, 'official', 'a2']]
    rows += [['test-normal', False, None, 1 if i == 0 else 0, 9, None, f'n{i}'] for i in range(10)]
    part = dict(scenario='SCN', arm='mlp', threshold=1.0, recordings=rows)
    p = tmp_path / 'part.json'; p.write_text(json.dumps(part))
    out = tmp_path / 'merged.json'
    dl.merge([str(p)], out)
    doc = json.loads(out.read_text())
    off, dev = doc['summary']['mlp']['official']['pooled'], doc['summary']['mlp']['development']['pooled']
    assert (off['attack_recordings'], off['detected']) == (2, 1) and (dev['attack_recordings'], dev['detected']) == (1, 1)
    assert off['normal_recordings'] + dev['normal_recordings'] == 10
    assert doc['parts']['SCN/mlp']['threshold'] == 1.0 and 'recordings' not in doc['parts']['SCN/mlp']
