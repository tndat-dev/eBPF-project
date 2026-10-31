import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('chids_runner', ROOT / 'scripts' / 'analysis' / 'lidds_chids.py')
ch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ch)


def test_outcome_detects_after_the_exploit_and_counts_earlier_episodes():
    ends = [1.0, 2.0, 3.0, 9.0, 10.0, 11.0]
    errs = [0.5, 0.0, 0.0, 0.5, 0.0, 0.5]
    row = ch.outcome(ends, errs, 0.1, 10.0, 'test-normal_and_attack', 'a', 'official')
    assert row == ['test-normal_and_attack', True, 1.0, 2, 6, 'official', 'a']   # 1.0 and 9.0: two episodes
    assert ch.outcome(ends, errs, 0.6, None, 'test-normal', 'n', None)[1:4] == [False, None, 0]


def test_published_threshold_index_is_theta_1_4():
    thetas = [round(0.2 * (i + 1), 1) for i in range(10)]
    assert thetas[int(round(ch.THETA / 0.2)) - 1] == 1.4
