from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml-service"))
from collection_timing import minimum_duration_satisfied, wait_until


def test_wait_until_does_not_collapse_after_an_external_event():
    now = [0.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    wait_until(60.0, clock=lambda: now[0], sleeper=sleep, maximum_sleep=7.0)
    assert now[0] == 60.0
    assert sum(sleeps) == 60.0
    assert max(sleeps) <= 7.0


def test_duration_gate_allows_only_shutdown_tolerance():
    assert minimum_duration_satisfied(4318.1, 4320.0)
    assert not minimum_duration_satisfied(180.0, 4320.0)
