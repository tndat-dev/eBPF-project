"""map_capacity_test.py: a level's lost events and failed inserts come from the loader's own lines."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import map_capacity_test as mc  # noqa: E402


def test_summarize_counts_losses_inside_the_level():
    grams = [dict(window_end=10.5, events=400, grams=[[1, 2, 3, 4, 1]] * 300),
             dict(window_end=11.0, events=500, grams=[[1, 2, 3, 4, 1]] * 400),
             dict(window_end=30.0, events=99, grams=[])]                         # another level
    drains = [dict(observed_at=9.0, insert_fail_cumulative=5, drain_seconds=0.01),
              dict(observed_at=10.6, insert_fail_cumulative=5, drain_seconds=0.02),
              dict(observed_at=11.2, insert_fail_cumulative=45, drain_seconds=0.04)]
    r = mc.summarize(100000, dict(threads=8, events=1000, seconds=1.0), 10.0, 11.0, grams, drains)
    assert r['window_events'] == 900 and r['events_lost'] == 100 and r['failed_inserts'] == 40
    assert r['distinct_grams_per_window'] == dict(p50=350.0, max=400) and r['drain_seconds']['max'] == 0.04
