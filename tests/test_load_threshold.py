"""load-threshold-v1: bins by the window's own event count, per-bin Gumbel thresholds, the cluster study helpers."""
from pathlib import Path
import sys

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

from sentinel_pulse.detector import load_threshold as lt  # noqa: E402
import load_threshold_study as ls  # noqa: E402


def test_edges_are_snapped_quantiles_and_bins_are_half_open():
    events = [10] * 50 + [200] * 50
    assert lt.edges_of(events, 2) == [128] and lt.edges_of(events, 1) == []
    assert lt.bin_of(127, [128]) == 0 and lt.bin_of(128, [128]) == 1 and lt.bin_of(5, []) == 0
    assert lt.snap(0) == 1 and lt.snap(3) == 4 and lt.snap(5) == 4


def test_fit_bins_falls_back_when_a_bin_has_few_units():
    rng = np.random.default_rng(1)
    thr = lt.fit_bins([list(rng.gumbel(5, 1, 200)), [9.0] * 5], fallback=42.0, alpha=0.0003)
    assert thr[1] == 42.0 and 10 < thr[0] < 20
    t = lt.LoadThreshold([128], thr)
    assert t(10) == thr[0] and t(500) == 42.0 and t.to_json()['edges'] == [128]
    with pytest.raises(ValueError):
        lt.LoadThreshold([128], [1.0])


def test_matches_the_fit_rule_of_token_branch_fit():
    import token_branch_fit as f
    x = list(np.random.default_rng(2).gumbel(4, 1.5, 500))
    assert abs(lt.threshold(lt.trimmed_gumbel(x, 0.005), 0.0003) - f.threshold(f.trimmed_gumbel(x, 0.005), 0.0003)) < 1e-12


def test_cluster_bins_from_the_load_dump():
    doc = dict(block=60.0, events={'10': 60, '300': 40},
               blocks=[[ 'p', 'c', b, {'3': 5.0 + (b % 7), '8': 9.0 + (b % 5)}] for b in range(100)])
    edges, thr, blocks = ls.workload_bins(doc, (2, False), 99.0, 0.0003)
    # the median 10 snaps to 8, so class 3 (8-15 events) and class 8 both fall in the upper bin; the empty lower bin
    # takes the fallback
    assert edges == [8] and set(blocks[0][1]) == {1} and thr[0] == 99.0 and thr[1] < 99.0
    edges0, thr0, _ = ls.workload_bins(doc, None, 99.0, 0.0003)
    assert edges0 == [] and thr0 == [99.0]
    assert ls.quantile_from_hist({10: 60, 300: 40}, 0.5) == 10 and ls.quantile_from_hist({10: 60, 300: 40}, 0.7) == 300


def test_cluster_must_needs_lower_pooled_and_bounded_peaks():
    ref = dict(pooled=dict(share=0.007))
    good = dict(pooled=dict(share=0.005), regimes=dict(steady=dict(share=0.004), burst=dict(share=0.007), peak=dict(share=0.005)))
    bad = dict(pooled=dict(share=0.005), regimes=dict(steady=dict(share=0.004), burst=dict(share=0.02), peak=dict(share=0.005)))
    assert ls.cluster_must(good, ref) and not ls.cluster_must(bad, ref)
