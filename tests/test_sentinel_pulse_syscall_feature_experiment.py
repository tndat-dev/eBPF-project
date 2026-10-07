import numpy as np
import pytest

from sentinel_pulse.features import PulseFeatureBuilder, SENSITIVE_IDS, TRACKED_SYSCALLS
from sentinel_pulse.syscall_feature_experiment import (
    explicit_channels, masked_contexts, training_frequency_proxy, variant_masks,
)


def columns():
    return list(PulseFeatureBuilder().columns)


def test_leave_one_out_removes_four_explicit_channels_only():
    names = columns()
    proxy = {name: float(i) for i, name in enumerate(TRACKED_SYSCALLS.values())}
    variants, _, kept = variant_masks(names, proxy)
    assert len(variants) == 32
    assert variants["full"] == []
    assert [names[i] for i in variants["drop_read"]] == [
        "log_count:read", "ratio:read", "rolling_mean:read", "rolling_std:read",
    ]
    assert len(variants["no_explicit_channels"]) == 116
    for variant in variants.values():
        assert names.index("sensitive_ratio") not in variant
        assert names.index("syscall_bin:0") not in variant
        assert names.index("transition_bin:0") not in variant
        assert names.index("log_count:other") not in variant
    assert {TRACKED_SYSCALLS[n] for n in SENSITIVE_IDS} <= set(kept)


def test_mask_applies_to_all_four_windows_without_mutating_holdout():
    names = columns()
    x = np.ones((2, 996), dtype=np.float32)
    masked = masked_contexts(x, explicit_channels(names)["read"], 249, 3)
    assert np.all(x == 1)
    for lag in range(4):
        assert masked[0, names.index("log_count:read") + lag * 249] == 0
        assert masked[0, names.index("syscall_bin:0") + lag * 249] == 1
    assert (masked == 0).sum() == 2 * 4 * 4


def test_calibration_prefix_and_test_data_cannot_affect_ranking():
    names = columns()
    seq = np.zeros((100, 249), dtype=np.float32)
    slot = names.index("log_count:read")
    seq[:70, slot] = np.log1p(2)
    seq[70:, slot] = np.log1p(1000)
    first = training_frequency_proxy([seq], names, 3)
    seq[70:, slot] = np.log1p(100000)
    second = training_frequency_proxy([seq], names, 3)
    assert first == second
    assert first["read"] == pytest.approx(140, rel=1e-6)
    assert first["write"] == 0


def test_unusable_short_sequences_do_not_affect_ranking():
    proxy = training_frequency_proxy([np.ones((8, 249))], columns(), 3)
    assert not any(proxy.values())


@pytest.mark.parametrize("mutation", ["duplicate", "missing", "negative_proxy", "nan_proxy", "missing_proxy"])
def test_invalid_feature_selection_input_is_rejected(mutation):
    names = columns()
    proxy = {name: 0.0 for name in TRACKED_SYSCALLS.values()}
    if mutation == "duplicate":
        names.append(names[0])
    elif mutation == "missing":
        names.remove("log_count:read")
    elif mutation == "negative_proxy":
        proxy["read"] = -1
    elif mutation == "nan_proxy":
        proxy["read"] = float("nan")
    else:
        del proxy["read"]
    with pytest.raises(ValueError):
        variant_masks(names, proxy)


@pytest.mark.parametrize("change", ["shape", "nan", "empty", "bad_slot"])
def test_bad_context_or_mask_is_rejected(change):
    x = np.ones((2, 996), dtype=np.float32)
    indices = [0]
    if change == "shape":
        x = x[:, :-1]
    elif change == "nan":
        x[0, 0] = np.nan
    elif change == "empty":
        x = x[:0]
    else:
        indices = [249]
    with pytest.raises(ValueError):
        masked_contexts(x, indices, 249, 3)


def test_ranking_ties_are_deterministic_and_do_not_change_count_set():
    names = columns()
    proxy = {name: 0.0 for name in TRACKED_SYSCALLS.values()}
    _, ranked, kept = variant_masks(names, proxy)
    assert ranked == sorted(TRACKED_SYSCALLS.values())
    assert set(kept) <= set(TRACKED_SYSCALLS.values())
