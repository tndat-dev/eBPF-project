import numpy as np
import pytest
import copy
import hashlib
import json

from sentinel_pulse.features import PulseFeatureBuilder, SENSITIVE_IDS, TRACKED_SYSCALLS
from sentinel_pulse.syscall_feature_experiment import (
    explicit_channels, load_checkpoint, masked_contexts, training_frequency_proxy, validate_proxy_roundoff, variant_masks,
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


def checkpoint_fixture(tmp_path):
    from sentinel_pulse.integrity import sha256_file
    key='test/workload:app'
    start={'schema':'sentinel-pulse-explicit-syscall-experiment-start-v1',
           'input_sha256':{'data':'fixed'},'software':{'python':'fixed'},
           'training_fraction':.7,'history':3,'alpha':.001,'window_seconds':.5,
           'workloads':[key],'expected_fits':32,'variants_per_workload':32,
           'source':{'source_git_commit':'parent'},
           'source_module_sha256':{n:'fixed' for n in ['model.py','features.py','train.py','encoding.py']}}
    (tmp_path/'START.json').write_text(json.dumps(start))
    proxy={name:0. for name in TRACKED_SYSCALLS.values()}
    _,ranking,retained=variant_masks(columns(),proxy)
    artifact=hashlib.sha256(key.encode()).hexdigest()[:16]+'__full.npz'
    np.savez_compressed(tmp_path/artifact,score=np.array([.1,.9]),
                        conformal_p=np.array([.9,.001]),anomalous=np.array([False,True]))
    records={'full':{'status':'measured','masked_columns':[],
             'prediction_artifact':artifact,'prediction_sha256':sha256_file(tmp_path/artifact),
             'heldout_contexts':2,'raw_anomalous_contexts':1},
             'drop_read':{'status':'error','message':'preserved in parent'}}
    result={'schema':'sentinel-pulse-explicit-syscall-experiment-results-v1',
            'start_sha256':sha256_file(tmp_path/'START.json'),
            'workloads':{key:{'training_count_proxy':proxy,'training_rank':ranking,
                  'top16_plus_sensitive_retained_syscalls':retained,'variants':records}}}
    (tmp_path/'RESULTS.json').write_text(json.dumps(result))
    return start,result


def test_resume_reuses_verified_successes_and_preserves_original_files(tmp_path):
    start,_=checkpoint_fixture(tmp_path)
    before={p.name:p.read_bytes() for p in tmp_path.iterdir()}
    carried,receipt=load_checkpoint(tmp_path,start)
    assert receipt['reused_fits']==1
    assert set(carried['test/workload:app']['variants'])=={'full'}
    assert carried['test/workload:app']['variants']['full']['carried_from_source_commit']=='parent'
    assert before=={p.name:p.read_bytes() for p in tmp_path.iterdir()}


@pytest.mark.parametrize('change',['software','input','source','hash','mask','path','result_start','ranking','schema'])
def test_resume_rejects_unbound_or_tampered_checkpoint(tmp_path,change):
    start,result=checkpoint_fixture(tmp_path);expected=copy.deepcopy(start)
    variant=result['workloads']['test/workload:app']['variants']['full']
    if change=='software':expected['software']['python']='other'
    elif change=='input':expected['input_sha256']['data']='other'
    elif change=='source':expected['source_module_sha256']['model.py']='other'
    elif change=='hash':variant['prediction_sha256']='0'*64
    elif change=='mask':variant['masked_columns']=['log_count:read']
    elif change=='path':variant['prediction_artifact']='../outside.npz'
    elif change=='result_start':result['start_sha256']='0'*64
    elif change=='ranking':result['workloads']['test/workload:app']['training_rank'].reverse()
    else:result['schema']='other'
    (tmp_path/'RESULTS.json').write_text(json.dumps(result))
    with pytest.raises(ValueError):load_checkpoint(tmp_path,expected)


def test_cross_cpu_one_ulp_proxy_difference_does_not_change_selection():
    old={name:0. for name in TRACKED_SYSCALLS.values()};old['read']=76804.0012292337
    current={**old,'read':np.nextafter(old['read'],0)}
    differences=validate_proxy_roundoff(old,current,columns())
    assert len(differences)==1 and differences[0]['syscall']=='read'
    assert differences[0]['absolute_difference']==np.spacing(old['read'])


@pytest.mark.parametrize('change',['large','rank','zero'])
def test_proxy_tolerance_does_not_admit_changed_counts_or_rank(change):
    old={name:0. for name in TRACKED_SYSCALLS.values()};old['read']=10.;old['write']=10.
    current=old.copy()
    if change=='large':current['read']+=1e-8
    elif change=='rank':current['write']=np.nextafter(10.,11.)
    else:current['close']=np.nextafter(0.,1.)
    with pytest.raises(ValueError):validate_proxy_roundoff(old,current,columns())
