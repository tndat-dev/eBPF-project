from types import SimpleNamespace
import numpy as np
import pytest

from sentinel_pulse.support_model import PulseSupportEnsemble
from sentinel_pulse.diagnose_attack_gates import classify, verified_records


class ConstantTree:
    def predict_proba(self, x):
        return np.tile([.8,.2], (len(x),1))


def base(n=1300):
    return SimpleNamespace(feature_dim=3, history=3, estimator=ConstantTree(),
                           calibration_scores=np.full(n,.2), alpha=.001)


def test_unseen_constant_feature_can_be_scored_without_changing_tree_weights():
    model = PulseSupportEnsemble(base())
    training = np.zeros((200,3),dtype=np.float32)
    calibration = np.zeros((1300,3),dtype=np.float32)
    fit=model.fit_support(training,calibration)
    x=np.zeros((2,12),dtype=np.float32);x[1,-1]=1
    result=model.predict_contexts(x)
    assert fit['constant_training_coordinates']==3
    assert result['tree_p'].tolist()==[1.,1.]
    assert result['anomalous'].tolist()==[False,True]
    assert result['joint_p'][1]==2/1301


def test_combination_corrects_multiple_branch_testing_and_window_budget():
    model=PulseSupportEnsemble(base())
    assert model.alpha==.05/30
    assert model.minimum_calibration_examples_per_branch==1199
    # Tail support is calibrated as a max across all dimensions, not 249 ORs.
    model.fit_support(np.zeros((100,3)),np.zeros((1300,3)))
    result=model.predict_contexts(np.zeros((1,12)))
    assert result['joint_p'][0]==1.


@pytest.mark.parametrize('n',[0,999,1198])
def test_small_calibration_does_not_force_an_unrepresentable_threshold(n):
    model=PulseSupportEnsemble(base())
    with pytest.raises(ValueError,match='resolution'):
        model.fit_support(np.zeros((100,3)),np.zeros((n,3)))


@pytest.mark.parametrize('args',[(0,30),(.05,0),(float('nan'),30),(.05,True)])
def test_invalid_budget_rejected(args):
    with pytest.raises(ValueError): PulseSupportEnsemble(base(),*args)


def test_support_reference_uses_training_not_calibration_to_set_range():
    model=PulseSupportEnsemble(base())
    model.fit_support(np.zeros((100,3)),np.ones((1300,3)))
    assert model.high.tolist()==[0,0,0]
    assert model.support_calibration[0]==20
    # Calibration shift raises the threshold; it does not refit reference.
    assert not model.predict_contexts(np.tile([0]*9+[1]*3,(1,1)))['anomalous'][0]


def test_invalid_live_context_and_nonfinite_reference_rejected():
    model=PulseSupportEnsemble(base())
    with pytest.raises(RuntimeError):model.support_scores(np.zeros((1,3)))
    with pytest.raises(ValueError): model.fit_support(np.full((100,3),np.nan),np.zeros((1300,3)))
    model.fit_support(np.zeros((100,3)),np.zeros((1300,3)))
    with pytest.raises(ValueError):model.predict_contexts(np.zeros((1,11)))


@pytest.mark.parametrize('flags,stage',[
    ({},'no_raw_model_anomaly'),
    ({'raw_model_anomalous':True},'score_excess_veto'),
    ({'raw_model_anomalous':True,'score_corroborated':True},'semantic_or_event_time_join_veto'),
    ({'raw_model_anomalous':True,'score_corroborated':True,'semantic_corroborated':True},'temporal_confirmation_or_attribution_veto')])
def test_descriptive_gate_analysis_does_not_rerun_or_relabel_misses(flags,stage):
    trial=dict(status='observed',detected=False,injected_at=10,workload_key='w',pod_uid='p',node_name='n',cgroup_id=1)
    record=dict(status='suppressed',workload_key='w',pod_uid='p',node_name='n',cgroup_id='1',
                window_end=11,alerted_at=11.1,score=.5,conformal_p=.001,**flags)
    assert classify(trial,[record])['first_limiting_stage']==stage
    assert trial['detected'] is False


def test_late_or_wrong_identity_does_not_count_as_horizon_evidence():
    trial=dict(status='observed',detected=False,injected_at=10,workload_key='w',pod_uid='p',node_name='n',cgroup_id=1)
    record=dict(status='alert',workload_key='w',pod_uid='p',node_name='n',cgroup_id='1',window_end=11,alerted_at=26)
    assert classify(trial,[record])['first_limiting_stage']=='no_scored_horizon_window'
    assert classify(dict(trial,status='infrastructure_unknown'),[])['first_limiting_stage']=='infrastructure_unknown'


def test_streamed_diagnosis_checks_binding_even_outside_target_horizon(tmp_path):
    import json
    path = tmp_path / 'tail.jsonl'
    row = dict(status='normal', model_manifest_sha256='model', decision_policy_sha256='policy')
    path.write_text(json.dumps(row)+'\n'+json.dumps(dict(row, decision_policy_sha256='changed'))+'\n')
    start = dict(model_manifest_sha256='model', decision_policy_sha256='policy')
    records = verified_records(path, start)
    assert iter(records) is records
    assert next(records) == row
    with pytest.raises(ValueError, match='mismatch'):
        next(records)
