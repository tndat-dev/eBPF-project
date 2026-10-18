import pytest
from sentinel_pulse.syscall_study.syscall_frequency_report import describe


def cohort():
    return dict(evidence_class='descriptive_normal_frequency_only',input_errors=[],eligible_capture_count=1,
        input_capture_count=1,workload_revision_regime_summaries=[dict(container_name='app',traffic_regime='steady',
        syscall_ids=[dict(id=0,count=3),dict(id=202,count=7)],syscall_total=10),dict(container_name='pod-slice',
        traffic_regime='steady',syscall_ids=[dict(id=0,count=100)],syscall_total=100)])


def test_frequency_not_importance_and_pod_scope_excluded():
    d=describe(cohort(),{0:'read',1:'write'})
    assert d['overall']['syscall_entries']==10
    assert d['overall']['explicit_share']==.3
    assert d['overall']['explicit_not_observed']==[dict(id=1,name='write')]
    assert d['recall'] is None and d['no_feature_selection_or_model_change']


def test_bad_totals_not_hidden():
    c=cohort();c['workload_revision_regime_summaries'][0]['syscall_total']=11
    with pytest.raises(ValueError,match='total'):describe(c,{0:'read'})
