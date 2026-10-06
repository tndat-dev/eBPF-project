import copy
import pytest
from sentinel_pulse.review_observation import review


def snapshot():
    return {'schema':'sentinel-pulse-soak-inspection-v1','checked_at_unix':3700,
        'registration':{'started_at_unix':100,'binding':{'protocol':{
            'minimum_wall_seconds':7200,'target_valid_seconds_per_workload':3600}}},
        'registration_sha256':'frozen','campaign_service':{'ActiveState':'active'},
        'terminal_present':False,'active_segments':[{'run_id':'s2'}],
        'status':{'valid_seconds_per_workload':{'redis':1800,'web':2700},'excluded_rows':{'health_degraded':10}},
        'segments':[{'run_id':'s1','all_alerts':{'redis':1},'eligible_alerts':{},'failures':{}},
                    {'run_id':'s0','all_alerts':{},'eligible_alerts':{},'failures':{'worker':'preflight'}}]}


def test_excluded_alert_is_retained_without_false_positive_claim():
    s=snapshot();original=copy.deepcopy(s);r=review(s)
    assert s==original
    assert r['retained_alerts_total']==1 and r['alerts_outside_admitted_exposure']=={'redis':1}
    assert r['all_alerts_per_campaign_wall_hour']==1
    assert r['false_positive_rate'] is None and r['precision'] is None and r['recall'] is None
    assert not r['automatic_promotion'] and r['excluded_rows']=={'health_degraded':10}
    assert r['pending_audits_or_preflight_failures'][0]['run_id']=='s0'


def test_wall_and_bottleneck_exposure_progress_are_separate():
    r=review(snapshot())
    assert r['wall_progress_percent']==50
    assert r['valid_progress_percent_range']==[50,75]
    assert r['valid_exposure_fraction_range']==[.5,.75]
    assert r['bottleneck_workloads']==['redis']
    assert r['valid_exposure_fraction_is_not_collector_availability']


@pytest.mark.parametrize('change', ['nan','negative_exposure','future_exposure','zero_target','negative_alert','excess_eligible','duplicate'])
def test_invalid_snapshot_is_not_reported_as_progress(change):
    s=snapshot()
    if change=='nan':s['checked_at_unix']=float('nan')
    elif change=='negative_exposure':s['status']['valid_seconds_per_workload']['redis']=-1
    elif change=='future_exposure':s['status']['valid_seconds_per_workload']['redis']=3601
    elif change=='zero_target':s['registration']['binding']['protocol']['minimum_wall_seconds']=0
    elif change=='negative_alert':s['segments'][0]['all_alerts']['redis']=-1
    elif change=='excess_eligible':s['segments'][0]['eligible_alerts']['redis']=2
    else:s['segments'].append(copy.deepcopy(s['segments'][0]))
    with pytest.raises(ValueError):review(s)


def test_zero_recorded_alerts_does_not_imply_zero_false_positive_rate():
    s=snapshot();s['segments'][0]['all_alerts']={}
    r=review(s)
    assert r['retained_alerts_total']==0 and r['all_alerts_per_campaign_wall_hour']==0
    assert r['false_positive_rate'] is None and r['confusion_matrix_measured'] is None
