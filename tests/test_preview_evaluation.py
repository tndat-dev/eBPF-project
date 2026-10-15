import pytest
from sentinel_pulse.preview_evaluation import evaluate_interval, summarize
from sentinel_pulse.matched_worker import full_delta
from sentinel_pulse.features import TRACKED_SYSCALLS


def fixtures(label='attack'):
    ident=dict(workload_key='production/catalog:app',node_name='worker',pod_uid='uid',
               container_name='app',workload_revision='r1',cgroup_id=42)
    trial=dict(ident,start_at=100.,label=label,kernel_event_at=100.1)
    rows=[dict(ident,window_start=100+i*.5,window_end=100+(i+1)*.5,
        candidate_manifest_sha256='a'*64,policy_sha256='b'*64,alert=False,policy_applied=False,
        serving_compatible=False,status='candidate-raw-score-only',policy_evaluated=True,
        candidate_alert_preview=False,eligible_for_normal_review=True,
        preview_emitted_at=100+(i+1)*.5+.1) for i in range(30)]
    return trial,rows


def test_attack_and_equal_duration_control_matrix():
    trial,rows=fixtures();rows[2]['candidate_alert_preview']=True
    tp=evaluate_interval(rows,trial,'a'*64,'b'*64)
    assert tp['outcome']=='TP' and tp['kernel_to_preview_seconds']==pytest.approx(1.5)
    trial['label']='expected_normal'
    fp=evaluate_interval(rows,trial,'a'*64,'b'*64)
    report=summarize([tp,fp])
    assert report['confusion_matrix_expected_control_labels']==dict(TP=1,FN=0,FP=1,TN=0)
    assert report['precision_expected']==.5 and report['confirmed_precision'] is None
    assert report['kernel_to_alert'] is None


@pytest.mark.parametrize('mutation',['coverage','binding','stale','wrong_identity','infra'])
def test_unobservable_or_mismatched_trials_never_become_tn(mutation):
    trial,rows=fixtures('expected_normal')
    if mutation=='coverage':rows=rows[:20]
    if mutation=='binding':rows[0]['policy_sha256']='0'*64
    if mutation=='stale':
        for r in rows:r['preview_emitted_at']+=30
    if mutation=='wrong_identity':
        for r in rows:r['workload_revision']='other'
    if mutation=='infra':trial['infrastructure_issue']='rollout'
    result=evaluate_interval(rows,trial,'a'*64,'b'*64)
    assert result['outcome']=='unknown'


def test_prewindow_and_late_positives_do_not_count_as_detection():
    trial,rows=fixtures()
    before=dict(rows[0],window_start=99.5,window_end=100.,candidate_alert_preview=True)
    rows[-1]['candidate_alert_preview']=True  # emitted after the 15s horizon
    result=evaluate_interval([before,*rows],trial,'a'*64,'b'*64)
    assert result['outcome']=='FN'


def test_exposure_union_does_not_double_count_replayed_rows():
    trial,rows=fixtures()
    result=evaluate_interval(rows[:15]*4,trial,'a'*64,'b'*64)
    assert result['scored_seconds']==7.5 and result['outcome']=='unknown'


def test_missing_kernel_provenance_retained_as_unknown():
    trial,rows=fixtures();trial['kernel_event_at']=None
    assert evaluate_interval(rows,trial,'a'*64,'b'*64)['outcome']=='unknown'


def test_warming_without_policy_binding_reduces_exposure_without_false_mismatch():
    trial,rows=fixtures('expected_normal')
    rows[0].update(status='warming',policy_sha256=None,eligible_for_normal_review=False)
    result=evaluate_interval(rows,trial,'a'*64,'b'*64)
    assert result['outcome']=='TN_expected'
    assert result['scored_seconds']==14.5
    assert result['issues']==[]
    rows[0]['candidate_manifest_sha256']='c'*64
    assert evaluate_interval(rows,trial,'a'*64,'b'*64)['outcome']=='unknown'


def test_scored_row_without_policy_hash_remains_invalid():
    trial,rows=fixtures('expected_normal');rows[0]['policy_sha256']=None
    result=evaluate_interval(rows,trial,'a'*64,'b'*64)
    assert result['outcome']=='unknown'
    assert result['issues']==['model_or_policy_binding_mismatch']


def test_full_id_projection_and_delta_share_exact_same_words():
    counts={0:2,202:8};bins=[0]*64
    for k,v in counts.items():bins[((k*2654435761)&0xffffffff)>>26]+=v
    row=dict(full_counts={str(k):v for k,v in counts.items()},total=10,syscall_bins=bins,
             counts={str(k):counts.get(k,0) for k in TRACKED_SYSCALLS})
    _,delta=full_delta(row,{0:1,202:3})
    assert delta=={'0':1,'202':5}
    row['counts']['0']=3
    with pytest.raises(ValueError,match='explicit'):full_delta(row,None)


def test_full_id_native_projection_matches_every_id_and_bin(tmp_path):
    import subprocess
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    output=tmp_path/'full-id-test'
    subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',
        '-I',str(root/'sentinel_pulse/ebpf'),str(root/'tests/c/pulse_counter_full_ids.c'),
        '-o',str(output)],check=True,capture_output=True)
    result=subprocess.run([str(output)],check=True,capture_output=True,text=True)
    assert 'PASS' in result.stdout


def test_writer_side_tail_keeps_identity_rotation_and_ignores_partial_line(tmp_path):
    import json
    from sentinel_pulse.preview_read_tail import read
    base=dict(window_end=100.,pod_uid='uid',cgroup_id=42)
    for n in (1,2):
        folder=tmp_path/'segments'/f's{n:05d}';folder.mkdir(parents=True)
        (folder/'decisions.jsonl').write_text(json.dumps(base)+'\n'+
            json.dumps(dict(base,pod_uid='wrong'))+'\n'+json.dumps(base)[:12])
    result=list(read(tmp_path,99,'uid',42))
    assert result==[base,base]
