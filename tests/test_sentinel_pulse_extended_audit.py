import json
import pytest
from sentinel_pulse.audit_extended_collection import audit_segment
from sentinel_pulse.extended_capture import ExtendedFeatureStream
from sentinel_pulse.integrity import sha256_file
from test_sentinel_pulse_extended_capture import raw,META


def fixture(tmp_path,frames=16):
    directory=tmp_path/'capture';directory.mkdir();output=tmp_path/'audit';output.mkdir()
    stream=ExtendedFeatureStream();raw_rows=[];features=[];header=False
    for i in range(frames):
        boundary=10+i*.5;row=raw(i)
        raw_rows.extend([row,dict(type='snapshot_end',observed_at=boundary,targets=1,snapshots=1)])
        result=stream.snapshot(row,boundary,META,boundary+.1)
        if result:
            record,schema=result
            if not header:features.append(schema);header=True
            features.append(record)
    for name,data in [('raw.jsonl',raw_rows),('features.jsonl',features),('observations.jsonl',[
            dict(event='resolver_generation',observed_at=10,metadata=dict(cgroups=META))])]:
        (directory/name).write_text(''.join(json.dumps(r)+'\n' for r in data))
    (directory/'loader.stderr').write_text('fixture only\n');seal(directory)
    return directory,output


def seal(directory):
    (directory/'TERMINAL.json').write_text(json.dumps(dict(raw_sha256=sha256_file(directory/'raw.jsonl'),
                                                         features_sha256=sha256_file(directory/'features.jsonl'))))


def test_raw_replay_exact_vector_and_reference_export_without_normal_claim(tmp_path):
    directory,output=fixture(tmp_path);report=audit_segment(directory,output)
    assert report['all_features_replayed']
    assert report['totals']['replayed_feature_rows']==15
    w=report['workloads']['production/test:app']
    assert w['eligible_rows']==5 and w['verified_reference_rows']==5
    assert w['eligible_union_seconds']==2.5 and w['contiguous_contexts']==2
    assert w['skip_delta']==15
    assert report['normal_training_admission'] is False and report['precision'] is None
    assert len((output/'reference.jsonl').read_text().splitlines())==6


def test_seal_corruption_is_not_normal(tmp_path):
    directory,output=fixture(tmp_path)
    with (directory/'raw.jsonl').open('a') as f:f.write('{}\n')
    with pytest.raises(ValueError,match='seal mismatch'):audit_segment(directory,output)


def test_preserves_report_and_quarantines_semantic_mismatch_in_sealed_features(tmp_path):
    directory,output=fixture(tmp_path)
    records=[json.loads(line) for line in (directory/'features.jsonl').read_text().splitlines()]
    records[-1]['exact_total']+=1
    (directory/'features.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records));seal(directory)
    report=audit_segment(directory,output)
    assert not report['all_features_replayed'] and report['totals']['mismatched_feature_rows']==1
    assert report['workloads']['production/test:app']['verified_reference_rows']==4
    assert report['mismatch_examples'][0]['fields']==['exact_total']


def test_unplaced_resolver_outage_is_retained_and_not_admitted(tmp_path):
    directory,output=fixture(tmp_path)
    with (directory/'observations.jsonl').open('a') as f:f.write(json.dumps(dict(event='resolver_unavailable',error='fixture outage'))+'\n')
    report=audit_segment(directory,output)
    assert report['unplaced_observation_events']==1 and not report['all_features_replayed']
    assert report['workloads']['production/test:app']['verified_reference_rows']==0


def test_eligibility_cannot_be_changed_without_audit_notice(tmp_path):
    directory,output=fixture(tmp_path)
    records=[json.loads(line) for line in (directory/'features.jsonl').read_text().splitlines()]
    records[-1]['eligible_for_normal_review']=False
    (directory/'features.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records));seal(directory)
    report=audit_segment(directory,output)
    assert report['totals']['mismatched_feature_rows']==1
    assert 'eligibility' in report['mismatch_examples'][0]['fields']
