import json
import pickle
from types import SimpleNamespace
import numpy as np
import pytest
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.support_model import PulseSupportEnsemble
from sentinel_pulse.support_analysis import analyze


class ConstantTree:
    def predict_proba(self,x):return np.tile([.8,.2],(len(x),1))


def fixture(tmp_path):
    root=tmp_path/'run';root.mkdir()
    model=tmp_path/'model';model.mkdir()
    (model/'manifest.json').write_text(json.dumps(dict(feature_columns=['a','b','c'])))
    base=SimpleNamespace(feature_dim=3,history=3,alpha=.001,calibration_scores=np.full(1300,.2),estimator=ConstantTree())
    ensemble=PulseSupportEnsemble(base);ensemble.fit_support(np.zeros((200,3)),np.zeros((1300,3)))
    with (root/'model.pkl').open('wb') as stream:pickle.dump(ensemble,stream)
    x=np.zeros((2,12),dtype=np.float32);x[1,-1]=1
    archive=tmp_path/'normal.npz';np.savez(archive,workload=x)
    analysis=tmp_path/'analysis.json';analysis.write_text(json.dumps(dict(context_archive=dict(path=str(archive)))))
    (root/'START.json').write_text(json.dumps(dict(analysis_sha256=sha256_file(analysis),context_archive_sha256=sha256_file(archive),base_manifest_sha256=sha256_file(model/'manifest.json'))))
    (root/'RESULTS.json').write_text(json.dumps(dict(start_sha256=sha256_file(root/'START.json'),workloads={
        'workload':dict(artifact='model.pkl',artifact_sha256=sha256_file(root/'model.pkl')),
        'missing':dict(artifact='model.pkl',artifact_sha256=sha256_file(root/'model.pkl'))})))
    (root/'TERMINAL.json').write_text(json.dumps(dict(state='completed')))
    return root,analysis,model,tmp_path/'report.json'


def test_matched_budget_comparison_preserves_missing_holdout_and_null_metrics(tmp_path):
    report=analyze(*fixture(tmp_path))
    assert report['totals']==dict(normal_contexts=2,tree_original_alpha=0,tree_matched_branch_budget=0,support_branch=1,support_only=1,combined=1)
    assert report['workloads']['workload']['support_normal_anomaly_argmax_counts']=={'c':1}
    assert report['workloads']['missing']['holdout_status'].startswith('missing')
    assert report['precision'] is None and report['recall'] is None
    assert report['automatic_promotion'] is False


def test_matched_comparison_refuses_modified_artifact(tmp_path):
    args=fixture(tmp_path);(args[0]/'model.pkl').write_bytes(b'changed')
    with pytest.raises(ValueError,match='checksum'):analyze(*args)
