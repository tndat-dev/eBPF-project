import importlib.metadata
import __main__
import json
import pickle
import platform
import numpy as np
from sentinel_pulse import benchmark_extended_reference_cli as bench
from sentinel_pulse.model import PulseExtraTrees
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.extended_reference_experiment import PulseExtendedReferenceTree


class FixtureModel:
    def __init__(self):self.base=PulseExtraTrees()
    def predict_contexts(self,values):return {'anomalous':np.zeros(len(values),dtype=bool)}


def test_load_reference_model_restores_trainer_main_module_pickle(tmp_path,monkeypatch):
    artifact=tmp_path/'legacy-main.pkl'
    model_type=PulseExtendedReferenceTree
    original_module=model_type.__module__
    monkeypatch.setattr(model_type,'__module__','__main__')
    monkeypatch.setattr(__main__,'PulseExtendedReferenceTree',model_type,raising=False)
    try:
        with artifact.open('wb') as f:pickle.dump(model_type(),f)
    finally:
        monkeypatch.setattr(model_type,'__module__',original_module)
    loaded=bench.load_reference_model(artifact)
    assert type(loaded) is model_type


def test_single_context_timing_keeps_missing_model_and_never_calls_flags_fp(tmp_path,monkeypatch):
    source=tmp_path/'source';source.mkdir();experiment=tmp_path/'reference';experiment.mkdir();output=tmp_path/'bench';output.mkdir()
    hashes={'sentinel_pulse/'+n:'bound' for n in ['extended_reference_experiment.py','model.py','support_model.py','syscall_analysis.py']}
    monkeypatch.setattr(bench,'clean_source',lambda _:('frozen',hashes))
    (experiment/'START.json').write_text(json.dumps(dict(source_files=hashes,software=dict(
        python=platform.python_version(),numpy=np.__version__,sklearn=importlib.metadata.version('scikit-learn')))))
    with (experiment/'fixture.pkl').open('wb') as f:pickle.dump(FixtureModel(),f)
    records=[dict(node_name='node',pod_uid='pod',container_name='app',workload_revision='r',cgroup_id=1,
                  window_start=23+i*.5,window_end=23.5+i*.5,vector=[0,1]) for i in range(30)]
    (experiment/'fixture.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
    (experiment/'INDEX.json').write_text(json.dumps(dict(train_cut=10,holdout_cut=20,workloads={'demo':dict(
        file='fixture.jsonl',sha256=sha256_file(experiment/'fixture.jsonl'))})))
    (experiment/'RESULTS.json').write_text(json.dumps(dict(workloads={'demo':dict(artifact='fixture.pkl',
        artifact_sha256=sha256_file(experiment/'fixture.pkl')),'missing':dict(error='no calibration')})))
    bench.run(source,experiment,output,samples=16)
    result=json.loads((output/'RESULTS.json').read_text())
    assert result['not_kernel_to_alert'] and result['workloads']['demo']['samples']==16
    assert result['workloads']['demo']['reference_flags_are_not_false_positives']
    assert result['workloads']['missing']['state']=='missing_model'
