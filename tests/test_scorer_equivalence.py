import json

from sentinel_pulse.pipeline.scorer_equivalence import frames, key_of


def test_frames_group_by_boundary_and_skip_schema_header(tmp_path):
    path = tmp_path / 'features.jsonl'
    rows = [{'schema': 'header', 'feature_schema_sha256': 'x'},
            {'window_end': 1.0, 'n': 1}, {'window_end': 1.0, 'n': 2}, {'window_end': 1.5, 'n': 3}]
    path.write_text(''.join(json.dumps(r) + '\n' for r in rows) + '{"window_end": 2.0')
    assert [(b, [r['n'] for r in rs]) for b, rs in frames(path)] == [(1.0, [1, 2]), (1.5, [3])]


def test_key_normalizes_cgroup_type():
    a = dict(workload_key='w', pod_uid='p', container_name='c', workload_revision='r', cgroup_id=7, window_end=1.5)
    assert key_of(a) == key_of(dict(a, cgroup_id='7'))


def test_legacy_flat_module_pickles_still_load():
    import io
    import pickle
    from sentinel_pulse.common import load_artifact
    from sentinel_pulse.detector.support_model import PulseSupportEnsemble
    model = PulseSupportEnsemble(base=None)
    data = pickle.dumps(model, protocol=0)
    legacy = data.replace(b'sentinel_pulse.detector.support_model', b'sentinel_pulse.support_model')
    assert legacy != data
    loaded = load_artifact(io.BytesIO(legacy))
    assert isinstance(loaded, PulseSupportEnsemble) and loaded.alpha == model.alpha
