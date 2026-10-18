import copy
import numpy as np
import pytest

from sentinel_pulse.syscall_study.matched_holdout import ContextBuilder, aggregate, merged, validate_row
from sentinel_pulse.syscall_study.matched_study import contexts


def rows(n=200):
    result = []
    for i in range(n):
        result.append(dict(window_start=100+i*.5, window_end=100+(i+1)*.5,
            node_name='worker', pod_uid='pod', workload_revision='revision',
            container_name='app', cgroup_id=19, eligible_for_normal_review=True,
            workload_key='production/test:app', exact_total=3+(i % 7),
            full_counts_delta={'0': 1, '202': 2+(i % 7)}, vector=np.zeros(249, dtype=np.float32),
            schema='sentinel-pulse-extended-feature-v2',
            telemetry_contract='pulse-entered-plus-seccomp-skip-idle-v2', run_id='r'))
    return result


@pytest.mark.parametrize('spec', [dict(add=[], drop=[]), dict(add=[202, 321], drop=[]),
                                dict(add=[], drop=[43, 288])])
def test_holdout_context_matches_frozen_fitting_preprocessor(spec):
    data = rows()
    # Restrict to the exact frozen training phase; histories reset at its start.
    training = [r for r in data if r['window_end'] < 168]
    expected = contexts(data, spec, 100, 200)['train']
    builder = ContextBuilder(spec, 100, 200)
    actual = [x for row in training if (x := builder.observe(row)) is not None]
    np.testing.assert_array_equal(np.stack(actual), expected)


def test_holdout_resets_after_gap_and_never_uses_pre_registration_history():
    data = rows(100)
    builder = ContextBuilder(dict(add=[], drop=[]), 105, 130)
    scored = [r['window_end'] for r in data if builder.observe(r) is not None]
    assert min(scored) == 112  # 10 rolling + 3 temporal windows, then current.
    assert max(scored) <= 130
    builder = ContextBuilder(dict(add=[], drop=[]), 100, 200)
    for row in data[:30]:
        builder.observe(row)
    assert builder.observe(data[31]) is None
    for row in data[32:44]:
        assert builder.observe(row) is None
    assert builder.observe(data[44]) is not None


def test_ineligible_resets_and_overlap_cannot_bridge_history():
    data = rows(60)
    builder = ContextBuilder(dict(add=[], drop=[]), 100, 200)
    for row in data[:30]:
        builder.observe(row)
    invalid = copy.deepcopy(data[30]); invalid['eligible_for_normal_review'] = False
    assert builder.observe(invalid) is None
    assert builder.observe(data[31]) is None
    for row in data[32:44]:
        assert builder.observe(row) is None
    assert builder.observe(data[44]) is not None
    overlapping = copy.deepcopy(data[45]); overlapping['window_start'] -= .1
    assert builder.observe(overlapping) is None


def test_source_validation_rejects_identity_and_count_mismatch():
    row = rows(1)[0]
    assert validate_row(row, 'worker', 'r', {'production/test:app'})
    with pytest.raises(ValueError, match='identity'):
        validate_row(row, 'other', 'r', {'production/test:app'})
    row['exact_total'] += 1
    with pytest.raises(ValueError, match='delta'):
        validate_row(row, 'worker', 'r', {'production/test:app'})


def test_union_exposure_and_episode_count_do_not_count_replicas_twice():
    tag = 'production/test:app|base29|73021'
    report = dict(counts={'input_rows': 20}, scored_intervals={'production/test:app': [[0, 20]]},
        positive_episodes={tag: [[1, 2], [25, 26]]},
        model_counts={tag: {'scored_windows': 20, 'raw_positive_windows': 2}})
    summary = aggregate([report, report], ['production/test:app', 'production/missing:app'])
    assert summary['pooled_valid_workload_hours'] == 20/3600
    assert summary['model_counts'][tag]['unadjudicated_positive_episodes'] == 2
    assert summary['missing_scored_workloads'] == ['production/missing:app']
    assert summary['confusion_matrix'] == dict(TP=None, FP=None, TN=None, FN=None)
    assert merged([[0, 1], [.5, 2], [17, 18]], gap=15) == [[0, 18]]


def test_segment_scoring_keeps_positive_evidence_and_never_invents_ground_truth(tmp_path, monkeypatch):
    import gzip
    import json
    from types import SimpleNamespace
    from sentinel_pulse.integrity import sha256_file
    from sentinel_pulse.encoding import compact_record, schema_digest
    from sentinel_pulse.syscall_study.matched_holdout import score_segment

    class Model:
        alpha = .05
        base = SimpleNamespace(feature_dim=249, estimator=SimpleNamespace(n_jobs=-1))

        def predict_contexts(self, contexts):
            n = len(contexts)
            return dict(tree_p=np.full(n, .01), support_p=np.ones(n),
                        tree_score=np.full(n, .8), support_score=np.zeros(n),
                        joint_p=np.full(n, .02), anomalous=np.ones(n, dtype=bool))

    monkeypatch.setattr('sentinel_pulse.syscall_study.matched_holdout.load_artifact', lambda stream: Model())
    segment = tmp_path/'source'; segment.mkdir()
    columns = ['f'+str(i) for i in range(249)]
    with (segment/'features.jsonl').open('w') as stream:
        stream.write(json.dumps(dict(columns=columns, feature_schema_sha256=schema_digest(columns)))+'\n')
        for row in rows(40):
            row['columns'] = columns
            row, _ = compact_record(row)
            stream.write(json.dumps(row)+'\n')
    for name in ('issues.jsonl', 'decisions.jsonl'):
        (segment/name).write_text('')
    seals = {name: sha256_file(segment/name) for name in ('features.jsonl', 'decisions.jsonl', 'issues.jsonl')}
    (segment/'TERMINAL.json').write_text(json.dumps(dict(seals=seals)))
    artifact = tmp_path/'toy.pkl'; artifact.write_bytes(b'fixture')
    tag = 'production/test:app|base29|73021'
    terminal = dict(completed={tag: dict(artifact='toy.pkl', sha256=sha256_file(artifact))})
    registration = dict(holdout_start_unix=100, planned_end_unix=120,
        workload_keys=['production/test:app'], capture_run_id='r', seeds=[73021], episode_quiet_seconds=15.)
    result = score_segment(segment, 'worker', registration,
        dict(arms={'base29': dict(add=[], drop=[])}, columns=columns), terminal, tmp_path, tmp_path/'out', batch_size=8)
    assert result['model_counts'][tag]['scored_windows'] == 27
    assert result['model_counts'][tag]['candidate_preview_positive_windows'] == 27
    assert result['precision'] is None and result['recall'] is None
    with gzip.open(tmp_path/'out'/'positive-windows.jsonl.gz', 'rt') as stream:
        positives = [json.loads(line) for line in stream]
    assert len(positives) == 27
    assert all(p['normal_label'] == 'unadjudicated_observation' for p in positives)
    assert all(p['kernel_to_alert_seconds'] is None and p['operational_alert'] is False for p in positives)
    (segment/'issues.jsonl').write_text('changed')
    with pytest.raises(ValueError, match='checksum'):
        score_segment(segment, 'worker', registration, dict(arms={}), terminal,
                      tmp_path, tmp_path/'tampered')
