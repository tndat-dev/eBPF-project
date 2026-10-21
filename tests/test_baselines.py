import hashlib
import json
import pickle
from types import SimpleNamespace

import numpy as np

from sentinel_pulse.encoding import compact_record, schema_digest
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.syscall_study import baselines as bl
from sentinel_pulse.syscall_study.arm_budget import load_holdout
from sentinel_pulse.syscall_study.score_dump import load_study

KEY = 'production/test:app'


def test_freq_profile_is_zero_at_training_mean_and_grows_with_deviation():
    rng = np.random.default_rng(1)
    x = rng.normal(size=(500, 249))
    profile = bl.FreqProfile(x)
    center = x.mean(0, keepdims=True)
    shifted = center.copy(); shifted[0, bl.FREQ_COLUMNS[:5]] += 3
    other = center.copy(); other[0, 0] += 50   # log-count column: not part of the frequency profile
    assert profile.score(center)[0] < 1e-9 and profile.score(other)[0] == profile.score(center)[0]
    assert profile.score(shifted)[0] > profile.score(center + 0.1)[0] > 0


def test_every_baseline_ranks_an_outlier_above_training_like_rows():
    rng = np.random.default_rng(2)
    train = rng.normal(size=(400, 249))
    models = bl.fit_workload(train, seeds=(73021,))
    test = np.vstack([rng.normal(size=(20, 249)), np.full((1, 249), 8.0)])
    scores = bl.baseline_scores(models, test)
    assert set(scores) == {('iforest', 73021), ('autoencoder', 73021), ('freq_profile', 73021)}
    for s in scores.values():
        assert s.shape == (21,) and s[-1] > s[:-1].max()


def test_spans():
    assert bl.in_spans(10, 10.5, [(9, 11)]) and not bl.in_spans(11, 11.5, [(9, 11)])


def capture(tmp_path, n=600):
    columns = ['f'+str(i) for i in range(249)]
    segment = tmp_path/'workers'/'worker'/'segments'/'s000001'; segment.mkdir(parents=True)
    with (segment/'features.jsonl').open('w') as stream:
        stream.write(json.dumps(dict(columns=columns, feature_schema_sha256=schema_digest(columns))) + '\n')
        for i in range(n):
            row = dict(window_start=100+i*.5, window_end=100+(i+1)*.5, node_name='worker', pod_uid='pod',
                       workload_revision='revision', container_name='app', cgroup_id=19, eligible_for_normal_review=True,
                       workload_key=KEY, exact_total=3+(i % 7), full_counts_delta={'0': 1, '202': 2+(i % 7)},
                       vector=np.full(249, i % 5, dtype=np.float32), columns=columns)
            stream.write(json.dumps(compact_record(row)[0]) + '\n')
    (segment/'TERMINAL.json').write_text('{}')
    return columns


def test_score_writes_holdout_dump_and_replay_that_arm_budget_reads(tmp_path, monkeypatch):
    columns = capture(tmp_path)

    class Model:
        alpha = .05/30
        base = SimpleNamespace(estimator=SimpleNamespace(n_jobs=-1))

        def predict_contexts(self, contexts):
            return dict(tree_score=contexts[:, -1].astype(float), support_score=-contexts[:, -1].astype(float))

    monkeypatch.setattr(bl, 'load_artifact', lambda stream: Model())
    class Scorer:
        disabled = []

        def __call__(self, workload, model, ctx):
            return model.predict_contexts(ctx)

    monkeypatch.setattr(bl, 'VerifiedFastScorer', Scorer)
    study = tmp_path/'study'; study.mkdir()
    (study/'toy.pkl').write_bytes(b'fixture')
    (study/'TERMINAL.json').write_text(json.dumps(dict(completed={
        f'{KEY}|base29|73021': dict(artifact='toy.pkl', sha256=sha256_file(study/'toy.pkl'))})))
    (study/'INDEX.json').write_text(json.dumps(dict(workloads={KEY: {}}, columns=columns)))
    fitted = tmp_path/'baselines'; fitted.mkdir()
    path = fitted/(hashlib.sha256(KEY.encode()).hexdigest() + '.pkl')
    models = bl.fit_workload(np.random.default_rng(3).normal(size=(300, 249)), seeds=(73021,))
    path.write_bytes(pickle.dumps(dict(workload=KEY, models=models)))
    (fitted/'FIT.json').write_text(json.dumps(dict(workloads={KEY: dict(sha256=sha256_file(path))})))
    campaign = tmp_path/'campaign'; (campaign/'trials'/'1').mkdir(parents=True)
    trial = dict(trial_id='1:attack', label='attack', start_at=300., kernel_event_at=300.2, workload_key=KEY,
                 node_name='worker', pod_uid='pod', container_name='app', workload_revision='revision', cgroup_id=19)
    (campaign/'trials'/'1'/'EVALUATION_INPUT.json').write_text(json.dumps(dict(attack=trial)))
    (campaign/'INTERVALS.jsonl').write_text(json.dumps(dict(start_at=300.)) + '\n')
    (campaign/'TERMINAL.json').write_text(json.dumps(dict(finished_at_unix=316.)))
    out = tmp_path/'out'
    stats = bl.score(tmp_path/'workers', study, fitted, [campaign], out, holdout=(100., 400.), batch=64, nodes=['worker'])
    bl.register(out, study, (100., 400.))

    load_study(out)   # registration hashes and arms are what arm_budget expects
    replay = [json.loads(line) for line in (out/'replay'/'windows.jsonl').read_text().splitlines()]
    assert sorted(r['tag'].split('|')[1] for r in replay) == ['autoencoder', 'base29', 'freq_profile', 'iforest', 'tree_ae']
    assert {len(r['windows']) for r in replay} == {94}   # 270 .. 317 s, continuous history, every window scored
    assert all(w['alpha'] == Model.alpha for r in replay for w in r['windows'])
    for arm in ('base29', 'iforest'):
        h = load_holdout(out/'score-dump', arm)[f'{KEY}|{arm}|73021']
        # campaign 300..316 s +- 60 s is not normal; the first context needs 13 windows of history
        assert not ((h['window_end'] > 240) & (h['window_end'] - .5 < 376)).any()
        assert h['window_end'].min() == 107. and h['window_end'].max() == 400.
        assert len(h['window_end']) == stats['holdout_rows']

    tree_ae = next(r for r in replay if '|tree_ae|' in r['tag'])['windows']
    base = next(r for r in replay if '|base29|' in r['tag'])['windows']
    ae = next(r for r in replay if '|autoencoder|' in r['tag'])['windows']
    assert [w['tree_score'] for w in tree_ae] == [w['tree_score'] for w in base]
    assert [w['support_score'] for w in tree_ae] == [w['tree_score'] for w in ae]

    # combine() on an evaluation without combos reproduces the on-the-fly arm exactly
    plain = tmp_path/'plain'; (plain/'replay').mkdir(parents=True)
    (plain/'replay'/'windows.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in replay if '|tree_ae|' not in r['tag']))
    for npz in (out/'score-dump').glob('*/s*/scores.npz'):
        with np.load(npz, allow_pickle=False) as d:
            kept = {k: d[k] for k in d.files if '|tree_ae|' not in k}
        target = plain/'score-dump'/npz.parent.parent.name/npz.parent.name/'scores.npz'; target.parent.mkdir(parents=True)
        np.savez(target, **kept)
    derived = tmp_path/'derived'
    bl.combine(plain, derived, study, (100., 400.))
    load_study(derived)
    a, b = load_holdout(out/'score-dump', 'tree_ae'), load_holdout(derived/'score-dump', 'tree_ae')
    assert a.keys() == b.keys() and all(np.array_equal(a[k][f], b[k][f]) for k in a for f in a[k])
    again = {json.loads(l)['tag']: json.loads(l)['windows'] for l in (derived/'replay'/'windows.jsonl').read_text().splitlines()}
    assert again[f'{KEY}|tree_ae|73021'] == tree_ae and set(t.split('|')[1] for t in again) == {'base29', 'tree_ae'}


def test_score_feature_group_arms_without_baselines(tmp_path, monkeypatch):
    """Feature-group study: every arm gets its own context (here history1 = 2 windows) at the same windows."""
    from sentinel_pulse.syscall_study.feature_groups import feature_arms
    columns = capture(tmp_path)
    widths = []

    class Model:
        alpha = .05/30
        base = SimpleNamespace(estimator=SimpleNamespace(n_jobs=-1))

        def predict_contexts(self, contexts):
            widths.append(contexts.shape[1])
            return dict(tree_score=contexts[:, -1].astype(float), support_score=-contexts[:, -1].astype(float))

    class Scorer:
        disabled = []

        def __call__(self, workload, model, ctx):
            return model.predict_contexts(ctx)

    monkeypatch.setattr(bl, 'load_artifact', lambda stream: Model())
    monkeypatch.setattr(bl, 'VerifiedFastScorer', Scorer)
    arms = feature_arms()
    study = tmp_path/'study'; study.mkdir()
    (study/'toy.pkl').write_bytes(b'fixture')
    item = dict(artifact='toy.pkl', sha256=sha256_file(study/'toy.pkl'))
    (study/'TERMINAL.json').write_text(json.dumps(dict(completed={f'{KEY}|{a}|73021': item for a in ('base29', 'history1')})))
    (study/'INDEX.json').write_text(json.dumps(dict(workloads={KEY: {}}, columns=columns,
                                                    arms={a: arms[a] for a in ('base29', 'history1')})))
    campaign = tmp_path/'campaign'; (campaign/'trials'/'1').mkdir(parents=True)
    trial = dict(trial_id='1:attack', label='attack', start_at=300., kernel_event_at=300.2, workload_key=KEY,
                 node_name='worker', pod_uid='pod', container_name='app', workload_revision='revision', cgroup_id=19)
    (campaign/'trials'/'1'/'EVALUATION_INPUT.json').write_text(json.dumps(dict(attack=trial)))
    (campaign/'INTERVALS.jsonl').write_text(json.dumps(dict(start_at=300.)) + '\n')
    (campaign/'TERMINAL.json').write_text(json.dumps(dict(finished_at_unix=316.)))
    out = tmp_path/'out'
    bl.score(tmp_path/'workers', study, None, [campaign], out, holdout=(100., 400.), batch=64, nodes=['worker'],
             study_arms=('base29', 'history1'))
    bl.register(out, study, (100., 400.), arms=('base29', 'history1'))
    load_study(out)
    assert set(widths) == {249*4, 249*2}
    a, b = (load_holdout(out/'score-dump', arm)[f'{KEY}|{arm}|73021'] for arm in ('base29', 'history1'))
    assert np.array_equal(a['window_end'], b['window_end'])          # matched windows across arms
    np.testing.assert_array_equal(a['tree'], b['tree'])                # same current vector, last column
    tags = {json.loads(l)['tag'] for l in (out/'replay'/'windows.jsonl').read_text().splitlines()}
    assert tags == {f'{KEY}|base29|73021', f'{KEY}|history1|73021'}
