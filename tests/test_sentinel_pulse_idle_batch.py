import unittest

try:
    import numpy as np
except ImportError:
    np = None


@unittest.skipIf(np is None, 'NumPy required; execute with the worker runtime venv')
class IdleBatchTests(unittest.TestCase):
    def setUp(self):
        from sentinel_pulse.detector.idle_batch import score_batch
        class Model:
            def __init__(self): self.calls = 0
            def predict_contexts(self, values):
                self.calls += 1
                score = values[:, -249]
                p = np.where(score > .5, .001, .5)
                return dict(tree_score=score, support_score=score, tree_p=p, support_p=p,
                            joint_p=p, anomalous=p < .01)
        class Scorer:
            manifest = dict(history_windows=3, workloads={'production/a:app': {}, 'production/b:app': {}})
            manifest_sha256 = 'frozen'
            def __init__(self): self.models = {k: Model() for k in self.manifest['workloads']}
            def score_context(self, k, context): return score_batch(self, k, np.asarray(context).reshape(1,-1))[0]
        class Policy:
            def __init__(self, scorer): self.scorer = scorer
            def evaluate(self, score, context=None):
                return dict(policy_evaluated=True, policy_sha256='policy',
                            candidate_alert_preview=score['raw_model_anomaly'])
        self.scorer, self.Policy = Scorer(), Policy

    def row(self, key='production/a:app', pod='p', index=0, value=0.):
        return dict(schema='sentinel-pulse-extended-feature-v2',
            telemetry_contract='pulse-entered-plus-seccomp-skip-idle-v2', vector_dim=249,
            workload_key=key, pod_uid=pod, container_name='app', workload_revision='rev', cgroup_id=pod,
            window_end=(index+1)*.5, vector=np.full(249, value, dtype=np.float32).tolist())

    def test_scores_match_scalar_and_batch_is_one_model_call(self):
        from sentinel_pulse.detector.idle_batch import score_batch
        x = np.zeros((8,996),np.float32);x[4:,-249:]=1
        scalar = [self.scorer.score_context('production/a:app', row) for row in x]
        before = self.scorer.models['production/a:app'].calls
        batch = score_batch(self.scorer, 'production/a:app', x)
        self.assertEqual(self.scorer.models['production/a:app'].calls-before, 1)
        self.assertEqual(scalar,batch)

    def test_history_policy_order_and_outputs_match_scalar_runtime(self):
        from sentinel_pulse.detector.idle_batch import IdleBatchRuntime
        from sentinel_pulse.detector.candidate_shadow import CandidateShadowRuntime
        policy = self.Policy(self.scorer)
        scalar = CandidateShadowRuntime(self.scorer, policy=policy)
        batched = IdleBatchRuntime(self.scorer, policy=policy)
        rows = [self.row(pod=pod,index=i,value=float(i==3)) for i in range(4) for pod in ('a','b')]
        expected = [scalar.observe(r) for r in rows]
        actual = batched.observe_many(rows)
        for a,b in zip(expected,actual):
            for field in ('status','pod_uid','history_available','raw_model_anomaly','joint_p','candidate_alert_preview'):
                self.assertEqual(a.get(field),b.get(field),field)
            self.assertIs(b['alert'],False)
        self.assertEqual(actual[-1]['batch_contexts'],2)

    def test_gap_and_new_pod_reset_history(self):
        from sentinel_pulse.detector.idle_batch import IdleBatchRuntime
        runtime = IdleBatchRuntime(self.scorer)
        runtime.observe_many([self.row(index=i) for i in range(4)])
        rows = runtime.observe_many([self.row(index=8),self.row(pod='new',index=9)])
        self.assertEqual([r['status'] for r in rows],['warming','warming'])
        self.assertEqual(rows[0]['reset_reason'],'non_contiguous_window')

    def test_unknown_model_invalid_row_and_workload_groups_remain_distinct(self):
        from sentinel_pulse.detector.idle_batch import IdleBatchRuntime
        runtime = IdleBatchRuntime(self.scorer)
        rows = [self.row(key=k,index=i,value=v) for i in range(4)
                for k,v in [('production/a:app',0.),('production/b:app',1.)]]
        result = runtime.observe_many(rows + [self.row(key='production/missing:app'),{}])
        self.assertFalse(result[-4]['raw_model_anomaly'])
        self.assertTrue(result[-3]['raw_model_anomaly'])
        self.assertEqual(result[-2]['status'],'candidate-model-unavailable')
        self.assertEqual(result[-1]['status'],'record_rejected')


if __name__ == '__main__':
    unittest.main()
