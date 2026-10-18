"""Batch the frozen idle-aware scorer while retaining per-container histories."""
from __future__ import annotations

from collections import defaultdict
import time

import numpy as np

from .candidate_shadow import CandidateShadowRuntime, is_valid_feature_schema_record
from .idle_candidate import FEATURE_DIM


SCORE_FIELDS = ('tree_score', 'tree_p', 'support_score', 'support_p', 'joint_p')


def score_batch(scorer, workload, contexts):
    values = np.asarray(contexts, dtype=np.float32)
    width = (scorer.manifest['history_windows'] + 1) * FEATURE_DIM
    if values.ndim != 2 or values.shape[1] != width or not len(values) or not np.isfinite(values).all():
        raise ValueError('batch must contain finite complete temporal contexts')
    model = scorer.models.get(workload)
    if model is None:
        return [dict(status='candidate-model-unavailable', workload_key=workload,
                     candidate_manifest_sha256=scorer.manifest_sha256, alert=False) for _ in values]
    raw = model.predict_contexts(values)
    arrays = {name: np.asarray(raw[name]).reshape(-1) for name in (*SCORE_FIELDS, 'anomalous')}
    if any(len(a) != len(values) for a in arrays.values()):
        raise ValueError('batch result cardinality differs from contexts')
    if any(not np.isfinite(arrays[name]).all() for name in SCORE_FIELDS):
        raise ValueError('candidate produced non-finite batch scores')
    return [dict(status='candidate-raw-score-only', workload_key=workload,
        candidate_manifest_sha256=scorer.manifest_sha256,
        **{name: float(arrays[name][i]) for name in SCORE_FIELDS},
        raw_model_anomaly=bool(arrays['anomalous'][i]), alert=False,
        policy_applied=False, serving_compatible=False) for i in range(len(values))]


class DeferredScorer:
    """Prepare the same contexts as the scalar runtime without predicting yet."""
    def __init__(self, manifest, manifest_sha256):
        self.manifest, self.manifest_sha256 = manifest, manifest_sha256
        self.models = {key: None for key in manifest['workloads']}
        self.requests = []

    def score_context(self, workload_key, context):
        self.requests.append((workload_key, np.asarray(context, dtype=np.float32).copy()))
        return dict(status='batch-pending', workload_key=workload_key,
                    candidate_manifest_sha256=self.manifest_sha256, alert=False)


class IdleBatchRuntime:
    """Group prepared contexts by workload; keep output ordering and policy."""
    def __init__(self, scorer, policy=None, max_gap_seconds=.8, max_identities=10000):
        if policy is not None and policy.scorer is not scorer:
            raise ValueError('policy must bind the supplied frozen scorer')
        self.scorer, self.policy = scorer, policy
        self.deferred = DeferredScorer(scorer.manifest, scorer.manifest_sha256)
        self.history = CandidateShadowRuntime(self.deferred, max_gap_seconds=max_gap_seconds,
                                             max_identities=max_identities)

    def observe_many(self, records, *, prepared_at=None):
        if len(records) > 256:
            raise ValueError('bounded runtime batch accepts at most 256 records')
        self.deferred.requests.clear()
        out, requests = [], defaultdict(list)
        for record in records:
            try:
                if is_valid_feature_schema_record(record):
                    continue
                decision = self.history.observe(record, processed_at=prepared_at)
                if decision['status'] == 'batch-pending':
                    key, context = self.deferred.requests[-1]
                    requests[key].append((len(out), context))
            except (KeyError, TypeError, ValueError) as exc:
                decision = dict(schema='sentinel-pulse-candidate-shadow-score-v1', status='record_rejected',
                    reason=type(exc).__name__, processed_at=time.time(), alert=False,
                    policy_applied=False, serving_compatible=False)
            out.append(decision)
        for key, pending in requests.items():
            begin = time.perf_counter()
            scores = score_batch(self.scorer, key, np.stack([context for _, context in pending]))
            elapsed_ms = (time.perf_counter() - begin) * 1000
            for (index, _), score in zip(pending, scores):
                decision = out[index]
                decision.update(score)
                if self.policy is not None:
                    decision.update(self.policy.evaluate(score))
                completed = time.time()
                decision.update(processed_at=completed, inference_ms=elapsed_ms,
                    batch_inference_ms=elapsed_ms, batch_contexts=len(pending),
                    amortized_inference_ms=elapsed_ms/len(pending),
                    feature_event_age_seconds=completed-decision['window_end'],
                    alert=False, policy_applied=False, serving_compatible=False)
        self.deferred.requests.clear()
        return out
