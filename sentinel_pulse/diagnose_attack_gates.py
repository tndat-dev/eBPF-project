"""Descriptive gate attribution of an exposed matrix; never tune thresholds."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from .integrity import sha256_file
from .run_500ms_blind_matrix import atomic_json


def classify(trial, records):
    if trial['status'] != 'observed':
        return {'first_limiting_stage': 'infrastructure_unknown', 'scored_horizon_windows': 0}
    begin = float(trial['injected_at'])
    selected = [r for r in records if r.get('status') in {'normal','suppressed','alert'}
                and r.get('workload_key') == trial['workload_key'] and r.get('pod_uid') == trial['pod_uid']
                and r.get('node_name') == trial['node_name'] and str(r.get('cgroup_id')) == str(trial['cgroup_id'])
                and begin <= float(r.get('window_end',0)) <= begin+15
                and float(r.get('alerted_at',begin+16)) <= begin+15]
    raw = sum(r.get('raw_model_anomalous') is True for r in selected)
    model_score = sum(r.get('raw_model_anomalous') is True and r.get('score_corroborated') is True for r in selected)
    same = sum(r.get('raw_model_anomalous') is True and r.get('score_corroborated') is True
               and r.get('semantic_corroborated') is True for r in selected)
    stage = ('detected' if trial['detected'] else 'no_scored_horizon_window' if not selected
             else 'no_raw_model_anomaly' if not raw else 'score_excess_veto' if not model_score
             else 'semantic_or_event_time_join_veto' if not same else 'temporal_confirmation_or_attribution_veto')
    return dict(first_limiting_stage=stage, scored_horizon_windows=len(selected),
                raw_anomalous_windows=raw, raw_and_score_windows=model_score, raw_score_semantic_windows=same,
                max_score=max((r['score'] for r in selected), default=None),
                minimum_conformal_p=min((r['conformal_p'] for r in selected), default=None),
                any_semantic_windows=sum(r.get('semantic_corroborated') is True for r in selected))


def verified_records(path, start):
    """Stream large tails; do not materialize all workload decisions in RAM."""
    if not path.exists():
        raise ValueError('observed trial has no decision tail')
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row.get('status') in {'normal','suppressed','alert'} and (
                    row.get('model_manifest_sha256') != start['model_manifest_sha256']
                    or row.get('decision_policy_sha256') != start['decision_policy_sha256']):
                raise ValueError('decision tail model/policy mismatch')
            yield row


def analyze(root, output):
    start = json.loads((root/'START.json').read_text())
    policy = json.loads(Path(start['config']['policy']).read_text())
    if sha256_file(Path(start['config']['policy'])) != start['decision_policy_sha256']:
        raise ValueError('frozen policy changed')
    raw = (root/'TRIALS.jsonl').read_bytes()
    trials = [json.loads(l) for l in raw.splitlines()]
    details, scenarios, workloads = [], defaultdict(Counter), defaultdict(Counter)
    for trial in trials:
        records = []
        if trial['status'] == 'observed':
            index = int(trial['injection_id'].rsplit(':',1)[1])
            records = verified_records(root/'trials'/f'{index:04d}'/'decision-tail.jsonl', start)
        detail = classify(trial,records)
        details.append(dict(injection_id=trial['injection_id'], scenario=trial['scenario'],
                            workload_key=trial['workload_key'], **detail))
        scenarios[trial['scenario']][detail['first_limiting_stage']] += 1
        workloads[trial['workload_key']][detail['first_limiting_stage']] += 1
    import hashlib
    report = dict(schema='pulse-exposed-attack-gate-diagnosis-v1',
        frozen_model_manifest_sha256=start['model_manifest_sha256'],
        frozen_decision_policy_sha256=start['decision_policy_sha256'],
        trial_receipts=len(trials), trial_prefix_sha256=hashlib.sha256(raw).hexdigest(),
        full_controller_seal_present=(root/'EVIDENCE_SEAL.json').exists(),
        scenarios={k:dict(v) for k,v in scenarios.items()}, workloads={k:dict(v) for k,v in workloads.items()},
        details=details, semantic_fields=policy['same_window_corroboration']['security_activity_fields'],
        evidence_class='exposed_test_descriptive_diagnosis_not_fresh_validation',
        thresholds_or_models_selected_from_this_report=False, automatic_promotion=False)
    atomic_json(output,report)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);analyze(a.root,a.output)


if __name__=='__main__':main()
