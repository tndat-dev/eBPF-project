import copy

from sentinel_pulse.rca.audit_cases import validate
from sentinel_pulse.rca.tree import build_tree


def case():
    signal = dict(status='candidate-raw-score-only', candidate_manifest_sha256='model',
        policy_sha256='policy', policy_evaluated=True, candidate_alert_preview=True,
        node_name='worker', pod_uid='uid', container_name='app', cgroup_id=123,
        workload_key='production/test:app', window_end=100.)
    return build_tree(signal, [])


def test_valid_empty_context_is_reported_without_rejecting_case():
    assert validate(case(), 'model', 'policy') == []


def test_audit_rejects_dangling_edges_and_cross_container_attribution():
    tree = case()
    tree['nodes'][1]['pod_uid'] = 'another-pod'
    tree['edges'].append(dict(source='unknown-node', target=tree['nodes'][1]['id']))
    assert validate(tree, 'model', 'policy') == [
        'container_trigger_identity_mismatch', 'dangling_graph_edge']


def test_audit_rejects_binding_and_unsupported_causal_claims():
    tree = copy.deepcopy(case())
    tree['causal_root_confirmed'] = True
    errors = validate(tree, 'different-model', 'policy')
    assert 'trigger_model_policy_or_kind_mismatch' in errors
    assert 'unsupported_causal_or_response_claim' in errors
