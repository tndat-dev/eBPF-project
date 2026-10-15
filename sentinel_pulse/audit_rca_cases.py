"""Read-only structural and provenance audit of retained live RCA evidence trees."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import time

from .rca_tree import case_id, identity, trigger_kind
from .integrity import sha256_file


def validate(tree, model_hash, policy_hash):
    errors = []
    if tree.get('schema') != 'sentinel-pulse-rca-evidence-tree-v1':
        return ['unsupported_case_schema']
    nodes = tree.get('nodes', [])
    signal = [node for node in nodes if node.get('kind') == 'signal']
    if len(signal) != 1:
        return ['missing_or_duplicate_signal']
    trigger = signal[0].get('trigger', {})
    try:
        kind = trigger_kind(trigger, model_hash, policy_hash)
        if not kind or kind != tree.get('trigger_kind'):
            errors.append('trigger_model_policy_or_kind_mismatch')
        if case_id(trigger) != tree.get('case_id'):
            errors.append('case_identity_mismatch')
        for node in nodes:
            if node.get('kind') == 'container':
                if identity(node) != identity(trigger) or node.get('workload_key') != trigger.get('workload_key'):
                    errors.append('container_trigger_identity_mismatch')
    except (KeyError, ValueError, TypeError):
        errors.append('invalid_trigger_identity_or_time')
    ids = [node.get('id') for node in nodes]
    if None in ids or len(ids) != len(set(ids)):
        errors.append('invalid_or_duplicate_node_id')
    for edge in tree.get('edges', []):
        if edge.get('source') not in ids or edge.get('target') not in ids:
            errors.append('dangling_graph_edge')
    connects = [node for node in nodes if node.get('kind') == 'connect_attempt']
    if len(connects) != tree.get('retained_connect_events'):
        errors.append('connect_count_mismatch')
    for node in connects:
        digest = node.get('evidence_sha256', '')
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            errors.append('missing_connect_evidence_hash')
        if node.get('success') != 'unknown_no_return_probe':
            errors.append('unsupported_connection_success_claim')
    if tree.get('causal_root_confirmed') is not False or tree.get('automatic_response') is not False:
        errors.append('unsupported_causal_or_response_claim')
    if tree.get('application_payload_captured') is not False or tree.get('affects_model_decision') is not False:
        errors.append('unexpected_payload_or_model_side_effect')
    return sorted(set(errors))


def audit(config):
    cfg = json.loads(config.read_text())
    root = Path(cfg['output'])
    status = json.loads((root/'STATUS.json').read_text())
    counts = Counter(); sources = {}; issues = {}; delays = []
    for path in sorted((root/'cases').glob('*.json')):
        try:
            payload = path.read_bytes()
        except FileNotFoundError:
            counts['expired_during_audit'] += 1
            continue
        import hashlib
        sources[path.name] = hashlib.sha256(payload).hexdigest()
        tree = json.loads(payload)
        errors = validate(tree, cfg['model_hash'], cfg['policy_hash'])
        counts['cases_checked'] += 1
        counts['cases_with_errors'] += bool(errors)
        counts['cases_without_connect_context'] += not tree.get('matched_connect_events')
        counts['cases_with_connect_context'] += bool(tree.get('matched_connect_events'))
        counts['cases_truncated'] += tree.get('truncated') is True
        counts['cases_outside_connect_selector'] += tree.get('coverage', {}).get('connect_policy_selected') is False
        counts['cases_stale_inventory'] += (tree.get('coverage', {}).get('inventory_age_seconds') or 0) > 120
        if errors:
            issues[path.name] = errors
        signals = [n for n in tree['nodes'] if n['kind'] == 'signal']
        if len(signals) == 1:
            trigger = signals[0]['trigger']
            emitted = trigger.get('preview_emitted_at')
            if isinstance(emitted, (float, int)) and math.isfinite(emitted):
                delay = tree['created_at']-emitted
                if delay >= 0:
                    delays.append(delay)
    delays.sort()
    def percentile(p):
        if not delays:
            return None
        position = (len(delays)-1)*p
        lo = int(position); hi = min(lo+1, len(delays)-1)
        return delays[lo]+(delays[hi]-delays[lo])*(position-lo)
    return dict(schema='sentinel-pulse-retained-rca-audit-v1', checked_at_unix=time.time(),
        config_sha256=sha256_file(config), counts=dict(counts), case_source_sha256=sources,
        structural_issues=issues, service_status_at_unix=status['updated_at_unix'],
        service_counts=status['counts'], streams=status['streams'],
        preview_to_case_seconds=dict(samples=len(delays), p50=percentile(.5), p95=percentile(.95), p99=percentile(.99)),
        latency_scope='retained cases only; includes post-context wait and subscriber backlog',
        causal_root_confirmed=False, labels_adjudicated=False,
        source_events_completeness='not_verified_by_this_structural_audit', automatic_response=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.config), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
