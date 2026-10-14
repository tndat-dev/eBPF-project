"""Read-only preflight for C3 feature captures; never fits/scores or ranks holdout.

Counts usable temporal contexts against a pinned legacy training schema. This
is input compatibility evidence, not false-positive or detection evidence.
"""
from __future__ import annotations

import argparse
import array
import base64
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import sys
import time
import zlib

from .syscall_histogram_analysis import sha256_file, verify_seals


IDENTITY = ('workload_key', 'node_name', 'pod_uid', 'container_name', 'cgroup_id', 'workload_revision')
FAILURE_COUNTERS = ('task_state_update_fail', 'snapshot_projection_fail',
                    'snapshot_consistency_retry_exhausted', 'target_snapshot_gap')


def verify_capture_source(campaign, start, receipt):
    original = json.loads((campaign/'START.json').read_text())['contract']
    amendment_hash = receipt.get('operational_amendment_sha256')
    if amendment_hash is None:
        if start['source_commit'] != original['source_commit']:
            raise ValueError('capture source changed without bound amendment')
        return
    from .syscall_capture_campaign import verify_amendment
    path = campaign/'AMENDMENT-target-settle-20261014.json'
    amendment = json.loads(path.read_text())
    effective = amendment['effective_contract']
    verify_amendment(original, effective, path, amendment_hash, sha256_file(campaign/'START.json'))
    if (start['source_commit'] != effective['source_commit']
            or start['runner_sha256'] != amendment['unchanged_runtime_sha256']['syscall_histogram_pilot.py']):
        raise ValueError('amended capture source/runner differs')


def decode(row, dimension):
    if row.get('vector_dim') != dimension:
        raise ValueError('feature dimension mismatch')
    compressed = base64.b64decode(row['vector_f32_zlib_b64'], validate=True)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, dimension * 4 + 1)
    if len(raw) != dimension * 4 or not decoder.eof or decoder.unused_data:
        raise ValueError('invalid bounded float32 payload')
    values = array.array('f')
    values.frombytes(raw)
    if sys.byteorder != 'little':
        values.byteswap()
    if not all(math.isfinite(v) for v in values):
        raise ValueError('non-finite vector')
    return values


def audit_rows(stream, columns, revisions, probe_start, probe_end, node_name):
    schema = hashlib.sha256(json.dumps(columns, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    counts, history, by_workload, observed_revisions = Counter(), {}, defaultdict(Counter), defaultdict(set)
    saw_schema = False
    for line in stream:
        row = json.loads(line)
        if row.get('schema') == 'sentinel-pulse-feature-schema-v1':
            if row.get('columns') != columns or row.get('feature_schema_sha256') != schema:
                raise ValueError('sealed feature columns differ from training')
            saw_schema = True
            continue
        if not saw_schema or row.get('schema') != 'sentinel-pulse-feature-v1':
            raise ValueError('missing schema or unsupported feature record')
        if row.get('feature_schema_sha256') != schema:
            raise ValueError('row schema mismatch')
        decode(row, len(columns))
        key = tuple(row.get(k) for k in IDENTITY)
        if any(v is None or v == '' for v in key) or row['node_name'] != node_name:
            raise ValueError('missing or inconsistent source identity')
        start, end = row['window_start'], row['window_end']
        if not all(isinstance(x, (int, float)) and math.isfinite(x) for x in (start, end)) or end <= start:
            raise ValueError('invalid interval')
        exact = row.get('exact_counts', {})
        if not exact or any(type(v) is not int or v < 0 for v in exact.values()) or sum(exact.values()) != row.get('exact_total'):
            raise ValueError('invalid exact counts')
        workload = row['workload_key']
        counts['feature_rows'] += 1
        by_workload[workload]['feature_rows'] += 1
        observed_revisions[workload].add(row['workload_revision'])
        stats = row.get('collector_stats')
        reason = None
        if start < probe_start or end > probe_end:
            reason = 'outside_probe_interval'
        elif workload not in revisions:
            reason = 'no_frozen_variant_model'
        elif row['workload_revision'] not in revisions[workload]:
            reason = 'unapproved_revision'
        elif not .35 <= end - start <= .75:
            reason = 'cadence_invalid'
        elif not isinstance(stats, dict) or any(k not in stats for k in FAILURE_COUNTERS):
            reason = 'missing_collector_integrity'
        elif any(stats[k] != 0 for k in FAILURE_COUNTERS):
            reason = 'collector_integrity_counter_nonzero'
        if reason:
            counts[reason] += 1
            by_workload[workload][reason] += 1
            history.pop(key, None)
            continue
        previous_end, previous_count = history.get(key, (None, 0))
        if previous_end is not None and abs(start - previous_end) > 1e-4:
            counts['history_gap_resets'] += 1
            by_workload[workload]['history_gap_resets'] += 1
            previous_count = 0
        name = 'eligible_four_window_contexts' if previous_count >= 3 else 'warming_rows'
        counts[name] += 1
        by_workload[workload][name] += 1
        history[key] = (end, min(3, previous_count + 1))
    if not saw_schema or not counts['feature_rows']:
        raise ValueError('empty feature capture')
    return dict(counts=dict(counts), workloads={k: dict(v) for k, v in by_workload.items()},
                observed_revisions={k: sorted(v) for k, v in observed_revisions.items()})


def audit_campaign(campaign, split, training_manifest, training_hash, variant_manifest, variant_hash):
    for path, expected in ((training_manifest, training_hash), (variant_manifest, variant_hash)):
        if sha256_file(path) != expected:
            raise ValueError('pinned manifest hash mismatch')
    training, variants = [json.loads(p.read_text()) for p in (training_manifest, variant_manifest)]
    if variants['training_manifest_sha256'] != training_hash or variants['history'] != 3:
        raise ValueError('variant/training binding or history differs')
    columns = training['feature_columns']
    if len(columns) != 249 or len(set(columns)) != 249:
        raise ValueError('legacy 249-column schema required')
    revisions = {k: training['approved_workload_revisions'].get(k, []) for k in variants['workloads']}
    campaign_hash = sha256_file(campaign / 'START.json')
    captures, seen = {}, set()
    # Read a stable prefix of the append-only journal; never include active or
    # rejected attempts, and never change a running capture/coordinator.
    lines = (campaign / 'attempts.jsonl').read_bytes().splitlines(keepends=True)
    for line in lines:
        if not line.endswith(b'\n'):
            continue
        item = json.loads(line)
        attempt = item['attempt']
        if not item['accepted'] or attempt['split'] != split:
            continue
        for run_id in attempt['runs'].values():
            if Path(run_id).name != run_id or run_id in seen:
                raise ValueError('unsafe or duplicate capture')
            seen.add(run_id)
            root = campaign / split / run_id
            seals = verify_seals(root)
            if not {'features.jsonl', 'FEATURE_CAPTURE.json', 'traffic-receipt.json'} <= seals.keys():
                raise ValueError('feature sidecar/receipt not sealed')
            start, terminal, receipt, feature = [json.loads((root / name).read_text()) for name in
                ('START.json', 'TERMINAL.json', 'traffic-receipt.json', 'FEATURE_CAPTURE.json')]
            verify_capture_source(campaign, start, receipt)
            if (receipt.get('campaign_start_sha256') != campaign_hash or receipt.get('split') != split
                    or terminal['state'] != 'completed' or start['run_id'] != run_id
                    or not start.get('no_attack_injection')):
                raise ValueError('capture does not match normal campaign')
            parallel = start.get('parallel_feature_capture', {})
            if (parallel.get('schema') != 'sentinel-pulse-feature-v1' or parallel.get('include_idle') is not False
                    or parallel.get('rolling_windows') != 5 or parallel.get('snapshot_interval_ms') != 500):
                raise ValueError('incompatible feature capture settings')
            if (feature.get('unexpected_exit') or feature.get('loader_exit_status') != 0
                    or feature.get('error') or feature['capture']['malformed'] or feature['capture']['unresolved']):
                raise ValueError('feature sidecar failed')
            with (root / 'features.jsonl').open() as stream:
                result = audit_rows(stream, columns, revisions, terminal['probe_started_at_unix'],
                                    terminal['probe_ended_at_unix'], start['node_name'])
            if result['counts']['feature_rows'] != feature['capture']['emitted']:
                raise ValueError('feature row count differs from sidecar receipt')
            captures[run_id] = dict(regime=attempt['regime'], seals=seals, **result)
    return dict(schema='pulse-variant-capture-preflight-v1', checked_at_unix=time.time(), split=split,
        campaign_start_sha256=campaign_hash, training_manifest_sha256=training_hash,
        variant_manifest_sha256=variant_hash, auditor_sha256=sha256_file(Path(__file__)), captures=captures,
        captures_verified=len(captures), expected_captures=15, scores_computed=False,
        normal_labels_adjudicated=False, precision=None, recall=None, kernel_to_alert=None,
        limitations=['compatibility only; health/traffic interval adjudication still required',
                     'no model fitting, score inspection, feature ranking or holdout tuning'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('campaign', 'training-manifest', 'variant-manifest', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--split', choices=('selection', 'holdout'), required=True)
    p.add_argument('--training-sha256', required=True)
    p.add_argument('--variant-sha256', required=True)
    a = p.parse_args()
    result = audit_campaign(a.campaign, a.split, a.training_manifest, a.training_sha256,
                            a.variant_manifest, a.variant_sha256)
    with a.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'captures_verified': result['captures_verified'], 'output': str(a.output)}))


if __name__ == '__main__':
    main()
