"""Audit sealed segment prefixes; retain alerts even in excluded intervals.

This is an observational report, never a legacy formal PASS. Healthy intervals
survive a later segment failure. Rollout/unknown rows remain coverage gaps.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import subprocess

from .detector_freshness import check, complete
from .encoding import decode_vector
from .integrity import sha256_file
from .operational_soak import merge_intervals
from .telemetry_recovery import digest, RecoveryTracker, feature_eligibility
from collections import deque
from .recovery_formal import add_interval, source_key


def audit(root, marker, health_rows, manifest=None):
    # Raw preservation is verified independently of the child's pass verdict.
    subprocess.run(['sha256sum', '--check', '--strict', 'FORMAL_WORKER_SHA256SUMS'],
                   cwd=root, check=True, capture_output=True, timeout=900)
    excluded = []
    previous = marker['started_at_unix']
    for health in health_rows:
        now = health['checked_at_unix']
        if now < previous:
            raise ValueError('non-monotonic health journal')
        if health.get('fatal') or health.get('degraded') or now - previous > 180:
            excluded.append([previous, now + 30])
        if health.get('excluded_interval'):
            excluded.append(health['excluded_interval'])
        previous = now
    excluded = merge_intervals(excluded)
    ends = [b for _, b in excluded]
    statuses, exclusions, all_alerts, admitted_alerts = Counter(), Counter(), Counter(), Counter()
    intervals, counts, volumes = defaultdict(list), defaultdict(Counter), Counter()
    rows, last_checked = 0, None
    errors = []
    tracker = RecoveryTracker(marker['telemetry_recovery_contract']['profile'])
    previous_source = {}
    histories = {}
    alert_hashes = Counter()
    # The recorder emits a recovery snapshot before the feature rows it covers.
    snapshot_ok = False
    snapshot_state = None
    with (root / 'features.jsonl').open() as fs, (root / 'decisions.jsonl').open() as ds:
        for line in fs:
            feature = json.loads(line)
            schema = feature.get('schema')
            if schema == 'sentinel-pulse-recovery-snapshot-v1':
                snapshot_state = tracker.replay(feature)
                snapshot_ok = snapshot_state['can_score']
                if not snapshot_ok:
                    histories.clear()
                continue
            if schema != 'sentinel-pulse-feature-v1':
                continue
            raw = ds.readline()
            if not raw:
                exclusions['unconsumed_feature'] += 1
                continue
            row = json.loads(raw)
            if source_key(row) != source_key(feature) or row.get('workload_key') != feature.get('workload_key'):
                raise ValueError('feature/decision alignment mismatch')
            if (row.get('model_manifest_sha256') != marker['model_manifest_sha256'] or
                    row.get('decision_policy_sha256') != marker['decision_policy_sha256'] or
                    row.get('run_id') != marker['run_id']):
                raise ValueError('decision model/policy/run mismatch')
            rows += 1
            key, status = row['workload_key'], row['status']
            statuses[status] += 1
            if status == 'alert':
                all_alerts[key] += 1
                alert_hashes[digest(row)] += 1
            begin, end = row['window_start'], row['window_end']
            if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in (begin, end)) or end <= begin:
                raise ValueError('invalid time interval')
            meta = row['detector_freshness']
            checked = check(feature, meta['checked_at'], last_checked)
            if complete(checked, end, meta['decision_completed_at']) != meta:
                raise ValueError('freshness replay mismatch')
            last_checked = meta['checked_at']
            if row.get('telemetry_recovery') != feature.get('telemetry_recovery'):
                raise ValueError('feature/decision recovery mismatch')
            if row.get('workload_revision') != feature.get('workload_revision'):
                raise ValueError('feature/decision revision mismatch')
            recovery = feature['telemetry_recovery']
            expected_eligibility = feature_eligibility(
                snapshot_state,
                tracker.profile, recovery['rolling_history_before'], begin, end, feature['emitted_at'])
            if (recovery['snapshot_sequence'] != tracker.sequence or recovery['epoch'] != tracker.epoch
                    or recovery['profile_sha256'] != tracker.profile_sha256
                    or (recovery['eligible'], recovery['reason']) != expected_eligibility):
                raise ValueError('feature recovery eligibility mismatch')
            source = source_key(feature)[:4]
            if end <= previous_source.get(source, -math.inf):
                raise ValueError('non-monotonic source windows')
            previous_source[source] = end
            if manifest is not None:
                history = histories.setdefault(source, deque(maxlen=manifest['history_windows']))
                if not recovery['eligible'] or not meta['eligible']:
                    history.clear()
                else:
                    if history and (end-history[-1][0] > manifest['max_contiguous_gap_seconds']
                                    or history[-1][1] != feature.get('traffic_regime')):
                        history.clear()
                    approved = feature.get('workload_revision') in manifest.get('approved_workload_revisions', {}).get(key, [])
                    if approved and (status in {'normal', 'suppressed', 'alert'}) != (len(history) == manifest['history_windows']):
                        raise ValueError('scoring history mismatch')
                    history.append((end,feature.get('traffic_regime')))
            reason = None
            if status not in {'normal', 'suppressed', 'alert'}:
                reason = status
            elif not snapshot_ok or not feature.get('telemetry_recovery', {}).get('eligible'):
                reason = 'telemetry_ineligible'
            else:
                if not meta['eligible']:
                    reason = 'stale'
            if manifest is not None and feature.get('workload_revision') not in manifest.get('approved_workload_revisions', {}).get(key, []):
                reason = 'unapproved_revision'
            i = bisect_right(ends, begin)
            if not health_rows or begin < marker['started_at_unix'] or end > previous:
                reason = 'health_unobserved'
            elif i < len(excluded) and excluded[i][0] < end:
                reason = 'health_degraded'
            if reason:
                exclusions[reason] += 1
                continue
            # Require finite features and nonnegative integer exact counts.
            vector = decode_vector(feature)
            if len(vector) != 249 or not all(math.isfinite(float(v)) for v in vector):
                raise ValueError('invalid feature vector')
            exact = feature['exact_counts']
            if any(type(v) is not int or v < 0 for v in exact.values()) or sum(exact.values()) != feature['exact_total']:
                raise ValueError('invalid exact counts')
            add_interval(intervals[key], begin, end)
            counts[key].update(exact)
            volumes[key] += feature['exact_total']
            if status == 'alert':
                admitted_alerts[key] += 1
        if ds.readline():
            raise ValueError('unbound extra decision')
    # Verify every alert, including those in degraded/excluded time, is retained.
    recorded = Counter()
    with (root / 'alerts.jsonl').open() as stream:
        for line in stream:
            row = json.loads(line)
            recorded[digest(row)] += 1
    if recorded != alert_hashes:
        raise ValueError('alert file content mismatch')
    return {'schema': 'sentinel-pulse-observation-segment-v1', 'run_id': marker['run_id'],
            'decisions': rows, 'statuses': dict(statuses), 'excluded_rows': dict(exclusions),
            'all_alerts': dict(all_alerts), 'eligible_alerts': dict(admitted_alerts),
            'valid_intervals': {k: merge_intervals(v) for k, v in intervals.items()},
            'exact_counts': {k: dict(v) for k, v in counts.items()}, 'exact_totals': dict(volumes),
            'raw_sha256': {name: sha256_file(root / name) for name in ('features.jsonl', 'decisions.jsonl', 'alerts.jsonl')},
            'normal_labels_adjudicated': False, 'precision': None, 'recall': None,
            'legacy_formal_pass': False, 'errors': errors}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--marker', type=Path, required=True)
    p.add_argument('--health', type=Path, required=True)
    args = p.parse_args()
    marker = json.loads(args.marker.read_text())
    health = [json.loads(l) for l in args.health.read_text().splitlines()]
    print(json.dumps(audit(args.root, marker, health), allow_nan=False))


if __name__ == '__main__':
    main()
