"""Read-only progress/alert review of an observation inspection snapshot.

This does not audit raw streams, change gates, adjudicate alerts, or promote a
model. Rates are descriptive alert counts, never precision, recall, or FPR.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path


def number(value, name):
    if (
        isinstance(value, bool)
        or not isinstance(value, (float, int))
        or not math.isfinite(value)
    ):
        raise ValueError("invalid " + name)
    return float(value)


def alert_counts(values):
    if not isinstance(values, dict):
        raise ValueError("invalid alert counts")
    if any(type(v) is not int or v < 0 for v in values.values()):
        raise ValueError("invalid alert count")
    return Counter(values)


def review(snapshot):
    if snapshot.get('schema') != 'sentinel-pulse-soak-inspection-v1':
        raise ValueError('unsupported inspection schema')
    checked = number(snapshot['checked_at_unix'], 'inspection time')
    registration = snapshot['registration']
    protocol = registration['binding']['protocol']
    elapsed = checked - number(registration['started_at_unix'], 'registration time')
    wall_target = number(protocol['minimum_wall_seconds'], 'wall target')
    exposure_target = number(protocol['target_valid_seconds_per_workload'], 'exposure target')
    if elapsed <= 0 or wall_target <= 0 or exposure_target <= 0:
        raise ValueError('invalid campaign duration')
    status = snapshot['status']
    exposure = {
        k: number(v, 'valid exposure')
        for k, v in status['valid_seconds_per_workload'].items()
    }
    if not exposure or any(v < 0 or v > elapsed for v in exposure.values()):
        raise ValueError('invalid valid exposure')
    all_alerts = Counter()
    eligible_alerts = Counter()
    seen = set()
    for segment in snapshot['segments']:
        if segment['run_id'] in seen:
            raise ValueError('duplicate segment receipt')
        seen.add(segment['run_id'])
        retained = alert_counts(segment['all_alerts'])
        eligible = alert_counts(segment['eligible_alerts'])
        if any(v > retained[k] for k,v in eligible.items()):
            raise ValueError('eligible alerts exceed retained alerts')
        all_alerts.update(retained);eligible_alerts.update(eligible)
    pending = []
    for segment in snapshot['segments']:
        if segment.get('failures'):
            pending.append({
                'run_id': segment['run_id'],
                'failures': segment['failures'],
            })
    low = min(exposure.values())
    high = max(exposure.values())
    return {
        'schema':'sentinel-pulse-observation-review-v1',
        'checked_at_unix':checked,'registration_sha256':snapshot['registration_sha256'],
        'campaign_service':snapshot['campaign_service'],
        'terminal_present':snapshot['terminal_present'],
        'active_segments':[r['run_id'] for r in snapshot['active_segments']],
        'elapsed_wall_hours':elapsed/3600,'wall_progress_percent':min(100,elapsed/wall_target*100),
        'exposure_from':'STATUS.json snapshot; can lag corrections and active segments',
        'valid_hours_range':[low/3600,high/3600],
        'valid_progress_percent_range':[min(100,low/exposure_target*100),min(100,high/exposure_target*100)],
        'bottleneck_workloads':[k for k,v in exposure.items() if v == low],
        'valid_exposure_fraction_range':[low/elapsed,high/elapsed],
        'valid_exposure_fraction_is_not_collector_availability':True,
        'registered_workloads':len(exposure),
        'retained_alerts_from_audited_receipts':dict(all_alerts),
        'retained_alerts_total':sum(all_alerts.values()),
        'eligible_alerts_from_audited_receipts':dict(eligible_alerts),
        'alerts_outside_admitted_exposure':dict(+(all_alerts-eligible_alerts)),
        'all_alerts_per_campaign_wall_hour':sum(all_alerts.values())/(elapsed/3600),
        'wall_rate_is_fleet_wide_not_fpr':True,
        'alerts_require_ground_truth_adjudication':True,
        'precision':None,'recall':None,'false_positive_rate':None,
        'confusion_matrix_measured':None,
        'excluded_rows':status['excluded_rows'],
        'pending_audits_or_preflight_failures':pending,
        'does_not_verify_raw_seals':True,'automatic_promotion':False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspection', type=Path, required=True)
    args = parser.parse_args()
    result = review(json.loads(args.inspection.read_text(encoding='utf-8')))
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
