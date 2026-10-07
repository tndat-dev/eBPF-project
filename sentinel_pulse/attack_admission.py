"""Admission of completed observation evidence, NOT a zero-alert quality gate."""
from __future__ import annotations

import json
import math
from pathlib import Path

from .integrity import sha256_file


def admit(root: Path, manifest: dict, model_sha: str, policy_sha: str) -> dict:
    start = json.loads((root / 'START.json').read_text())
    terminal = json.loads((root / 'TERMINAL.json').read_text())
    if start.get('schema') != 'sentinel-pulse-observation-registration-v1':
        raise ValueError('not an observation registration')
    if (terminal.get('schema') != 'sentinel-pulse-observation-summary-v1'
            or terminal.get('status') != 'completed'
            or terminal.get('exposure_target_reached') is not True
            or terminal.get('automatic_promotion') is not False):
        raise ValueError('observation coverage is not completed')
    binding = start['binding']
    if (binding['model_manifest_sha256'] != model_sha
            or binding['decision_policy_sha256'] != policy_sha):
        raise ValueError('soaked candidate binding mismatch')
    expected = {k for k, v in manifest['workloads'].items() if v['status'] == 'candidate'}
    exposure = terminal['valid_seconds_per_workload']
    target = binding['protocol']['target_valid_seconds_per_workload']
    wall = terminal['elapsed_wall_seconds']
    if (set(exposure) != expected or not expected or isinstance(target, bool)
            or not isinstance(target, (int, float)) or not math.isfinite(target) or target <= 0
            or not isinstance(wall, (int, float)) or isinstance(wall, bool)
            or not math.isfinite(wall) or wall < target):
        raise ValueError('invalid soak coverage')
    for value in exposure.values():
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or not target <= value <= wall):
            raise ValueError('insufficient or invalid workload exposure')
    alerts = terminal['all_alerts']
    if not isinstance(alerts, dict) or any(type(n) is not int or n < 0 for n in alerts.values()):
        raise ValueError('invalid retained alert counts')
    # Deliberately do NOT gate on all_alerts, eligible_alerts or quality_budget_met.
    return {
        'schema': 'sentinel-pulse-attack-normal-admission-v1',
        'start_sha256': sha256_file(root / 'START.json'),
        'terminal_sha256': sha256_file(root / 'TERMINAL.json'),
        'model_manifest_sha256': model_sha, 'decision_policy_sha256': policy_sha,
        'coverage_workloads': sorted(expected), 'all_alerts': alerts,
        'quality_budget_met': terminal.get('quality_budget_met'),
        'zero_alert_gate': False, 'normal_alerts_await_adjudication': True,
        'precision': None, 'false_positive_rate': None,
        'raw_seals_reaudited_by_admission': False,
        'automatic_promotion': False,
    }
