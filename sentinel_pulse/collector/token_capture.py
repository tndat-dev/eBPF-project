"""Token windows of the lidds-ml-v3 probe (loader built with ``make tokens``, ``--tokens grams``).

The loader prints one ``token_grams`` line per (cgroup, closed 0.5 s window of CLOCK_MONOTONIC) with the window's
distinct 4-grams and their counts, and one ``token_drain`` line per frame. ``token_window`` checks a line and gives
it the identity the feature records carry (workload_key, pod, container, revision), or None for a cgroup outside the
production namespace, as ExtendedFeatureStream does.
"""
from __future__ import annotations

import math

from .capture import workload_key

CONTRACT = 'pulse-token-select1f-v1'
SCHEMA = 'sentinel-pulse-token-window-v1'
TOK_NONE = 0xFFFFFFFF


def check_grams(grams, events):
    total = 0
    for gram in grams:
        if len(gram) != 5:
            raise ValueError('token gram is not 4 tokens and a count')
        *tokens, count = (int(v) for v in gram)
        if count <= 0 or any(not 0 <= t <= TOK_NONE for t in tokens) or tokens[3] == TOK_NONE:
            raise ValueError('token gram out of range')
        seen_token = False
        for t in tokens:                    # empty slots only in front (thread start)
            if t != TOK_NONE:
                seen_token = True
            elif seen_token:
                raise ValueError('empty slot inside a token gram')
        total += count
    if total != int(events):
        raise ValueError('token gram counts differ from window events')


def token_window(row: dict, metadata: dict):
    if row.get('type') != 'token_grams' or row.get('contract') != CONTRACT:
        raise ValueError('wrong token telemetry contract')
    window_end = float(row['window_end'])
    if not math.isfinite(window_end) or int(row['window']) < 0:
        raise ValueError('token window out of range')
    check_grams(row['grams'], row['events'])
    cg = int(row['cgroup_id'])
    item = metadata.get(str(cg))
    if not item or item.get('namespace') != 'production':
        return None
    if not all(item.get(k) for k in ('node_name', 'pod_uid', 'container_name', 'workload_revision')):
        return None
    return dict(type='token_window', schema=SCHEMA, telemetry_contract=CONTRACT, workload_key=workload_key(item),
                cgroup_id=str(cg), pod_name=item.get('pod_name'), pod_uid=item['pod_uid'],
                container_name=item['container_name'], workload_revision=item['workload_revision'],
                node_name=item['node_name'], window=int(row['window']), window_end=window_end,
                events=int(row['events']), grams=row['grams'])
