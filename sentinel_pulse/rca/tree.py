"""Evidence trees for post-alert investigation, never a causal verdict.

Aggregate syscall anomalies do not identify an offending process. Only exact
pod/container/node identity and a bounded time interval are joined here.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math


def event_time(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
        raise ValueError('missing or invalid event timestamp')
    return float(value)


def trigger_kind(row, model_hash, policy_hash):
    if row.get('candidate_manifest_sha256') != model_hash or row.get('policy_sha256') != policy_hash:
        return None
    scored = row.get('status') == 'candidate-raw-score-only' and row.get('policy_evaluated') is True
    tripwire = row.get('tripwire_alert') is True and row.get('tripwire_status') == 'judged'
    if not (scored or tripwire):
        return None
    if not all(row.get(k) for k in ('node_name', 'pod_uid', 'container_name', 'workload_key')):
        return None
    event_time(row.get('window_end'))
    # A preview is not relabeled as an operational alert, even if both flags exist.
    if scored and row.get('candidate_alert_preview') is True:
        return 'candidate_alert_preview'
    if scored and row.get('alert') is True:
        return 'operational_alert'
    # tripwire A1 (rules/tripwire.py) beside ML: it judges every window of a modelled workload, warming ones too
    if tripwire:
        return 'tripwire_alert'
    return None


def identity(row):
    return tuple(str(row[k]) for k in ('node_name', 'pod_uid', 'container_name'))


def case_id(row):
    fields = {k: row.get(k) for k in ('run_id', 'capture_segment', 'node_name', 'pod_uid',
              'container_name', 'cgroup_id', 'window_end', 'candidate_manifest_sha256', 'policy_sha256')}
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:24]


def build_tree(trigger, edges, *, before_seconds=30, after_seconds=5, max_edges=200,
               coverage=None):
    at = event_time(trigger.get('window_end'))
    matched = []
    for edge in edges:
        source = edge.get('source', {})
        # Never join solely by PID, pod name, workload name or an IP address.
        key = (edge.get('node_name'), source.get('pod_uid'), source.get('container_name'))
        if key != identity(trigger):
            continue
        if trigger.get('container_id') and source.get('container_id') != trigger['container_id']:
            continue
        if at-before_seconds <= event_time(edge.get('observed_at')) <= at+after_seconds:
            matched.append(edge)
    matched.sort(key=lambda e: (event_time(e['observed_at']), e['raw_event_sha256']))
    selected = matched[:max_edges]
    nodes, links = {}, []
    root = 'signal:'+case_id(trigger)
    nodes[root] = dict(id=root, kind='signal', trigger=trigger)
    pod_id = 'container:'+'|'.join(identity(trigger))
    nodes[pod_id] = dict(id=pod_id, kind='container', node_name=trigger['node_name'],
        pod_uid=trigger['pod_uid'], container_name=trigger['container_name'],
        workload_key=trigger['workload_key'])
    links.append(dict(source=root, target=pod_id, relation='signal_on_container'))
    for edge in selected:
        source, parent = edge['source'], edge.get('parent', {})
        # Exec ID carries process start identity; PID fallback is deliberately forbidden.
        if source.get('exec_id'):
            proc = 'exec:'+trigger['node_name']+':'+source['exec_id']
        else:
            proc = 'unknown-process:'+edge['raw_event_sha256']
        nodes[proc] = dict(id=proc, kind='process', **source)
        links.append(dict(source=pod_id, target=proc, relation='observed_process_in_container'))
        parent_exec = source.get('parent_exec_id')
        if parent_exec and parent_exec != source.get('exec_id'):
            par = 'exec:'+trigger['node_name']+':'+parent_exec
            details = parent if parent.get('exec_id') == parent_exec else {'exec_id': parent_exec}
            nodes.setdefault(par, dict(id=par, kind='process_parent', **details))
            links.append(dict(source=par, target=proc, relation='parent_of',
                              evidence='tetragon_exec_identity'))
        connect_id = 'connect:'+edge['raw_event_sha256']
        nodes[connect_id] = dict(id=connect_id, kind='connect_attempt',
            observed_at=edge['observed_at'], socket_fd=edge['connection']['socket_fd'],
            success='unknown_no_return_probe', evidence_sha256=edge['raw_event_sha256'])
        dest = edge['destination']
        dest_id = 'destination:'+json.dumps([dest.get('family'), dest.get('address'), dest.get('port')])
        nodes[dest_id] = dict(id=dest_id, kind='destination', **dest)
        links.extend([dict(source=proc, target=connect_id, relation='called_connect'),
                      dict(source=connect_id, target=dest_id, relation='attempted_destination')])
    unique_links = {json.dumps(link, sort_keys=True): link for link in links}
    return dict(schema='sentinel-pulse-rca-evidence-tree-v1', case_id=case_id(trigger),
        trigger_kind='candidate_alert_preview' if trigger.get('candidate_alert_preview') is True else 'operational_alert',
        causal_root_confirmed=False, automatic_response=False, affects_model_decision=False,
        join=dict(node_pod_uid_container=True, before_seconds=before_seconds, after_seconds=after_seconds,
                  process_causality='not_established_by_aggregate_anomaly'),
        coverage=coverage or {}, matched_connect_events=len(matched), retained_connect_events=len(selected),
        truncated=len(matched)>len(selected), application_payload_captured=False,
        limitations=['connect_entry_is_an_attempt_not_a_success_receipt',
                     'no_l7_payload_or_tls_plaintext', 'time_join_is_not_proof_of_root_cause',
                     'missing_events_are_unknown_not_evidence_of_no_connection'],
        nodes=list(nodes.values()), edges=list(unique_links.values()))


def render_markdown(tree):
    trigger = tree['nodes'][0]['trigger']
    lines = ['# Cây bằng chứng sau tín hiệu Pulse', '',
        f"Case: `{tree['case_id']}`. Nguồn: `{tree['trigger_kind']}`.", '',
        f"Workload: `{trigger['workload_key']}`; node: `{trigger['node_name']}`; pod UID: `{trigger['pod_uid']}`.", '',
        'Đây là bằng chứng tương quan, chưa xác nhận process nào gây anomaly hoặc root cause.', '',
        f"Connect khớp: {tree['matched_connect_events']}; giữ trong cây: {tree['retained_connect_events']}.", '',
        '| Loại | Bằng chứng |', '|---|---|']
    def safe(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ').replace('`', "'")
    for node in tree['nodes']:
        if node['kind'] in ('process', 'process_parent'):
            lines.append(f"| {node['kind']} | binary={safe(node.get('binary'))}; pid={safe(node.get('pid'))}; exec_id={safe(node.get('exec_id'))} |")
        if node['kind']=='destination':
            lines.append(f"| Đích connect (chưa biết thành công) | {safe(node.get('address'))}:{safe(node.get('port'))}; K8s={safe(node.get('kubernetes'))} |")
    lines.extend(['', '## Phạm vi quan sát', '', '```json', json.dumps(tree['coverage'], indent=2, ensure_ascii=False), '```', '',
        'Không thu nội dung ứng dụng, mật khẩu, argv hoặc TLS plaintext. JSON kèm theo chứa đầy đủ node/edge và hash bằng chứng.', ''])
    return '\n'.join(lines)
