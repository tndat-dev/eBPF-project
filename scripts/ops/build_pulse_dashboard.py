#!/usr/bin/env python3
"""Write the Grafana dashboard of the Pulse operational alert path (English; uid sentinel-pulse-alerts).

Panels read the alert bridge's Prometheus metrics (``sentinel_pulse_*``, scraped every 5 s, ``pull_profile="fast"``)
and, for the RCA table, the bridge's ``/cases.json`` through the Infinity datasource (free Grafana plugin
``yesoreyeram-infinity-datasource``, uid ``sentinel-pulse-infinity``, provisioned by
``testbed/k8s/monitoring/sentinel-pulse-infinity-datasource.yaml``). Every case row links to the bridge's case page
and SVG tree.

    python3 scripts/ops/build_pulse_dashboard.py [--bridge http://10.1.16.234:9478] > testbed/k8s/monitoring/sentinel-pulse-dashboard.json
"""
import argparse
import json

PROM = {'type': 'prometheus', 'uid': '${datasource}'}
INFINITY = {'type': 'yesoreyeram-infinity-datasource', 'uid': 'sentinel-pulse-infinity'}
F = 'pull_profile="fast"'
CLASSES = ('tripwire', 'security_operation', 'new_binary', 'probe_only', 'other')


def panel(pid, kind, title, x, y, w, h, targets, description='', unit='short', **extra):
    return dict(id=pid, type=kind, title=title, description=description, datasource=extra.pop('datasource', PROM),
                gridPos=dict(x=x, y=y, w=w, h=h), fieldConfig=dict(defaults=dict(unit=unit), overrides=[]),
                targets=targets, **extra)


def prom(expr, legend='', ref='A', instant=False):
    return dict(refId=ref, expr=expr, legendFormat=legend, instant=instant)


def build(bridge):
    p = []
    p.append(panel(1, 'text', 'How to read this dashboard', 0, 0, 24, 4, [], options=dict(mode='markdown', content=(
        'Sentinel Pulse runs in **shadow mode**: an alert is a preview of the frozen model and policy, never an automatic '
        'response. *Containers alerting* counts open alert episodes; an *episode* is consecutive alerting windows of one '
        'container (gap > 3 s ends it). *Immediate* alerts are tripwire hits or RCA cases with a credential, namespace, mount '
        'or ptrace operation; probe-only and other cases stay on this dashboard. Episode counts here include attack-campaign '
        'trials and Kubernetes exec probes, so they are not the thesis burden metric (normal time only, per replica-hour). '
        'Click a case id to open its evidence tree (association by identity and time, not proven causality).'))))
    p.append(panel(2, 'stat', 'Containers alerting now', 0, 4, 4, 4,
                   [prom(f'count(sentinel_pulse_preview_active{{{F}}}) or vector(0)')]))
    p.append(panel(3, 'stat', 'Alert episodes in range', 4, 4, 4, 4,
                   [prom(f'sum(increase(sentinel_pulse_bridge_events_total{{{F},event="episodes_started"}}[$__range]))')]))
    p.append(panel(4, 'stat', 'Immediate notifications in range', 8, 4, 4, 4,
                   [prom(f'sum(increase(sentinel_pulse_bridge_events_total{{{F},event=~"notifications_.*"}}[$__range])) or vector(0)')],
                   description='Triage alerts routed to the immediate receiver (tripwire or security operation).'))
    p.append(panel(5, 'stat', 'p95 preview → Alertmanager → webhook (push)', 12, 4, 4, 4,
                   [prom(f'histogram_quantile(0.95, sum by (le) (increase(sentinel_pulse_alert_delivery_seconds_bucket{{{F},path="push"}}[$__range])))')],
                   unit='s'))
    p.append(panel(6, 'stat', 'Decision streams connected', 16, 4, 4, 4,
                   [prom(f'sum(sentinel_pulse_decision_stream_up{{{F}}})')], description='One per worker node; 3 expected.'))
    p.append(panel(7, 'stat', 'RCA cases in range', 20, 4, 4, 4,
                   [prom(f'sum(increase(sentinel_pulse_bridge_events_total{{{F},event=~"rca_cases_.*"}}[$__range])) or vector(0)')]))
    p.append(panel(8, 'timeseries', 'Containers alerting, by workload', 0, 8, 24, 8,
                   [prom(f'count by (workload) (sentinel_pulse_preview_active{{{F}}})', '{{workload}}')]))
    lat = []
    for i, (q, path) in enumerate((('0.5', 'push'), ('0.95', 'push'), ('0.5', 'pull-fast'), ('0.95', 'pull-fast'),
                                   ('0.5', 'pull-default'), ('0.95', 'pull-default'))):
        lat.append(prom(f'histogram_quantile({q}, sum by (le) (increase(sentinel_pulse_alert_delivery_seconds_bucket{{{F},path="{path}"}}[30m])))',
                        f'p{int(float(q) * 100)} {path}', chr(65 + i)))
    p.append(panel(9, 'timeseries', 'Preview → webhook latency by path (p50 / p95, trailing 30 min)', 0, 16, 12, 8, lat, unit='s',
                   description='From the decision preview to the webhook receipt; not kernel → recipient.'))
    p.append(panel(10, 'timeseries', 'RCA cases per hour, by triage class', 12, 16, 12, 8,
                   [prom(f'sum(increase(sentinel_pulse_bridge_events_total{{{F},event="rca_cases_{c}"}}[1h]))', c, chr(65 + i))
                    for i, c in enumerate(CLASSES)]))
    p.append(panel(11, 'timeseries', 'Alert episodes per hour (whole cluster)', 0, 24, 12, 8,
                   [prom(f'sum(increase(sentinel_pulse_bridge_events_total{{{F},event="episodes_started"}}[1h]))', 'episodes/hour')]))
    p.append(panel(12, 'timeseries', 'Immediate notifications per hour, by class', 12, 24, 12, 8,
                   [prom(f'sum(increase(sentinel_pulse_bridge_events_total{{{F},event="notifications_{c}"}}[1h]))', c, chr(65 + i))
                    for i, c in enumerate(('tripwire', 'security_operation'))]))
    columns = [('created_at', 'Created', 'timestamp_epoch_s'), ('case_id', 'Case', 'string'), ('rca_class', 'Class', 'string'),
               ('notify', 'Notify', 'string'), ('workload', 'Workload', 'string'), ('node', 'Node', 'string'),
               ('top_binary', 'Top suspect', 'string'), ('top_reasons', 'Reasons', 'string'), ('top_score', 'Score', 'number'),
               ('connections', 'Network destinations', 'number'), ('svg_url', 'Tree', 'string')]
    table = panel(13, 'table', 'Recent RCA cases (last 6 h)', 0, 32, 24, 12, [dict(
        refId='A', datasource=INFINITY, type='json', source='url', format='table', parser='backend',
        url=f'{bridge}/cases.json?hours=6', url_options=dict(method='GET'),
        columns=[dict(selector=s, text=t, type=k) for s, t, k in columns])], datasource=INFINITY,
        options=dict(showHeader=True, sortBy=[dict(displayName='Created', desc=True)]),
        description='From the alert bridge (/cases.json). Case opens the English case page; Tree opens the SVG drawing.')
    table['fieldConfig']['overrides'] = [
        dict(matcher=dict(id='byName', options='Case'), properties=[dict(id='links', value=[
            dict(title='Open RCA case', url=f'{bridge}/cases/${{__value.raw}}', targetBlank=True)])]),
        dict(matcher=dict(id='byName', options='Tree'), properties=[
            dict(id='links', value=[dict(title='Open evidence tree (SVG)', url='${__value.raw}', targetBlank=True)]),
            dict(id='mappings', value=[dict(type='regex', options=dict(pattern='.*', result=dict(text='open tree')))])]),
        dict(matcher=dict(id='byName', options='Notify'), properties=[
            dict(id='custom.cellOptions', value=dict(type='color-background')),
            dict(id='mappings', value=[dict(type='value', options={'immediate': dict(color='red', index=0),
                                                                   'dashboard': dict(color='transparent', index=1)})])])]
    p.append(table)
    p.append(panel(14, 'table', 'Pulse alerts firing in Prometheus (pull path)', 0, 44, 24, 8,
                   [prom('ALERTS{alertname="SentinelPulseAnomalyPull",alertstate="firing",path="pull-fast"}', instant=True)],
                   options=dict(showHeader=True)))
    return dict(uid='sentinel-pulse-alerts', title='Sentinel Pulse – operational alerts and RCA', tags=['sentinel-pulse'],
                timezone='browser', schemaVersion=39, version=2, refresh='10s', time=dict(**{'from': 'now-6h', 'to': 'now'}),
                templating=dict(list=[dict(name='datasource', type='datasource', query='prometheus', label='Prometheus')]),
                panels=p)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bridge', default='http://10.1.16.234:9478')
    print(json.dumps(build(ap.parse_args().bridge), indent=1, ensure_ascii=False))
