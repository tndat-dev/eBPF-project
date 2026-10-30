"""RCA cases as operator-facing views for the alert bridge (RCA integration, 30/10).

The RCA service writes ``<case_id>.json`` (evidence tree) and ``<case_id>.md`` into its ``cases/`` directory; the
case id of the first trigger of an alert episode equals the bridge's episode id. This module only reads those files:

- ``summarize``: the facts an operator needs first (top suspect, its reasons and binary, security operations,
  network destinations, probe-only label) and a triage class used for alert routing:

  ``tripwire``            the alert came from tripwire A1 (a syscall never seen in the workload)   -> notify now
  ``security_operation``  a suspect performed a credential / namespace / mount / ptrace operation  -> notify now
  ``probe_only``          every exec in the window was a Kubernetes probe of the pod spec          -> dashboard
  ``new_binary``          the top suspect is a new or unknown binary, no security operation        -> dashboard
  ``other``               anything else                                                            -> dashboard

  The class is a delivery decision only: the case, the detector's decision and every evaluation metric stay as
  they are (a probe-only alert is still counted as an alert).
- ``CaseIndex``: incremental scan of the cases directory (parse each file once), newest first.
- ``render_html`` / ``case_svg``: a static English page per case and the tree drawing of
  ``scripts/analysis/rca_case_graph.py`` (Graphviz ``dot``, when installed).
"""
from __future__ import annotations

import html
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading

CASE_ID = re.compile(r'^[0-9a-f]{24}$')
NOTIFY = {'tripwire': 'immediate', 'security_operation': 'immediate', 'probe_only': 'dashboard',
          'new_binary': 'dashboard', 'other': 'dashboard'}
NEW_BINARY = {'novel_binary', 'unknown_binary'}
GRAPH = Path(__file__).resolve().parents[2]/'scripts'/'analysis'/'rca_case_graph.py'


def signal(case):
    return next((n.get('trigger') or {} for n in case.get('nodes', []) if n.get('kind') == 'signal'), {})


def classify(case):
    suspects = case.get('suspects') or []
    if case.get('trigger_kind') == 'tripwire_alert':
        return 'tripwire'
    if any('security_operation' in (s.get('reasons') or []) for s in suspects):
        return 'security_operation'
    if (case.get('triage') or {}).get('probe_only'):
        return 'probe_only'
    if suspects and NEW_BINARY & set(suspects[0].get('reasons') or []):
        return 'new_binary'
    return 'other'


def summarize(case, base_url=''):
    trig = signal(case)
    suspects = case.get('suspects') or []
    top = suspects[0] if suspects else {}
    cls = classify(case)
    cid = case.get('case_id')
    target, _, workload = str(trig.get('workload_key', '')).partition('/')
    return dict(case_id=cid, created_at=case.get('created_at'), trigger=case.get('trigger_kind'),
                node=trig.get('node_name'), pod_uid=trig.get('pod_uid'), container=trig.get('container_name'),
                target_namespace=target, workload=workload, window_end=trig.get('window_end'),
                rca_class=cls, notify=NOTIFY[cls],
                top_binary=top.get('binary'), top_reasons=list(top.get('reasons') or []), top_score=top.get('score'),
                suspects=len(suspects),
                security_operation_suspects=sum('security_operation' in (s.get('reasons') or []) for s in suspects),
                connections=len(case.get('network_destinations') or []),
                connect_events=case.get('matched_connect_events', 0), flow_events=case.get('matched_flow_events', 0),
                probe_only=bool((case.get('triage') or {}).get('probe_only')),
                follow_up_of=trig.get('follow_up_of'),
                url=f'{base_url}/cases/{cid}', svg_url=f'{base_url}/cases/{cid}.svg')


def alert_annotations(summary):
    """Alertmanager annotations of an alert whose RCA case is ready (all values are strings)."""
    top = summary['top_binary'] or 'none'
    return dict(rca_class=summary['rca_class'], rca_notify=summary['notify'], rca_top_suspect=str(top),
                rca_top_reasons=', '.join(summary['top_reasons']) or 'none', rca_top_score=str(summary['top_score']),
                rca_security_operation_suspects=str(summary['security_operation_suspects']),
                rca_connections=str(summary['connections']), rca_probe_only=str(summary['probe_only']).lower(),
                rca_url=summary['url'], rca_tree_svg=summary['svg_url'],
                rca_summary=f"top suspect {top} ({', '.join(summary['top_reasons']) or 'no reason'}); "
                            f"{summary['connections']} network destinations; class {summary['rca_class']}")


class CaseIndex:
    """Summaries of the case files in ``directory``; each file is parsed once (by name and mtime)."""

    def __init__(self, directory, base_url='', limit=2000):
        self.dir, self.base_url, self.limit = Path(directory), base_url, limit
        self.seen, self.lock = {}, threading.Lock()

    def refresh(self):
        if not self.dir.is_dir():
            return []
        new = []
        with os.scandir(self.dir) as entries:
            for e in entries:
                if not e.name.endswith('.json') or not CASE_ID.match(e.name[:-5]):
                    continue
                mtime = e.stat().st_mtime
                old = self.seen.get(e.name[:-5])
                if old is not None and old[0] == mtime:
                    continue
                try:
                    s = summarize(json.loads(Path(e.path).read_text()), self.base_url)
                except (ValueError, OSError):
                    continue                                     # partially written or removed: next scan
                with self.lock:
                    self.seen[e.name[:-5]] = (mtime, s)
                if old is None:
                    new.append(s)
        with self.lock:                                          # bounded: drop the oldest summaries
            if len(self.seen) > self.limit:
                for cid, _ in sorted(self.seen.items(), key=lambda kv: kv[1][1]['created_at'] or 0)[:len(self.seen) - self.limit]:
                    del self.seen[cid]
        return new

    def get(self, cid):
        with self.lock:
            hit = self.seen.get(cid)
        return hit[1] if hit else None

    def recent(self, since=None, limit=500):
        with self.lock:
            rows = [s for _, s in self.seen.values() if since is None or (s['created_at'] or 0) >= since]
        return sorted(rows, key=lambda s: s['created_at'] or 0, reverse=True)[:limit]

    def path(self, cid, suffix):
        if not CASE_ID.match(cid or ''):
            return None
        p = self.dir/(cid + suffix)
        return p if p.is_file() else None


def _graph_module():
    spec = importlib.util.spec_from_file_location('rca_case_graph', GRAPH)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def case_svg(case_path: Path, cache_dir: Path):
    """SVG drawing of one case, cached next to the bridge's output; None when Graphviz is not installed."""
    if shutil.which('dot') is None:
        return None
    cache_dir.mkdir(parents=True, exist_ok=True)
    out = cache_dir/(case_path.stem + '.svg')
    if not out.exists() or out.stat().st_mtime < case_path.stat().st_mtime:
        dot = _graph_module().to_dot(json.loads(case_path.read_text()))
        tmp = out.with_suffix('.svg.tmp')
        subprocess.run(['dot', '-Tsvg', '-o', str(tmp)], input=dot.encode(), check=True, timeout=30)
        os.replace(tmp, out)
    return out.read_bytes()


def render_html(summary, case, svg=None):
    e = html.escape
    rows = ''.join(f"<tr><td>{s.get('rank')}</td><td><code>{e(str(s.get('binary')))}</code></td><td>{s.get('pid')}</td>"
                   f"<td>{s.get('score')}</td><td>{e(', '.join(s.get('reasons') or []))}</td></tr>"
                   for s in (case.get('suspects') or [])[:10])
    facts = ''.join(f'<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>' for k, v in (
        ('Case', summary['case_id']), ('Workload', f"{summary['target_namespace']}/{summary['workload']}"),
        ('Node / container', f"{summary['node']} / {summary['container']}"), ('Trigger', summary['trigger']),
        ('Triage class', f"{summary['rca_class']} (notify: {summary['notify']})"),
        ('Network destinations', summary['connections']),
        ('Events', ', '.join(f'{k} {v}' for k, v in sorted((case.get('event_categories') or {}).items())) or 'none'),
        ('Follow-up of', summary['follow_up_of'] or '-')))
    drawing = svg.decode() if svg else '<p>Tree drawing unavailable (Graphviz <code>dot</code> is not installed on the bridge host).</p>'
    limits = ''.join(f'<li>{e(x)}</li>' for x in case.get('limitations') or [])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>RCA case {e(summary['case_id'])}</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;color:#111}}table{{border-collapse:collapse;margin:8px 0}}
td,th{{border:1px solid #bbb;padding:4px 8px;text-align:left;vertical-align:top}}th{{background:#f2f2f2}}
.svg{{border:1px solid #ddd;overflow:auto;max-height:80vh}}</style></head><body>
<h1>Sentinel Pulse RCA case {e(summary['case_id'])}</h1>
<p>Evidence tree for one alert. It shows association by identity and time, not proven causality; no automatic response was taken.
Raw files: <a href="{e(summary['case_id'])}.json">JSON (evidence)</a> · <a href="{e(summary['case_id'])}.md">Markdown</a> ·
<a href="{e(summary['case_id'])}.svg">SVG</a> · <a href="../cases">recent cases</a></p>
<table>{facts}</table><h2>Suspects (triage order, not probability)</h2>
<table><tr><th>Rank</th><th>Binary</th><th>PID</th><th>Score</th><th>Reasons</th></tr>{rows}</table>
<h2>Evidence tree</h2><div class="svg">{drawing}</div><h2>Limitations recorded in the case</h2><ul>{limits}</ul></body></html>"""


def render_index(rows):
    e = html.escape
    body = ''.join(f"<tr><td>{e(str(r['created_at']))}</td><td><a href=\"cases/{r['case_id']}\">{r['case_id']}</a></td>"
                   f"<td>{e(r['workload'] or '')}</td><td>{e(r['node'] or '')}</td><td>{e(r['rca_class'])}</td>"
                   f"<td>{e(r['notify'])}</td><td><code>{e(str(r['top_binary']))}</code></td></tr>" for r in rows)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sentinel Pulse RCA cases</title>
<style>body{{font-family:Arial,sans-serif;margin:24px}}td,th{{border:1px solid #bbb;padding:4px 8px}}
table{{border-collapse:collapse}}th{{background:#f2f2f2}}</style></head><body><h1>Recent RCA cases</h1>
<table><tr><th>Created (unix)</th><th>Case</th><th>Workload</th><th>Node</th><th>Class</th><th>Notify</th><th>Top suspect</th></tr>{body}</table></body></html>"""
