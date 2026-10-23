#!/usr/bin/env python3
"""Draw one RCA case (sentinel_pulse/rca case JSON) as a readable graph: Graphviz DOT, and SVG when ``dot`` exists.

Kept: the trigger, the container, every process and its parents (suspect rank and reasons on the process), and the
process lineage. Collapsed, with counts, per process: runtime operations (exec / fork / ptrace / exit ...) and network
evidence (connect attempts and sampled flows) grouped by what the destination resolved to. The drawing adds nothing
to the case: no inference, same identities; it is a view for reading, the JSON stays the evidence.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import shutil
import subprocess


def q(text):
    return '"' + str(text).replace('\\', '\\\\').replace('"', '\\"') + '"'


def destination_group(node):
    k = node.get('kubernetes') or {}
    addr = str(node.get('address'))
    if node.get('family') == 'AF_UNIX':
        return 'socket Unix (cục bộ)'
    if k.get('kind') == 'KubeletProbe':
        return 'health probe của kubelet (Istio ambient)'
    if k.get('kind') == 'Node':
        return f"Node {k.get('name')} (IP dùng chung, peer thật không rõ)"
    if k:
        return f"{k.get('kind')} {k.get('namespace')}/{k.get('name')}"
    if addr.startswith('127.') or addr == '::1':
        return 'loopback'
    return f'chưa ánh xạ {addr}'


def to_dot(case):
    nodes = {n['id']: n for n in case['nodes']}
    suspects = {s['process']: s for s in case.get('suspects', [])}
    out = ['digraph rca {', 'rankdir=LR; node [shape=box, fontname="Arial", fontsize=10]; edge [fontsize=9];']
    trigger = next((n.get('trigger', {}) for n in case['nodes'] if n['kind'] == 'signal'), {})
    label = f"Pulse {case.get('trigger_kind', '')}\nwindow_end {trigger.get('window_end')}\njoint_p {trigger.get('joint_p')}"
    if case.get('triage'):
        tr = case['triage']
        label += f"\ntriage: probe_only={tr.get('probe_only')} (exec probe {tr.get('probe_execs')}/{tr.get('execs')}; chỉ là nhãn)"
    out.append(f"signal [shape=octagon, style=filled, fillcolor=\"#fde2e2\", label={q(label)}];")
    ops, net = defaultdict(Counter), defaultdict(Counter)
    for e in case['edges']:
        s, t = nodes.get(e['source'], {}), nodes.get(e['target'], {})
        if e['relation'].startswith('performed_'):
            ops[e['source']][t.get('operation') or e['relation'][10:]] += 1
        elif e['relation'] in ('attempted_destination', 'flow_destination'):
            owner = next((x['source'] for x in case['edges'] if x['target'] == e['source']), None)
            net[owner][(('connect' if e['relation'] == 'attempted_destination' else 'flow'), destination_group(t))] += 1
    for n in case['nodes']:
        if n['kind'] == 'container':
            out.append(f"{q(n['id'])} [shape=folder, label={q(n.get('workload_key', '') + chr(10) + 'node ' + n.get('node_name', ''))}];")
            out.append(f"signal -> {q(n['id'])} [label=\"trên container\"];")
        elif n['kind'] in ('process', 'process_parent'):
            s = suspects.get(n['id'])
            label = f"{n.get('binary')}\npid {n.get('pid')}" + ('' if n['kind'] == 'process' else '\n(tiến trình cha)')
            style = ', style=filled, fillcolor="#f8d7da", penwidth=2' if s and s['rank'] == 1 else (', style=filled, fillcolor="#fff3cd"' if s else '')
            if s:
                label += f"\nnghi phạm hạng {s['rank']}: {', '.join(s['reasons'])}"
            out.append(f"{q(n['id'])} [label={q(label)}{style}];")
    for e in case['edges']:
        if e['relation'] == 'parent_of':
            out.append(f"{q(e['source'])} -> {q(e['target'])} [label=\"cha của\"];")
        elif e['relation'] == 'observed_process_in_container':
            out.append(f"{q(e['source'])} -> {q(e['target'])} [style=dotted, arrowhead=none];")
    for i, (proc, counts) in enumerate(ops.items()):
        out.append(f"ops{i} [shape=note, label={q(', '.join(f'{k} ×{v}' for k, v in counts.most_common()))}];")
        out.append(f"{q(proc)} -> ops{i} [label=\"thao tác\"];")
    for i, (proc, counts) in enumerate(net.items()):
        lines = [f'{kind} ×{v} → {dest}' for (kind, dest), v in sorted(counts.items(), key=lambda x: -x[1])]
        shown = lines[:12] + ([f'... {len(lines) - 12} nhóm khác'] if len(lines) > 12 else [])
        out.append(f"net{i} [shape=component, label={q(chr(10).join(shown))}];")
        out.append(f"{q(proc)} -> net{i} [label=\"mạng\"];")
    out.append('}')
    return '\n'.join(out) + '\n'


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('case', type=Path)
    p.add_argument('--output', type=Path, required=True, help='DOT path; an .svg is written next to it when dot exists')
    a = p.parse_args()
    dot = to_dot(json.loads(a.case.read_text()))
    a.output.write_text(dot)
    if shutil.which('dot'):
        subprocess.run(['dot', '-Tsvg', str(a.output), '-o', str(a.output.with_suffix('.svg'))], check=True)


if __name__ == '__main__':
    main()
