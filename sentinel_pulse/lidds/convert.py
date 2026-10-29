"""LID-DS 2021 recordings as the 0.5 s windows Pulse scores (RESEARCH_IDEAS G3, a public dataset with real exploits).

A LID-DS 2021 recording (one inner zip per recording: ``.sc`` syscall trace of the victim container, ``.json``
metadata with the exploit time, ``.pcap``, ``.res``) is replayed into the frames Pulse's eBPF loader writes:

- every syscall **entry** (``>`` line) increments the full-ID count of its x86-64 number (names from
  ``asm/unistd_64.h``; sysdig pseudo-events and unknown names are counted apart, never mapped);
- the syscall-ID hash bin is ``(id * 2654435761) >> 26`` and the transition bin of a thread's previous syscall
  ``((prev * 31 + cur) * 2654435761) >> 26`` when the previous one of the same thread came at most 5 s earlier
  (``sentinel_pulse/ebpf/pulse_counter.bpf.c``);
- cumulative snapshots are cut on a 0.5 s grid; seccomp skips are not recorded by LID-DS and stay 0.

The snapshots go through ``collector.extended_capture.ExtendedFeatureStream`` unchanged, so a window carries the
same 249 features, history and ``full_counts_delta`` as a live window. The container is a synthetic production
identity: workload ``lid-ds-<scenario>``, container ``victim``, pod UID = recording name.

Line format (LID-DS 2021): ``timestamp_ns user_id process_id process_name thread_id syscall direction args...``.
"""
from __future__ import annotations

import io
import json
import math
import re
import zipfile
import zlib
from collections import Counter
from pathlib import Path

from ..collector.extended_capture import CONTRACT, ExtendedFeatureStream
from ..collector.features import TRACKED_SYSCALLS

HEADER = Path('/usr/include/x86_64-linux-gnu/asm/unistd_64.h')
WINDOW = 0.5
TRANSITION_GAP_NS = 5_000_000_000
NODE = 'lid-ds'
# sysdig spells four syscalls without the ABI suffix of unistd_64.h (lidds-evaluation-v1 amendment 1, 29/10:
# the registered run dropped them as unmapped, ~15 M entries in 12 of 15 scenarios)
SYSDIG_ALIASES = {'pread': 'pread64', 'pwrite': 'pwrite64', 'sigreturn': 'rt_sigreturn', 'prlimit': 'prlimit64'}


def syscall_ids(header: Path = HEADER, aliases: bool = True) -> dict[str, int]:
    """unistd_64.h names -> numbers; ``aliases`` adds sysdig's spellings (False = the registered v1 conversion)."""
    ids = {name: int(nr) for name, nr in re.findall(r'^#define __NR_(\w+)\s+(\d+)$', Path(header).read_text(), re.M)}
    if len(ids) < 300:
        raise ValueError('unexpected syscall header')
    if aliases:
        ids.update({alias: ids[name] for alias, name in SYSDIG_ALIASES.items() if name in ids})
    return ids


def id_bin(i: int) -> int:
    return ((i * 2654435761) & 0xffffffff) >> 26


def transition_bin(prev: int, cur: int) -> int:
    return (((prev * 31 + cur) & 0xffffffff) * 2654435761 & 0xffffffff) >> 26


def entries(lines, ids):
    """(ts_ns, thread_id, syscall id) of every syscall entry; Counter of names without an x86-64 number."""
    unmapped = Counter()
    out = []
    for line in lines:
        parts = line.split(' ', 7)
        if len(parts) < 7 or parts[6] != '>':
            continue
        nr = ids.get(parts[5])
        if nr is None:
            unmapped[parts[5]] += 1
            continue
        out.append((int(parts[0]), int(parts[4]), nr))
    return out, unmapped


def snapshots(events, cgroup_id, window=WINDOW):
    """Cumulative loader-style snapshots on a ``window`` grid from the first event's window to the last one's end."""
    if not events:
        return
    events = sorted(events)
    full, bins, trans, last = Counter(), [0] * 64, [0] * 64, {}
    t0 = math.floor(events[0][0] / 1e9 / window) * window
    t_end = math.floor(events[-1][0] / 1e9 / window) * window + window
    k, boundary = 0, t0
    while boundary <= t_end + 1e-9:
        while k < len(events) and events[k][0] / 1e9 < boundary:
            ts, tid, nr = events[k]
            full[nr] += 1; bins[id_bin(nr)] += 1
            prev = last.get(tid)
            if prev is not None and 0 <= ts - prev[0] <= TRANSITION_GAP_NS:
                trans[transition_bin(prev[1], nr)] += 1
            last[tid] = (ts, nr)
            k += 1
        yield boundary, dict(type='cgroup_snapshot_extended', telemetry_contract=CONTRACT, cgroup_id=cgroup_id,
                             counts={str(i): full.get(i, 0) for i in TRACKED_SYSCALLS}, syscall_bins=list(bins),
                             transition_bins=list(trans), total=sum(bins), seccomp_skipped_or_emulated=0,
                             full_counts={str(i): v for i, v in full.items()})
        boundary = round(boundary + window, 6)


def windows(events, scenario, recording, window=WINDOW):
    """Pulse feature records (as the worker's features.jsonl rows) with full_counts_delta."""
    cgroup_id = zlib.crc32(recording.encode()) or 1
    meta = {str(cgroup_id): dict(namespace='production', workload_name=f'lid-ds-{scenario.lower()}', container_name='victim',
                                 node_name=NODE, pod_uid=recording, pod_name=recording, workload_revision='lid-ds-2021')}
    stream = ExtendedFeatureStream(include_idle=True)
    previous = None
    for boundary, snap in snapshots(events, cgroup_id, window):
        full = {int(k): v for k, v in snap['full_counts'].items()}
        out = stream.snapshot(snap, boundary, meta, boundary)
        delta = None if previous is None else {str(k): v - previous.get(k, 0) for k, v in full.items() if v - previous.get(k, 0)}
        previous = full
        if out is None or delta is None:
            continue
        record, schema = out
        if sum(delta.values()) != record['exact_total']:
            raise ValueError('full delta and feature total differ')
        record['full_counts_delta'] = delta
        yield record, schema


def recording(inner: bytes):
    """(metadata, syscall lines) of one inner recording zip."""
    z = zipfile.ZipFile(io.BytesIO(inner))
    names = z.namelist()
    meta = json.loads(z.read(next(n for n in names if n.endswith('.json'))))
    sc = z.read(next(n for n in names if n.endswith('.sc'))).decode(errors='replace').splitlines()
    return meta, sc


def scenario_recordings(path: Path):
    """(split, recording name, inner zip bytes) for every recording of one scenario archive."""
    outer = zipfile.ZipFile(path)
    for name in sorted(outer.namelist()):
        if not name.endswith('.zip') or name.startswith('__MACOSX'):
            continue
        parts = name.split('/')
        split = '/'.join(parts[1:-1])                      # training, validation, test/normal, test/normal_and_attack
        yield split, parts[-1][:-4], outer.read(name)


def exploit_times(meta) -> list[float]:
    return sorted(float(e['absolute']) for e in (meta.get('time') or {}).get('exploit') or [])


def convert_scenario(archive: Path, output: Path, header: Path = HEADER) -> dict:
    """One scenario archive -> <output>/<split>.jsonl.gz (one Pulse window per line, with LID-DS labels)."""
    import gzip
    ids = syscall_ids(header)
    scenario = Path(archive).stem
    output.mkdir(parents=True, exist_ok=True)
    sinks, summary, unmapped = {}, Counter(), Counter()
    try:
        for split, name, blob in scenario_recordings(archive):
            meta, lines = recording(blob)
            events, un = entries(lines, ids); unmapped.update(un)
            exploit = exploit_times(meta)
            key = split.replace('/', '-')
            sink = sinks.get(key) or sinks.setdefault(key, gzip.open(output / f'{key}.jsonl.gz', 'wt'))
            summary[f'{key}:recordings'] += 1
            for record, _ in windows(events, scenario, name):
                record['lidds'] = dict(scenario=scenario, split=split, recording=name, exploit=bool(meta.get('exploit')),
                                       exploit_at=exploit[0] if exploit else None)
                sink.write(json.dumps(record, separators=(',', ':')) + '\n')
                summary[f'{key}:windows'] += 1
    finally:
        for sink in sinks.values():
            sink.close()
    doc = dict(scenario=scenario, archive=str(archive), counts=dict(summary), unmapped_names=dict(unmapped))
    (output / 'SUMMARY.json').write_text(json.dumps(doc, indent=1))
    return doc


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('archive', type=Path, nargs='+', help='LID-DS 2021 scenario zip(s)')
    p.add_argument('--output', type=Path, required=True, help='one sub-directory per scenario is written here')
    p.add_argument('--header', type=Path, default=HEADER)
    a = p.parse_args()
    for archive in a.archive:
        print(json.dumps(convert_scenario(archive, a.output / archive.stem, a.header)))
