"""CB-DS (container breakout dataset, El Khairi et al., CCSW 2022) as one LID-DS 2021 scenario archive
(protocol cbds-confirmation-v1), so convert.py and scripts/analysis/lidds_evaluate_v2.py run on it unchanged.

The release (``CB-DS/NORMAL/*.scap``: 1,701 recordings of an E-shop Apache container; ``CB-DS/<attack>/*.scap``:
9 breakout scenarios x 100) has no split and no exploit time. The archive ``CB-DS.zip`` holds:

- ``CB-DS/training``, ``CB-DS/validation``, ``CB-DS/test/normal``: the NORMAL recordings, names sorted
  numerically, numpy ``default_rng(SPLIT_SEED)`` permutation, first 210 training, next 60 validation (the usual
  LID-DS 2021 counts per scenario), the rest test;
- ``CB-DS/test/normal_and_attack``: every attack recording as ``<attack>_<n>``, exploit time = its first kept
  event, so an attack recording counts as detected when any window alarms (per recording, as CHIDS); the
  "latency" is the time from the recording's start, not a detection latency.

Each ``.scap`` is decoded by ``sysdig -r`` (in a container without network, read-only input) into the LID-DS 2021
line format ``timestamp_ns user_id process_id process_name thread_id syscall direction args``. Pulse counts per
container, so only the events of the recording's main container (the non-host container id with the most events)
are kept; events of other containers and of the host are counted in SUMMARY, never scored.
"""
from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

import numpy as np

SPLIT_SEED = 20261031
TRAINING, VALIDATION = 210, 60
ATTACKS = ('CVE-2016-9962', 'CVE-2019-5736', 'CVE-2022-0492', 'M-MKNOD', 'M-NET', 'M-SYS_ADMIN', 'M-SYS_MOD',
           'M_SOCKET', 'M_UHELPER')
FORMAT = '%evt.rawtime %user.uid %proc.pid %proc.name %thread.tid %evt.type %evt.dir %container.id %evt.args'
IMAGE = 'sysdig/sysdig:0.41.4'
SCENARIO = 'CB-DS'


def release_recordings(names):
    """{(group, number): entry name} of the release, group = 'NORMAL' or an attack; anything else is refused."""
    out = {}
    for name in names:
        if name.endswith('/'):
            continue
        m = re.fullmatch(r'CB-DS/([A-Za-z0-9_-]+)/(\d+)\.scap', name)
        if not m or (m.group(1) != 'NORMAL' and m.group(1) not in ATTACKS):
            raise ValueError(f'unexpected entry in the release: {name!r}')
        out[(m.group(1), int(m.group(2)))] = name
    return out


def normal_split(numbers, seed=SPLIT_SEED):
    """{number: 'training' | 'validation' | 'test/normal'} of the NORMAL recordings."""
    names = sorted(numbers)
    order = np.random.default_rng(seed).permutation(len(names))
    split = {}
    for rank, i in enumerate(order):
        split[names[i]] = 'training' if rank < TRAINING else 'validation' if rank < TRAINING + VALIDATION else 'test/normal'
    return split


def main_container(lines):
    """(kept lines in the LID-DS 2021 format, Counter of events per container id, main container id)."""
    per = Counter()
    parsed = []
    for line in lines:
        parts = line.split(' ', 8)
        if len(parts) < 8 or not parts[0].isdigit() or not parts[4].isdigit():
            per['<malformed>'] += 1
            continue
        per[parts[7]] += 1
        parsed.append(parts)
    containers = [c for c, _ in per.most_common() if c not in ('host', '<malformed>')]
    main = containers[0] if containers else None
    kept = [' '.join(p[:7] + p[8:9]) for p in parsed if p[7] == main]
    return kept, per, main


def inner_zip(name, lines, attack):
    """One recording as the inner zip of a LID-DS 2021 archive (``.sc`` + ``.json``)."""
    first = int(lines[0].split(' ', 1)[0]) / 1e9 if lines else None
    meta = dict(exploit=attack is not None, time=dict(exploit=[dict(absolute=first)] if attack and first else []),
                cbds=dict(attack=attack))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(f'{name}.json', json.dumps(meta))
        z.writestr(f'{name}.sc', '\n'.join(lines) + '\n')
    return buf.getvalue()


class DockerSysdig:
    """Decode a batch of .scap files with sysdig in a container: no network, input mounted read-only."""

    def __init__(self, image=IMAGE):
        self.image = image

    def digest(self):
        r = subprocess.run(['docker', 'image', 'inspect', '--format', '{{index .RepoDigests 0}}', self.image],
                           capture_output=True, text=True, check=True)
        return r.stdout.strip()

    def __call__(self, directory: Path, files):
        out = directory / 'out'
        out.mkdir()
        script = 'for f in "$@"; do sysdig -r "/in/$f" -p "$FMT" > "/out/$f.txt" || exit 1; done'
        subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--user', 'root', '-e', f'FMT={FORMAT}',
                        '-v', f'{directory / "in"}:/in:ro', '-v', f'{out}:/out', '--entrypoint', 'sh', self.image,
                        '-c', script, 'sh', *files], check=True, capture_output=True)
        return {f: (out / f'{f}.txt').read_text(errors='replace').splitlines() for f in files}


def build_archive(release: Path, output: Path, decoder=None, batch=40, workers=4, log=print):
    """CB-DS release zip -> LID-DS 2021 layout archive ``output`` + ``output``.SUMMARY.json."""
    decoder = decoder or DockerSysdig()
    src = zipfile.ZipFile(release)
    recs = release_recordings(src.namelist())
    split = normal_split([n for g, n in recs if g == 'NORMAL'])
    plan = []
    for (group, number), entry in sorted(recs.items()):
        if group == 'NORMAL':
            plan.append((entry, split[number], f'normal_{number}', None))
        else:
            plan.append((entry, 'test/normal_and_attack', f'{group}_{number}', group))
    counts, per_recording = Counter(), {}

    def decode(chunk):
        work = Path(tempfile.mkdtemp(prefix='cbds-'))
        try:
            (work / 'in').mkdir()
            files = []
            for i, (entry, *_rest) in enumerate(chunk):
                f = f'{i}.scap'
                (work / 'in' / f).write_bytes(src.read(entry))
                files.append(f)
            text = decoder(work, files)
            return [(item, main_container(text[f])) for item, f in zip(chunk, files)]
        finally:
            shutil.rmtree(work, ignore_errors=True)

    chunks = [plan[i:i + batch] for i in range(0, len(plan), batch)]
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix('.partial')
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_STORED) as out, ThreadPoolExecutor(workers) as pool:
        for k, done in enumerate(pool.map(decode, chunks)):
            for (entry, where, name, attack), (kept, per, main) in done:
                out.writestr(f'{SCENARIO}/{where}/{name}.zip', inner_zip(name, kept, attack))
                counts[f'{where}:recordings'] += 1
                per_recording[name] = dict(entry=entry, split=where, main_container=main, kept=len(kept),
                                           other_events=sum(v for c, v in per.items() if c != main))
            log(f'batch {k + 1}/{len(chunks)}')
    tmp.replace(output)
    summary = dict(release=str(release), release_sha256=sha256(release), split_seed=SPLIT_SEED,
                   sysdig_image=decoder.digest() if hasattr(decoder, 'digest') else None, counts=dict(counts),
                   recordings_with_other_events=sum(bool(r['other_events']) for r in per_recording.values()),
                   empty_recordings=sorted(n for n, r in per_recording.items() if not r['kept']),
                   recordings=per_recording)
    Path(f'{output}.SUMMARY.json').write_text(json.dumps(summary, indent=1))
    return summary


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('release', type=Path, help='CB-DS.zip as released')
    ap.add_argument('--output', type=Path, required=True, help='LID-DS 2021 layout archive, e.g. .../archives/CB-DS.zip')
    ap.add_argument('--image', default=IMAGE)
    ap.add_argument('--batch', type=int, default=40)
    ap.add_argument('--workers', type=int, default=4)
    a = ap.parse_args()
    s = build_archive(a.release, a.output, DockerSysdig(a.image), a.batch, a.workers)
    print(json.dumps({k: v for k, v in s.items() if k != 'recordings'}, indent=1))
