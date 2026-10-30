"""LID-DS 2019 scenarios as LID-DS 2021 layout archives (protocol lidds2019-confirmation-v1), so
``convert.py`` and ``scripts/analysis/lidds_evaluate_v2.py`` run on them unchanged.

A 2019 scenario is ``<scenario>.tar.gz`` with ``<scenario>/<recording>.txt`` (sysdig text, one event per line:
``event_number HH:MM:SS.nnnnnnnnn cpu user_id process_name thread_id direction syscall args...``; no date, no process
id) and ``runs.csv`` (``image_name, scenario_name, is_executing_exploit, warmup_time, recording_time,
exploit_start_time``). The archive ``<scenario>.zip`` holds one inner zip per recording (``.sc`` in the 2021 line
format ``timestamp_ns user_id process_id process_name thread_id syscall direction args`` + ``.json`` metadata):

- timestamps: seconds of the day in ns, plus one day each time the clock wraps past midnight inside a recording;
  process id = thread id (2019 records no process id; Pulse counts per container, STIDE per thread);
- splits in ``runs.csv`` order, as the dataset README and the LID-DS library: the first 200 normal recordings
  ``training``, the next 50 ``validation``, the other normal recordings ``test/normal``, every exploit recording
  ``test/normal_and_attack``;
- exploit time (primary) = first event + ``exploit_start_time`` s; the LID-DS library's convention (first event +
  ``warmup_time`` − 2 s) is kept in the metadata as ``exploit_library`` for a sensitivity analysis. In the data the
  primary time is later (exploit_start_time 13–39 s, warmup 10 s), so it is the stricter one.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import tarfile
import zipfile

TRAINING, VALIDATION = 200, 50
DAY_NS = 86_400_000_000_000


def parse_runs(text):
    """[(recording, is_exploit, warmup_s, recording_s, exploit_start_s)] in file order."""
    rows = list(csv.reader(io.StringIO(text), skipinitialspace=True))
    out = []
    for r in rows[1:]:
        if len(r) < 6:
            continue
        out.append((r[1].strip(), r[2].strip().lower() in ('true', '1', 'yes'), float(r[3]), float(r[4]), float(r[5])))
    return out


def splits(runs):
    """{recording: split} in runs.csv order."""
    out, normal = {}, 0
    for name, exploit, *_ in runs:
        if exploit:
            out[name] = 'test/normal_and_attack'
        else:
            out[name] = 'training' if normal < TRAINING else 'validation' if normal < TRAINING + VALIDATION else 'test/normal'
            normal += 1
    return out


def clock_ns(stamp):
    h, m, s = stamp[0:2], stamp[3:5], stamp[6:8]
    frac = (stamp[9:] + '000000000')[:9]
    return ((int(h) * 60 + int(m)) * 60 + int(s)) * 1_000_000_000 + int(frac)


def to_2021(lines):
    """2019 sysdig lines -> 2021 format lines (bad lines dropped, counted)."""
    out, bad, offset, last = [], 0, 0, None
    for line in lines:
        p = line.rstrip('\n').split(' ', 8)
        if len(p) < 8 or len(p[1]) < 8 or p[1][2] != ':' or not p[5].isdigit():
            bad += 1
            continue
        try:
            t = clock_ns(p[1]) + offset
        except ValueError:
            bad += 1
            continue
        if last is not None and t < last - DAY_NS // 2:            # wrapped past midnight
            offset += DAY_NS; t += DAY_NS
        last = t
        args = p[8] if len(p) > 8 else ''
        out.append(f'{t} {p[3]} {p[5]} {p[4]} {p[5]} {p[7]} {p[6]} {args}'.rstrip())
    return out, bad


def inner_zip(name, lines, run):
    _, exploit, warmup, recording, start = run
    first = int(lines[0].split(' ', 1)[0]) / 1e9 if lines else None
    times = dict(exploit=[dict(absolute=first + start, relative=start)] if exploit and first is not None else [],
                 exploit_library=[dict(absolute=first + warmup - 2)] if exploit and first is not None else [],
                 warmup_end=dict(relative=warmup))
    meta = dict(exploit=exploit, recording_time=recording, time=times, lidds2019=dict(recording=name))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(f'{name}.json', json.dumps(meta))
        z.writestr(f'{name}.sc', '\n'.join(lines) + '\n')
    return buf.getvalue()


def build_scenario(tar_path: Path, output: Path, scenario: str | None = None, log=print):
    """One 2019 scenario tar.gz -> ``output`` (LID-DS 2021 layout zip) + ``output``.SUMMARY.json. Two streaming
    passes: runs.csv first (its position in the tar is not fixed), then the recordings."""
    runs = None
    with tarfile.open(tar_path, 'r|gz') as t:
        for m in t:
            if m.isfile() and m.name.endswith('runs.csv'):
                runs = parse_runs(t.extractfile(m).read().decode()); break
    if runs is None:
        raise ValueError(f'{tar_path}: no runs.csv')
    scenario = scenario or Path(tar_path).name.split('.tar')[0]
    by_name = {r[0]: r for r in runs}
    where = splits(runs)
    counts, bad_lines, missing, empty = {}, 0, set(by_name), []
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix('.partial')
    with tarfile.open(tar_path, 'r|gz') as t, zipfile.ZipFile(tmp, 'w', zipfile.ZIP_STORED) as out:
        for m in t:
            if not (m.isfile() and m.name.endswith('.txt')):
                continue
            name = Path(m.name).stem
            if name not in by_name:
                continue                                         # not listed in runs.csv: never scored
            lines, bad = to_2021(t.extractfile(m).read().decode(errors='replace').splitlines())
            bad_lines += bad; missing.discard(name)
            if not lines:
                empty.append(name)
            out.writestr(f'{scenario}/{where[name]}/{name}.zip', inner_zip(name, lines, by_name[name]))
            counts[where[name]] = counts.get(where[name], 0) + 1
    tmp.replace(output)
    summary = dict(scenario=scenario, source=str(tar_path), counts=counts, runs_rows=len(runs), bad_lines=bad_lines,
                   listed_but_missing=sorted(missing), empty_recordings=sorted(empty))
    Path(f'{output}.SUMMARY.json').write_text(json.dumps(summary, indent=1))
    log(json.dumps(summary))
    return summary


def build_release(release_zip: Path, out_dir: Path, scenarios=None, work: Path | None = None, log=print):
    """The 2019 release zip (``LID-DS-2019/<scenario>.tar.gz``) -> ``out_dir/<scenario>.zip`` for each scenario; each
    tar.gz is copied out to ``work`` first (stream reads of a zip member cannot seek)."""
    z = zipfile.ZipFile(release_zip)
    work = work or out_dir
    work.mkdir(parents=True, exist_ok=True)
    done = []
    for member in sorted(n for n in z.namelist() if n.endswith('.tar.gz')):
        name = Path(member).name[:-len('.tar.gz')]
        if scenarios and name not in scenarios:
            continue
        local = work/Path(member).name
        with z.open(member) as src, open(local, 'wb') as dst:
            while chunk := src.read(1 << 20):
                dst.write(chunk)
        done.append(build_scenario(local, out_dir/f'{name}.zip', name, log))
        local.unlink()
    return done


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('release', type=Path, help='LID-DS-2019.zip as released')
    ap.add_argument('--output', type=Path, required=True, help='directory for <scenario>.zip archives')
    ap.add_argument('--scenario', action='append')
    a = ap.parse_args()
    build_release(a.release, a.output, a.scenario)
