import io
import tarfile
import zipfile

from sentinel_pulse.lidds import convert, lidds2019 as l19

NAMES = ['read', 'write', 'close', 'epoll_wait', 'openat', 'accept']


def _txt(start_s, n=40, wrap=False):
    lines = []
    for i in range(n):
        t = start_s + i * 0.25
        if wrap:
            t = (t % 86400)
        h, m, s = int(t // 3600), int(t % 3600 // 60), t % 60
        stamp = f'{h:02d}:{m:02d}:{int(s):02d}.{int(round((s % 1) * 1e9)):09d}'
        name = NAMES[i % len(NAMES)]
        lines.append(f'{i} {stamp} 3 101 nginx {24000 + i % 3} > {name} ')
        lines.append(f'{i} {stamp} 3 101 nginx {24000 + i % 3} < {name} res=1')
    return '\n'.join(lines) + '\nnot a sysdig line\n'


def _tar(tmp_path, normal=260, attack=3):
    rows = ['image_name, scenario_name, is_executing_exploit, warmup_time, recording_time, exploit_start_time']
    files = {}
    for i in range(normal):
        rows.append(f'img, n{i:04d}, False, 10, 35, -1'); files[f'n{i:04d}'] = _txt(40000 + i)
    for i in range(attack):
        rows.append(f'img, a{i}, True, 10, 35, 22'); files[f'a{i}'] = _txt(50000 + i)
    path = tmp_path/'SCN.tar.gz'
    with tarfile.open(path, 'w:gz') as t:
        for name in sorted(files, reverse=True):              # tar order differs from runs.csv order
            data = files[name].encode(); info = tarfile.TarInfo(f'SCN/{name}.txt'); info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        data = '\n'.join(rows).encode(); info = tarfile.TarInfo('SCN/runs.csv'); info.size = len(data)
        t.addfile(info, io.BytesIO(data))                       # runs.csv last
    return path


def test_line_format_clock_and_midnight_wrap():
    lines, bad = l19.to_2021(_txt(86399.5, n=4, wrap=True).splitlines())
    assert bad == 1 and len(lines) == 8
    ts = [int(l.split(' ', 1)[0]) for l in lines]
    assert ts == sorted(ts) and ts[-1] > 86_400_000_000_000          # continued past midnight
    assert lines[0].split(' ')[1:7] == ['101', '24000', 'nginx', '24000', 'read', '>']
    assert l19.clock_ns('11:11:51.284588185') == ((11 * 60 + 11) * 60 + 51) * 10**9 + 284588185


def test_splits_follow_runs_csv_order():
    runs = [(f'n{i}', False, 10, 35, -1) for i in range(260)] + [('a', True, 10, 35, 22)]
    s = l19.splits(runs)
    assert [s[f'n{i}'] for i in (0, 199, 200, 249, 250)] == ['training', 'training', 'validation', 'validation', 'test/normal']
    assert s['a'] == 'test/normal_and_attack'


def test_scenario_archive_converts_and_exploit_times_are_the_strict_ones(tmp_path):
    out = tmp_path/'out'/'SCN.zip'
    summary = l19.build_scenario(_tar(tmp_path), out, log=lambda *_: None)
    assert summary['counts'] == {'training': 200, 'validation': 50, 'test/normal': 10, 'test/normal_and_attack': 3}
    assert summary['bad_lines'] == 263 and not summary['listed_but_missing']
    z = zipfile.ZipFile(out)
    meta, sc = convert.recording(z.read('SCN/test/normal_and_attack/a0.zip'))
    first = int(sc[0].split(' ', 1)[0]) / 1e9
    assert meta['exploit'] is True and abs(meta['time']['exploit'][0]['absolute'] - (first + 22)) < 1e-6
    assert abs(meta['time']['exploit_library'][0]['absolute'] - (first + 8)) < 1e-6
    assert convert.exploit_times(meta) == [first + 22]
    splits = sorted({n.split('/')[1] for n in z.namelist()})
    assert splits == ['test', 'training', 'validation']
    assert len(convert.entries(sc, {n: i for i, n in enumerate(NAMES)})[0]) == 40      # entry lines kept
