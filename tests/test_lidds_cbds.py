import gzip
import json
import zipfile

import pytest

from sentinel_pulse.lidds import cbds, convert

NAMES = ['read', 'write', 'close', 'epoll_wait', 'futex', 'openat']


def _sysdig_lines(seed, start_ns, attack=False):
    """sysdig -r output in cbds.FORMAT: the victim container 'c0ffee', plus host and sibling events for attacks."""
    lines = []
    for i in range(400):
        ts = start_ns + i * 75_000_000
        name = NAMES[(seed + i) % len(NAMES)]
        lines.append(f'{ts} 33 9236 apache2 {9236 + i % 3} {name} > c0ffee ')
        lines.append(f'{ts + 1000} 33 9236 apache2 {9236 + i % 3} {name} < c0ffee res=12')
    if attack:
        lines += [f'{start_ns + 5} 0 77 dockerd 77 connect > host ', f'{start_ns + 6} 0 88 sh 88 execve > beef00 ']
    lines.sort(key=lambda l: int(l.split(' ', 1)[0]))
    return lines + (['<NA> <NA> <NA> <NA> <NA> switch > host '] if attack else [])


def _decoder(directory, files):
    out = {}
    for f in files:
        tag = (directory / 'in' / f).read_text()
        group, number = tag.split(':')
        out[f] = _sysdig_lines(int(number), 1_000_000_000_000 + int(number) * 60_000_000_000, group != 'NORMAL')
    return out


@pytest.fixture
def release(tmp_path, monkeypatch):
    monkeypatch.setattr(cbds, 'TRAINING', 6)
    monkeypatch.setattr(cbds, 'VALIDATION', 3)
    path = tmp_path / 'CB-DS.zip'
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('CB-DS/', '')
        z.writestr('CB-DS/NORMAL/', '')
        for n in range(1, 13):
            z.writestr(f'CB-DS/NORMAL/{n}.scap', f'NORMAL:{n}')
        for n in range(1, 4):
            z.writestr(f'CB-DS/M-MKNOD/{n}.scap', f'M-MKNOD:{n}')
    return path


def test_split_is_seeded_and_sized():
    a = cbds.normal_split(range(1, 1701))
    assert a == cbds.normal_split(list(reversed(range(1, 1701))))
    c = {s: sum(v == s for v in a.values()) for s in ('training', 'validation', 'test/normal')}
    assert c == {'training': 210, 'validation': 60, 'test/normal': 1430}


def test_release_entries_outside_the_known_layout_are_refused():
    assert cbds.release_recordings(['CB-DS/', 'CB-DS/M_SOCKET/7.scap']) == {('M_SOCKET', 7): 'CB-DS/M_SOCKET/7.scap'}
    for bad in ('CB-DS/../x.scap', 'CB-DS/NORMAL/a.scap', 'CB-DS/OTHER/1.scap', 'evil/NORMAL/1.scap'):
        with pytest.raises(ValueError):
            cbds.release_recordings([bad])


def test_only_the_main_container_is_kept_in_the_lidds_line_format():
    kept, per, main = cbds.main_container(_sysdig_lines(0, 5_000_000_000, attack=True))
    assert main == 'c0ffee' and per['host'] == 1 and per['beef00'] == 1 and per['<malformed>'] == 1   # '<NA>' line
    assert len(kept) == 800 and kept[0].split(' ') == ['5000000000', '33', '9236', 'apache2', '9236', 'read', '>', '']
    assert kept[1].endswith('< res=12')


def test_archive_has_the_lidds_layout_and_converts(tmp_path, release):
    out = tmp_path / 'archives' / 'CB-DS.zip'
    s = cbds.build_archive(release, out, decoder=_decoder, batch=4, workers=2, log=lambda *_: None)
    assert s['counts'] == {'training:recordings': 6, 'validation:recordings': 3, 'test/normal:recordings': 3,
                           'test/normal_and_attack:recordings': 3}
    assert s['recordings_with_other_events'] == 3 and s['empty_recordings'] == []
    z = zipfile.ZipFile(out)
    meta, sc = convert.recording(z.read('CB-DS/test/normal_and_attack/M-MKNOD_2.zip'))
    assert meta['exploit'] is True and meta['cbds'] == {'attack': 'M-MKNOD'}
    assert convert.exploit_times(meta) == [int(sc[0].split(' ')[0]) / 1e9]          # exploit = first kept event
    assert all(' dockerd ' not in l and ' sh ' not in l for l in sc)
    header = tmp_path / 'unistd.h'
    header.write_text('\n'.join(f'#define __NR_{n} {i}' for i, n in enumerate(NAMES + [f'x{j}' for j in range(320)])) + '\n')
    doc = convert.convert_scenario(out, tmp_path / 'conv' / 'CB-DS', header=header)
    assert doc['counts']['test-normal_and_attack:recordings'] == 3 and doc['unmapped_names'] == {}
    with gzip.open(tmp_path / 'conv' / 'CB-DS' / 'test-normal_and_attack.jsonl.gz', 'rt') as f:
        row = json.loads(f.readline())
    assert row['workload_key'] == 'production/lid-ds-cb-ds:victim' and row['lidds']['exploit_at'] is not None
