import io
import json
import zipfile

from sentinel_pulse.collector.features import TRACKED_SYSCALLS
from sentinel_pulse.encoding import decode_vector
from sentinel_pulse.lidds import convert as c

IDS = {'read': 0, 'write': 1, 'openat': 257, 'close': 3, 'setns': 308}


def line(t_s, tid, name, direction='>'):
    return f'{int(t_s * 1e9)} 33 {tid} apache2 {tid} {name} {direction} fd=3'


def test_entries_keep_only_syscall_entries_and_count_unknown_names():
    lines = [line(1.0, 7, 'read'), line(1.0001, 7, 'read', '<'), line(1.1, 7, 'switch'), 'garbage']
    events, unmapped = c.entries(lines, IDS)
    assert events == [(1_000_000_000, 7, 0)] and unmapped == {'switch': 1}


def test_snapshots_follow_the_kernel_counters():
    ev, _ = c.entries([line(10.1, 1, 'read'), line(10.2, 1, 'write'), line(10.3, 2, 'write'), line(10.6, 1, 'read'),
                       line(16.0, 1, 'read')], IDS)                       # 16.0 - 10.6 > 5 s: no transition
    snaps = list(c.snapshots(ev, cgroup_id=9))
    assert snaps[0][0] == 10.0 and snaps[0][1]['total'] == 0          # baseline before the first event
    b, s = snaps[1]                                                    # boundary 10.5: three events
    assert b == 10.5 and s['total'] == 3 and s['counts']['0'] == 1 and s['counts']['1'] == 2
    assert s['syscall_bins'][c.id_bin(1)] == 2 and sum(s['transition_bins']) == 1     # only thread 1: read -> write
    assert s['transition_bins'][c.transition_bin(0, 1)] == 1
    last = snaps[-1][1]
    assert last['total'] == 5 and sum(last['transition_bins']) == 2   # write -> read on thread 1; not the 5.4 s gap
    assert set(last['counts']) == {str(i) for i in TRACKED_SYSCALLS} and snaps[-1][0] == 16.5


def test_transition_bin_matches_the_bpf_u32_arithmetic():
    for prev, cur in ((0, 1), (308, 59), (1023, 1023)):
        assert c.transition_bin(prev, cur) == ((((prev * 31 + cur) * 2654435761) & 0xffffffff) >> 26)


def test_windows_are_pulse_feature_rows_with_full_deltas():
    lines = [line(100 + i * .05, 1 + i % 3, ['read', 'write', 'openat', 'close'][i % 4]) for i in range(400)]
    lines.append(line(118.0, 2, 'setns'))
    ev, _ = c.entries(lines, IDS)
    rows = list(c.windows(ev, 'CVE-X', 'rec_1'))
    assert rows and all(len(decode_vector(r)) == 249 for r, _ in rows)
    assert {r['workload_key'] for r, _ in rows} == {'production/lid-ds-cve-x:victim'}
    assert all(sum(r['full_counts_delta'].values()) == r['exact_total'] for r, _ in rows)
    assert any(r['full_counts_delta'].get('308') == 1 for r, _ in rows)


def test_a_scenario_archive_converts_to_split_files(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, 'w') as z:
        z.writestr('rec_1.json', json.dumps(dict(exploit=True, time=dict(exploit=[dict(absolute=101.0)]))))
        z.writestr('rec_1.sc', '\n'.join(line(100 + i * .1, 1, 'read') for i in range(40)))
    outer = tmp_path/'CVE-X.zip'
    with zipfile.ZipFile(outer, 'w') as z:
        z.writestr('CVE-X/test/normal_and_attack/rec_1.zip', inner.getvalue())
        z.writestr('__MACOSX/CVE-X/._x', b'')
    import gzip
    (tmp_path/'unistd.h').write_text('\n'.join(f'#define __NR_n{i} {i}' for i in range(400)) + '\n#define __NR_read 0\n')
    doc = c.convert_scenario(outer, tmp_path/'out', header=tmp_path/'unistd.h')
    rows = [json.loads(l) for l in gzip.open(tmp_path/'out'/'test-normal_and_attack.jsonl.gz', 'rt')]
    assert doc['counts']['test-normal_and_attack:recordings'] == 1 and len(rows) == doc['counts']['test-normal_and_attack:windows']
    assert rows[0]['lidds'] == dict(scenario='CVE-X', split='test/normal_and_attack', recording='rec_1', exploit=True, exploit_at=101.0)


def test_sysdig_spellings_map_to_their_abi_numbers():
    ids = c.syscall_ids()
    assert (ids['pread'], ids['pwrite'], ids['sigreturn'], ids['prlimit']) == (17, 18, 15, 302)
    assert 'pread' not in c.syscall_ids(aliases=False) and ids['pread64'] == 17
    events, unmapped = c.entries(['1000000000 0 1 p 7 pread > fd=3', '1000000001 0 1 p 7 procexit > x'], ids)
    assert events == [(1_000_000_000, 7, 17)] and unmapped == {'procexit': 1}
