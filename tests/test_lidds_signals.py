from collections import Counter

from sentinel_pulse.lidds import signals as s


def test_open_paths_mode_and_prefix_from_sysdig_exit_lines():
    ok = 'fd=5(<f>/service/upload/a.zip) name=a.zip(/service/upload/a.zip) flags=4358(O_TRUNC|O_CREAT|O_WRONLY|O_CLOEXEC) mode=066'
    assert s.open_path(ok) == ('w', '/service/upload/a.zip')
    failed = 'fd=-2(ENOENT) name=/usr/lib/jvm/java/bin/../lib/jli/tls/libjli.so flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=0'
    assert s.open_path(failed) == ('r', '/usr/lib/jvm/java/lib/jli/tls/libjli.so')      # lexical '..' resolution
    assert s.prefix('/usr/lib/jvm/java/lib/jli/tls/libjli.so') == '/usr/lib/jvm'
    assert s.prefix('/etc/passwd') == '/etc' and s.prefix('passwd') == 'rel:'
    assert s.error_of(failed) == 'ENOENT' and s.error_of('res=-22(EINVAL)') == 'EINVAL' and s.error_of('res=12') is None
    assert s.bucket(65535) == 15 and s.bucket(16384) == 14 and s.bucket(1) == 0


def _line(t, tid, name, direction, args=''):
    return f'{int(t * 1e9)} 0 {tid} srv {tid} {name} {direction} {args}'


def test_recording_signals_per_window():
    lines = [_line(10.1, 1, 'openat', '>'),
             _line(10.1001, 1, 'openat', '<', 'fd=3(<f>/srv/data/x) name=x flags=1(O_RDONLY)'),
             _line(10.2, 1, 'read', '>'), _line(10.2001, 1, 'read', '<', 'res=4096 data=AA'),
             _line(10.7, 1, 'sendfile', '>'), _line(10.7001, 1, 'sendfile', '<', 'res=-22(EINVAL)'),
             _line(10.8, 1, 'write', '>'), _line(10.8001, 1, 'write', '<', 'res=70000 data=BB')]
    w = s.recording_signals(lines, n=2)
    assert w[10.5]['paths'] == [('r', '/srv/data', '/srv/data/x')] and w[10.5]['bytes'] == Counter({('in', 12): 1})
    assert w[11.0]['errors'] == Counter({('sendfile', 'EINVAL'): 1}) and w[11.0]['bytes'] == Counter({('out', 15): 1})
    assert w[10.5]['ngrams'] == [('openat', 'read')] and len(w[11.0]['ngrams']) == 2


def _window(paths=(), errors=None, sizes=None, ngrams=()):
    return dict(paths=list(paths), errors=Counter(errors or {}), bytes=Counter(sizes or {}), ngrams=list(ngrams))


def test_reference_novelty_ranges_and_max_validation_limits():
    ref = s.Reference()
    ref.learn({0.5: _window([('w', '/srv/upload', '/srv/upload/a')], {('open', 'ENOENT'): 2}, {('out', 12): 3}, [('a', 'b')])})
    val = [_window([('w', '/srv/upload', '/srv/upload/b')], {('open', 'ENOENT'): 4}, {('out', 13): 1})]
    for v in val:
        ref.widen(v)
    limits = s.thresholds(ref, val)
    assert limits['path_w'] == 1 and limits['prefix_w'] == 0              # new upload names are normal, new dirs not
    attack = _window([('w', '/etc', '/etc/passwd')], {('open', 'ENOENT'): 5}, {('out', 15): 1}, [('x', 'y')])
    alarms = s.branch_alarms(ref, limits, {1.0: attack, 1.5: val[0]})
    assert alarms['path'] == {1.0: True, 1.5: False} and alarms['errno'] == {1.0: True, 1.5: False}
    assert alarms['bytes'] == {1.0: True, 1.5: False} and alarms['ngram'][1.0] is True
