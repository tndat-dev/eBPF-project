import json
from pathlib import Path

from sentinel_pulse.rca import service


class FakeChild:
    stdout = None


def test_event_stream_is_bounded_inside_the_sensor_container(monkeypatch):
    seen = []
    monkeypatch.setattr(service.subprocess, 'Popen', lambda args, **_: seen.append(args) or FakeChild())
    svc = service.Service.__new__(service.Service)
    svc.cfg = dict(kubeconfig='/dev/null', runtime_events=True, connect_policy='p', stream_rotate_seconds=600)
    svc.streams = {}
    svc.issue = lambda *a, **k: None
    svc.start_stream('n1', 'tetragon-x', 'policy')
    svc.start_stream('n1', 'tetragon-x', 'lifecycle')
    for args in seen:
        tail = args[args.index('--')+1:]
        assert tail[:3] == ['timeout', '600', 'tetra']


def test_campaign_provenance_capture_has_an_in_container_timeout():
    text = (Path(__file__).resolve().parents[1]/'sentinel_pulse/attack/preview_campaign.py').read_text()
    assert "'--','timeout','24','tetra','getevents'" in text


def _service(**cfg):
    svc = service.Service.__new__(service.Service)
    svc.cfg = dict(model_hash='m', policy_hash='p', case_cooldown_seconds=300, **cfg)
    svc.db = service.database(':memory:')
    svc.counts = {}
    svc.started_at = -1e9   # exec log long since warm
    return svc


def _row(window_end):
    return dict(candidate_manifest_sha256='m', policy_sha256='p', status='candidate-raw-score-only',
                policy_evaluated=True, node_name='n1', pod_uid='u1', container_name='app',
                workload_key='production/app:app', window_end=window_end, candidate_alert_preview=True)


def _exec_event(svc, at, binary='/tmp/x'):
    svc.db.execute('insert into events values(?,?,?,?,?,?)', (f'h{at}', at, 'n1', 'u1', 'app',
                   '{"operation":"exec","source":{"binary":"%s"}}' % binary))
    svc.db.execute('insert into exec_log values(?,?,?,?,?)', ('n1', 'u1', 'app', binary, at))


def test_new_exec_inside_cooldown_opens_a_bounded_follow_up_case():
    svc = _service(follow_up_on_new_exec=True, follow_up_max_per_cooldown=1)
    svc.observe_trigger(_row(100.0), now=101.0)
    svc.observe_trigger(_row(105.0), now=106.0)          # no new exec -> grouped
    _exec_event(svc, 110.0)
    svc.observe_trigger(_row(112.0), now=113.0)          # new exec, 12 s later -> follow-up
    _exec_event(svc, 130.0)
    svc.observe_trigger(_row(131.0), now=132.0)          # cap of 1 follow-up reached -> grouped
    cases = svc.db.execute('select trigger from cases order by created').fetchall()
    assert len(cases) == 2 and 'follow_up_of' in cases[1][0]
    assert svc.counts['follow_up_cases_on_new_exec'] == 1
    assert svc.counts['positive_decisions_grouped_by_cooldown'] == 2


def test_follow_up_is_off_unless_registered():
    svc = _service()
    svc.observe_trigger(_row(100.0), now=101.0)
    _exec_event(svc, 110.0)
    svc.observe_trigger(_row(112.0), now=113.0)
    assert svc.db.execute('select count(*) from cases').fetchone()[0] == 1


def test_periodic_probe_binaries_do_not_open_follow_ups():
    svc = _service(follow_up_on_new_exec=True, before_seconds=30)
    _exec_event(svc, 40.0, '/bin/sh')                     # probe seen before the first case window
    _exec_event(svc, 95.0, '/tmp/benign')                 # launched inside the first case window
    svc.observe_trigger(_row(100.0), now=101.0)
    _exec_event(svc, 110.0, '/bin/sh')                    # probe again -> not new
    svc.observe_trigger(_row(112.0), now=113.0)
    _exec_event(svc, 120.0, '/tmp/benign')                # same path as the benign launch -> still new
    svc.observe_trigger(_row(124.0), now=125.0)
    assert svc.db.execute('select count(*) from cases').fetchone()[0] == 2


def test_probe_older_than_the_ring_still_counts_as_seen():
    svc = _service(follow_up_on_new_exec=True, before_seconds=30)
    _exec_event(svc, 0.0, '/usr/local/bin/python')       # health probe, long before; only in exec_log
    svc.db.execute('delete from events')                  # ring expired, exec log kept
    svc.observe_trigger(_row(250.0), now=251.0)
    _exec_event(svc, 400.0, '/usr/local/bin/python')     # probe again 150 s after the first case
    svc.observe_trigger(_row(402.0), now=403.0)
    assert svc.db.execute('select count(*) from cases').fetchone()[0] == 1


def test_no_follow_up_while_exec_log_is_warming_up():
    svc = _service(follow_up_on_new_exec=True)
    svc.started_at = 0.0
    svc.observe_trigger(_row(100.0), now=101.0)
    _exec_event(svc, 110.0)
    svc.observe_trigger(_row(112.0), now=113.0)
    assert svc.db.execute('select count(*) from cases').fetchone()[0] == 1


def test_decision_follower_streams_only_new_lines_across_segments(tmp_path):
    import subprocess, sys, time
    seg1 = tmp_path/'segments'/'s00001'; seg1.mkdir(parents=True)
    (seg1/'decisions.jsonl').write_text('{"old": 1}\n')
    child = subprocess.Popen([sys.executable, '-u', '-c', service.DECISION_FOLLOWER, str(tmp_path)],
                             stdout=subprocess.PIPE)
    try:
        time.sleep(0.8)
        with (seg1/'decisions.jsonl').open('a') as f:
            f.write('{"n": 1}\n{"n": 2}\n')
        time.sleep(0.5)
        seg2 = tmp_path/'segments'/'s00002'; seg2.mkdir()
        with (seg1/'decisions.jsonl').open('a') as f:
            f.write('{"n": 3}\n')          # last line of the old segment written before switching
        (seg2/'decisions.jsonl').write_text('{"n": 4}\n')
        time.sleep(1.0)
    finally:
        child.terminate()
    out = child.stdout.read().decode().split()
    assert out == ['{"n":', '1}', '{"n":', '2}', '{"n":', '3}', '{"n":', '4}']


def test_streamed_decision_lines_feed_the_trigger_path():
    svc = _service()
    svc.ingest_decision_line(json.dumps(_row(100.0)).encode(), 'n1', 101.0)
    assert svc.db.execute('select count(*) from cases').fetchone()[0] == 1
    assert svc.counts['decision_rows_read'] == 1
    import pytest
    with pytest.raises(ValueError):
        svc.ingest_decision_line(json.dumps(_row(102.0)).encode(), 'other-node', 103.0)
