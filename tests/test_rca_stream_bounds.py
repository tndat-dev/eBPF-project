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
    return svc


def _row(window_end):
    return dict(candidate_manifest_sha256='m', policy_sha256='p', status='candidate-raw-score-only',
                policy_evaluated=True, node_name='n1', pod_uid='u1', container_name='app',
                workload_key='production/app:app', window_end=window_end, candidate_alert_preview=True)


def _exec_event(svc, at):
    svc.db.execute('insert into events values(?,?,?,?,?,?)', (f'h{at}', at, 'n1', 'u1', 'app',
                   '{"operation":"exec","source":{"binary":"/tmp/x"}}'))


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
