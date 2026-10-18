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
