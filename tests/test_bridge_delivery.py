"""Episodes of the alert bridge against the alerts Alertmanager received."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'analysis'))

import bridge_delivery as m  # noqa: E402


def test_delivered_and_lost_episodes_inside_and_outside_a_stall():
    episodes = [dict(event='start', episode='a', preview_emitted_at=10.0), dict(event='end', episode='a', ended_at=30.0),
                dict(event='start', episode='b', preview_emitted_at=50.0), dict(event='start', episode='c', preview_emitted_at=55.0),
                dict(event='start', episode='d', preview_emitted_at=90.0)]
    deliveries = [dict(path='push', episode='a', received_at=10.25), dict(path='pull-fast', episode='b', received_at=58.0),
                  dict(path='push', episode='c', received_at=57.0)]
    out = m.analyse(episodes, deliveries, stalls=[(45.0, 60.0)])
    assert out['episodes'] == 4
    assert out['outside_stall'] == dict(episodes=2, delivered=1, not_delivered=1,
                                        decision_to_receipt_seconds=dict(n=1, p50=0.25, p95=0.25, p99=0.25, max=0.25))
    assert (out['inside_stall']['episodes'], out['inside_stall']['delivered'], out['inside_stall']['not_delivered']) == (2, 1, 1)
