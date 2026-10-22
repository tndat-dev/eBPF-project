import json
import sqlite3

from sentinel_pulse.rca.baseline_seed import build, seed
from sentinel_pulse.rca.ranking import rank_suspects
from sentinel_pulse.rca.service import database


def test_campaign_binaries_never_become_known_and_seeded_ones_are_not_novel(tmp_path):
    camp = tmp_path/'campaign'; camp.mkdir()
    (camp/'INTERVALS.jsonl').write_text(json.dumps(dict(start_at=1000.0)) + '\n')
    (camp/'TERMINAL.json').write_text(json.dumps(dict(finished_at_unix=2000.0)))
    old = database(tmp_path/'old.sqlite3')
    old.executemany('insert into binaries values(?,?,?)', [
        ('production/db:postgres', '/controller/manager', 5000.0),      # rare periodic task, after the campaign
        ('production/db:postgres', '/usr/bin/pg_isready', 10.0),
        ('production/db:postgres', '/tmp/attack-fixture', 1500.0),       # first seen inside the campaign
        ('production/db:postgres', '/tmp/late', 950.0)])                 # inside the 60 s margin
    old.commit(); old.close()
    workloads, stats = build([(str(tmp_path/'old.sqlite3'), [str(camp)])])
    assert workloads == {'production/db:postgres': ['/controller/manager', '/usr/bin/pg_isready']}
    assert stats == dict(kept=2, left_out_first_seen_in_campaign=2)
    new = database(tmp_path/'new.sqlite3')
    new.execute("insert into binaries values('production/db:postgres','/usr/bin/pg_isready',123.0)")
    assert seed(new, workloads) == 1                                      # existing rows are kept as they are
    baseline = dict(new.execute('select binary, first_seen from binaries').fetchall())
    assert baseline == {'/controller/manager': 0.0, '/usr/bin/pg_isready': 123.0}
    tree = dict(nodes=[dict(id='p', kind='process', binary='/controller/manager', exec_id='e', container_name='c'),
                       dict(id='q', kind='process', binary='/tmp/attack-fixture', exec_id='f', container_name='c')],
                edges=[])
    ranked = {r['binary']: r['reasons'] for r in rank_suspects(tree, baseline, frozen_at=100.0)}
    assert 'novel_binary' not in ranked['/controller/manager'] and 'unknown_binary' not in ranked['/controller/manager']
    assert 'unknown_binary' in ranked['/tmp/attack-fixture']


def test_service_seeds_once_and_records_it(tmp_path, monkeypatch):
    from sentinel_pulse.rca.service import Service
    seed_file = tmp_path/'seed.json'
    seed_file.write_text(json.dumps(dict(workloads={'production/db:postgres': ['/controller/manager']})))
    config = tmp_path/'CONFIG.json'
    config.write_text(json.dumps(dict(output=str(tmp_path/'rca'), model_hash='m', policy_hash='p',
        case_cooldown_seconds=300, before_seconds=30, after_seconds=5, ring_seconds=180, max_ring_events=1000,
        max_cases=10, workers=[], runtime_events=True, connect_policy='x', binary_baseline_seed=str(seed_file))))
    service = Service(config)
    assert service.db.execute('select first_seen from binaries').fetchall() == [(0.0,)]
    meta = json.loads(service.db.execute("select value from metadata where key='baseline_seed'").fetchone()[0])
    assert meta['added'] == 1 and meta['path'] == str(seed_file)
    service.lock.close(); service.db.close()
    again = Service(config)                                    # a restart does not seed twice
    assert again.db.execute('select count(*) from binaries').fetchone()[0] == 1


def test_rca_service_and_seed_import_without_numpy():
    """The RCA service runs on the system Python (no numpy): its import chain must not pull numpy in."""
    import subprocess, sys
    code = ("import sys, builtins; real = builtins.__import__\n"
            "def guard(name, *a, **k):\n"
            "    if name == 'numpy' or name.startswith('numpy.'): raise ImportError('numpy not allowed')\n"
            "    return real(name, *a, **k)\n"
            "builtins.__import__ = guard\n"
            "import sentinel_pulse.rca.service, sentinel_pulse.rca.baseline_seed, sentinel_pulse.rca.triage\n")
    subprocess.run([sys.executable, '-c', code], check=True, cwd=str(__import__('pathlib').Path(__file__).parents[1]))


def test_service_in_alert_mode_builds_cases_from_alertmanager_delivered_alerts(tmp_path):
    from sentinel_pulse.rca.service import Service
    triggers = tmp_path/'triggers.jsonl'
    old = dict(delivered_at=1.0, path='push', episode='old', row={})
    triggers.write_text(json.dumps(old) + '\n')                     # written before the service started: not replayed
    config = tmp_path/'CONFIG.json'
    config.write_text(json.dumps(dict(output=str(tmp_path/'rca'), model_hash='m', policy_hash='p',
        case_cooldown_seconds=300, before_seconds=30, after_seconds=5, ring_seconds=180, max_ring_events=1000,
        max_cases=10, workers=[], runtime_events=True, connect_policy='x', alert_trigger_file=str(triggers))))
    service = Service(config)
    assert json.loads((tmp_path/'rca'/'START.json').read_text())['trigger'] == 'alertmanager_delivered_alert'
    service.tail_alert_triggers()
    row = dict(schema='s', status='candidate-raw-score-only', policy_evaluated=True, candidate_alert_preview=True,
               alert=False, run_id='r', capture_segment='s1', node_name='w1', pod_uid='u', container_name='c',
               cgroup_id=1, workload_key='production/db:postgres', window_start=99.5, window_end=100.0,
               preview_emitted_at=100.1, candidate_manifest_sha256='m', policy_sha256='p')
    with triggers.open('a') as handle:
        handle.write(json.dumps(dict(delivered_at=100.2, path='push', episode='e1', row=row)) + '\n')
    service.tail_alert_triggers()
    service.tail_alert_triggers()                                     # nothing new: no second case
    cases = service.db.execute('select trigger from cases').fetchall()
    assert len(cases) == 1
    trigger = json.loads(cases[0][0])
    assert trigger['trigger_source'] == 'alertmanager' and trigger['alert_delivered_at'] == 100.2 and trigger['alert_path'] == 'push'
    assert service.counts['alert_triggers_read'] == 1
