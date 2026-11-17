"""rca_coverage.py: attack cases, rank of the attack binary, and (pulse-live-v6-v1 H6) rank 1 by step order."""
import json
from pathlib import Path
import subprocess
import sys

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'analysis' / 'rca_coverage.py'


def test_rank_one_is_split_by_step_order(tmp_path):
    cases, camp = tmp_path / 'cases', tmp_path / 'campaign'
    cases.mkdir()
    ident = dict(node_name='n', pod_uid='p', container_name='c')
    for pair, (start, order, rank) in enumerate([(1000.0, ['admin', 'benign', 'attack'], 1),
                                                 (2000.0, ['attack', 'benign', 'admin'], 2),
                                                 (3000.0, ['benign', 'attack'], 1)], 1):
        d = camp / 'trials' / f'{pair:04d}'
        d.mkdir(parents=True)
        (d / 'EVALUATION_INPUT.json').write_text(json.dumps(dict(attack=dict(ident, start_at=start, binary_path='/x'))))
        (d / 'ORDER.json').write_text(json.dumps(dict(order=order)))
        trig = dict(ident, window_end=start + 1, preview_emitted_at=start + 1.1)
        (cases / f'{pair}.json').write_text(json.dumps(dict(nodes=[dict(kind='signal', trigger=trig)], created_at=start + 3,
                                                            suspects=[dict(binary='/x', rank=rank)])))
    out = tmp_path / 'out.json'
    subprocess.run([sys.executable, str(SCRIPT), '--cases', str(cases), '--campaign', str(camp), '--output', str(out)],
                   check=True, capture_output=True)
    r = json.loads(out.read_text())
    assert r['attack_cases'] == 3 and abs(r['stored_rank_top1'] - 2 / 3) < 1e-9
    assert r['rank_top1_by_order']['attack_after_benign'] == dict(cases=2, top1=2, share=1.0)
    assert r['rank_top1_by_order']['attack_before_benign'] == dict(cases=1, top1=0, share=0.0)
