"""Isolated audit probes. No live config, telemetry or model is changed."""
import hashlib
import json
from pathlib import Path
import tempfile
import time
from unittest.mock import patch

import numpy as np
import sentinel_pulse.matched_study as study


class ProbeStop(Exception):
    pass


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj))


def setup(directory):
    root=directory/'study'
    workers={str(i):dict(node_name='node-'+str(i),output=str(directory/str(i))) for i in range(3)}
    config=directory/'CONFIG.json'
    write(config,dict(study_output=str(root),selection_start=10,selection_end=3010,
        selection_seconds=3000,workers=workers,workload_keys=['production/example:app'],
        campaign_output=str(directory/'campaign')))
    # Initialize a real START binding without executing collection or fitting.
    with patch.object(study.time,'sleep',side_effect=ProbeStop):
        try:study.run(config)
        except ProbeStop:pass
    return root,config,workers


def lost_checkpoint():
    with tempfile.TemporaryDirectory(prefix='pulse-readonly-audit-') as name:
        root,config,_=setup(Path(name))
        write(root/'STATUS.json',dict(state='fitting_matched_variants',
            completed={'example|base29|73021':dict(artifact='already-fitted.pkl')},unknown={}))
        before=json.loads((root/'STATUS.json').read_text())
        with patch.object(study.time,'sleep',side_effect=ProbeStop):
            try:study.run(config)
            except ProbeStop:pass
        after=json.loads((root/'STATUS.json').read_text())
        return dict(reproduced='completed' not in after,before_completed=len(before['completed']),
                    after_completed=len(after.get('completed',{})),after_state=after['state'])


def changed_index():
    with tempfile.TemporaryDirectory(prefix='pulse-readonly-audit-') as name:
        directory=Path(name);root,config,workers=setup(directory)
        for w in workers.values():write(Path(w['output'])/'STATUS.json',dict(completed_seconds=4000))
        write(root/'INPUTS.json',dict(files=[]))
        rows=root/'rows.jsonl';rows.write_text('')
        old=dict(arms={'base29':dict(add=[],drop=[])},
            workloads={'production/example:app':dict(path=str(rows),sha256=study.sha256_file(rows))},
            input_manifest_sha256=study.sha256_file(root/'INPUTS.json'))
        write(root/'INDEX.json',old)
        old_hash=study.sha256_file(root/'INDEX.json')
        completed={}
        for seed in study.SEEDS:
            artifact=root/f'{seed}.pkl';artifact.write_bytes(b'audit-only existing artifact')
            completed[f'production/example:app|base29|{seed}']=dict(
                artifact=artifact.name,sha256=study.sha256_file(artifact),feature_dim=249)
        write(root/'STATUS.json',dict(state='fitting_matched_variants',completed=completed,
            unknown={},index_sha256=old_hash))
        changed=json.loads(json.dumps(old));changed['arms']['base29']['add']=[202]
        changed['input_manifest_sha256']='f'*64
        write(root/'INDEX.json',changed)
        # The probe isolates binding validation; no tree is trained. Shapes
        # represent valid admission for the altered 253-dimensional arm.
        parts={key:np.zeros((1200,4*253),dtype=np.float32) for key in ('train','calibration')}
        with patch.object(study,'sealed_selection_files',return_value=([rows],3011)),\
             patch.object(study,'contexts',return_value=parts):
            study.run(config)
        end=json.loads((root/'TERMINAL.json').read_text())
        return dict(reproduced=end['state']=='completed_matched_fits',terminal_state=end['state'],
            old_index_hash=old_hash,new_index_hash=study.sha256_file(root/'INDEX.json'),
            stored_input_manifest_hash_mismatch=True,expected_new_feature_dim=253,
            reused_artifact_feature_dims=sorted(set(x['feature_dim'] for x in end['completed'].values())),
            reused_models=len(end['completed']))


if __name__=='__main__':
    result=dict(inspected_at_unix=time.time(),source_file=study.__file__,
        source_sha256=study.sha256_file(Path(study.__file__)),
        scope='temporary fixture and mocked readiness/context admission; no live job or ML quality measurement',
        checkpoint_lost_while_waiting=lost_checkpoint(),changed_index_reuses_checkpoint=changed_index())
    print(json.dumps(result,indent=2))
