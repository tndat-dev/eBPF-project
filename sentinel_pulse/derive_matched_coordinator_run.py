"""Fork study/campaign coordinators while keeping an active worker capture."""
import argparse
import json
import math
from pathlib import Path
import re
import subprocess
import time

from .integrity import sha256_file


def derive(capture_config, source, root, run_id, *, selection_delay=180,
           selection_seconds=5400, attack_delay=120, selection_start_at=None,
           campaign_workloads=None):
    if not re.fullmatch(r'[a-z0-9-]{3,60}', run_id):
        raise ValueError('unsafe coordinator run id')
    base=json.loads(capture_config.read_text())
    source=source.resolve()
    if not source.is_absolute() or any(c.isspace() for c in str(source)):
        raise ValueError('unsafe source path')
    if not (source/'sentinel_pulse/matched_study.py').is_file():
        raise ValueError('source does not contain matched study')
    if not (source/'sentinel_pulse/preview_campaign.py').is_file():
        raise ValueError('source does not contain preview evaluator')
    if len(base.get('workers',{}))!=3 or len(base.get('workload_keys',[]))!=21:
        raise ValueError('capture run must bind three workers and 21 frozen workload keys')
    if base.get('matched_observable')!='500ms full-ID + 249 baseline + transitions + rolling10 + history3 + tree/support':
        raise ValueError('capture observable differs from registered matched schema')
    for worker in base['workers'].values():
        if not Path(worker['output']).is_absolute():
            raise ValueError('worker output must be a shared absolute path')
    candidate=Path(base['candidate'])
    policy=Path(base['policy'])
    if sha256_file(candidate/'CANDIDATE_MANIFEST.json')!=base['model_hash']:
        raise ValueError('candidate manifest differs from registered capture')
    if sha256_file(policy)!=base['policy_hash']:
        raise ValueError('decision policy differs from registered capture')
    binary=Path(base['binary'])
    if sha256_file(binary)!=base['binary_hash']:
        raise ValueError('attack fixture differs from registered capture')
    exec_policy=source/'sentinel/k8s/tetragon-sentinel-pulse-exec-provenance.yaml'
    now=time.time()
    start=now+selection_delay if selection_start_at is None else float(selection_start_at)
    if not math.isfinite(start) or start<=0 or selection_seconds<=0 or attack_delay<0:
        raise ValueError('invalid selection timing')
    selected=set(campaign_workloads or base['workload_keys'])
    if not selected or not selected<=set(base['workload_keys']):
        raise ValueError('campaign subset is outside frozen workload keys')
    schedule=[item for item in base['schedule'] if item['workload_key'] in selected]
    if not schedule:raise ValueError('campaign subset has no registered trials')
    root.mkdir(parents=True,exist_ok=False)
    cfg=dict(base)
    cfg.update(run_id=run_id,source=str(source),
        source_commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip(),
        campaign_output=str(root/'pulse-development-matrix'),
        study_output=str(root/'syscall-matched-study'),
        traffic_output=str(root/'traffic-coordinator-unused'),traffic_schedule=[],
        schedule=schedule,campaign_workloads=sorted(selected),
        exec_provenance_policy=str(exec_policy),
        exec_provenance_policy_sha256=sha256_file(exec_policy),
        coordinator_parent_config_sha256=sha256_file(capture_config),
        prior_campaign_outputs=sorted(set(base.get('prior_campaign_outputs',[])+[base['campaign_output']])),
        derived_at_unix=now)
    cfg.update(selection_start=start,selection_seconds=selection_seconds,
               selection_end=start+selection_seconds,
               attack_not_before=start+selection_seconds+attack_delay)
    path=root/'CONFIG.json'
    path.write_text(json.dumps(cfg,indent=2)+'\n');path.chmod(0o444)
    return path


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture-config',type=Path,required=True)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--run-id',required=True)
    p.add_argument('--selection-delay',type=int,default=180)
    p.add_argument('--selection-start-at',type=float,
                   help='Reuse an explicit capture boundary for a corrected study; preserve parent registration')
    p.add_argument('--selection-seconds',type=int,default=5400)
    p.add_argument('--attack-delay',type=int,default=120)
    p.add_argument('--campaign-workload',action='append',
                   help='Run a recorded workload subset in a separate follow-up; retains original results')
    a=p.parse_args()
    print(derive(a.capture_config,a.source,a.root,a.run_id,
        selection_delay=a.selection_delay,selection_seconds=a.selection_seconds,
        attack_delay=a.attack_delay,selection_start_at=a.selection_start_at,
        campaign_workloads=a.campaign_workload))
