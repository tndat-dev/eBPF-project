"""Derive a versioned matrix from recorded previews after evaluator corrections."""
import argparse
import json
from pathlib import Path
import time

from .integrity import sha256_file
from .preview_evaluation import evaluate_interval, summarize
from .syscall_histogram_pilot import atomic_json


def replay(config, output):
    cfg=json.loads(config.read_text())
    source=Path(cfg['campaign_output'])
    inputs={name:sha256_file(source/name)
            for name in ('START.json','RESULTS.json','TERMINAL.json')}
    start=json.loads((source/'START.json').read_text())
    binding=start['binding']
    if binding['config_sha256']!=sha256_file(config):
        raise ValueError('parent campaign config binding differs')
    for key in ('model_hash','policy_hash'):
        if binding[key]!=cfg[key]:raise ValueError('parent '+key+' differs')
    original=json.loads((source/'RESULTS.json').read_text())
    outcomes=[];changes=[];replayed=0;preserved=0;receipts={}
    for key, pair in sorted(original['completed'].items(),key=lambda item:int(item[0])):
        path=source/'trials'/f'{int(key):04d}'/'EVALUATION_INPUT.json'
        if not path.exists():
            # Failed dispatch/staging may have no saved rows. Keep its recorded
            # unknowns and controls; no replacement exposure is manufactured.
            outcomes.extend(pair);preserved+=1;continue
        receipts[str(path)]=sha256_file(path)
        data=json.loads(path.read_text())
        for label in ('control','attack'):
            trial=data[label]
            if trial['trial_id']!=f'{int(key)}:{label}':
                raise ValueError('saved trial identity differs: '+str(path))
            result=evaluate_interval(data['decisions'],trial,cfg['model_hash'],cfg['policy_hash'])
            previous=next(row for row in pair if row['label']==trial['label'])
            if result['outcome']!=previous['outcome'] or result['issues']!=previous.get('issues',[]):
                changes.append(dict(pair=int(key),label=trial['label'],
                    before=previous['outcome'],after=result['outcome'],
                    issues_before=previous.get('issues',[]),issues_after=result['issues']))
            outcomes.append(result)
        replayed+=1
    registration=dict(parent_config=str(config.resolve()),parent_config_sha256=sha256_file(config),
        parent_campaign=str(source),parent_file_sha256=inputs,evaluation_inputs_sha256=receipts,
        evaluator_sha256=sha256_file(Path(__file__).with_name('preview_evaluation.py')),
        replay_source_sha256=sha256_file(Path(__file__)),evidence_class='development_candidate_preview_replay',
        model_hash=cfg['model_hash'],policy_hash=cfg['policy_hash'],fresh_blind=False,
        correction='unscored warming without policy hash reduces coverage; explicit wrong hashes remain invalid',
        automatic_promotion=False,registered_at_unix=time.time())
    output.mkdir(parents=True,exist_ok=False)
    atomic_json(output/'START.json',registration)
    atomic_json(output/'OUTCOMES.json',outcomes)
    atomic_json(output/'CHANGES.json',changes)
    report=dict(summarize(outcomes),state='completed_recorded_preview_replay',
        replayed_pairs=replayed,preserved_pairs_without_raw_input=preserved,
        changed_outcomes=sum(row['before']!=row['after'] for row in changes),
        expected_pairs=len(cfg['schedule']),completed_pairs=len(original['completed']),
        parent_terminal_sha256=inputs['TERMINAL.json'],fresh_blind=False,finished_at_unix=time.time())
    atomic_json(output/'TERMINAL.json',report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(replay(a.config,a.output),sort_keys=True))
