"""Derive rolling-10 features from sealed C3 raw; retain all original evidence.

First replay rolling-5 and require exact agreement with every original vector,
identity, timestamp and exact count. Then recompute rolling-10; the other 191
features and source identities must still match. Never edits models/thresholds.
"""
import argparse
import fcntl
import json
from pathlib import Path
import time

import numpy as np

from .capture import run as capture_run
from .encoding import decode_vector
from .feature_profile import training_profile
from .integrity import sha256_file,verify_sha256
from .syscall_histogram_pilot import atomic_json
from .variant_capture_audit import IDENTITY


class VerifySink:
    def __init__(self,original,destination=None):
        self.original=original;self.destination=destination;self.rows=0;self.changed_rolling=0

    def write(self,text):
        for line in text.splitlines():
            actual=json.loads(line);expected=json.loads(next(self.original))
            if actual['schema']!=expected['schema']:raise ValueError('replay schema/order mismatch')
            if actual['schema']=='sentinel-pulse-feature-schema-v1':
                if actual!=expected:raise ValueError('replay columns differ')
                if self.destination:self.destination.write(json.dumps(expected,separators=(',',':'))+'\n')
                continue
            for key in (*IDENTITY,'window_start','window_end','exact_counts','exact_total','collector_stats'):
                if actual.get(key)!=expected.get(key):raise ValueError('raw replay provenance/count mismatch: '+key)
            x,y=decode_vector(actual),decode_vector(expected)
            if x.shape!=(249,) or y.shape!=(249,):raise ValueError('replay shape differs')
            if self.destination is None:
                if not np.array_equal(x,y):raise ValueError('rolling-5 reference replay differs')
            else:
                if not np.array_equal(x[:191],y[:191]):raise ValueError('non-rolling features changed')
                self.changed_rolling+=int(not np.array_equal(x[191:],y[191:]))
                for key in ('vector_f32_zlib_b64','vector_dim','feature_schema_sha256'):expected[key]=actual[key]
                expected['rolling_windows']=10
                self.destination.write(json.dumps(expected,separators=(',',':'))+'\n')
            self.rows+=1
        return len(text)

    def flush(self):
        if self.destination:self.destination.flush()

    def finish(self):
        if next(self.original,None) is not None:raise ValueError('raw replay omitted original feature rows')


def run(campaign,training_path,selection_audit,holdout_audit,output):
    profile=training_profile(training_path)
    if profile['name']!='exact-ebpf-500ms-rolling-10':raise ValueError('unexpected original training profile')
    audits={split:json.loads(path.read_text()) for split,path in [('selection',selection_audit),('holdout',holdout_audit)]}
    if any(a['split']!=split or a['captures_verified']!=15 for split,a in audits.items()):raise ValueError('complete audits required')
    output.mkdir(parents=True,exist_ok=True);lock=(output/'run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    binding=dict(training_manifest_sha256=sha256_file(training_path),training_profile=profile,
        campaign_start_sha256=sha256_file(campaign/'START.json'),
        audit_sha256=dict(selection=sha256_file(selection_audit),holdout=sha256_file(holdout_audit)),
        source_sha256={n:sha256_file(Path(__file__).with_name(n)) for n in
            ('repair_legacy_profile.py','feature_profile.py','capture.py','features.py','encoding.py')},
        source_profile='exact-ebpf-500ms-rolling-5',target_profile=profile['name'],
        no_model_or_threshold_change=True)
    start=output/'START.json'
    if start.exists():
        if json.loads(start.read_text())['binding']!=binding:raise ValueError('resume repair binding changed')
    else:atomic_json(start,dict(binding=binding,registered_at_unix=time.time()))
    completed={}
    for split,audit in audits.items():
        if audit['training_manifest_sha256']!=binding['training_manifest_sha256']:raise ValueError('training binding differs')
        for run_id,report in sorted(audit['captures'].items()):
            if Path(run_id).name!=run_id:raise ValueError('unsafe capture')
            source=campaign/split/run_id;final=output/split/run_id;receipt=final/'DERIVED.json'
            for name in ('features.jsonl','feature-raw.jsonl','metadata-snapshots.jsonl','START.json'):
                verify_sha256(source/name,report['seals'][name])
            if receipt.exists():
                d=json.loads(receipt.read_text());verify_sha256(final/'features.jsonl',d['corrected_features_sha256'])
                if d['source_features_sha256']!=report['seals']['features.jsonl']:raise ValueError('resume capture differs')
            else:
                temporary=output/split/(run_id+'.partial-'+str(time.time_ns()));temporary.mkdir(parents=True)
                with (source/'metadata-snapshots.jsonl').open() as stream:
                    first=json.loads(next(stream))
                if not first['identity_match'] or first.get('error'):raise ValueError('initial metadata not eligible')
                metadata=temporary/'metadata.json';atomic_json(metadata,first['document'])
                with (source/'features.jsonl').open() as original,(source/'feature-raw.jsonl').open() as raw:
                    verifier=VerifySink(iter(original));stats=capture_run(raw,verifier,metadata,5,.35,.75,.5);verifier.finish()
                if stats['malformed'] or stats['unresolved'] or verifier.rows!=report['counts']['feature_rows']:
                    raise ValueError('reference replay counts differ')
                with (source/'features.jsonl').open() as original,(source/'feature-raw.jsonl').open() as raw, \
                        (temporary/'features.jsonl').open('x') as destination:
                    corrected=VerifySink(iter(original),destination)
                    stats=capture_run(raw,corrected,metadata,10,.35,.75,.5);corrected.finish()
                if stats['malformed'] or stats['unresolved'] or corrected.rows!=verifier.rows:raise ValueError('correction count mismatch')
                d=dict(run_id=run_id,split=split,regime=report['regime'],source_features_sha256=report['seals']['features.jsonl'],
                    source_raw_sha256=report['seals']['feature-raw.jsonl'],training_profile=profile['name'],rolling_windows=10,
                    reference_replay_rows=verifier.rows,corrected_rows=corrected.rows,changed_rolling_rows=corrected.changed_rolling,
                    nonrolling_191_features_unchanged=True,reference_vectors_exact=True,
                    corrected_features_sha256=sha256_file(temporary/'features.jsonl'),repair_start_sha256=sha256_file(start))
                atomic_json(temporary/'DERIVED.json',d)
                if final.exists():raise ValueError('unsealed repair destination')
                temporary.rename(final)
            completed[split+'/'+run_id]=d
            atomic_json(output/'STATUS.json',dict(state='repairing_preprocessing',completed_captures=len(completed),
                expected_captures=30,updated_at_unix=time.time(),binding=binding))
    result=dict(state='completed_profile_repair',binding=binding,completed_captures=30,captures=completed,
        finished_at_unix=time.time(),start_sha256=sha256_file(start),original_evidence_modified=False,
        quality_claim=False,model_or_threshold_changed=False)
    atomic_json(output/'STATUS.json',result);atomic_json(output/'TERMINAL.json',result)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('campaign','training-manifest','selection-audit','holdout-audit','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();run(a.campaign,a.training_manifest,a.selection_audit,a.holdout_audit,a.output)


if __name__=='__main__':main()
