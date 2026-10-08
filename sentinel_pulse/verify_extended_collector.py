"""Verify the integrated extended collector in this unit's cgroup only."""
import argparse
import json
from pathlib import Path
import select
import subprocess
import time
import platform
from .integrity import sha256_file
from .run_500ms_blind_matrix import atomic_json


def verify(build,root):
    line=next(x for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
    path=line[3:]
    if not path.startswith('/system.slice/pulse-extended-proof-'):
        raise ValueError('proof must run in its own system unit, not an SSH/root cgroup')
    cg=Path('/sys/fs/cgroup'+path).stat().st_ino
    root.mkdir(parents=True,exist_ok=False);allowed=root/'allowed-cgroup'
    allowed.write_text(str(cg)+'\n')
    files=['pulse_counter_extended_loader','pulse_counter_extended.bpf.o','seccomp_fixture']
    atomic_json(root/'START.json',dict(schema='pulse-extended-proof-start-v1',cgroup_id=cg,cgroup_path=path,
        kernel=platform.release(),started_at_unix=time.time(),source_commit=subprocess.check_output(
        ['git','-c','safe.directory='+str(Path(__file__).resolve().parents[1]),
         '-C',str(Path(__file__).resolve().parents[1]),'rev-parse','HEAD'],text=True).strip(),
        artifact_sha256={name:sha256_file(build/name) for name in files},isolated_cgroup_only=True,
        modifies_production_policies=False))
    with (root/'loader.stderr').open('wb') as err,(root/'raw.jsonl').open('w') as raw:
        proc=subprocess.Popen([str(build/files[0]),'--object',str(build/files[1]),
            '--allow-cgroup-file',str(allowed),'--interval-ms','500'],stdout=subprocess.PIPE,stderr=err)
        snapshots=[];buffer=b''
        def boundary():
            nonlocal buffer
            until=time.monotonic()+15
            while time.monotonic()<until:
                if not select.select([proc.stdout],[],[],max(0,until-time.monotonic()))[0]:break
                import os
                chunk=os.read(proc.stdout.fileno(),65536)
                if not chunk:raise RuntimeError('extended collector exited before boundary')
                buffer+=chunk
                while b'\n' in buffer:
                    line,buffer=buffer.split(b'\n',1);record=json.loads(line)
                    raw.write(line.decode()+'\n');raw.flush()
                    if record.get('type')=='cgroup_snapshot_extended':snapshots.append(record)
                    if record.get('type')=='snapshot_end':return snapshots[-1]
            raise RuntimeError('extended collector snapshot timeout')
        try:
            before=boundary()
            fixture=subprocess.run([str(build/'seccomp_fixture')],capture_output=True,timeout=10,check=True)
            (root/'fixture.stdout').write_bytes(fixture.stdout);(root/'fixture.stderr').write_bytes(fixture.stderr)
            after=boundary()
            delta={k:int(after['counts'][k])-int(before['counts'][k]) for k in ['10','308','317']}
            skipped=after['seccomp_skipped_or_emulated']-before['seccomp_skipped_or_emulated']
            valid=delta['308']==20 and delta['317']==20 and delta['10']>=40 and skipped==40
            receipt=dict(schema='pulse-extended-integrated-proof-v1',valid=valid,cgroup_id=cg,
                counts_delta={'mprotect':delta['10'],'setns':delta['308'],'seccomp':delta['317']},
                seccomp_skipped_or_emulated_delta=skipped,fixture=json.loads(fixture.stdout),
                baseline_before=before,after=after,not_a_model_accuracy_measurement=True)
            atomic_json(root/'RESULTS.json',receipt)
            if not valid:raise ValueError('integrated collector fixture counts differ')
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
    return receipt


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--root',type=Path,required=True)
    a=p.parse_args();verify(a.build,a.root)


if __name__=='__main__':main()
