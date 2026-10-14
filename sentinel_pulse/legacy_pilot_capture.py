"""Owned bounded legacy rolling-10 capture alongside the idle-aware ML pilot."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

from .capture import run as capture_run
from .integrity import sha256_file
from .syscall_histogram_pilot import atomic_json


def run(loader,obj,output,seconds):
    output.mkdir(parents=True,exist_ok=False)
    atomic_json(output/'START.json',dict(registered_at_unix=time.time(),duration_seconds=seconds,
        feature_profile='exact-ebpf-500ms-rolling-10',loader_sha256=sha256_file(loader),object_sha256=sha256_file(obj),
        metadata_start=json.loads(Path('/run/sentinel-pulse/cgroups.json').read_text()),
        source_sha256={n:sha256_file(Path(__file__).with_name(n)) for n in ('capture.py','features.py','encoding.py')},
        prospective_attack_possible=True,model_fitting=False))
    stopping=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,stop)
    result={};started=time.monotonic()
    with (output/'loader.log').open('x') as errors:
        child=subprocess.Popen([str(loader),'--object',str(obj),'--allow-cgroup-file',
            '/run/sentinel-pulse/allowed-cgroups','--interval-ms','500'],stdout=subprocess.PIPE,stderr=errors,text=True)
        def pump():
            try:
                with (output/'raw.jsonl').open('x') as raw,(output/'features.jsonl').open('x') as features:
                    def lines():
                        for line in child.stdout:
                            raw.write(line);yield line
                    result['capture']=capture_run(lines(),features,Path('/run/sentinel-pulse/cgroups.json'),10,.35,.75,.5)
                    for sink in (raw,features):sink.flush();os.fsync(sink.fileno())
            except BaseException as exc:result['error']=type(exc).__name__+': '+str(exc)
        thread=threading.Thread(target=pump);thread.start()
        while not stopping and time.monotonic()-started<seconds and child.poll() is None and thread.is_alive():
            time.sleep(.5)
            total=sum(p.stat().st_size for p in output.iterdir() if p.is_file())
            if total>1024**3:result['budget_reached']=True;break
        child.terminate()
        try:child.wait(timeout=10)
        except subprocess.TimeoutExpired:child.kill();child.wait()
        thread.join(timeout=15)
        if thread.is_alive():raise RuntimeError('legacy stream did not close')
    atomic_json(output/'TERMINAL.json',dict(state='closed_legacy_pilot_capture',elapsed_seconds=time.monotonic()-started,
        loader_exit_status=child.returncode,metadata_end=json.loads(Path('/run/sentinel-pulse/cgroups.json').read_text()),
        **result,seals={p.name:sha256_file(p) for p in output.iterdir() if p.is_file()}))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('loader','object','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--seconds',type=int,default=1800);a=p.parse_args()
    if not 60<=a.seconds<=3600:raise ValueError('bounded duration required')
    run(a.loader,a.object,a.output,a.seconds)


if __name__=='__main__':main()
