"""Stage/remove one checksum-pinned fixture in an exact CRI container."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from ..integrity import sha256_file

ATTACK_PATHS = {
    '/tmp/sentinel-runtime-attack-blind',
    '/run/sentinel-runtime-attack-blind',
    '/etc/istio/proxy/sentinel-runtime-attack-blind',
    '/operator/sentinel-runtime-attack-blind',
}
# the benign-exec control copy beside each (attack/cluster.py benign_path_for)
ALLOWED_PATHS = ATTACK_PATHS | {p.rsplit('/', 1)[0] + '/sentinel-benign-exec-control' for p in ATTACK_PATHS}


def target(container_id, pod_uid, container_name):
    container_id=container_id.removeprefix('containerd://')
    if len(container_id)!=64 or any(c not in '0123456789abcdef' for c in container_id):
        raise ValueError('invalid CRI container ID')
    doc=json.loads(subprocess.check_output(['crictl','inspect',container_id],timeout=15))
    labels=doc['status']['labels']
    if (labels.get('io.kubernetes.pod.namespace')!='production'
            or labels.get('io.kubernetes.pod.uid')!=pod_uid
            or labels.get('io.kubernetes.container.name')!=container_name
            or doc['status']['state']!='CONTAINER_RUNNING'):
        raise ValueError('CRI target identity/readiness changed')
    pid=int(doc['info']['pid'])
    if pid<=1:raise ValueError('invalid container init pid')
    return pid


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['stage','cleanup'])
    for key in ('container-id','pod-uid','container-name','binary','sha256','path'):
        p.add_argument('--'+key,required=True)
    a=p.parse_args()
    if a.path not in ALLOWED_PATHS:
        raise ValueError('unregistered container path')
    pid=target(a.container_id,a.pod_uid,a.container_name)
    destination=Path('/proc')/str(pid)/'root'/a.path.lstrip('/')
    if a.command=='stage':
        src=Path(a.binary)
        if sha256_file(src)!=a.sha256:raise ValueError('fixture hash changed')
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
        with os.fdopen(fd,'wb') as out,src.open('rb') as inp:
            import shutil
            shutil.copyfileobj(inp,out);out.flush();os.fsync(out.fileno())
        if sha256_file(destination)!=a.sha256:raise ValueError('staged hash differs')
    else:
        if destination.is_symlink() or sha256_file(destination)!=a.sha256:
            raise ValueError('refuse cleanup of changed fixture')
        destination.unlink()
    print(json.dumps(dict(container_id=a.container_id,pod_uid=a.pod_uid,container_name=a.container_name,
                         pid=pid,path=a.path,command=a.command,sha256=a.sha256)))


if __name__=='__main__':main()
