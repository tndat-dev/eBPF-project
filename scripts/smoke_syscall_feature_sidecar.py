"""Bounded host-cgroup integration smoke; output is not research normal data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import time
from types import SimpleNamespace

from sentinel_pulse.encoding import decode_vector
from sentinel_pulse.syscall_histogram_pilot import FeatureSidecar, atomic_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--loader', type=Path, required=True)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError('root required for bounded eBPF smoke')
    relative = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                    if line.startswith('0::'))
    if 'pulse-syscall-sidecar-smoke-' not in relative:
        raise ValueError('run in its dedicated systemd smoke unit')
    cgroup_id = (Path('/sys/fs/cgroup') / relative.lstrip('/')).stat().st_ino
    root = args.output
    root.mkdir(parents=True, exist_ok=False)
    allowlist = root / 'allowed-cgroups'
    allowlist.write_text(str(cgroup_id) + '\n')
    metadata = root / 'metadata.json'
    atomic_json(metadata, dict(schema='sentinel-pulse-cgroups-v1', cgroups={str(cgroup_id): dict(
        node_name=socket.gethostname(), namespace='host-engineering', workload_name='sidecar-smoke',
        container_name='systemd', pod_uid=relative, pod_name=None, workload_revision='engineering-fixture')}))
    atomic_json(root / 'START.json', dict(evidence_class='host_cgroup_integration_smoke',
        use_for_training_or_evaluation=False, cgroup_id=cgroup_id, cgroup_path=relative,
        loader_sha256=hashlib.sha256(args.loader.read_bytes()).hexdigest(),
        object_sha256=hashlib.sha256(args.object.read_bytes()).hexdigest(), started_at_unix=time.time()))
    sidecar = FeatureSidecar(SimpleNamespace(feature_loader=args.loader, feature_object=args.object,
                                             allowlist=allowlist, metadata=metadata, output=root))
    sidecar.start()
    try:
        until = time.monotonic() + 12
        while time.monotonic() < until:
            # Harmless reads generate known activity inside the allowed cgroup.
            Path('/proc/self/status').read_text()
            time.sleep(0.05)
    finally:
        result = sidecar.finish()
    rows = [json.loads(line) for line in (root / 'features.jsonl').read_text().splitlines()]
    features = [row for row in rows if row.get('schema') == 'sentinel-pulse-feature-v1']
    schemas = {row['feature_schema_sha256'] for row in rows if row.get('schema') == 'sentinel-pulse-feature-schema-v1'}
    success = (not result.get('error') and not result.get('unexpected_exit')
               and result.get('capture', {}).get('malformed') == 0
               and len(features) >= 4 and len(schemas) == 1
               and all(decode_vector(row).shape == (249,) for row in features))
    terminal = dict(state='passed' if success else 'failed', feature_rows=len(features),
        feature_schema_sha256=sorted(schemas), sidecar=result, use_for_training_or_evaluation=False,
        finished_at_unix=time.time())
    atomic_json(root / 'TERMINAL.json', terminal)
    print(json.dumps(terminal))
    if not success:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
