"""Recover the legacy rolling contract from hash-bound capture provenance."""
import json
from pathlib import Path
import re

from .integrity import sha256_file,verify_sha256


def training_profile(training_path):
    training=json.loads(training_path.read_text())
    provenance=training_path.with_name('features.jsonl.manifest.json')
    verify_sha256(provenance,training['dataset_manifest_sha256'])
    dataset=json.loads(provenance.read_text());profiles=set();receipts={}
    for node,record in dataset['source_manifest_sha256'].items():
        path=Path(record['path']);verify_sha256(path,record['sha256'])
        manifest=json.loads(path.read_text());profile=manifest['capture_profile']
        profiles.add(profile);receipts[node]=dict(path=str(path),sha256=record['sha256'],profile=profile)
    if len(profiles)!=1:raise ValueError('training capture profiles differ')
    profile=profiles.pop();match=re.fullmatch(r'exact-ebpf-(\d+)ms-rolling-(\d+)',profile)
    if not match:raise ValueError('unsupported training preprocessing profile')
    return dict(name=profile,interval_ms=int(match[1]),rolling_windows=int(match[2]),include_idle=False,
        dataset_manifest_sha256=sha256_file(provenance),capture_receipts=receipts)
