"""Separate feature contract for entered calls plus returning seccomp skips.

Never feed these records into a frozen v1 model: counts now include skips,
and seccomp_skipped_or_emulated is not universally a denial/attack label.
"""
from __future__ import annotations
import math
import numpy as np
from .features import PulseFeatureBuilder, PulseSnapshot, TRACKED_SYSCALLS
from .capture import workload_key
from .encoding import compact_record

CONTRACT='pulse-entered-plus-seccomp-skip-v1'
SCHEMA='sentinel-pulse-extended-feature-v1'


class ExtendedFeatureStream:
    def __init__(self):
        self.builders={};self.previous={};self.last_boundary=None;self.stats={}

    def snapshot(self, record, boundary, metadata, received_at):
        if record.get('type')!='cgroup_snapshot_extended' or record.get('telemetry_contract')!=CONTRACT:
            raise ValueError('legacy or wrong extended telemetry contract')
        cg=int(record['cgroup_id']);item=metadata.get(str(cg))
        counts={int(k):int(v) for k,v in record['counts'].items()}
        bins=[int(v) for v in record['syscall_bins']];transitions=[int(v) for v in record['transition_bins']]
        skipped=int(record['seccomp_skipped_or_emulated']);total=int(record['total'])
        if (len(bins)!=64 or len(transitions)!=64 or set(counts)!=set(TRACKED_SYSCALLS)
                or min([total,skipped,*counts.values(),*bins,*transitions])<0
                or sum(bins)!=total or sum(counts.values())>total or skipped>total
                or not math.isfinite(boundary) or not math.isfinite(received_at)):
            raise ValueError('extended snapshot integrity violation')
        if not item or item.get('namespace')!='production':return None
        identity=(item.get('node_name'),item.get('pod_uid'),item.get('container_name'),item.get('workload_revision'),cg)
        if not all(identity[:4]) or 'unknown' in identity[:4]:return None
        previous=self.previous.get(identity)
        cumulative=np.asarray([*(counts[i] for i in TRACKED_SYSCALLS),*bins,*transitions,skipped],dtype=np.uint64)
        reset=(previous is not None and (not .35<=boundary-previous[0]<=.8 or np.any(cumulative<previous[1])))
        hard_loss=any(int(self.stats.get(k,0))>0 for k in ['task_state_update_fail','snapshot_projection_fail'])
        if reset or hard_loss:self.builders.pop(identity,None)
        self.previous[identity]=(boundary,cumulative)
        builder=self.builders.setdefault(identity,PulseFeatureBuilder(rolling_windows=10))
        builder.columns=tuple('seccomp_skipped_or_emulated' if c=='seccomp_denied' else c for c in builder.columns)
        history=builder.history_windows_available(cg)
        # Reuse the mathematical delta slot only, not the old field's meaning.
        snapshot=PulseSnapshot(cg,boundary,counts,{},dict(enumerate(bins)),dict(enumerate(transitions)),skipped)
        feature=builder.ingest(snapshot,workload_key(item))
        if feature is None:
            # Idle boundaries must not make old active rows look adjacent.
            fresh=PulseFeatureBuilder(rolling_windows=10);fresh.columns=builder.columns
            fresh.ingest(snapshot,workload_key(item));self.builders[identity]=fresh
            return None
        if skipped- (int(previous[1][-1]) if previous is not None else skipped)>feature.exact_total:
            raise ValueError('extended skip delta exceeds total delta')
        record=feature.as_record();record['schema']=SCHEMA
        record.update(telemetry_contract=CONTRACT,normal_label='unadjudicated_observation',
                      pod_name=item.get('pod_name'),pod_uid=item['pod_uid'],node_name=item['node_name'],
                      container_name=item['container_name'],workload_revision=item['workload_revision'],
                      emitted_at=received_at,history_before=history,rolling_windows=10,collector_stats=dict(self.stats),
                      eligible_for_normal_review=not hard_loss and history>=10 and 0<=received_at-boundary<=1,
                      not_accepted_by_frozen_model=True)
        output,schema=compact_record(record)
        schema['schema']='sentinel-pulse-extended-feature-schema-v1';schema['telemetry_contract']=CONTRACT
        return output,schema
