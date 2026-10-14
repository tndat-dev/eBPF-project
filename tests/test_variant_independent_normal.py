import unittest
import array
import base64
import hashlib
import io
import json
import zlib

from sentinel_pulse.variant_capture_audit import audit_rows

try:
    import numpy
except ImportError:
    numpy=None
else:
    from sentinel_pulse.variant_independent_normal import temporal_contexts


COLS=['x','y'];SCHEMA=hashlib.sha256(json.dumps(COLS,separators=(',',':')).encode()).hexdigest()
REV={'prod/app:app':['rev']}


def record(i,**extra):
    row=dict(schema='sentinel-pulse-feature-v1',feature_schema_sha256=SCHEMA,vector_dim=2,
        vector_f32_zlib_b64=base64.b64encode(zlib.compress(array.array('f',[float(i),float(i+1)]).tobytes())).decode(),
        node_name='node',pod_uid='pod',container_name='app',cgroup_id=1,workload_revision='rev',
        workload_key='prod/app:app',window_start=i*.5,window_end=(i+1)*.5,
        exact_counts={'read':1},exact_total=1,collector_stats=dict(task_state_update_fail=0,
            snapshot_projection_fail=0,snapshot_consistency_retry_exhausted=0,target_snapshot_gap=0))
    return dict(row,**extra)


def stream(rows):
    schema=dict(schema='sentinel-pulse-feature-schema-v1',columns=COLS,feature_schema_sha256=SCHEMA)
    return io.StringIO(''.join(json.dumps(r)+'\n' for r in [schema,*rows]))


@unittest.skipIf(numpy is None,'NumPy required; run in the pinned C2 venv')
class ContextTests(unittest.TestCase):
    def contexts(self,rows):return list(temporal_contexts(stream(rows),COLS,REV,0,100,'node'))

    def test_order_and_complete_history(self):
        result=self.contexts([record(i) for i in range(4)])
        self.assertEqual(len(result),1)
        self.assertEqual(result[0][1].tolist(),[0,1,1,2,2,3,3,4])
        self.assertEqual(result[0][2]['source_line'],5)

    def test_no_bridge_gap_or_pod(self):
        self.assertEqual(self.contexts([record(i) for i in (0,1,2,4)]),[])
        self.assertEqual(self.contexts([record(i) for i in range(3)]+[record(3,pod_uid='new')]),[])

    def test_same_admission_as_auditor(self):
        rows=[record(i) for i in range(20)]
        rows[4]['collector_stats']['snapshot_projection_fail']=1
        rows[9]['workload_revision']='new'
        rows[15]['workload_key']='unknown'
        audit=audit_rows(stream(rows),COLS,REV,0,100,'node')
        self.assertEqual(len(self.contexts(rows)),audit['counts']['eligible_four_window_contexts'])

    def test_invalid_schema_not_silently_ignored(self):
        with self.assertRaisesRegex(ValueError,'schema'):
            self.contexts([record(0,feature_schema_sha256='changed')])


if __name__=='__main__':unittest.main()
