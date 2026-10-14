import array
import base64
import json
from pathlib import Path
import tempfile
import unittest
import zlib

try:
    import numpy
except ImportError:
    numpy=None
else:
    from sentinel_pulse.development_distribution_audit import read_input,merge


@unittest.skipIf(numpy is None,'run in pinned C2 venv')
class DistributionTests(unittest.TestCase):
    def test_sufficient_statistics_and_admission(self):
        columns=[str(i) for i in range(249)]
        def row(value,revision='rev'):
            return dict(schema='sentinel-pulse-feature-v1',workload_key='app',workload_revision=revision,
                vector_dim=249,vector_f32_zlib_b64=base64.b64encode(zlib.compress(array.array('f',[value]*249).tobytes())).decode(),
                window_start=0,window_end=.5,collector_stats=dict(task_state_update_fail=0,snapshot_projection_fail=0,
                    snapshot_consistency_retry_exhausted=0,target_snapshot_gap=0))
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'features.jsonl'
            rows=[dict(schema='sentinel-pulse-feature-schema-v1',columns=columns),row(1),row(3),row(9,'unapproved')]
            path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
            d=read_input(path,columns,{'app'},{'app':['rev']},(0,1))
        self.assertEqual(d['workloads']['app']['rows'],2)
        self.assertEqual(d['workloads']['app']['sum'][0],4)
        self.assertEqual(d['workloads']['app']['squares'][0],10)
        self.assertEqual(d['excluded'],{'unapproved_revision':1})
        combined=merge([d['workloads'],d['workloads']])
        self.assertEqual(combined['app']['rows'],4)
        self.assertEqual(combined['app']['sum'][0],8)


if __name__=='__main__':unittest.main()
