import io
import json
import unittest

try:
    import numpy
except ImportError:
    numpy=None
else:
    from sentinel_pulse.encoding import compact_record
    from sentinel_pulse.repair_legacy_profile import VerifySink


@unittest.skipIf(numpy is None,'use pinned C2 venv')
class ReplayTests(unittest.TestCase):
    def row(self,change=None):
        vector=[0.]*249
        if change is not None:vector[change]=1.
        return compact_record(dict(schema='sentinel-pulse-feature-v1',columns=[str(i) for i in range(249)],
            vector=vector,workload_key='w',node_name='n',pod_uid='p',container_name='c',cgroup_id=1,
            workload_revision='r',window_start=0.,window_end=.5,exact_counts={'read':1},exact_total=1,collector_stats={}))[0]

    def test_reference_must_match_every_feature(self):
        expected=self.row();actual=self.row(200)
        sink=VerifySink(iter([json.dumps(expected)]))
        with self.assertRaisesRegex(ValueError,'reference replay'):sink.write(json.dumps(actual)+'\n')

    def test_corrected_only_changes_rolling(self):
        expected=self.row();actual=self.row(200);dest=io.StringIO()
        sink=VerifySink(iter([json.dumps(expected)]),dest);sink.write(json.dumps(actual)+'\n');sink.finish()
        self.assertEqual(sink.changed_rolling,1)
        self.assertEqual(json.loads(dest.getvalue())['rolling_windows'],10)

    def test_nonrolling_or_identity_change_rejected(self):
        sink=VerifySink(iter([json.dumps(self.row())]),io.StringIO())
        with self.assertRaisesRegex(ValueError,'non-rolling'):sink.write(json.dumps(self.row(190))+'\n')


if __name__=='__main__':unittest.main()
