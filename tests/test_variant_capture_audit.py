import array
import base64
import hashlib
import json
import zlib

import pytest

from sentinel_pulse.variant_capture_audit import audit_rows, decode


COLS = ['x', 'y']
SCHEMA = hashlib.sha256(json.dumps(COLS, separators=(',', ':')).encode()).hexdigest()


def row(index):
    raw = array.array('f', [1., 2.]).tobytes()
    return dict(schema='sentinel-pulse-feature-v1', feature_schema_sha256=SCHEMA,
        vector_dim=2, vector_f32_zlib_b64=base64.b64encode(zlib.compress(raw)).decode(),
        node_name='node', pod_uid='pod', container_name='app', cgroup_id=1,
        workload_revision='rev', workload_key='prod/app:app', window_start=index*.5,
        window_end=(index+1)*.5, exact_counts={'read': 1}, exact_total=1,
        collector_stats=dict(task_state_update_fail=0, snapshot_projection_fail=0,
            snapshot_consistency_retry_exhausted=0, target_snapshot_gap=0))


def audit(rows):
    schema = dict(schema='sentinel-pulse-feature-schema-v1', columns=COLS, feature_schema_sha256=SCHEMA)
    return audit_rows(map(json.dumps, [schema, *rows]), COLS, {'prod/app:app': ['rev']}, 0, 100, 'node')


def test_four_adjacent_windows_form_one_context():
    result = audit([row(i) for i in range(4)])
    assert result['counts']['eligible_four_window_contexts'] == 1
    assert result['counts']['warming_rows'] == 3


def test_gap_cannot_be_bridged():
    result = audit([row(i) for i in (0, 1, 2, 4)])
    assert result['counts'].get('eligible_four_window_contexts', 0) == 0
    assert result['counts']['history_gap_resets'] == 1


@pytest.mark.parametrize('field,value,reason', [
    ('workload_revision', 'new-rev', 'unapproved_revision'),
    ('workload_key', 'prod/other:app', 'no_frozen_variant_model'),
    ('collector_stats', {}, 'missing_collector_integrity'),
])
def test_ineligible_not_silently_normal(field, value, reason):
    r = row(0); r[field] = value
    assert audit([r])['counts'][reason] == 1


def test_counter_fault_resets_history():
    rows = [row(i) for i in range(7)]
    rows[3]['collector_stats']['snapshot_projection_fail'] = 1
    result = audit(rows)
    assert result['counts'].get('eligible_four_window_contexts', 0) == 0
    assert result['counts']['collector_integrity_counter_nonzero'] == 1


def test_identity_does_not_mix_pods():
    rows = [row(i) for i in range(4)]
    rows[3]['pod_uid'] = 'different'
    assert audit(rows)['counts'].get('eligible_four_window_contexts', 0) == 0


def test_float_payload_bounded_and_finite():
    r = row(0)
    assert list(decode(r, 2)) == [1., 2.]
    r['vector_f32_zlib_b64'] = base64.b64encode(zlib.compress(b'\0' * 10000)).decode()
    with pytest.raises(ValueError, match='bounded'):
        decode(r, 2)


def test_invalid_counts_or_schema_rejected():
    r = row(0); r['exact_total'] = 3
    with pytest.raises(ValueError, match='counts'):
        audit([r])
    r = row(0); r['feature_schema_sha256'] = 'different'
    with pytest.raises(ValueError, match='schema'):
        audit([r])
