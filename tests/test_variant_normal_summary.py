import pytest
from sentinel_pulse.variant_normal_summary import aggregate


def terminal():
    return dict(state='completed_independent_normal_raw_scores',completed={
        'a|full':dict(contexts=10,raw_model_positive=2,source_captures=[dict(start_row=0,rows=10,raw_model_positive=2,regime='peak')]),
        'a|drop_read':dict(contexts=10,raw_model_positive=3,source_captures=[dict(start_row=0,rows=10,raw_model_positive=3,regime='peak')])})


def test_positives_not_confusion_labels_and_no_double_context_count():
    d=aggregate(terminal())
    assert d['unique_source_contexts']==10 and d['variants']==2
    assert d['variant_counts']['full']['raw_model_positive']==2
    assert d['confusion_matrix']['FP'] is None and d['precision'] is None


def test_variant_context_mismatch_rejected():
    d=terminal();d['completed']['a|drop_read']['contexts']=9
    d['completed']['a|drop_read']['source_captures'][0]['rows']=9
    with pytest.raises(ValueError,match='context mismatch'):aggregate(d)


def test_source_counts_not_trusted_without_consistency():
    d=terminal();d['completed']['a|full']['source_captures'][0]['raw_model_positive']=1
    with pytest.raises(ValueError,match='source sums'):aggregate(d)
