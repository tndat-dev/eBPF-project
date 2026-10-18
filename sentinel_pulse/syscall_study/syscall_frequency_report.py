"""Describe sealed selection frequencies; never rank, train or use holdout."""
import argparse
import ast
from collections import Counter,defaultdict
import json
from pathlib import Path

from ..integrity import sha256_file


def describe(cohort,tracked):
    if (cohort['evidence_class']!='descriptive_normal_frequency_only' or cohort['input_errors']
            or cohort['eligible_capture_count']!=cohort['input_capture_count']):
        raise ValueError('fully verified descriptive cohort required')
    regimes=defaultdict(Counter)
    for row in cohort['workload_revision_regime_summaries']:
        if row['container_name']=='pod-slice':continue
        counts={i['id']:i['count'] for i in row['syscall_ids']}
        if len(counts)!=len(row['syscall_ids']) or sum(counts.values())!=row['syscall_total']:
            raise ValueError('histogram total mismatch')
        if any(type(k) is not int or k<0 or type(v) is not int or v<0 for k,v in counts.items()):
            raise ValueError('invalid ID/count')
        regimes[row['traffic_regime']].update(counts)
    total=Counter()
    def summary(counts):
        n=sum(counts.values());explicit=sum(counts[i] for i in tracked)
        return dict(syscall_entries=n,distinct_observed_ids=sum(v>0 for v in counts.values()),
            explicit_entries=explicit,explicit_share=explicit/n if n else None,
            other_entries=n-explicit,counts_by_id={str(k):v for k,v in sorted(counts.items())},
            explicit_not_observed=[dict(id=k,name=v) for k,v in tracked.items() if not counts[k]])
    for counts in regimes.values():total.update(counts)
    return dict(schema='pulse-selection-frequency-description-v1',captures=cohort['eligible_capture_count'],
        excludes_pod_slice=True,regimes={k:summary(v) for k,v in sorted(regimes.items())},overall=summary(total),
        no_feature_selection_or_model_change=True,precision=None,recall=None,
        limitations=['selection-only descriptive syscall-entry frequencies, not successful outcomes',
            'absence in normal capture is not evidence a rare security syscall is useless',
            'other remains in aggregates/bins; it is not dropped telemetry',
            'no ablation/attack utility conclusion from frequency alone'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('cohort','feature-source','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();tree=ast.parse(a.feature_source.read_text())
    tracked=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.AnnAssign)
        and isinstance(n.target,ast.Name) and n.target.id=='TRACKED_SYSCALLS')
    if len(tracked)!=29:raise ValueError('expected frozen explicit 29 definition')
    cohort=json.loads(a.cohort.read_text())
    if any(Path(c['capture_dir']).parent.name!='selection' for c in cohort['captures']):
        raise ValueError('only selection captures may be described here')
    result=describe(cohort,tracked)
    result['binding']={str(p):sha256_file(p) for p in (a.cohort,a.feature_source,Path(__file__))}
    with a.output.open('x') as handle:json.dump(result,handle,indent=2);handle.write('\n')
    print(json.dumps(result['overall']))


if __name__=='__main__':main()
