#!/usr/bin/env python3
"""Arms of syscall-ablation-loo-v1 stage 2 (confirmation, seeds 73021-73023), by the registered rule applied to the
stage-1 receipts: base29; every arm whose recall or separation difference to base29, at 1 or 5 episodes per
replica-hour on either attack set, has a 95 % CI excluding 0 or a point estimate beyond +-2 points; the 11 sensitive
syscalls and execve, execveat regardless; and, per amendment 1, every group and 'everywhere' arm.

    python3 syscall_loo_stage2_arms.py --stage1 validation-evidence/results-20261101/syscall-loo-stage1 --output arms.json
"""
import argparse
import json
from pathlib import Path

SENSITIVE = ('mprotect', 'chmod', 'ptrace', 'setuid', 'setgid', 'capset', 'pivot_root', 'mount', 'unshare', 'setns', 'seccomp',
             'execve', 'execveat')
BUDGETS = ('1', '5')


def differs(d):
    if not d:
        return False
    lo, hi = d['ci95']
    return lo > 0 or hi < 0 or abs(d['point']) > 0.02


def select(boots):
    arms, why = {'base29'}, {'base29': ['reference']}
    for name, b in boots.items():
        for budget in BUDGETS:
            for arm, r in b['budgets'][budget].items():
                for key in ('recall_diff', 'separation_diff'):
                    if arm != 'base29' and differs(r.get(key)):
                        arms.add(arm); why.setdefault(arm, []).append(f'{name} budget {budget} {key} {r[key]["point"]:+.3f} {r[key]["ci95"]}')
    every = set().union(*(b['budgets'][BUDGETS[0]].keys() for b in boots.values()))
    for arm in every:
        if arm.startswith(('drop_group_', 'drop_everywhere_')):
            arms.add(arm); why.setdefault(arm, []).append('amendment 1 group or everywhere arm')
        if arm.removeprefix('drop_') in SENSITIVE:
            arms.add(arm); why.setdefault(arm, []).append('sensitive or exec syscall, kept regardless')
    return sorted(arms), why


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--stage1', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    boots = {p.stem.removeprefix('BOOTSTRAP-'): json.loads(p.read_text()) for p in sorted(a.stage1.glob('BOOTSTRAP-*.json'))}
    arms, why = select(boots)
    a.output.write_text(json.dumps(dict(schema='syscall-loo-stage2-arms-v1', protocol='sentinel_pulse/protocol/syscall-ablation-loo-v1.json',
                                        seeds=[73021, 73022, 73023], arms=arms, why=why), indent=1))
    print(len(arms), 'arms:', ', '.join(arms))


if __name__ == '__main__':
    main()
