#!/usr/bin/env python3
"""Apply the criteria of protocol tripwire-a1-blind-v1 to a ``novel_syscalls.py`` result (primary reference)."""
import argparse
import json
from pathlib import Path


def verdict(result: dict, criteria: dict) -> dict:
    by = result['by_scenario']; rare = criteria['rare_syscall_scenarios']
    shares = {s: by.get(s, {}).get('attack', {}).get('share') for s in rare}
    delays = [by.get(s, {}).get('attack', {}).get('delay_p95') for s in rare]
    checks = dict(
        benign=result['overall']['benign'] <= criteria['benign_max'],
        control=result['overall']['control'] <= criteria['control_max'],
        rare_syscall_scenarios=all(v is not None and v >= criteria['rare_syscall_scenario_min'] for v in shares.values()),
        rare_syscall_delay=all(d is not None and d <= criteria['rare_syscall_delay_p95_max_seconds'] for d in delays))
    return dict(passed=all(checks.values()), checks=checks, rare_syscall_shares=shares, rare_syscall_delay_p95=delays,
                overall=result['overall'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--result', required=True); p.add_argument('--protocol', required=True); p.add_argument('--output', required=True)
    a = p.parse_args()
    result = json.loads(Path(a.result).read_text()); protocol = json.loads(Path(a.protocol).read_text())
    out = dict(schema='pulse-tripwire-verdict-v1', protocol=a.protocol,
               primary=verdict(result, protocol['primary']['criteria']),
               secondary_descriptive=verdict(result['secondary'], protocol['primary']['criteria']) if 'secondary' in result else None)
    Path(a.output).write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
