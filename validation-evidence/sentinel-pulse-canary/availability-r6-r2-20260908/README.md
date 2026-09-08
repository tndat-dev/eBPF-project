# Sentinel Pulse availability canary R6-r2

This directory indexes the terminal result of the prospective normal-only
canary `sentinel-pulse-availability-r6-r2-20260908T033340Z`. Full raw evidence
remains immutable on the control plane at:

`/home/dat/sentinel-pulse-evidence/canary-availability/sentinel-pulse-availability-r6-r2-20260908T033340Z`

## Frozen identity

- source commit: `105e4527e427e77a7c1ec330a811d00f4a3e5c0b`
- model manifest SHA-256: `2e37ffd1ef4476b09e123315b467e47814613b9ff22dfd0b4e28fbb375952a81`
- decision policy SHA-256: `711e66a920be6e6d532c665afe6b2ae02e2afac00a73d0f7fbab1672e6b631da`
- nominal snapshot interval: 0.5 seconds
- minimum telemetry availability: 0.999
- maximum single gap: 10 seconds
- requested duration: 7,200 seconds
- evidence class: `nonformal_live_normal_canary`
- automatic promotion: false

## Terminal result

- aggregate valid: true
- minimum observed node duration: 7,201.874613 seconds
- decisions/scored/alerts: 517,459 / 512,694 / 0
- statuses: 510,297 normal; 2,397 suppressed; 4,765 warming
- workload coverage: 20/20; no missing or unexpected keys
- inference p50/p95/p99/max: 16.822 / 24.504 / 29.778 / 2,517.857 ms
- post-window processing p50/p95/p99/max: 0.161 / 0.302 / 0.353 / 2.852 s
- window-start-to-decision p50/p95/p99/max: 0.665 / 0.806 / 0.858 / 3.356 s

| Node | Observed snapshots | Estimated missing | Availability | Maximum gap | Hard-integrity errors |
|---|---:|---:|---:|---:|---:|
| k8s-worker1.local | 14,304 | 0 | 1.000000 | 0.607576 s | 0 |
| k8s-worker3.local | 14,295 | 5 | 0.999650 | 2.852798 s | 0 |
| k8s-worker4.local | 14,262 | 4 | 0.999720 | 2.574224 s | 0 |

Decision replay at the two delayed loader snapshots confirms that affected
workload sources entered `warming` with `warming_reason=temporal_gap`. The
detector therefore did not join temporal evidence across missing telemetry.
Counts of all temporal-gap warmups must not be interpreted as node-pause counts:
sparse workload activity and container identity transitions can also reset a
per-source history.

## Integrity

- `AGGREGATE.json` SHA-256:
  `e73375762b69cff016ce071626e2a250fe6dc895165a7724c318781aaed741f8`
- `FINAL_SHA256SUMS` SHA-256:
  `18cb3a2de90e388ea51e882a216d830b2789f0b709ba627f03a54af5ac7a7373`
- both start and final checksum indexes were verified entry-by-entry on the
  control plane after terminal finalization.

## Claim boundary

This result validates the prospectively registered telemetry-availability
contract and supports a p99 normal-path latency below two seconds. It does not
estimate formal FPR or recall, does not measure true blind-attack
kernel-to-alert latency, does not establish a two-second maximum, and does not
authorize automatic or manual production promotion. The next admissible step
is a new 24-hour formal normal soak under the same frozen contract.
