# burst-round-v1 (27-28/11): sale-day capture and refit

Protocol: `sentinel_pulse/protocol/burst-round-v1.json`, registered 27/11 19:39 (+07), before the capture.

Owner decision 27/11: "Thử thêm vòng burst".

## Capture

`pulse-token-capture-sale-1127` was recorded from 27/11 19:41 to 28/11 03:41 (+07).

| Item | Value |
|---|---|
| Duration per worker | 28,800 s, three workers, state `completed_capture` |
| Snapshot | `runtime-6cd1233-20261127` |
| Probe | `pulse-tokens-prog-bee57bf` |
| Traffic profile | `TRAFFIC_PROFILE=sale`, seed 83458 |
| Phases | 61, every one applied with return code 0 |
| Burst | 12 spans, 2.59 h |
| Other regimes | peak 2.57 h, steady 1.90 h, recovery 0.95 h |
| Issues | `cadence_gap` only: worker1 8, worker3 44, worker4 0 (capture 1124: 27/63/21) |
| Kubernetes events | 5,997 |

`capture-CONFIG.json` holds the capture configuration.

## Fit

Fit directory: `/mnt/sentinel-pulse-archive/pulse-live-burst-fit-1128` on NFS (via .234). It was run by `scripts/burst_fit_chain_1128.sh` (unit `burst-fit-chain-1128`); `chain.log` holds its log.

- **Learning data.** The three-day fit's data plus the sale capture as one more extra run. The parameters are the same as the three-day fit.
- **t3.** Pooled held-out exceedance over all blocks is 2,378/354,257 (0.671 %).
  - `token-MODELS.json` sha256 `d6d1aef4...`.
- **A6.** 9 of 21 workloads get a factor below 1; the lowest is rabbitmq at 0.712.
- **Pooled session model.** Threshold 13.109 (it was 13.103).
- **Alert-path configuration.** `SESSION-S1a-A6.json`, sha256 `bed55930...`.

## Metric

The metric is `burst_round.py`: held-out blocks of capture 1124 only, A6 thresholds, Wilson 95 % intervals (`burst-round.json`, baseline `burst-baseline.json`).

| regime | three-day fit (1126) | with sale capture |
|---|---|---|
| burst | 2.44 % (67/2,747; 1.93-3.09) | **1.71 %** (47/2,747; 1.29-2.27) |
| peak | 1.07 % | 0.95 % |
| steady | 0.72 % | 0.64 % |
| toolmix | 0.56 % | 0.52 % |
| recovery | 0.44 % | 0.44 % |
| night | 0.43 % | 0.41 % |
| pooled | 0.698 % | **0.631 %** (0.60-0.67) |
| burst / pooled | 3.49 | **2.71** |

Every metric rule is met:
- burst is at most 3 × pooled, and below 2.44 %;
- no other regime rose by more than 0.1 point;
- pooled is not above 0.698 %.

## Attacks on pulse-live-final-1119 intervals

The intervals are the H0 denominators; the system is S1a + A6. Files: `attacks-1119.json` (fit with the sale capture) and `attacks-1119-fit1126.json` (three-day fit, scored for attribution).

| set | fit 1123 (one day) | fit 1126 (three days) | fit with sale capture |
|---|---|---|---|
| primary attacks | 296/296 | 296/296 | 296/296 |
| PAD 300, on-off, 0.1 and 0.5 per s | 100 % | 100 % | 100 % |
| living off the land | 666/666 | **634/666 (95.2 %)** | **634/666 (95.2 %)** |
| event generator | 549/556 | 549/556 | 549/556 |
| harmless binaries | 672/672 | 672/672 | 672/672 |
| operator commands flagged | 594/606 | 428/606 | 465/606 |
| idle control | 0/694 | 0/694 | 0/694 |
| p95 kernel → end of alarm window | 0.49 s | 0.49 s | 0.49 s |

The attack rule holds: every family is at least 95 %, and living off the land is at 95.2 %.

The fall in living off the land comes with the three-day fit, not with the sale capture: fits 1126 and sale give the same 634/666.

The three-day data learn the routine operator commands of capture 1124 (sh, sleep, find, grep, stat, wc) as normal. The living-off-the-land step is an `sh` loop of `cat`, `ls` and `sleep`. Learning operator activity therefore lowers both the operator commands flagged (594 → 428) and the living-off-the-land recall (666 → 634). This trade-off is reported as a finding.

## Decision

Every must is met, so the final live run uses `pulse-live-burst-fit-1128`. Datasets are not rescored, because the change is cluster learning data only; the t3 gate of 27/11 holds.
