| Arm | Recall | Recall, all rates | Control | Benign launch | Precision | p95 (s) | Episodes/replica-hour | Δ episodes [CI] | Δ p95 (s) [CI] |
|---|---|---|---|---|---|---|---|---|---|
| A — ML only | 98.7% | 94.5% | 1.3% | 85.7% | 98.7% | 2.91 | 1.42 | — | — |
| B1 — ML + Falco | 98.7% | 95.2% | 2.9% | 86.0% | 97.2% | 2.48 | 2.54 | 1.120 [0.000; 3.252] | [-1.35; -0.01] |
| B2 — ML + tripwire | 98.7% | 96.6% | 1.6% | 85.7% | 98.4% | 2.44 | 1.48 | 0.066 [0.020; 0.133] | [-1.62; -0.04] |
| B3 — ML, then probe triage | 98.7% | 94.5% | 1.3% | 85.7% | 98.7% | 5.90 | 1.09 | -0.330 [-0.751; -0.092] | [2.27; 3.60] |
| B_all — all | 98.7% | 96.6% | 3.2% | 86.0% | 96.9% | 4.82 | 2.28 | 0.860 [-0.409; 3.018] | [0.84; 2.39] |

`pulse-peer-discount-confirm`, registered subset (6, 12, 24 per second; 524 attack trials at all rates). Normal: campaign end to capture end, 706.8 replica-hours, the same for every arm. Delay = the arm's first alert − kernel_event_at (B3: RCA case creation). Δ against A: workload-clustered bootstrap, 10,000 draws; Δ p95: trial bootstrap. Protocol rule-integration-v1 + amendments 1, 2.
