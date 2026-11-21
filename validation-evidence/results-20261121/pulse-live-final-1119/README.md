# pulse-live-final-1119 (19/11 02:47 → 21/11 00:06 UTC)

Protocol `sentinel_pulse/protocol/pulse-live-final-v1.json` (45 h). System: token model `t3` alone in the alert path
(top 3 windows, trim 0.5 %, α′ 0.0003; fit `pulse-live-v7-fit-1118`, `/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/token/MODELS.json`),
lineage build on the three workers, count branches (C, tree, support) in shadow. Campaign: 21 workloads × 5 fixtures at
rates 0.1, 0.5, 1, 3, 6, 12, 24 per second, plus on-off 10 s and PAD 300 at 12 per second; per pair a 17 s idle control,
then in a seeded random order an operator command, the harmless binary, the attack fixture, a living-off-the-land (lotl)
step and an event-generator action.

Run health: workers 162,000 s each (exit 0); probe `insert_fail_cumulative` 0 and `dir_fail_cumulative` 0 on all three
workers (`TERMINAL.json` `token_drain`), so no gram-map overflow; issues only `cadence_gap` (6 / 3 / 0). 20.96 million
token windows scored. Analyses on `.234` 21/11 04:50–12:20 UTC, each in `systemd-run` with `MemoryMax`
(`final-h0` 16G, `final-rest` 16G, `final-rca` 6G as root, `final-labels` 8G, `final-rule-intent` 16G, `final-native-h0` 12G).

## Hypotheses

| | Registered | Result | Receipt |
|---|---|---|---|
| H0 | primary set (6, 12, 24/s): recall ≥ 95 %, control ≤ 5 %, precision ≥ 95 %, p95 kernel → end of alarm window ≤ 3 s | **met**: 296/296 [98.7; 100], control 0/296, precision 296/296, p95 0.463 s (p50 0.258 s) | `pulse-live-final.json` (arm T) |
| H3 | PAD 300: recall ≥ 95 % | **met**: 95/95 [96.1; 100], p95 0.448 s | `pulse-live-final.json` (dilution) |
| H7 | slow rates 0.5 and 0.1/s: recall ≥ 95 % each | **met**: 0.5/s 100/100, 0.1/s 99/99 | `pulse-live-final.json` (recall_by_rate) |
| H8 | on-off 10 s: recall ≥ 95 % | **met**: 96/96 [96.2; 100], control 0/96, p95 0.40 s | `pulse-live-final.json` (dilution) |

## Reported (protocol list)

- **All rates (arm T):** attack 694/694, control 0/694, precision 694/694, p95 0.463 s. By rate: 0.1: 99/99, 0.5:
  100/100, 1: 99/99, 3: 100/100, 6: 101/101, 12: 99/99, 24: 96/96. By fixture (all rates) 100 % each (136–142 trials).
- **Model alone on the other steps:** harmless binary 288/288 primary (672/672 all rates); operator commands 254/260
  (585/606); lotl 286/286 (666/666); event generator 238/241 (549/556), per action 0.949 (`RemoveBulkDataFromDisk`
  37/39) to 1.0 over 13 actions.
- **Native stream (pulse-live-v6-v1 H1 method):** on the H0 denominators (`native-stream-h0pairs.json`, option
  `--h0-pairs`: pairs with an attack interval) the native part flags admin 0/606, harmless binary 1/672, idle control
  0/694, attack 0/694, lotl 0/666, event generator 0/556; the whole window flags 585/606, 672/672, 0/694, 694/694,
  666/666, 549/556, exactly the H0 counts. Over every interval of the campaign (`native-stream.json`): admin 0/621,
  harmless binary 1/691. The campaign enters through `kubectl exec`, so its steps are session lineage.
- **Burden on the normal tail after the campaign (9.5 h):** 223 episodes in 616.8 replica-hours = 0.362 per
  replica-hour [0.278; 0.443] (clustered bootstrap). Replica consensus: 217 single-replica, 6 multi-replica; incidents
  (same workload, < 600 s apart) 172 = 434 per day. Attack harm of the consensus label: 5 of 1,371 detected attack and
  lotl trials have a concurrent alarm on another replica (0.36 %). `pulse-live-final.json` (burden), `burden-context.json`.
  Labels (`burden-labels.json`, same 223 episodes): by stream, 176 contain windows with session-lineage events
  (exec-launched processes) as well as native ones, 47 are native only, none is session only; the mixed ones are the
  application services and Redis/Kafka (`search-recommendation-service` 28, `auth-service` 24, `cart-service` 19, ...),
  the native-only ones the operators and stateful sidecars (Kafka topic operator 7, MinIO sidecar 6, RabbitMQ 6,
  waypoint 6, ...). By Kubernetes events (D10: an operational event of the same workload in [start − 300 s, end + 60 s]),
  5 episodes are labelled, all `aims-waypoint` autoscaling (HPA rescale, new pod scheduled and started); the other 218
  have no rollout, scaling, restart or probe-failure event near them. The event recorder's last row is 23:49:30 UTC,
  17 min before the run end (1 episode after it).
- **Scoring latency (window close → score):** token p50 0.169 s, p95 0.232 s, p99 0.327 s over 20,964,760 windows.
- **Attack-specific alarm (part A of live attribution):** primary 296/296, all rates 684/694 (launch-only 7);
  first attack-specific alarm primary p50 0.49 s, p95 0.69 s; all rates p50 0.49 s, p95 0.73 s. Offline rescoring of
  149,709 interval windows matches the live score exactly (largest difference 0.0). `live-attribution.json.gz`.
- **Alert path:** bridge delivered 5,313/5,313 episodes, decision → Alertmanager receipt p50 0.084 s, p95 3.23 s, p99
  4.96 s, no stalled span (`bridge-delivery.json`). Kernel → Alertmanager (push) for the attack trials with a recorded
  start: 749/809 alerted by a push, p50 0.62 s, p95 3.04 s, max 11.0 s; the other 60 matched an alert already open
  from an earlier step of the same trial (56) or an episode without a push time (4). Prometheus scrape fast p50 6.18 s,
  default p50 59.8 s. `alert-delivery.json.gz`. The H0 latency (kernel → end of alarm window) is the primary latency.
- **RCA:** 766 own attack cases; the attack binary is rank 1 in 68.8 %, in the top 5 in 93.2 %; by order after the
  harmless binary 258/377 (68.4 %), before it 269/389 (69.2 %); 24 grouped after another case, 19 after the benign case;
  preview → case p50 2.6 s, p95 8.7 s. `rca-coverage.json`.
- **Rule R1/R2 (with vs without, `rule-e.json`):** with R1, admin false alarms 254/260 → 0/260, but lotl recall
  286/286 → 0/286 (all rates 684/684 → 0/684): R1 downgrades every lotl attack, as on v6; not adopted.
- **Count branches (shadow):** C 127/296 (p95 3.86 s), tree 25/296, support 110/296.

## Rule track (protocol `sentinel_pulse/protocol/rule-intent-v1.json`, registered 21/11 19:01 +07 before any rule flag)

Frozen intent catalogue of exec-intent-v1 (ptrace, setns, unshare, mount, pivot_root, capset, setuid, setgid, seccomp,
execveat, chmod; mprotect only without execve/execveat in the window or the one before), run in parallel with t3 (adds
alerts, never removes one). `rule-intent.json`, code `scripts/analysis/rule_intent.py` (unit `final-rule-intent`, 36 min
CPU). All rates, H0 denominators:

| Interval | ML only | Rule only | ML or rule |
|---|---|---|---|
| Attack (fixture) | 694/694 | 694/694 | 694/694 |
| Lotl | 666/666 | 663/666 | 666/666 |
| Event generator | 549/556 | 555/556 | 555/556 |
| Idle control | 0/694 | 461/694 | 461/694 |
| Admin | 585/606 | 605/606 | 605/606 |
| Harmless binary | 672/672 | 670/672 | 672/672 |
| Burden (episodes per replica-hour, normal tail, 615.6 replica-hours) | 0.362 (223) | 6.395 (3,937) | 6.437 (3,963) |

The rule recovers 6 of the 7 event-generator actions the model missed; it fires almost only on setuid, setgid, capset
and seccomp (normal tail: about 425,000 windows each), which the runtime calls for every exec'd process, including the
kubelet's exec probes in idle containers. Decision: recall gain 6 intervals, but control 66.4 % > 5 % and burden 6.44 >
1.76: **not adopted**. The family variant (fchmod, fchmodat, setres*, ...) gives the same numbers. The ML-only column
reproduces H0 (585/606, 0/694, 223 episodes).

## Side by side with pulse-live-v6-1117 (lidds-ml-v5)

| | v6 (v5 model, rates 1–24) | final (t3, rates 0.1–24) |
|---|---|---|
| Primary recall | 315/315 | 296/296 |
| Primary control | 1/315 | 0/296 |
| Primary precision | 99.68 % | 100 % (296/296) |
| p50 / p95 (kernel → end of alarm window) | 0.25 / 0.45 s | 0.26 / 0.46 s |
| All rates recall | 524/525 | 694/694 |
| PAD 300 | 105/105 | 95/95 |
| Admin flagged (primary) | 275/284 | 254/260 |
| Harmless binary flagged (all rates) | 525/525 | 672/672 |
| Lotl detected (all rates) | 524/525 | 666/666 |
| Event generator | not in v6 | 549/556 |
| Native part: admin / harmless binary | 1/475 / 1/525 | 0/621 / 1/691 |
| Burden (episodes per replica-hour) | 0.078 (51.1 replica-hours) | 0.362 (616.8 replica-hours) |
| Scoring latency p95 | 0.23 s | 0.23 s |
| RCA rank 1 / own cases | 75.9 % / 711 | 68.8 % / 766 |
| Kernel → Alertmanager (push) p95 | 1.53 s | 3.04 s |

The v6 normal tail was short (the campaign covered almost the whole run), so its burden is not a like-for-like
comparison; v5 measured 104 episodes in 630.1 replica-hours (0.165).

## Files

| File | From |
|---|---|
| `pulse-live-final.json` | `scripts/analysis/pulse_live_v4.py` (H0, H3, H7, H8, burden, scoring latency, per-action event generator) |
| `native-stream.json`, `native-stream-h0pairs.json` | `scripts/analysis/native_stream.py` (the second with `--h0-pairs`) |
| `rule-intent.json` | `scripts/analysis/rule_intent.py` |
| `live-attribution.json.gz` | `scripts/analysis/live_attribution.py` |
| `rule-e.json` | `scripts/analysis/rule_e_benefit.py` |
| `burden-context.json` | `scripts/analysis/burden_context.py` |
| `burden-labels.json` | `scripts/analysis/burden_labels.py` |
| `bridge-delivery.json` | `scripts/analysis/bridge_delivery.py` |
| `alert-delivery.json.gz` | `scripts/analysis/alert_delivery_latency.py` |
| `rca-coverage.json` | `scripts/analysis/rca_coverage.py` (root, the cases are root-owned) |
