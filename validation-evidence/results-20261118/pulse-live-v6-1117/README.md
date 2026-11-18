# pulse-live-v6-1117 (17/11 11:56 → 18/11 13:57)

Protocol `sentinel_pulse/protocol/pulse-live-v6-v1.json` + amendment 1 (26 h, all 735 trials). System: lidds-ml-v5 token
model alone, fresh fit `pulse-live-v6-fit-1117` (21 models), lineage build on the three workers, count branch in shadow.
Campaign: 525 base trials (21 workloads × 5 fixtures × rates 1, 3, 6, 12, 24/s) + 105 at PAD 30 + 105 at PAD 300 (12/s);
per trial a 15 s idle control, then in a seeded random order: a v6 operator command (tools never used before), the
harmless binary, the attack fixture, a living-off-the-land (lotl) step made of image tools.

Run health: 735/735 trials; workers 93,600 s each, token drain `insert_fail_cumulative` 0; issues only `cadence_gap`
(9 / 7 / 1: 17/11 12:35–12:48 and 13:16–13:19, 18/11 02:13, 07:14, 10:35). Analyses on `.234` 18/11 08:45–09:04 UTC,
units `v6-h0`, `v6-h1`, `v6-rule`, `v6-attr` (systemd-run with MemoryMax), RCA and bridge analyses as root (root-owned
cases).

## Hypotheses

| | Registered | Result | Receipt |
|---|---|---|---|
| H0 replication | primary recall ≥ 95 %, control ≤ 5 %, precision ≥ 95 %, p95 ≤ 3 s | **met**: 315/315 [98.8; 100], control 1/315, precision 99.68 % [98.23; 99.94], p95 0.45 s (p50 0.25 s) | `pulse-live-v6.json.gz` (arm T) |
| H1 native stream | native part flags ≤ 5 % of admin and harmless-binary intervals | **met**: admin 1/475 (0.21 %), harmless binary 1/525 (0.19 %); the whole window flags 460/475 and 525/525 | `native-stream.json` |
| H3 dilution | recall ≥ 95 % at PAD 30 and 300 | **met**: 105/105 and 105/105 (attack-specific 105/105 each) | `pulse-live-v6.json.gz` (dilution), `live-attribution.json` |
| H4 lotl / harm of R1 | descriptive | ML only detects 314/315 primary (524/525 all rates); with R1 0/315 (0/525): R1 downgrades every lotl attack | `rule-e.json` |
| H5 unseen admin tools | descriptive | ML only flags 275/284 primary, 460/475 all rates; with R1 0/284, 0/475 | `pulse-live-v6.json.gz`, `rule-e.json` |
| H6 RCA order | descriptive | own case 711/735 (96.7 %); attack binary rank 1 in 75.9 % of cases; by order: after the harmless binary 268/355 (75.5 %), before it 272/356 (76.4 %) | `rca-coverage.json`, `rca-follow-up.json` |

## Other numbers (arm T unless stated)

- All rates: attack 524/525, control 1/525, precision 99.81 %, p95 0.46 s; by rate 1/s 104/105, 3–24/s 105/105 each; by
  fixture seccomp_api_probe 104/105, the others 105/105.
- Native stream (H1 receipt): attack 0/525 and lotl 1/525 on the native part — every campaign attack enters through
  `kubectl exec` and is session lineage, as the protocol's limits said.
- Admin commands (v6 set) flagged by command: find, grep, head, ls_tmp, stat, wc, whoami 100 %; hostname 40/44,
  printenv 48/54, sleep 42/47.
- Attack-specific recall (part A definitions): primary 315/315, all rates 525/525, post-launch (alarm window ending ≥ 1.5 s
  after start) 419/525; launch-only 0. First attack-specific alarm after the interval start: primary p50 0.50 s, p95 0.87 s; all rates p50 0.52 s, p95 1.62 s.
- Burden: 4 episodes in 51.1 replica-hours = 0.078 per replica-hour [0.018; 0.157]. The campaign covered almost the whole
  run (attacks 17/11 13:29 → 18/11 13:10, run end 13:57), so the normal span outside the selection prefix and the
  campaign is short; not comparable with v5 (104 episodes in 630.1 replica-hours).
- Scoring latency (window close → score): p50 0.17 s, p95 0.23 s over 12.1 million windows.
- Alert path: bridge delivered 3,233/3,233 episodes, decision → Alertmanager p50 0.053 s, p95 1.21 s (v5: 0.064 s p95);
  kernel → Alertmanager (push) for 721/735 attack trials p50 0.49 s, p95 1.53 s; Prometheus scrape fast p50 5.54 s,
  default p50 58.7 s (326/735 in time). 460 attack trials matched an episode already open from an earlier step of the same
  trial (random step order), which shortens or lengthens the measured delivery; the H0 latency (kernel → end of alarm
  window) is the primary latency.
- RCA: 24 attacks without own case: 15 grouped after the benign case, 9 after another case; follow-up audit: exec missing
  10, exec known (refused) 15, no decision 5. Exec lag of the attack binary p95 0.14 s.
- Count branches (shadow): C 142/315, tree 37/315, support 113/315, p95 3.84 s.

## Reading

The model replicates on a fresh fit after the cluster change and resists dilution up to 300 padding pairs per operation.
Lineage separation is the first learnt mechanism that removes the false flags on harmless new processes (admin 96.8 % →
0.21 %, harmless binary 100 % → 0.19 % on the native part), but the same split removes the campaign's exec-launched
attacks from the native stream (0/525): which stream an alert comes from has to enter the decision. Rule R1 as defined
removes the admin false alarms and also every living-off-the-land attack (314 → 0), so it is not adopted. RCA rank 1 no
longer depends on the step order; it fell to 75.9 % because each v6 trial has a second attack (see below).

## Exploratory (not registered): why the attack fixture is not rank 1

Ad-hoc read of the 711 attack trials with a matched case (`cases/*.json` against each trial's `EVALUATION_INPUT.json`, the
`rca_coverage.py` matching rule; run as root on `.234`, 18/11): rank of the fixture binary 1: 540, 2: 80, 3: 1, 4: 23,
5: 6, 7: 3, 14: 1, 17: 38, not listed: 19. Of the 170 cases where it is not first, the first suspect is `sh` (84), `cat`
(67) or `rm` (11) in 162 — the processes of the same trial's living-off-the-land step (the v6 admin set has none of these
tools) — and an admin tool (`sleep`, `head`, `hostname`, `stat`: 5), the harmless binary (1), an exec probe
(`pg_isready`, 1) or one binary not in the printed top 12 (1) in the rest. Reasons of those first suspects: started in window
168, novel binary 165, spawned children 85, failed syscall 76. So a process of one of the trial's two attacks is first in
about 702 of 711 own cases (98.7 %); the fixture-only rank 1 (75.9 %) is the registered number.
