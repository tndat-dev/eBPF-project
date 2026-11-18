# improvement-round-v1 (registered 19/11 02:30, amendments 02:31 and later): results

Reference: lidds-ml-v5-t3 (top 3, trim 0.5 %, α′ 0.0003). Must-rule (lidds2019-development-v1 amendment 1): LID-DS 2021
development ≥ 529/544 with ≤ 6 false alarms, p95 ≤ 1.60 s, CB-DS ≥ 891 with ≤ 3; 2019 development false alarms ≤ 1 %.

## D13 io_uring (19/11)
`io_uring_setup` from a production pod (seccomp RuntimeDefault): **EPERM**; `/proc/sys/kernel/io_uring_disabled` = 0, so
seccomp blocks it. The io_uring path is closed by the runtime profile, and the probe's seccomp hook sees every attempt.

## D4, D14, D15, D16 (`improvement-offline.json`, `scripts/analysis/improvement_offline.py`, .234 19/11 19:3x UTC)

| Candidate | LID-DS 2021 dev (det / FA, p95) | CB-DS | 2019 dev, 1 s tolerance (det / FA) | Must |
|---|---|---|---|---|
| t3 (reference) | 529 / 5, 1.57 s | 891 / 3 | 310 / 9 | yes |
| D4 top-3 OR top-10 (5 splits) | 530 / 7 | 891 / 3 | 310 / 5–9 | no (7 > 6) |
| D15 Shewhart-CUSUM (4 settings) | 530–531 / 9–46 | 891 / 3–4 | 318 / 8–28 | no |
| D14 Kneser-Ney, top 3 | 530 / 6, 1.56 s | 891 / **0** | 288 / 7 | yes, but fewer 2019 detections |
| D14 Kneser-Ney, top 10 | 491 / 6 | 891 / 0 | 287 / 5 | no |
| D16 GEV pooled shape, censor 1, α′ 0.00018 | 529 / 5 | 891 / 3 | 310 / **3** | yes, better than t3 |
| D16 GEV pooled shape, censor 1, α′ 0.0003 | 529 / 6 | 891 / 3 | 310 / 5 | yes |
| D16 censor 2–3 | 529–530 / 8–15 | 891 / 3–4 | 310 / 3–11 | no |

Pooled GEV shape (top 3, censor 1): −0.02 (2021), +0.01 (2019), close to Gumbel.

**Official check of the passing D16 (`improvement-official2021.json`)**, LID-DS 2021 official, same scores as the amendment-1 run
(t3 reproduces 1,236/1,271 with 15 false alarms):

| | Detected | False-alarm recordings | p95 |
|---|---|---|---|
| t3 | 1,236 / 1,271 | 15 / 7,938 | 1.54 s |
| D16 censor 1, α′ 0.00018 | 1,233 / 1,271 | 15 / 7,938 | 1.54 s |
| D16 censor 1, α′ 0.0003 | 1,236 / 1,271 | 16 / 7,938 | 1.54 s |

The development gain of D16 (fewer 2019 false alarms) does not hold on the official part (three detections fewer, no false
alarm fewer). **Not adopted; t3 stays.** D4, D14, D15 fail their criterion.

## D1 gram-map overflow alert (`map-overflow-d1.json`, `scripts/map_overflow_test.py`, k8s-worker1 19/11)
gram_stress at 400,000 calls/s in one cgroup and a quiet loop in another, loader frames through `MapOverflow`: the first
alert names the stress cgroup, in the frame of the first insert failure (delay 0 s), no alert before it. **Met, adopted**
(worker: `token_alert_reason=gram_map_overflow`, frame flagged `token_incomplete`).

## D2 loader window end, D3 durable bridge queue
D2: `window_end` from `PULSE_TOK_WINDOW_NS`; the final build `pulse-tokens-final-f8ccbb2` passes the token proof on the three
workers (361,900 / 442,796 / 393,644 calls = tokens). D3: failed episode pushes kept on disk, exponential backoff to 30 s,
up to one hour, resumed after a restart; unit test with five refused pushes delivers once. **Both adopted.**

## D5(b) session-stream model (`session-channel.json`)
Learnt on the session parts of pulse-token-capture-v6-1116 (1,068,725 session windows; held-out half 535,351), scored on
the pulse-live-v6-1117 intervals (all rates, base pairs):

| Threshold | Attack | Living off the land | Admin (unseen tools) | Harmless binary | Control |
|---|---|---|---|---|---|
| Gumbel on 60 s blocks (13.30) | 525/525 | 524/525 | 470/475 | 525/525 | 0/525 |
| empirical 99.9 % (9.57) | 525/525 | 524/525 | 470/475 | 525/525 | 3/525 |
| empirical 99.99 % (15.13) | 525/525 | 524/525 | 470/475 | 525/525 | 0/525 |

The session channel flags operator commands and harmless binaries as often as attacks: **criterion not met** (≤ 20 %).
A model of normal exec sessions (health probes) cannot tell a new operator command from an attack.

## D6 small hook set (`overhead-d6-worker1.jsonl`, k8s-worker1, 5 rounds, median ns per operation)

| Operation | Off | Small build | Full build | Small − full |
|---|---|---|---|---|
| getpid | 1,074 | 1,469 | 1,468 | +1 |
| read 4 KB | 1,505 | 1,900 | 1,971 | −71 |
| futex | 1,138 | 1,555 | 1,587 | −32 |
| open + close | 8,072 | 10,158 | 9,973 | +184 |
| mmap + munmap | 7,492 | 8,589 | 8,744 | −156 |

Not lower on every operation: **not adopted** (the 39-syscall probe stays).

## D10, D11 (`burden-context.json`)
pulse-live-v6-1117: 4 normal episodes in 51.1 replica-hours, all single-replica, 4 incidents; 1 of 1,048 detected attack or
living-off-the-land trials has a concurrent alarm on another replica. With no multi-replica episode, replica consensus and
incident grouping remove nothing at this burden: **no benefit, not adopted**. The pulse-live-v5-1110 figures in the file
are not usable (its local decision copies, which held the normal windows, were deleted in the 18/11 cleanup; only alarm
rows remain on NFS), so the 630-replica-hour v5 normal cannot be re-read.

## D9 refit policy
The only aged measurement is model-aging (v5 models on the v6 capture after the cluster change: 0.59 % of blocks above
the threshold against 0.26 % held out). Operating rule: refit after every cluster change and before every live run.

## D12, D18
Campaign options for the final run: fractional rates down to 0.05/s and on-off trials (D12); the Falco event-generator
step with 14 registered actions (D18, binary sha256 6009e345… on NFS `tools/event-generator-0.13.0`).
