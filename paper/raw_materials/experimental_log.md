# Experimental log (PaperOrchestra input `experimental_log.md`)

Every number is copied from a committed receipt under `validation-evidence/` (path given per block) or from the audited
thesis text (`scripts/audit/headline_numbers.py`, 100/100 claims). `PENDING` = not measured yet; never fill by guess.
Development = data seen while designing; blind = LID-DS official split and live runs.

## E1. LID-DS 2021 official (blind) — `results-20261110/lidds-ml-v5/lidds-ml-v5-official.json`

Pre-registered levels (protocol lidds-ml-v5): development >= 530/544 with <= 12 false alarms and p95 <= 1.52 s; CB-DS
891/891 with <= 3; official >= 1,238/1,271 with <= 36 and p95 <= 1.5 s. All met.

| Metric | Target | Result [95 % CI] |
|---|---|---|
| Recall | >= 95 % | 97.40 % (1,238/1,271) [96.38; 98.15] |
| Normal recordings with a false alarm | reported | 0.33 % (26/7,938) [0.22; 0.48] |
| Precision at the dataset's base rate | >= 95 % | 97.9 % |
| Latency p50 / p95 (from first exploit timestamp) | p95 <= 3 s | 0.39 s / 1.47 s |
| Detected within 3 s | reported | 1,234/1,271 (97.1 %) |

Per scenario (detected, false alarms/normal): Bruteforce_CWE-307 97/97, 0/538; CVE-2012-2122 84/84, 0/533;
CVE-2014-0160 84/84, 1/531; CVE-2017-12635_6 83/83, 2/527; CVE-2017-7529 83/83, 0/510; CVE-2018-3760 85/85, 2/516;
CVE-2019-5418 84/84, 8/532; CVE-2020-13942 83/83, 0/529; CVE-2020-23839 84/84, 3/532; CVE-2020-9484 84/84, 0/531;
CWE-89-SQL-injection 84/84, 2/532; EPS_CWE-434 85/85, 1/531; Juice-Shop 52/85 (61.2 %), 3/532; PHP_CWE-434 83/83, 2/532;
ZipSlip 83/83, 2/532. 14/15 scenarios at 100 %.
- All misses are Juice-Shop; 28 of its 33 misses show no trace in any signal tried (new path, new error code, size,
  unseen sequence): information ceiling of those signals 1,243/1,271 (97.8 %). Missed type: login request with a
  modified SQL string, body 444 vs 55 bytes, same endpoint, no new process/path/error/size; traces keep only ~80 bytes of
  buffers.
- Base rate: same recall and false-alarm rate give precision 75.0 % at 1 % attacks and 22.9 % at 0.1 % (Arp et al. 2022).
- Published comparison: dataset authors' STIDE (7-syscall sequences, 100-syscall window, threshold = max validation
  score), mean per-scenario detection rate 0.59 (Grimmer et al. 2022); ours computed the same way 0.97. Their false
  alarms are counted per alarm cluster, so only detection rates compare.
- Limitation: official not fully unseen (alphabet designed after seeing other signals' results on the same recordings);
  ~60 validation recordings per scenario, so false alarms only verifiable pooled.

Development: 530/544 (97.43 %), 6/3,403 false alarms (0.18 %), p95 1.52 s. CB-DS: 891/891, 3/1,410 (0.21 %).
Old counting model (per-window syscall count vector, ExtraTrees + support) on all LID-DS 2021 test: 1,154/1,815
(63.6 %), p95 4.13 s; misses concentrate on in-process exploits (Heartbleed 113/120 missed, ZipSlip 114/118,
CVE-2018-3760 117/122, Juice-Shop 116/121, CVE-2019-5418 100/120). On official with the same threshold and one-window
rule: counting 662/1,271 (52.1 %), p95 13.15 s; token model 1,238/1,271, p95 1.47 s; counting next to token adds no
detection, false alarms 26 -> 36.

## E2. Design study (development + CB-DS only) — `results-20261112/token-design-study/`

Cache path reproduced stored scores on all 16 scenarios (max diff 2.8e-14) and 530/544, 6; CB-DS 891/891, 3.

Alphabets (alpha = 0.002, pre-cross-fit comparison; detected /544, false-alarm rate, p95):
select1f 530 (97.43 %), 0.56 %, 1.45 s | probe1f (probe emission order) 530, 0.56 %, 1.49 s | full 527, 0.59 %, 1.52 s |
no errno 528, 0.50 %, 1.53 s | no open mode/dir 523, 0.56 %, 1.51 s | requested size at entry 502, 0.38 %, 2.29 s |
no size 490, 0.56 %, 2.58 s | open info only 487, 0.47 %, 2.54 s | syscall name only 487 (89.52 %), 0.56 %, 2.59 s.

Leave-one-syscall-out among the 39 hooked (base 530, 6 FA, p95 1.52 s); 8 never appear; 24 change nothing; 7 change:
write 490 (-40; CVE-2019-5418 -36, ZipSlip -4; p95 2.22 s) | open 526 (-4) | read 528 (-2), 7 FA, p95 2.23 s | pread 529 |
recv/recvfrom 530, 9 FA | send/sendto 530, 7 FA | stat 530, 7 FA.
Backward elimination (36 scorings): 5 syscalls remain (open, read, recv+recvfrom, stat, write), identical per scenario
to all 39 (530, 6, 1.52 s; CB-DS 891, 3). Declared reuse on official: full 39 reproduced 1,238/26/1.47 s; the 5-syscall
set 1,238/1,271 with 17/7,938 FA (0.21 %), p95 1.46 s (CVE-2019-5418 8 -> 0). Adding 13 candidate syscall details: no
gain.

Parameters (detected/544 / FA/3,403; current bold): gram 2: 458/3, 3: 530/8, **4: 530/6**, 5: 526/6, 6: 493/6 | top-k 1:
123/7, 3: 528/5, 5: 529/7, **10: 530/6**, 20: 492/7 | alpha' 0.01: 531/51, 0.003: 530/25, 0.001: 530/15, 0.0005: 530/10,
**0.00018: 530/6**, 0.0001: 527/6, 0.00005: 525/6 | folds 3: 530/7, **5: 530/6**, 10: 530/7 | trim 0: 523/4, 0.5 %:
524/6, **1 %: 530/6**, 2 %: 530/9, 5 %: 530/15.

Gumbel check: Anderson-Darling rejects Gumbel for held-out maxima in 15/15 scenarios (Holm); GEV shape xi from -0.28 to
+0.77. At alpha' = 0.01 expected 34 normal exceedances, saw 51 (1.5x); at 0.00018 expected 0.6, saw 6 (9.8x).
Max detections per normal-only threshold rule within a false-alarm budget (<= 6 / <= 12 / <= 20 normal recordings):
moment Gumbel trimmed 1 % 530/530/530 | moment Gumbel all maxima 525/530/530 | normal 525/530/530 | MLE Gumbel
495/530/530 | MLE GEV none/459/496 | largest held-out maximum (conformal) none/none/497.

Model vs unseen-4-gram count rule (same tokens, cross-fit, threshold rule, one-window decision), detected at FA budget
<= 3 / 6 / 12 / 20 / 34: model 472/530/530/530/531, rule none/444/488/497/526. At budget 6 the model detects 86 more
(paired bootstrap 95 % CI [80; 93]). 53.4 % of normal recordings contain at least one unseen 4-gram.
Seen-only attacker simulation (drop every event with an unseen gram or token from each attack recording): model 0/544
(before: 530); rule 0 by definition. Semi-synthetic lower bound.

Rate branch (`results-20261115/w3b-rate-signal/`; score = max over seen grams of log((n_g+1)/(m_g+1))), development
detected/FA and CB-DS: token only 530/6, 891/3 | rate only 225/7, 891/3 | token or rate (shared alpha') 530/12, 891/4 |
split alpha' 0.9/0.1 530/7, 891/4. Adds no detection, only false alarms: not joined.

## E3. Live runs on the cluster (blind) — `results-20261110/pulse-live-v4-1109/`, `results-20261112/pulse-live-v5-1110/`

Two 24 h blind runs, all 21 workloads, 525 trials each; thresholds fitted before each run, fixed during it.
Run 1109: model from 12 h normal-only capture. Run v5-1110: also learnt the previous run's normal outside trials; adds an
operator command per trial; alerts through Alertmanager and RCA.

| Metric (primary set 6/12/24 per s) | Target | Run 1109 | Run v5-1110 |
|---|---|---|---|
| Recall | >= 95 % | 315/315 [98.8; 100.0] | 314/314 [98.8; 100.0] |
| Precision (1:1) | >= 95 % | 99.06 % [97.26; 99.68] | 100 % [98.79; 100.00] |
| Control positives | <= 5 % | 3/315 (0.95 %) [0.32; 2.76] | 0/314 [0.00; 1.21] |
| p95 kernel -> end of alarm window | <= 3 s, prefer < 2 s | 0.49 s (p50 0.34) | 0.49 s (p50 0.35) |
| Harmless binary flagged | reported | 313/315 | 314/314 |
| Operator command flagged | reported | n/a | 255/261 (all rates 419/436 = 96.1 %) |
| Burden (episodes/replica-hour) | as low as possible | 0.41 [0.15; 0.73] | 0.17 [0.06; 0.33] |

- All rates: 525/525 and 521/522 (one mprotect trial at 1/s missed); control 5/525 and 0/522.
- Scoring adds p50 0.15 s, p95 0.18 s per window. Burden 332 episodes / 817.1 replica-hours -> 104 / 630.1; in run 1109
  146/146 normal alarm windows in a 5-segment sample contained an unseen 4-gram, 89/118 episodes from one Kafka workload.
- Held-out 60 s blocks above threshold: 145/48,531 (0.299 %, 16.6x design 0.018 %); with more normal 350/134,905 (0.259 %).
- v5 run: virtualisation host stall 3.5 min (112 cadence issues, all issues of the run); excluding the 2 trial pairs
  inside it: 313/313, 0/313, burden 0.17.
- v5 protocol's acceptance on harmless binary and operator commands (<= 20 % each): not met.

Attribution of live recall (`results-20261113/ml-final-study/live-attribution.json`): attack-specific (grams of the same
trial's benign and admin intervals removed) 314/314 primary, 521/522 all; post-launch (alarm window ending >= 1.5 s after
start) 302/314; detected only through launch grams 0. Attack-specific first alarm p50 0.61 s, p95 0.73 s. Post-launch by
rate: 1/s 32/103, 3/s 80/105, 6/s 96/104, 12/s 103/105, 24/s 103/105.

## E4. Benign new processes (blind live data, ml-final-study-v1) — `results-20261113/ml-final-study/`

Why flagged (run 1109 sample: 136 control-binary launches, 134 flagged): launch burst (first alarm median 0.44 s;
top surprising tokens mprotect, prlimit64, arch_prctl, brk, seccomp, keyctl, setgid, setuid; 61/134 flagged only in the
first second) and the binary's own loop (1,321/1,323 later alarm windows contain clock_nanosleep, 1,309 getpid; 73/134).
Gate before the model (lidds-ml-v5 pre-registered): pool model drops development to 487-509/544; skipping 1-2 s after
execve drops development to 315-365/544 and CB-DS to 549-576/891: rejected.
B (learn all other operator commands): held-out command still flagged 362/439 (82.5 %) vs 422/439 (96.1 %); with all
commands learnt recall primary 314 -> 303/314, attack-specific 299/314, harmless binary 285/314. Not met.
B2 (other folds' admin sessions learnt): 372/439 (84.7 %). Not met.
B3 (lineage proxy: session = grams unseen by the workload model): native part flags control 0/525, admin 0/439, harmless
binary 0/523 (attack 1/522); session model thresholds 37.7 (tools) and 42.4 (tools + harmless binary), above every
measured score: detects 0/522 attacks. Exploratory: AUC attack vs harmless binary 1.00, attack vs admin 0.73.
Threshold rule on the cluster (part C): empirical quantile at alpha' instead of Gumbel halves burden (0.053 vs 0.105) but
detects 281/314 primary attacks and on LID-DS development 498/544 with 13 FA: rejected.

Lineage tag proof (`results-20261113/lineage-probe/`): all 8 checks valid on a test pod entered with `crictl exec`
(own loop native; exec and children session; backgrounded child outliving the session stays session); token proof still
one token per syscall (411,052 events = 411,052 syscalls). Proofs valid on all three workers with the run build (16/11).

Rule layer after the model (`results-20261115/rule-e-benefit/`), run v5 campaign, primary: recall 314/314 model only and
model + rule; operator commands (image tools) flagged 256/262 (97.7 %) -> 0/262; non-image harmless exec 314/314 kept
(labelled drift). All rates: recall 521/522 both; admin 422/439 -> 0/439; pooled false alarms over benign classes
942/1,487 -> 520/1,487. Harm side (living-off-the-land attacks with image tools), E7 H4: 314/315 -> 0/315 primary (524/525 -> 0/525); R1 not adopted.

## E5. Overhead — `results-20261107/token-probe-overhead/overhead-run3.json`, `results-20261116/lineage-overhead/`

Microbenchmark, three workers at once, 5 rounds, rotated conditions; range across workers:
| Op | No probe (ns) | Watched container: added ns | Added % | Unwatched container: added ns |
|---|---|---|---|---|
| getpid | 1,070-1,121 | 407-447 | 34-39 | 212-273 |
| read 4 KB | 1,534-1,564 | 453-514 | 32-34 | 214-312 |
| futex | 1,155-1,181 | 470-535 | 36-44 | 194-259 |
| open + close | 8,541-8,861 | 1,774-2,077 | 22-24 | 727-1,044 |
| mmap + munmap | 7,873-7,974 | 1,217-1,548 | 15-21 | 528-737 |
Worker CPU (loader + Python worker, incl. shadow count model): 7 h 05 min to 7 h 28 min CPU per 24 h, 0.30-0.31 core on
24-core nodes. Lineage tag vs the v5 build: in 12 cells (3 workers x getpid/futex/openclose/forkwait) every paired-ratio
95 % CI contains 0 except one negative (futex worker1 -2.4 %); fork + exit + wait 332-385 us.
Gram map capacity (`results-20261116/map-capacity/RESULTS.json`, worst case: every syscall a new gram, one cgroup):
calls/s, distinct grams per window (p50), failed inserts, drain p50: 50,000 25,202 0 0.06 s | 100,000 49,682 0 0.11 s |
200,000 97,168 0 0.22 s | 300,000 142,610 0 0.33 s (max 0.41) | 400,000 148,695 949,878 0.44 s (max 0.63) |
600,000 192,047 3,181,096 0.63 s | 800,000 258,401 4,888,620 0.64 s | 1,200,000 253,690 8,353,645 0.66 s. Heaviest node
window of run v5: 6,901 distinct grams (`ml-final-study/token-load.json`): about 20x headroom. Not measured: per-request
cost on a real application.

## E6. Alert path and RCA (run v5) — `results-20261112/pulse-live-v5-1110/`

Kernel event -> Alertmanager: push bridge 521/522, p50 0.51 s, p95 0.68 s (per rate p95 0.65-0.69 s); Prometheus scrape
in parallel: fast interval p50 5.29 s; default interval p50 60.3 s, in time for only 143/522. Outside the stall all
2,075/2,075 alert episodes reached Alertmanager (decision -> received p50 0.034 s, p95 0.064 s); during the 3.5-min stall
113/190 lost (3 retries, no durable queue).
RCA: own case 467/522 (89.5 %); attack binary rank 1 in 464/467 (99.4 %); alert -> case p50 2.33 s, p95 2.61 s; attack
exec event delay p95 0.10 s, max 0.38 s. 55 without own case: 40 re-runs merged by design, 14 a race (alarm on the launch
burst ~0.2 s after start, before the attack binary's exec; RCA considered execs only up to window end), 1 no decision.
Rank 1 is helped by the campaign order (attack always after the benign binary). Fix (consider execs up to the decision,
recheck after 2 s) measured live in E7: 711/735 own case (96.7 %).

## E7. Model aging and the latest live run (pulse-live-v6-v1 with amendment 1)

Model aging (`results-20261117/model-aging/`): v5 models and thresholds, unchanged, on the 12 h normal capture made after
the 12/11 VM resize and cluster recovery: 278/47,082 container blocks above threshold (0.59 %, Wilson 0.53-0.66 %) vs
350/134,905 (0.26 %, 0.23-0.29 %) on v5's own held-out blocks: about 2.3x. Excess in a few workloads (Redis 83/2,178 =
3.81 % vs 0.26 %, then api-gateway, Kafka, inventory); some lower (MinIO, order, security-telemetry). Refit used for v6.

Run pulse-live-v6-1117 (17/11 11:56 -> about 18/11 13:55; 735 trials = 525 base + 105 PAD 30 + 105 PAD 300; operator
command set never used before; seeded random step order; living-off-the-land step; lineage build; fresh fit
`pulse-live-v6-fit-1117`: 21 models, cross-fit over the v5 normal and the new 12 h capture):
- H0 replication: met. 315/315 [98.8, 100], control 1/315, precision 99.68 % [98.23, 99.94], p95 0.45 s (p50 0.25 s); all rates 524/525, control 1/525
- H1 native stream: met. admin 1/475, harmless 1/525, control 1/525 (whole window 460/475, 525/525); fixture attacks 0/525, lotl 1/525 on the native part
- H3 dilution: met. PAD 30 105/105, PAD 300 105/105
- H4 lotl: ML only 314/315 primary (524/525 all); with R1 0/315 (0/525); R1 not adopted
- H5 unseen operator tools: ML only 275/284 primary (460/475 all); with R1 0/284 (0/475)
- H6: own case 711/735; fixture rank 1 268/355 (75.5 %) after harmless, 272/356 (76.4 %) before; exploratory: lotl process first in 162/170 non-top-1 cases
- Burden: 4 episodes / 51.1 replica-hours = 0.078 [0.018, 0.157], not comparable (campaign covered almost the run). Bridge 3,233/3,233, decision -> Alertmanager p95 1.21 s, kernel -> Alertmanager p95 1.53 s (721/735)

## E8. LID-DS 2019 (once, lidds2019-confirmation-v2; reported with the 1 s label tolerance of amendment 1, set after the scoring)

Source: validation-evidence/results-20261118/lidds2019-confirmation/tolerance.json. 1,056/1,162 detected (90.88 % [89.08, 92.40]),
34/7,706 false-alarm recordings (0.44 % [0.32, 0.62]), p95 10.55 s (p50 1.10 s); C1 not met (recall, latency). Same rule on
LID-DS 2021 official: 1,238/1,271 unchanged. Per scenario: Bruteforce 92/98 (p95 14.37 s), CVE-2012-2122 152/155, CVE-2014-0160
24/100 (76 without alarm, p95 11.19 s), CVE-2017-7529 157/174, CVE-2018-3760 133/137, CVE-2019-5418 98/98, EPS 99/99, PHP
103/103 (p95 5.56 s), SQL 100/100 (p95 4.67 s), ZipSlip 98/98. Development study (lidds2019-development-v1, 30 % part, after the
scoring): 23 single changes + 90 combinations + rate branch, none keeps LID-DS 2021 development while raising recall; novelty
latency lower bound p95 9.39 s (validation-evidence/results-20261118/lidds2019-development/).
