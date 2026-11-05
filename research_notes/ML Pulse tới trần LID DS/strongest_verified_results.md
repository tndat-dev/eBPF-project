# Strongest verified learned HIDS results on syscall data, and how they reach low false alarms per recording

Research dates: 2026-11-02 and 2026-11-05. Builds on `research_notes/Cải thiện ML Pulse LID DS/published_ml_results.md`, which is not repeated here beyond single lines.

Markers on every number:
- **[full text]**: read in the paper's own text, table or figure label.
- **[abstract only]**: read only in the abstract.
- **[code]**: read in published source code.
- **[via X]**: reported by paper X, original not read.

Target set from the coordinator, on a learned language model plus an I/O tree at under 1 % false-alarm recordings (not checked by me, sample of about 36 attack recordings per scenario): CVE-2019-5418 5/36, Juice-Shop 15/36, Heartbleed 25/36, CVE-2018-3760 26/37, CVE-2020-13942 29/35.

## 1. What could be read of the earlier gaps, and the exact tables

### Takeaway
Gurbuz 2026 and Inter-PSSG 2026 were read in full and change the picture: they supply the first per-scenario, per-recording tables on LID-DS 2021. Guo 2024, Kim 2025, Ab-HIDS 2024, ICOECA 2026, CSCWD 2026 and Vyugov 2026 stay unread, so nothing below relies on their numbers.

### Cited Findings
Access status:

| Paper | Routes tried | Result |
|---|---|---|
| Gurbuz, McMaster MSc 2026 | MacSphere OAI-PMH record, then the bitstream URL that record lists | **Read in full** (173 pages) — [PDF](https://macsphere.mcmaster.ca/bitstreams/34fd8260-4c25-4202-abbc-91c80c90d0c5/download), [DOI](https://doi.org/10.71548/25675) |
| Kozachok & Vyugov, Inter-PSSG, Bezopasnost IT 2026 | Publisher PDF | **Read in full** — [PDF](https://bit.spels.ru/index.php/bit/article/download/2094/1617) |
| Cross-domain HIDS, Electronics 2022 | MDPI file host | **Read in full**, upgrades the earlier abstract-only entry — [PDF](https://mdpi-res.com/d_attachment/electronics/electronics-11-03631/article_deploy/electronics-11-03631.pdf) |
| Kim et al., IEEE Access 2025 (CC BY) | OpenAlex, Semantic Scholar, Unpaywall, Crossref (arnumber 10848062), IEEE PDF and document URLs, DOAJ | **Not read.** IEEE returned empty bodies; every index points back to IEEE — [DOI](https://doi.org/10.1109/access.2025.3532353) |
| Ab-HIDS, Concurrency and Computation 2024 (marked open access) | Unpaywall, OpenAlex, Wiley PDF and full-text URLs | **Not read.** Wiley returned a Cloudflare page or 403 — [PDF link](https://onlinelibrary.wiley.com/doi/pdfdirect/10.1002/cpe.8249) |
| Guo, DSAI 2024 | OpenAlex and Unpaywall (both closed), ACM PDF | **Not read.** ACM returned a Cloudflare page — [DOI](https://doi.org/10.1145/3677892.3677893) |
| ICOECA 2026, CSCWD 2026 | OpenAlex, Semantic Scholar (both closed) | **Not read.** No open copy — [ICOECA](https://doi.org/10.1109/icoeca68095.2026.11485567), [CSCWD](https://doi.org/10.1109/cscwd68734.2026.11581451) |
| Vyugov 2026 | DOI (404), the publisher URL Crossref lists (returned HTML, not the PDF) | **Not read** — [DOI](https://doi.org/10.21681/3034-4050-2026-2-58-69) |
| Craun et al. | No search hit in this session | **Not read** |

**Gurbuz 2026, Table 7.1 [full text]** — [PDF](https://macsphere.mcmaster.ca/bitstreams/34fd8260-4c25-4202-abbc-91c80c90d0c5/download)

Protocol:
- LID-DS 2021, official splits, all 15 scenarios.
- Detector: STIDE (not ML), n = 5, syscall names only, no thread or argument information, no window aggregation.
- Score: share of the recording's n-grams missing from the benign database.
- Threshold: "the smallest threshold such that at most 1% of validation recordings exceed it", on the benign-only validation split. **No attack data touched tuning.**
- Unit: recording. FPR is a rate over benign recordings.

| Scenario | Precision | Recall | F1 | FPR | TP | FP |
|---|---|---|---|---|---|---|
| PHP_CWE-434 | 0.96 | 1.00 | 0.98 | 0.007 | 118 | 5 |
| CVE-2017-7529 | 0.94 | 1.00 | 0.97 | 0.010 | 119 | 7 |
| **CVE-2018-3760** | 0.97 | **0.98** | 0.97 | **0.005** | 119 | 4 |
| CVE-2012-2122 | 0.91 | 1.00 | 0.95 | 0.016 | 120 | 12 |
| CVE-2020-9484 | 0.87 | 1.00 | 0.93 | 0.024 | 120 | 18 |
| CWE-89-SQL-injection | 0.87 | 0.94 | 0.90 | 0.022 | 113 | 17 |
| Bruteforce_CWE-307 | 1.00 | 0.68 | 0.81 | 0.000 | 95 | 0 |
| EPS_CWE-434 | 0.62 | 0.17 | 0.27 | 0.017 | 21 | 13 |
| **CVE-2019-5418** | 0.39 | **0.17** | 0.23 | **0.041** | 20 | 31 |
| **CVE-2014-0160** | 0.55 | **0.09** | 0.16 | **0.012** | 11 | 9 |
| ZipSlip | 0.20 | 0.01 | 0.02 | 0.005 | 1 | 4 |
| CVE-2017-12635_6 | 1.00 | 1.00 | 1.00 | 0.000 | 119 | 0 |
| CVE-2020-23839 | 0.51 | 0.77 | 0.61 | 0.116 | 92 | 88 |
| **Juice-Shop** | 1.00 | **0.12** | 0.21 | **0.000** | 14 | 0 |
| **CVE-2020-13942** | 0.00 | **0.00** | 0.00 | **0.068** | 0 | 51 |

Cost: "just over ten seconds" per trace at most, 19 ms at least, for detector plus explanation layer combined, and about 2.1 ms per thousand syscalls for STIDE alone [full text; batch figures including reading and parsing].

Conflict: Gurbuz says Grimmer et al. report per-scenario figures with CVE-2020-13942 at DR 0.00. The Dataset Report itself shows only 15-scenario averages (F-score 0.57, DR 0.59, 24.47 false alarms) in its Fig. 2 — [Dataset Report PDF](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf) [full text]. I could not find where that per-scenario 0.00 comes from.

**Kozachok & Vyugov 2026, Tables 6 and 7 [full text]** — [PDF](https://bit.spels.ru/index.php/bit/article/download/2094/1617)

This is the closest thing to a learned, per-recording table on LID-DS 2021 that I found.

Protocol:
- Model: Isolation Forest on 18 Inter-PSSG graph features per 1 s sliding window. Syscall structure only in Table 6.
- Split grouped by recording.
- Two-stage decision: window threshold calibrated on normal recordings to win-FPR 0.01; a recording is anomalous when the **share of windows above that threshold** exceeds a second threshold calibrated to req-FPR 0.01.
- The authors' reason for the second stage: LID-DS 2021 labels every window after the exploit start as attack, while the attack may occupy only a small part of them.
- Table 6 is self-detection: normal traces of a scenario for training, attack traces of the same scenario for checking. The calibration uses normal recordings; I did not find attack data used for thresholds.

| Scenario | Window AUROC | Episode F1 | Realised recording FPR | Estimated recall (mine) |
|---|---|---|---|---|
| CVE-2012-2122 | 0.859 | 0.881 | 0.021 | |
| ZipSlip | 0.770 | 0.325 | 0.003 | |
| **Juice-Shop** | 0.663 | 0.195 | 0.013 | about 0.12 |
| Bruteforce_CWE-307 | 0.625 | 0.900 | 0.012 | |
| CWE-89-SQL-injection | 0.595 | 0.413 | 0.013 | |
| EPS_CWE-434 | 0.581 | 0.665 | 0.018 | |
| PHP_CWE-434 | 0.576 | 0.615 | 0.007 | |
| **CVE-2018-3760** | 0.561 | 0.713 | 0.014 | about 0.60 |
| **CVE-2019-5418** | 0.553 | 0.277 | 0.011 | about 0.17 |

The last column is my derivation, not in the paper: TP = F1·(FP + P)/(2 − F1), assuming about 120 attack and 760 benign test recordings as in their Table 7. Treat it as an estimate.

Table 7, a fixed signature branch (not learned) on the source argument of `open`, `openat`, `openat2`, `creat`: at least three consecutive `../`, the markers `file:` and `://`, the encodings `%2e` and `%00`, or a null byte. A recording is detected if the rule fires in any window:

| Scenario | TP | FP |
|---|---|---|
| ZipSlip | 114/118 (97 %) | 0/760 |
| **CVE-2018-3760** | **122/122 (100 %)** | **0/737** |
| **CVE-2019-5418** | **0/120 (0 %)** | 0/760 |

### Inferences
- The older statement "no per-scenario table exists on LID-DS 2021" is no longer true. "No learned model reports all 15 scenarios per recording" still holds in what I could read: Gurbuz is STIDE, and Kozachok & Vyugov cover 9 of 15. Guo 2024, Kim 2025 and Ab-HIDS could still contradict it.

### Gaps
- Per-scenario figures, thresholds and LID-DS versions of Guo, Kim, Ab-HIDS, ICOECA and CSCWD remain unverified. Their accuracy claims should not be cited as comparable.
- I did not read Araujo & Vieira 2025 beyond its abstract; ScienceDirect returned 403.

## 2. The five scenarios the coordinator named

### Takeaway
On LID-DS 2021, the current model is already above every published low-false-alarm figure I could verify on Juice-Shop, Heartbleed and CVE-2020-13942. It is level on CVE-2019-5418. It is clearly **behind** on CVE-2018-3760, where plain 5-gram novelty (0.98 at 0.5 %) and a path signature (100 % at 0/737) both beat it. Nobody publishes a good low-alarm CVE-2019-5418 result on LID-DS 2021; the 1.00 figures are all on LID-DS 2019.

### Cited Findings
Best low-alarm results found, per scenario:

| Scenario | Current model (coordinator, unverified) | Best on LID-DS 2021 | Best on LID-DS 2019 (different recordings) |
|---|---|---|---|
| CVE-2019-5418 | 5/36 = 14 % | STIDE 0.17 at FPR 0.041 [full text]; Isolation Forest F1 0.277 at FPR 0.011, about 0.17 recall by my estimate [full text]; signature 0/120 [full text] | MLP+TI 1.00 / 0 alarms and AE W2 1.00 / 0 (test-selected among 30,000+ configurations); CHIDS 0.9989; supervised 1D-CNN F2 1.00 |
| Juice-Shop | 15/36 = 42 % | STIDE 0.12 at FPR 0.000; Isolation Forest F1 0.195 at FPR 0.013, about 0.12 by my estimate; window F1 0.1336 (Kozachok, already noted) [full text] | Not in 2019 |
| CVE-2014-0160 Heartbleed | 25/36 = 69 % | STIDE 0.09 at FPR 0.012 [full text]; no other number | STIDE+TI n=9, l=10: 0.95 / 18 alarms; SCG+TI 0.95 / 25; MLP+TI 0.01; AE+TI 0.00; supervised 1D-CNN F2 0.13, 0.85 after embedding transfer |
| CVE-2018-3760 | 26/37 = 70 % | **Signature 122/122 at 0/737; STIDE 0.98 at 0.005** [full text]; Isolation Forest about 0.60 by my estimate | MLP+TI 0.99 / 2; supervised 1D-CNN F2 1.00 |
| CVE-2020-13942 | 29/35 = 83 % | STIDE 0.00 at FPR 0.068; ordering-violation count F1 0.20, from a sweep on test, which the thesis calls an optimistic upper bound [full text] | Not in 2019 |

Sources: [Gurbuz 2026](https://macsphere.mcmaster.ca/bitstreams/34fd8260-4c25-4202-abbc-91c80c90d0c5/download); [Kozachok & Vyugov 2026](https://bit.spels.ru/index.php/bit/article/download/2094/1617); [Kozachok et al. 2026](https://arxiv.org/abs/2606.22581); [EISA 2021, via earlier notes](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf); [CHIDS](https://conand.me/publications/elkhairi-ccsw-2022.pdf); [Cross-domain 2022](https://mdpi-res.com/d_attachment/electronics/electronics-11-03631/article_deploy/electronics-11-03631.pdf).

**Why each is hard, as published**

Gurbuz's explanation, offered by him as "a hypothesis consistent with the results": an exploit changes what the server does, how often it does it, or only the data a call operates on. Name-order models see the first two kinds and miss most of the third — [Gurbuz §10.4](https://macsphere.mcmaster.ca/bitstreams/34fd8260-4c25-4202-abbc-91c80c90d0c5/download) [full text].

- **CVE-2019-5418**
  - The exploit is one request: `curl ... -H "Accept: ../../../../../../../../../../etc/passwd{{"` — [exploit.sh](https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/CVE-2019-5418/exploit/exploit.sh) [code].
  - Normal traffic is a random surfer clicking links — [README](https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/CVE-2019-5418/README.md) [code].
  - Gurbuz: benign test traffic already produces unfamiliar five-grams, so the attack does not stand out, and FPR reaches 4.1 % against a 1 % target [full text].
  - Kozachok & Vyugov: the framework dereferences the path before the kernel call, so the traversal literal is absent at syscall level, and they call this CVE observable neither structurally nor by signature [full text].
  - Their rule only looks for traversal markers. It does not test whether the resolved `/etc/passwd` path appears, which they did not measure.
- **Juice-Shop**
  - Three SQL injection variants share one label: schema dump and credential dump through `/rest/products/search`, and a fake-user login — [README](https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/Juice-Shop/README.md) [code].
  - Gurbuz: each is "a single query that reads, so there is neither a new operation nor a change of volume" [full text].
  - Kozachok & Vyugov note it still scores window AUROC 0.663, above Bruteforce's 0.625 [full text].
- **Heartbleed**
  - Normal users themselves send valid heartbeats, with payloads of 4073 to 16364 bytes — [heartbeat.py](https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/CVE-2014-0160/normal/heartbeat.py) [code]. So the heartbeat path is not novel.
  - The attack is Metasploit's `scanner/ssl/openssl_heartbleed` — [exploit.py](https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/CVE-2014-0160/exploit/exploit.py) [code].
  - CHIDS: the attack "neither produces a high number of syscalls, nor requests abnormal kernel features, and nor maliciously accesses sensitive files", giving "identical encoding" for normal and attack — [CHIDS](https://conand.me/publications/elkhairi-ccsw-2022.pdf) [full text].
  - Cross-domain 2022: Heartbleed and Bruteforce have "exactly the same set of system calls" on LID-DS 2019 (similarity 0.935) [full text].
- **CVE-2018-3760**
  - The exploit first requests `/assets/file:%2f%2f/etc/passwd`, then a doubly encoded traversal path — [exploit.py](https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/CVE-2018-3760/exploit/exploit.py) [code].
  - Kozachok & Vyugov: the literal reaches the syscall argument, yet structural AUROC is only 0.561 [full text].
  - Gurbuz: STIDE flags it, "so the trace contains five-grams absent from training", and where in the recording they occur "was not examined" [full text].
- **CVE-2020-13942**
  - The MVEL payload is `Runtime.exec("touch /tmp/mvel")`; there is also an OGNL variant — [exploit.py](https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/CVE-2020-13942/exploit/exploit.py) [code].
  - Gurbuz: "the benign workload is itself variable". STIDE gets 0 true positives with 51 false positives, and most ordering reversals occur before the attack, so the signal may come from surrounding activity rather than the exploit [full text].

### Inferences
- With about 36 attack recordings per scenario, the coordinator's rates carry roughly ±15 points (my rough binomial estimate), and they come from a different sample than the 120-recording test splits above. Even so, the gaps are large for Heartbleed, CVE-2020-13942 and Juice-Shop, and in the opposite direction for CVE-2018-3760. On CVE-2019-5418 the difference from 0.17 is within noise, and STIDE's 0.17 is at four times the alarm budget.
- **CVE-2018-3760 is the cheapest win.** Two published zero-learning signals beat the language model. Either the model smooths over unseen 5-grams, or its decision rule loses them. Adding an unseen-5-gram share per recording as a branch, and checking whether the file-path branch sees the `%2e`-style or `file:` literal, are direct copies of what worked. A fixed signature conflicts with the owner's rule that rules come last, so the 5-gram share is the admissible one for now.
- **CVE-2019-5418 is probably a data-only attack that needs path or size evidence.** A single request inside a large recording is diluted by any whole-recording ratio. Two cheap checks on the project's own traces, neither of which I ran: does the attack window contain an open of `/etc/passwd` that benign recordings lack; and is the response write size distinctive. If the path is present, a learned path-novelty branch should catch it; if absent, the scenario may be close to unobservable, as Kozachok & Vyugov claim.
- **Heartbleed's thread dependence should be tested on 2021.** On 2019, STIDE goes from 0.00 to 0.95 with thread information; on 2021 the only figure (0.09) has no thread information. So 0.09 may understate what thread-aware n-grams reach. No source tests this.
- Figures on LID-DS 2019 do not transfer. CVE-2019-5418 falls from 1.00 on 2019 to about 0.17 on 2021 across the methods above, though the methods and thresholds also differ.

### Gaps
- No published method reaches high recall at low false alarms on CVE-2019-5418 on LID-DS 2021.
- No published 2021 result exists for Heartbleed or CVE-2020-13942 from a learned model, in what I could read.
- No source localises the signal inside the recording for CVE-2018-3760 or CVE-2019-5418.

## 3. Other 2023–2026 work on LID-DS, container syscalls, and close datasets

### Takeaway
A reproduction study (SoK, JCP 2026) shows the literature's very high figures do not survive trace-level testing at low false-positive rates: on ADFA-LD the best normal-only method reaches 15.78 % TPR at 1 % FPR. Supervised methods look far better but collapse on NGIDS-DS. LLM and Transformer work on syscalls gives no LID-DS numbers.

### Cited Findings
**SoK, J. Cybersecur. Priv. 6(3):99, 2026 [full text, figure labels]** — [PDF](https://mdpi-res.com/d_attachment/jcp/jcp-06-00099/article_deploy/jcp-06-00099.pdf)

18 methods reproduced on the same splits at trace level; hyperparameters by grid search on validation; ADFA-LD 10 runs, NGIDS-DS 5 runs. LID-DS was not tested.

Score methods, ADFA-LD (normal-only training except M7):

| Method | AUC % | TPR at FPR 1 % | FPR at TPR 90 % |
|---|---|---|---|
| M1 TIDE (Hofmeyr), sliding-window mismatch | 87.09 | 5.74 | 22.59 |
| M2 / M3 STIDE and t-STIDE | 82.86 | 3.75 | 31.77 |
| M4 HMM | 47.37 | 2.46 | 97.72 |
| M5 binary-presence similarity with kNN | 84.15 | 11.78 | 35.11 |
| M7 semantic "word and sentence" features + ELM, trained on attacks | 83.81 | 1.71 | 34.19 |
| M9 combination of STIDE, HMM, OC-SVM | 85.49 | 14.02 | 35.04 |
| M10 sequence covering (SC4ID) | 86.90 | **15.78** | 21.26 |
| M11 n-gram frequency statistics + Isolation Forest | 76.79 | 2.20 | 53.15 |
| M14 WaveNet language model, whole-trace NLL | 81.38 | 3.85 | 34.31 |
| M15 three-WaveNet ensemble | 81.14 | 3.90 | 35.48 |

On NGIDS-DS, TPR at 1 % FPR is 0.99–3.04 for all methods that finished.

Prediction methods, ADFA-LD / NGIDS-DS:

| Method | TPR % ADFA | FPR % ADFA | TPR % NGIDS | FPR % NGIDS |
|---|---|---|---|---|
| M12 LSTM on 20-call windows, **any window flags the trace**, supervised | 95.82 | 23.49 | 99.97 | 99.94 |
| M13 TF-IDF 2–4-grams on the first 200 calls + MLP, supervised | 85.52 | 1.88 | 15.32 | 12.68 |
| M16 TF-IDF 5-grams + SVD + MLP, supervised | 79.78 | 1.84 | 0.00 | 0.00 |
| M17 sequence completion + Text-CNN, supervised | 86.62 | 24.84 | 0.00 | 0.00 |

Other SoK statements:
- On any-window: the rule "explains the highest FPR of all the reproduced methods" [full text].
- WaveNet ensembling showed "no significant improvement" over one model, despite the original claim [full text].
- M7's published figures could not be reproduced, even with the authors contacted [full text].
- "No unsupervised method performs as successfully as supervised" [full text].

**Supervised results that touch attack data**

| Paper | Data | Representation and rule | Numbers | Attack data in tuning? |
|---|---|---|---|---|
| [Discover Data 2023](https://link.springer.com/content/pdf/10.1007/s44248-023-00002-y.pdf) | LID-DS 2021: 14,944 benign + 298 attack traces. Only "normal" and "attack" classes kept, so the normal-plus-attack recordings are excluded | Whole-trace mean of W2V or GloVe embeddings, Extra Trees, stratified 5-fold | F1 99.71 %, recall 99.81 %, AUROC 99.9998 % [full text] | Yes, attacks in training. Not comparable: 2 % attacks, wrong recording class |
| [Cross-domain 2022](https://mdpi-res.com/d_attachment/electronics/electronics-11-03631/article_deploy/electronics-11-03631.pdf) | LID-DS 2019, 9 scenarios, about 1:10 attack:benign | 1D-CNN on tokens (n = 1), truncated at the third-quartile length, whole trace | F2 1.00 on six scenarios, 0.97 PHP, 0.80 Bruteforce, 0.13 Heartbleed; 0.85 after transfer [full text] | Yes |
| [CHASE preprint 2026](https://www.researchsquare.com/article/rs-11351546/latest.pdf) | Own container dataset, 22 CVEs | Trace-level features, fixed 0.5 threshold | RF F1 0.9006, SVM 0.9139, LSTM 0.8480; OC-SVM 0.3343, Isolation Forest 0.1408. Leave-one-family-out PR-AUC: Web Injection 0.8204, Path Traversal 0.9563 [full text] | Yes for the first three. Own data, not peer reviewed |

**Normal-only or close to it**

| Paper | Data | Method | Numbers | Tuning |
|---|---|---|---|---|
| [Ring et al., DTRAP 2021](https://par.nsf.gov/servlets/purl/10386265) (older, but it is the source of the rule) | ADFA-LD, PLAID | Language model; whole-trace NLL (TLAD) or **median NLL over an application's traces** (ALAD) | ADFA WaveNet1: AUC 0.830 → 0.993, FPR at TPR = 1 from 0.827 → 0.036. PLAID LSTM0: 0.886 → 0.985, 0.543 → 0.185 [full text] | Metrics are threshold sweeps. SoK could not make the ensemble claim hold |
| [Dual-Head, WiPiEC 2026](https://wipiec.digitalheritage.me/index.php/wipiecjournal/article/download/143/101) | ADFA-LD | CNN next-token NLL, window W = 32 | Pooled AUROC 0.916, F1 0.636 reshuffled; F1 0.403 on the 1 % train split, against Landauer's edit-distance 0.343 [via this paper] [full text] | τ maximises validation F1 |
| [Haic poster 2026](https://haic.fi/wp-content/uploads/2026/05/Explainable-Anomaly-Detection-in-System-Call-Sequences.pdf) | DongTing, ADFA-LD, PLAID | Self-supervised next-token model, per-token NLL | AUC 0.979 DongTing, 0.425 ADFA-LD, 0.878 PLAID (baseline 0.972 / 0.292 / 0.750) [full text, poster only] | Normal only; no FPR |
| [Fournier et al. 2023](https://arxiv.org/pdf/2309.02206) | Own kernel traces, 2 M web requests | LSTM and Transformer language models | F-score and AUROC above 95 % on most novelties [abstract only for the figure]; these are performance novelties, not exploits | Normal only |
| [SBSeg, Transformer with categories](https://sol.sbc.org.br/index.php/sbseg/article/download/36676/36463) | ADFA-LD | Transformer | F1 0.92, 25 FP and 37 FN, 2047 MB RAM; category encoding F1 0.90 at 150 MB [full text] | Supervised classification |
| [U-SCAD 2025](https://mdpi-res.com/d_attachment/futureinternet/futureinternet-17-00218/article_deploy/futureinternet-17-00218.pdf) | Own microservice data | Syscall2vec + reconstruction, POT threshold | F1 +23.88 % and +41.31 % over two baselines [abstract only for the figures] | POT on scores |
| [Araujo & Vieira, C&S 2025](https://doi.org/10.1016/j.cose.2025.104438) | Containerized services; dataset not in abstract | Graph representation, sliding-window post-processing | Detection "by at least 193 %", mean false alarms below 0.4 % [abstract only] | Unknown |
| [PROCATCH, CNS 2025](https://research.utwente.nl/en/publications/fde100ce-9ed4-4949-a405-db911b55ff58) | Ten container attacks | Execution stability, no training | Precision 99.77 %, recall 100 % [abstract only]; targets code execution | None claimed |
| [Feature-Weighted AE, EDM 2026](https://doi.org/10.1109/edm69524.2026.11632153) | Dataset not in abstract | Autoencoder, threshold from MSE and std | MCC 0.926–0.975 [abstract only] | Unknown |

**DongTing, other syscall LLM work**
- [A DongTing eBPF study (Al-Farouk J. 2026)](https://afjs.histr.edu.ly/index.php/afjs/article/download/800/724): supervised Random Forest, 99.60 % accuracy on DongTing, no trace-level FPR found [full text].
- [Phoenix, NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-582-paper.pdf) uses DongTing's normal calls only to measure a syscall filter's false positives (under 0.03 %), not a learned detector [full text].
- [HIDBench 2026](https://arxiv.org/pdf/2605.21773) benchmarks LLMs on DARPA-E3, E5 and NodLink logs; no syscall-trace dataset of this kind [full text].
- [AVITEC 2026](https://ejournals.itda.ac.id/index.php/avitec/article/download/3973/pdf): on ADFA-LD, 3-gram logistic regression with W = 100 (P 0.958, R 0.913, F1 0.935, AUROC 0.980) beats its Transformer, with max-probability window selection, supervised [full text].
- Dual-Head reports [via] He et al. BR-HIDF F1 0.972 and Shamim et al. F1 0.990 on the original ADFA-LD split, and Kim et al.'s finding that the original split's train and validation pools differ in distribution — [Dual-Head](https://wipiec.digitalheritage.me/index.php/wipiecjournal/article/download/143/101).

### Inferences
- A paper-ready statement: at 1 % FPR, 3 of the strongest normal-only families reach only 4–16 % TPR on ADFA-LD in an independent reproduction. By that yardstick, a detector at 42–83 % recall on LID-DS 2021 hard scenarios at under 1 % is unusual, though the datasets differ.
- The language model is not the top performer on ADFA-LD in the SoK: sequence coverage (M10) has four times the TPR at 1 % FPR of WaveNet (M14), both normal-only.

### Gaps
- I found no diffusion, contrastive or graph-kernel syscall result on LID-DS, nor a SysBERT-like model on LID-DS. Searches returned network-flow work. This is absence in what I searched, not proof.
- NGIDS-DS and DongTing trace-level FPR figures exist only in the SoK (NGIDS-DS); DongTing has none at a stated low FPR.
- I did not read the Turkish DongTing paper; the host did not respond.

## 4. Decision rule, thresholds, attack exposure, run-time cost

### Takeaway
The rules with the best false alarms per recording aggregate before deciding: a share of windows, a whole-recording ratio, a median across traces. Any-window rules are competitive only with a maximum-validation threshold and very specific inputs. Quantile calibration on benign validation recordings holds its target in most scenarios but not those with variable workloads.

### Cited Findings

| System | Window-to-recording rule | Threshold | Attack data in tuning | Result | Cost |
|---|---|---|---|---|---|
| EISA 2021 MLP+TI | Any score above threshold after a streaming mean over l (l = 1 best) | Maximum validation score | Configuration chosen on test from 30,000+ | 0.789 / 4.2 alarms, 2019 | Not given |
| Gurbuz STIDE | Whole-recording share of unseen n-grams | Smallest value with ≤ 1 % benign validation above | **None** | FPR ≤ 2.4 % in 12 of 15; 4.1 %, 6.8 %, 11.6 % in the others [full text] | 19 ms to about 10 s per trace with the explanation layer |
| Inter-PSSG Isolation Forest | **Share of windows above a window threshold** | Both thresholds calibrated on normal to 1 % | None found | Realised FPR 0.003–0.021 [full text] | Not read |
| CHIDS | One anomalous sequence flags the trace | γ × max training error; γ swept from 0.2 to 2; "optimal" γ = 1.4 "empirically" | **Likely yes** (my reading): the sweep is reported against detection and FP results, with no attack-free selection described | Recall 0.79–0.9998, 2019 [full text] | Sequence time reported, not extracted |
| Ring ALAD | **Median NLL across an application's traces** | Sweep | Metrics only | FPR at full detection falls by 10× or more on ADFA for most models [full text] | Evaluation time 27–93 s in Table 1 [full text]; needs several traces per application |
| SoK M12 LSTM | Any 20-call window | Classifier | Yes | FPR 23.49 % and 99.94 % [full text] | |
| SoK M13 | First 200 calls only | Classifier | Yes | FPR 1.88 % ADFA; fails on NGIDS [full text] | |
| AVITEC | Maximum-probability window | Validation | Yes | F1 0.935 ADFA [full text] | |
| Dual-Head | Per-window NLL, trace aggregation | Validation max F1 | Yes for τ | F1 0.636 [full text] | |

SoK also warns that a 1 % FPR on one-second units means "one false alarm every 100 s", "unmanageable", which is why per-recording figures flatter a system in continuous operation — [SoK](https://mdpi-res.com/d_attachment/jcp/jcp-06-00099/article_deploy/jcp-06-00099.pdf) [full text].

### Inferences
- A share-of-windows rule is the published answer to LID-DS 2021's labelling, and it is what the project's own diagnosis points at, since the two-window rule cost about 25 recall points (repo commit `fa376b2`). However, a share rule dilutes one-request exploits, so CVE-2019-5418 and Juice-Shop likely need a separate branch with a one-event rule. This combination is my proposal; no source tests it.
- Quantile calibration fails exactly on variable-workload scenarios (CVE-2019-5418, CVE-2020-13942, CVE-2020-23839). A per-scenario FPR above target should be expected and reported, rather than treated as a bug.
- The only strict normal-only low-alarm tables are Gurbuz and Kozachok & Vyugov. Most headline figures elsewhere involve attack data.

### Gaps
- Run-time per-event cost of the learned models above, in streaming mode, is rarely stated. No source gives kernel-to-alert latency on LID-DS.

## 5. Mechanisms that repeat across the best systems

### Takeaway
Four mechanisms recur: thread separation, unseen-item novelty, argument or path evidence, and aggregation over a unit. Longer sequences and larger models do not recur as winners.

### Cited Findings
- **Thread awareness.** STIDE on Heartbleed, 2019: 0.00 without, 0.95 with; MLP mean DR 0.40 → 0.79 with fewer alarms — [EISA 2021](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf) [via earlier notes, full text]. Gurbuz without threads gets 0.09 on 2021 [full text]. Ring's per-application grouping is a related idea at a higher level [full text].
- **Novelty of unseen items.** STIDE's unseen 5-gram share reaches recall ≥ 0.94 on 7 of 15 at 2021 [full text]. CHIDS combines unseen syscalls and unseen arguments [full text]. SoK: coverage methods M1 and M10 lead on AUC and low-FPR TPR among normal-only methods on ADFA-LD [full text].
- **Arguments.** Signature on open-family arguments: 122/122 and 114/118 at zero false alarms [full text]. CDL with frequency vectors only: recall about 0.01 on CVE-2019-5418 — [CHIDS](https://conand.me/publications/elkhairi-ccsw-2022.pdf) [full text]. Gurbuz: name-based models fit "attacks that change behaviour" and not "attacks that change data" [full text].
- **Short sequences.** MLP best at n = 7, l = 1 (EISA); STIDE at n = 5 (Gurbuz, chosen for cost, not competitiveness); LSTM 20 calls (M12), n-grams 2–5 (M13, M16). W = 32 peak on ADFA in Dual-Head [full text].
- **Bigger or ensembled language models do not help.** WaveNet ensemble no gain (SoK); Ring's larger models not consistently better [full text]; a 2 GB Transformer on ADFA gives F1 0.92 against 0.90 at 150 MB (SBSeg) [full text]; AVITEC's 3-gram logistic regression beats its Transformer [full text].

### Inferences
- The strongest evidence points to adding representation rather than capacity: thread-separated n-gram novelty and path or size evidence. These match the blind spots of a language model on calls with an I/O tree only if the tree does not already carry them, which needs a check against the project's own feature list.
- Evidence for thread awareness on LID-DS 2021 specifically is missing. All of it is from 2019.

### Gaps
- No source ablates thread awareness and arguments together on all 15 LID-DS 2021 scenarios.
