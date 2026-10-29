# Novelty is not maliciousness: learning, evaluation and public syscall datasets (for Sentinel Pulse)

Scope note (as of 2026-10-30): sources were read in full text where marked "(full text read)". Other entries rest on abstracts, official pages or search snippets, and are marked that way. Pulse numbers (99.4 %/99.4 %, 86-95 % benign-binary flag rate, LID-DS 2021 77.3 % at 3.0 %) come from the project context in the assignment. They appear only under Inferences, never as cited facts.

## Q1. Methods that make an anomaly detector learn or use the difference between benign novelty and malicious behaviour

### Takeaway
The literature agrees that a detector trained only on normal data is a novelty detector. Telling benign novelty from attack needs a second mechanism: analyst feedback or allowlisting, a prevalence or "seen elsewhere" prior, a few labelled attacks, or a reject option. The best measured false-alarm reductions come from host provenance and log data (NoDoze: 86 % fewer false alarms; AI2: 5x fewer false positives), not from syscall-count detectors. I found no syscall-level study that reports an FPR reduction for benign new binaries, so Pulse would be producing that evidence itself.

### Cited Findings
**The framing (novelty is not anomaly)**
- Fournier et al. (2023) define "a novelty is any deviation from previously observed behaviors. Novelties include anomalies since they are typically unknown and unexpected, but not all novelties are anomalies. For instance, new users and rare queries are novel yet normal behaviors." They say "learning a 'normal' behavior ... and identifying any deviations ... as abnormal" methods "would be better framed as novelty detection methods as an additional mechanism would be necessary to determine whether the novel behaviors are normal or abnormal" (full text read) — [Fournier et al., arXiv 2309.02206](https://arxiv.org/pdf/2309.02206)
- Sommer & Paxson (IEEE S&P 2010, classic) say anomaly detectors "are not targeting to identify malicious behavior but just report what has not been seen before, whether benign or not. We argue however that one cannot stop at that point." They also write: "machine-learning algorithms excel much better at finding similarities than at identifying activity that does not belong there" (full text read) — [Sommer & Paxson 2010](https://www.icir.org/robin/papers/oakland10-ml.pdf)
- Sommer & Paxson add: "by definition, a machine learning algorithm does not make any mistakes within its model of normality; yet for the operator it is the results' interpretation that matters". As a remedy they propose "the incorporation of local security policies", because "many security constraints are a site-specific property" — [Sommer & Paxson 2010](https://www.icir.org/robin/papers/oakland10-ml.pdf)

**Using a few labelled attacks (semi-supervised, PU)**
- Deep SAD (Ruff et al., ICLR 2020) extends Deep SVDD to use a small set of labelled anomalies (and labelled normals) alongside unlabelled data. The authors report "appreciable performance improvements even when provided with only little labeled data" (abstract or search snippet). Their benchmarks are generic anomaly-detection sets, and I did not confirm that they include syscall data — [Ruff et al., arXiv 1906.02694](https://arxiv.org/abs/1906.02694v2)
- DevNet (Pang et al., 2019) learns anomaly scores end-to-end from "a few labeled anomalies" and abundant unlabelled data. Normal scores are pushed toward a prior, and labelled anomalies are pushed to deviate significantly from it (abstract or snippet) — [Pang et al., arXiv 1911.08623](https://alphaxiv.org/abs/1911.08623)
- Positive-unlabelled (PU) learning has been applied to intrusion detection as nnPU with a focal-loss variant for imbalance, which beats plain nnPU under imbalance. This was network IDS, not syscalls (abstract) — [HIT Weihai nnPU IDS](https://scholar.hit.edu.cn/en/publications/intrusion-detection-based-on-non-negative-positive-unlabeled-lear/). A 2024 survey says PU/NU learning's "potential in cybersecurity remains largely untapped" — [Dilworth & Gudla, arXiv 2412.06203](https://arxiv.org/html/2412.06203v1)

**Analyst feedback, active learning and allowlisting**
- ALADIN (Stokes, Platt et al., Microsoft) uses active learning with rare-class discovery for host- or network-based IDS. It shows "interesting" items to an expert to reduce how many labels are needed (abstract) — [ALADIN](https://www.microsoft.com/en-us/research/publication/aladin-active-learning-for-statistical-intrusion-detection/)
- Active Anomaly Discovery (Das et al., ICDM 2016) updates the detector after each expert label. Its goal is to maximise the number of true anomalies shown to the analyst, not to build a classifier (abstract or snippet) — [Das et al. 2016](https://web.engr.oregonstate.edu/~afern/papers/icdm16-das.pdf)
- Siddiqui et al. (KDD 2018) re-rank tree-based anomaly detectors from analyst feedback using online convex optimisation. The cybersecurity experiment detects red-team attacks in real system audit data and "significantly reduces the time required" to find anomalies of interest. I did not extract an FPR number (abstract or snippet) — [Siddiqui et al. 2018](https://web.engr.oregonstate.edu/~afern/papers/kdd18-siddiqui.pdf)
- AI2 (Veeramachaneni et al.) combines an outlier ensemble, analyst feedback and supervised learning. Against an unsupervised baseline it reports a 3.41x higher detection rate and 5x fewer false positives on 3.6 billion log lines. The data are log lines, not syscalls (snippet) — [AI2 paper](https://people.csail.mit.edu/kalyan/AI2_Paper.pdf)
- Splunk UBA has a "False Positive Suppression Model": analysts tag false alerts, and new anomalies similar to tagged ones are down-ranked. This is vendor documentation with no independent evaluation — [Splunk blog](https://www.splunk.com/en_us/blog/security/reduce-false-alerts-automatically.html)

**Two-stage triage and "known-benign" priors on host data**
- NoDoze (Hassan et al., NDSS 2019) builds a causal dependency graph for each alert and scores each event "based on the frequency with which related events have happened before in the enterprise". It then propagates scores by network diffusion. The NDSS abstract reports that it "decreases the volume of false alarms by 86%" on 364 threat alerts and saves over 90 analyst-hours per week. An earlier version and press coverage of a 200-computer enterprise give 84 % — [NDSS abstract](https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage); [earlier PDF](https://www.cs.virginia.edu/~hur7wv/papers/hassan-ndss19.pdf); [UIUC news](https://siebelschool.illinois.edu/news/hassan-s-nodoze-brings-triage-security-phd-student-presents-paper-ndss-symposium)
- Bilot & Pasquier (2025) note that most state-of-the-art provenance IDSs produce coarse alerts with "tens of thousands" of nodes or events, which shifts the triage burden onto analysts (abstract or snippet) — [USENIX ;login: 2025](https://spg.cs.ubc.ca/publication/2025-usenix-login)
- Iacovazzi & Raza (2023, container syscalls) use a two-stage design. A Random Forest is "trained with normal behavior classes only; each class includes instances collected for a specific containerized workload". Its output then goes to "N independent IF [Isolation Forest] instances each ... trained with a dataset made of samples belonging to one normal behavior class and contaminated with anomalies randomly extracted from the remaining normal classes" (full text partly read) — [arXiv 2306.14750](https://arxiv.org/pdf/2306.14750)

**Conformal and reject-option designs**
- Transcend (Jordaney et al., USENIX Security 2017) and "Transcending Transcend" (Barbero et al., IEEE S&P 2022) use conformal evaluation to reject drifting samples and send them to expert review instead of auto-classifying them. The evaluation used a malware dataset spanning 5 years with sources of experimental bias removed, and the code is open source. This is malware classification, not HIDS (abstract) — [Barbero et al., arXiv 2010.03856](https://arxiv.org/pdf/2010.03856); [Transcend 2017 AAM](https://kclpure.kcl.ac.uk/ws/files/112249971/Transcend_Detecting_Concept_Drift_JORDANEY_Published16August2017_GREEN_AAM.pdf)

**Self-supervised and contrastive representations**
- Fournier et al. (2023) train LSTM and Transformer language models (self-supervised) on LTTng kernel traces of more than 2 million web requests with seven behaviours. They report "an F-score and AuROC greater than 95% on most novelties" (full text read). Their novelties are operational (misconfigurations, latency), not attacks — [arXiv 2309.02206](https://arxiv.org/pdf/2309.02206)
- A contrastive Transformer IDS (Koukoulis et al., IFIP Networking 2025) reports up to 3 % higher AUC within a dataset and up to 20 % higher AUC across datasets. It works on network packets, not syscalls (abstract or snippet) — [arXiv 2505.08816](https://arxiv.org/pdf/2505.08816)
- A self-supervised decoder-only Transformer on syscall sequences, trained on DongTing, produces token-level explanations (document title or snippet only) — [HAIC 2026](https://haic.fi/wp-content/uploads/2026/05/Explainable-Anomaly-Detection-in-System-Call-Sequences.pdf)

**Container syscall detectors (baseline numbers)**
- Abed et al. (2015) use bag-of-system-calls with a sliding window of 10 over epochs, on a single MySQL Docker container traced with strace. At a mismatch threshold of 10 % of the epoch size they report TPR 100 % and FPR 0.58 %. A stricter setting drops FPR to 0 % at some cost to detection (full text partly read) — [arXiv 1611.03053](https://arxiv.org/pdf/1611.03053)

### Inferences
- By Fournier's definition Pulse is a novelty detector. A benign `kubectl exec` binary being flagged in 86-95 % of trials is the expected outcome of the design, not a bug, and the fix is an "additional mechanism" (Fournier) or a site policy (Sommer & Paxson).
- The design with the most evidence behind it and the cheapest to try is a NoDoze-style prevalence prior. It would down-weight a new process whose identity (image, exe path or hash, parent, exec context) has been seen before across replicas, nodes or cluster history. A second option is an analyst-confirmed allowlist (AI2, Siddiqui, Splunk). Neither has been measured on syscall-count windows, so Pulse would have to report its own before/after alert burden.
- Pulse already outputs conformal p-values, so a Transcend-style reject option fits naturally. Windows that are novel but resemble a calibration set of known-benign novel binaries would go to a "review/low-priority" bucket instead of paging. Doing this needs a separate calibration set of benign novel binaries, kept apart from test data.
- Supervised second stages (Deep SAD, DevNet, PU) fed with only 5 attack scenarios are at high risk of learning the scenarios rather than intent (see Q3). Any such stage needs leave-one-scenario-out and cross-dataset testing.
- Threat-model caveat (my inference, consistent with Arp et al.'s P10 below): an allowlist keyed on binary identity can be evaded by living-off-the-land tools (`sh`, `curl`). The paper should say so explicitly.

### Gaps
- I found no paper evaluating PU learning, open-set recognition or contrastive representation learning on syscall or HIDS data with a reported FPR reduction. Open-set recognition was not covered by any retrieved source.
- I did not extract FPR or precision numbers for Siddiqui et al. 2018 or for Deep SAD and DevNet on security data.
- Container runtime-security "learning mode then allowlist" profiles (commercial tools) have no peer-reviewed evaluation in the retrieved sources.

## Q2. What critiques and guidelines say about benign controls, base rates, precision at realistic prevalence and alert volume

### Takeaway
Every major critique, from Axelsson 2000 and Sommer & Paxson 2010 through Arp et al. 2022, Apruzzese et al. 2023 and Bilot et al. 2025, says the false-alarm rate on realistic benign activity governs usefulness. Recall on a balanced lab mix does not. The recommended reporting is: precision and recall (or PR curves, MCC) at a stated realistic prevalence, FPR curves cut at a tractable FPR, false positives expressed as analyst workload (alarms per day, or per replica-hour), thresholds set without test labels, and statistical significance over repeated runs.

### Cited Findings
- Axelsson (ACM TISSEC 2000, classic) assumes 10 audit records per intrusion, 2 intrusions per day and 1,000,000 audit records per day, which gives a base rate P(I) of 2x10^-5. "Even for the unrealistically high detection rate 1.0, we have to have a very low false alarm rate (on the order of 1x10^-5) for the Bayesian detection rate to have a value of 66%". With detection rate 0.7 at the same false-alarm rate, the Bayesian detection rate is "about 58%". The Bayesian detection rate "is dominated by the false alarm rate". He also writes that "a requirement of only 100 false alarms per day is met by a large margin with a false alarm rate of 1x10^-5" (full text read) — [Axelsson 2000](https://www.profsandhu.com/cs6393_s20/p186-axelsson.pdf)
- Sommer & Paxson (2010) on errors: "A false positive requires spending expensive analyst time examining the reported incident only to eventually determine that it reflects benign underlying activity". "Limiting false positives must be a top priority for any anomaly detection system". "Likely the most important step towards fewer mistakes is reducing the system's scope". On the semantic gap, evaluations stop at deviation detection, while the operator needs "What does it mean?" (full text read) — [Sommer & Paxson 2010](https://www.icir.org/robin/papers/oakland10-ml.pdf)
- Arp et al. (USENIX Security 2022), pitfall P8, base rate fallacy: "If this class is predominant, even a very low false-positive rate can result in surprisingly high numbers of false positives". Their example: 99 % TPR at 1 % FPR with a 1:100 class ratio "actually corresponds to 100 false positives for every 99 true positives" (full text read) — [Arp et al., arXiv 2010.09470](https://arxiv.org/pdf/2010.09470)
- Arp et al.'s recommendations under P7/P8:
  - use precision and recall and PR curves for rare events;
  - "precision and recall can be misleading if the prevalence of the minority class is inflated, for example, due to sampling bias. In these cases ... Matthews Correlation Coefficient (MCC) [is] more suitable";
  - consider "curves only up to tractable false-positive rates and ... compute bounded AUC values";
  - discuss "false positives in relation to the base rate of the negative class, which enables the reader to get an understanding of the workload induced by false-positive decisions";
  - choose measures "aligned with day-to-day operation of the system".
  — [Arp et al.](https://arxiv.org/pdf/2010.09470)
- Arp et al. P9, lab-only evaluation, names as a common example "detection methods evaluated only in a closed-world setting with limited diversity and no consideration of non-stationarity". Their recommendation is to "approximate a real-world setting as accurately as possible" and analyse runtime and storage under practical conditions — [Arp et al.](https://arxiv.org/pdf/2010.09470)
- Arp et al.'s prevalence study covered 30 papers from top-4 venues over 10 years:
  - sampling bias (P1) and data snooping (P3) are "at least partly present in 90 % and 73 %";
  - threat model (P10), lab-only evaluation (P9) and performance measures (P7) are each at least partly present in more than 50 %;
  - "Every paper is affected by at least three pitfalls";
  - in the author survey, authors agree that lab-only evaluations (92 %) and the base rate fallacy (77 %) frequently occur, and 46 % say the base rate fallacy "can be easily avoided".
  — [Arp et al.](https://arxiv.org/pdf/2010.09470)
- Apruzzese et al. ("SoK: Pragmatic Assessment of ML for Network Intrusion Detection", EuroS&P 2023):
  - all 30 reviewed top-venue ML-NIDS papers evaluated against unknown attacks, and none considered different preprocessing;
  - among 12 practitioners, 90 % call the "lack of statistically significant comparisons" "very problematic", and 59 % see lack of data diversity as an issue;
  - they recommend repeating random train/test sampling many times ("e.g., 50").
  (full text read) — [Apruzzese et al., arXiv 2305.00550](https://arxiv.org/pdf/2305.00550)
- Engelen, Rimmer & Joosen (IEEE S&P Workshops 2021) found problems in CICIDS2017's traffic generation, flow construction, feature extraction and labelling. They reconstructed or relabelled more than a fifth of the traces, and benchmark results changed noticeably. This is a network dataset, but the lesson about dataset artifacts is general (abstract) — [Engelen et al. 2021](https://lirias.kuleuven.be/retrieve/713070)
- Bilot et al. ("Sometimes Simpler is Better", USENIX Security 2025) re-implemented 8 provenance IDSs and list 9 shortcomings: SC1 insufficient detection granularity; SC2 missing metric to measure attack detection; SC3 impractical thresholding; SC4 unfair baseline comparison; SC5 not measuring instability; SC6 featurisation trained on test data; SC7 overly complex architectures; SC8 insufficient scalability; SC9 lacking real-time detection (full text read) — [Bilot et al. PDF](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)
- Bilot SC3: tuning thresholds by "iterative 'trial and error' adjustments on the test set" is data snooping. Recommendation: "ensure that the threshold selection methods do not rely on data unavailable in realistic deployment scenarios ... consider using threshold-independent metrics, such as ADP". ADP is the area under a detection-vs-precision curve, defined in the paper — [Bilot et al.](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)
- Bilot headline: "a simple neural network reaches state-of-the-art detection on eight of nine DARPA datasets" (PDF fetched from usenix.org). The USENIX presentation page abstract, per a search snippet, says "five of seven", so check the camera-ready before citing — [USENIX page](https://www.usenix.org/conference/usenixsecurity25/presentation/bilot); [HAL](https://hal-lara.archives-ouvertes.fr/LISN-ROCS/hal-05245280v1)

### Inferences
- **Metrics this literature would recommend for Pulse:**
  1. Alert burden: alert episodes per replica-hour on long benign soaks. This is Axelsson's "false alarms per day" and Arp's "workload" metric, so the thesis choice is well grounded.
  2. Precision and MCC at a stated prevalence. Report them for several attack:benign ratios (1:1, 1:10, 1:100), with hard negatives (benign new binaries), not only idle windows.
  3. A Bayesian detection rate (P(attack | alert)) curve versus FPR, Axelsson-style.
  4. FPR on a benign-novelty control suite. Report it per benign binary class with CI, as a separate table.
  5. Partial AUC up to a tractable FPR, or a threshold-free attack-level curve (ADP-like).
  6. Latency (kernel-to-alert p95) and resource cost, which address Bilot SC8/SC9 and Arp P9.
- Reporting 99.4 % precision at a 1:1 mix where every negative is an idle window inflates prevalence and uses easy negatives. That is the P7/P8 pattern Arp describes. Illustrative arithmetic, assuming recall is unchanged and the negatives are the benign control binary flagged at 86-95 %: precision at 1:1 = 0.994/(0.994+0.86..0.95) ≈ 51-54 %. At 1 attack per 100 benign execs it is about 0.994/(0.994+90) ≈ 1.1 %. This is an inference, not a measurement.
- Window-level budget: one replica produces 7,200 windows of 0.5 s per hour. To stay near 1 false alert episode per replica-day, the effective per-episode false-trigger probability must be on the order of 1/172,800 ≈ 5.8x10^-6 per window. This is before crediting the 2-consecutive-window rule, whose effect depends on autocorrelation. It mirrors Axelsson's 1x10^-5.
- Pulse calibrates conformal thresholds on normal data only and fixes the 2-window rule before testing. That is exactly what Bilot SC3 asks for, and the paper should state it explicitly as a strength.

### Gaps
- I did not retrieve the 2023 provenance SoK (Inam et al., IEEE S&P 2023) or a dedicated HIDS-evaluation SoK. Bilot et al. 2025 is the closest recent HIDS-side critique I read.
- I found no community-standard "acceptable alerts per host-hour" figure. Axelsson's 100 false alarms per day is an illustrative operator budget, not a standard.
- The per-pitfall prevalence of P8 itself could not be read reliably from the two-column PDF layout of Arp's Figure 3, so it is omitted.

## Q3. Avoiding overfitting to the evaluated attack set; how many scenarios container-HIDS papers use; is there a notion of "coverage"?

### Takeaway
Rigorous papers keep attacks out of every tuning step: thresholds come from benign validation data, and featurisers are not fit on test data. They also measure generalisation by leaving out one attack class at a time and by testing across datasets. Container-HIDS papers use roughly 1 to 20 attack scenarios, with LID-DS 2021 at 15 and El Khairi et al. at 20 across two datasets. I found no accepted coverage metric. MITRE ATT&CK for Containers (10 tactics, 38 parent techniques in v20) is the obvious vocabulary for a coverage table.

### Cited Findings
- Apruzzese et al. measure unknown-attack detection by "excluding one malicious class from a given T [training set], re-training all the involved ML models on such new T, and testing them on the benign portion of E (for the fpr), and on the 'excluded' malicious class (and then averaging the resulting tpr)". The TPR drops, "which is expected because the attacks are unknown" (full text read) — [Apruzzese et al.](https://arxiv.org/pdf/2305.00550)
- Arp et al. P3, data snooping, comes in three variants (test, temporal and selective snooping, listed in their appendix). P5 is biased parameter selection. Their general rule is that test data must be held out from every design decision — [Arp et al.](https://arxiv.org/pdf/2010.09470)
- Bilot SC6: featurisation methods such as text embeddings must not be trained on test data. Systems that set thresholds on a validation set with no labelled attacks (SIGL, NodLink), or with MAD statistics (R-CAID), avoid snooping. Orthrus's original validation-based thresholding plus clustering is flagged as snooping, and fixing it "significantly lowers precision, even reaching 0% on E3-CLEARSCOPE" — [Bilot et al.](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)
- LID-DS design against positional artifacts: "the attack sequences should not always occur at the same position in the trace and are therefore started at a random point in time during the execution of normal behavior" (LID-DS 2019, full text read) — [Grimmer et al. 2019](https://dbs.uni-leipzig.de/file/BSI-LID-DS.pdf). LID-DS 2021 benign "User" behaviour has "timings sampled from real-world webserver logs" — [LID-DS 2021 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
- **Scenario counts in container or syscall HIDS work:**
  - LID-DS 2021 has 15 scenarios "corresponding to real security vulnerabilities" — [LID-DS 2021 abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
  - El Khairi et al. (ACM CCSW 2022) use "two datasets of 20 different attack scenarios containing 11,700 normal and 1,980 attack system call traces" — [UTwente record](https://research.utwente.nl/en/publications/contextualizing-system-calls-in-containers-for-anomaly-based-intr/)
  - Cui & Umphress 2020 cover a MySQL container with 7 attacks (Brute Force Login, DockerEscape, Malicious Script, Meterpreter, Remote Shell, SQL Injection, SQL Misbehavior). There are 10 traces per attack and 20 benign traces — [described in Iacovazzi & Raza 2023](https://arxiv.org/pdf/2306.14750)
  - Iacovazzi & Raza 2023 test "the two most common threats ... identified in cloud containers" on their own Mix-2022 dataset, plus Cui-2020 — [arXiv 2306.14750](https://arxiv.org/pdf/2306.14750)
  - Abed et al. 2015 use one MySQL container application — [arXiv 1611.03053](https://arxiv.org/pdf/1611.03053)
  - ADFA-LD has 6 attack types — [arXiv 1808.01717](https://arxiv.org/pdf/1808.01717)
- The MITRE ATT&CK Containers matrix (content v20) has 10 tactics: Initial Access 3, Execution 5, Persistence 7, Privilege Escalation 6, Stealth 4, Defense Impairment 1, Credential Access 3, Discovery 3, Lateral Movement 1, Impact 5. That sums to 38 parent techniques, a total I computed from the per-tactic counts. Execution includes Container Administration Command (T1609), Deploy Container (T1610) and User Execution (T1204, with Malicious Image T1204.003). Privilege Escalation includes Escape to Host (T1611) — [MITRE ATT&CK Containers](https://attack.mitre.org/matrices/enterprise/containers/)

### Inferences
- Pulse's attack launch path (`kubectl exec` of a new binary) is ATT&CK T1609, Container Administration Command, and the benign control uses exactly the same path. The control therefore isolates the "new binary via exec" novelty from the malicious payload. That is a strong experimental design, and it is the right hard negative.
- To defend against "tuned to 5 scenarios":
  1. Keep conformal calibration and the 2-window rule benign-only, which is already the case.
  2. Report the existing pre-registrations (e.g. the cbds-confirmation-v1 registration in the repo's git log) as the blind-set mechanism.
  3. If any supervised or intent stage is added, run leave-one-scenario-out over the 5 live scenarios, Apruzzese-style, and report the mean and worst TPR together with benign-novelty FPR.
  4. Use LID-DS 2021 and CB-DS as external, cross-dataset tests with no re-tuning.
  5. Publish a scenario × ATT&CK-technique (and tactic) coverage table and state which tactics are not covered.
- "Coverage" claims should be phrased as technique or tactic coverage of the evaluated set, not as a detection-coverage guarantee. No source defines an accepted coverage score.

### Gaps
- I found no source describing formal pre-registration practice in security-ML evaluations. Pulse's registrations would be unusual and are worth highlighting, but I have no citation for prevalence.
- I could not confirm which two datasets El Khairi et al. used or how the 20 scenarios split between them. The arithmetic 1,700 + 10,000 = 11,700 normal and 9×99 + 11×99 = 1,980 attack fits the project's CB-DS counts (1,700 normal, 9×99 attack) plus an 11-scenario LID-DS-style set. This is unverified.
- I found no container-HIDS paper that maps its scenarios to ATT&CK for Containers.

## Q4. ADFA-LD and ADFA-WD: format, kernel and OS, criticisms, and whether they can be replayed into time windows

### Takeaway
ADFA-LD (2013) is a set of per-process traces: each file is a sequence of integer syscall IDs. There are no timestamps, PIDs or TIDs, arguments, return values or container context. It was recorded on 32-bit Ubuntu 11.04 and has 833 training, 4,372 validation and 746 attack traces over 6 attack types. It cannot be replayed into 0.5 s per-container windows. At most one can build pseudo-time windows of N syscalls, which would not be comparable to Pulse's latency or alert-burden metrics.

### Cited Findings
- The official UNSW page describes ADFA-LD as "a contemporary Linux dataset for evaluation by traditional HIDS" and ADFA-WD as "a contemporary Windows dataset". It also lists ADFA-WD:SAA (Stealth Attacks Addendum). Academic use is free "in perpetuity" and commercial use is "strictly prohibited". The page was last updated 31 October 2013. It asks users to cite Creech & Hu (IEEE Trans. Computers; WCNC 2013, "Time to retire the KDD collection") and Creech's 2014 PhD thesis. It does not state OS, format or trace counts — [UNSW ADFA IDS datasets](https://research.unsw.edu.au/projects/adfa-ids-datasets)
- **Composition** (Liu et al., arXiv 1808.01717, full text read):
  - "746 files containing 6 types of attacks, 833 normal training files, and 4372 normal validation files". Their Table 2 says 4,373, an internal inconsistency;
  - per attack: Hydra_FTP 162, Hydra_SSH 176, Adduser 91, Java_Meterpreter 124, Meterpreter 75, Web_Shell 118.
  — [arXiv 1808.01717](https://arxiv.org/pdf/1808.01717)
  - The LID-DS loader enumerates the same 6 attacks and the directories Training_Data_Master, Validation_Data_Master and Attack_Data_Master — [LID-DS dataloader_adfa_ld.py](https://github.com/LID-DS/LID-DS/blob/master/dataloader/dataloader_adfa_ld.py)
- **OS:** "ADFA-LD was recorded on an Ubuntu 11.04 32 bit operating system". That paper mapped syscalls using kernel 2.6.35 sources (full text read) — [arXiv 1904.07118](https://arxiv.org/pdf/1904.07118)
- **No metadata:** "The ADFA-LD from 2013 is relatively up-to-date, but only contains sequences of system call IDs without their parameters, return values or other metadata" (Grimmer et al., LID-DS 2019 paper, full text read) — [BSI-LID-DS.pdf](https://dbs.uni-leipzig.de/file/BSI-LID-DS.pdf)
- **No timestamps (code evidence):** the LID-DS framework's ADFA-LD parser says "the ADFA-LD Dataset does not contain syscall names but integers". It assigns each syscall a "mocked timestamp" (`mocked_time`, also used as `line_id`), which shows that no real time exists in the data — [LID-DS syscall_adfa_ld.py](https://github.com/LID-DS/LID-DS/blob/master/dataloader/syscall_adfa_ld.py)
- **Criticisms:**
  - Fournier et al. (2023) say UNM, KDD98 and ADFA-LD "are small and obsolete, as explained by Creech and Hu ... Furthermore, these datasets lack the system call arguments ... As a result, these datasets are inadequate for effectively training large neural networks and are not representative of modern systems" — [arXiv 2309.02206](https://arxiv.org/pdf/2309.02206)
  - Grimmer et al. list three problems with older HIDS datasets: outdated software and kernels, missing thread information, and missing metadata (arguments, timestamps, return values). Not every problem applies to every dataset — [BSI-LID-DS.pdf](https://dbs.uni-leipzig.de/file/BSI-LID-DS.pdf)
  - Search snippets from reviews say labels are trace-level, so benign prefixes of attack traces carry the attack label, and that ADFA-LD is small. I did not read these in full — [NLP-in-HIDS review, arXiv 2201.08066](https://arxiv.org/pdf/2201.08066); [Processed ADFA-LD, Mendeley](https://data.mendeley.com/datasets/853sxvpx79/1)
- DongTing's authors also trained baselines on ADFA-LD (and PLAID) for comparison, and ship npz encodings of ADFA-LD — [DongTing README, Zenodo](https://zenodo.org/records/6627050)

### Inferences
- **Not usable for Pulse's main claims:**
  1. There is no wall-clock time, so neither 0.5 s windows nor kernel-to-alert latency can be built.
  2. There are no PIDs or TIDs and no cgroup or container context, so there is no per-container aggregation.
  3. Each file is a single process trace, not an interleaved host or container stream, so the "new binary appears in a running container" novelty cannot be emulated.
  4. The 2013 kernel (32-bit, 2.6.x) has a different syscall table from a modern x86-64 kernel, so count features need remapping.
- **Possible limited use:** a sequence-only appendix result, with count vectors over fixed-length syscall chunks, to compare Pulse's model family against classic ADFA-LD baselines. It must be labelled clearly as non-temporal. Under the "Paper gaps dropped" policy this is low priority.

### Gaps
- Primary-source details not verified this session: ADFA-WD's exact OS (commonly reported as Windows XP SP2), its DLL-call format, and ADFA-LD's tracing tool (auditd is commonly reported). Creech & Hu's IEEE TC paper and thesis are paywalled or not online.
- I did not retrieve Xie et al.'s ADFA-LD analyses or Haider et al.'s criticisms, and found no source for a "too easy / near-perfect AUC" critique. Do not assert one without a source.

## Q5. Other public syscall datasets (LID-DS 2019/2021, CB-DS, DongTing, 2023-2026) and their fitness for a 0.5 s, per-container, timestamped detector

### Takeaway
LID-DS 2021 is the only widely used public syscall dataset that combines nanosecond timestamps, PIDs and TIDs, arguments, Docker-based victims and exploit timing. CB-DS (scap) also has per-event timestamps and TIDs. Both can be replayed into 0.5 s windows. DongTing is large but sequence-only and about kernel bugs, not container attacks. BETH (eBPF, timestamped) covers only process and network events. I found no new public Kubernetes syscall attack dataset from 2024-2026.

### Cited Findings
- **LID-DS 2021**
  - 15 scenarios of real vulnerabilities, with about 8.5x as many syscalls as LID-DS 2019. Attacker, Victim and User are each "a Docker container". Records contain "system calls (incl. arguments, return values and other metadata), network data and other statistics of the victim". STIDE is harder on 2021 than on 2019 — [CRITIS 2022 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
  - Line format per the official parser: TIMESTAMP (unix ns), USER_ID, PROCESS_ID, PROCESS_NAME, THREAD_ID, SYSCALL_NAME, DIRECTION, then params — [syscall_2021.py](https://github.com/LID-DS/LID-DS/blob/master/dataloader/syscall_2021.py)
  - Download via Proton Drive links in the README; the code is GPL-3.0+ — [LID-DS GitHub](https://github.com/LID-DS/LID-DS)
- **LID-DS 2019**
  - Line fields: TIMESTAMP (time of day, converted by the parser using epoch midnight), CPU, USER_ID, PROCESS_NAME, THREAD_ID, DIRECTION, SYSCALL_NAME, params including `res=` — [syscall_2019.py](https://github.com/LID-DS/LID-DS/blob/master/dataloader/syscall_2019.py)
  - The paper says recordings include "system call IDs, their parameters and return values ... process IDs, process names and timestamps". Attacks include Heartbleed (CVE-2014-0160), Shellshock (CVE-2014-6271), CVE-2015-1427, CVE-2014-3120, CVE-2016-6515 and CVE-2015-5602, started at random times — [BSI-LID-DS.pdf](https://dbs.uni-leipzig.de/file/BSI-LID-DS.pdf)
- **CB-DS (El Khairi et al., CCSW 2022)**
  - The LID-DS loader supports "scap (CB-DS) recordings" — [LID-DS README](https://github.com/LID-DS/LID-DS)
  - Its scap line parser fields are EVT_NUM, EVT_TIME (time, optionally completed with a recording date), EVT_CPU, PROC_NAME, THREAD_TID, DIRECTION, SYSCALL_NAME, then params — [syscall_scap.py](https://github.com/LID-DS/LID-DS/blob/master/dataloader/syscall_scap.py)
  - Paper totals: 20 scenarios over two datasets, 11,700 normal and 1,980 attack traces — [UTwente](https://research.utwente.nl/en/publications/contextualizing-system-calls-in-containers-for-anomaly-based-intr/)
- **DongTing (Duan et al., J. Systems & Software 203:111745, 2023)**
  - 18,966 sequences. 12,116 abnormal sequences come from "17,855 bug-triggering programs" over 26 kernel releases. 6,850 normal sequences come from 4 kernel regression test suites.
  - "All of which are raw sequences"; npz encoding uses `syscall_64.tbl` from Linux 5.17; lengths are 8-4,495; the split is a random 80/10/10.
  - Size is 85 GB of data (about 87 GB total, 4.5 GB compressed downloads), under CC BY 4.0. The README documents no timestamps, PIDs or containers.
  — [Zenodo 6627050 and README](https://zenodo.org/records/6627050)
- **BETH (Highnam et al., 2021)**
  - Built from eBPF-based honeypot tracking: over 8 million events from 23 hosts. It records process creation, clone and termination events plus DNS, with 14 raw features and "sus"/"evil" labels. Attack events appear only in the test split, and each host has at most one attack. Hosted on Kaggle — [Eremin 2025, arXiv 2503.04178](https://arxiv.org/pdf/2503.04178); [Imperial record](https://spiral.imperial.ac.uk/handle/10044/1/90568); [Kaggle mirror listing](https://baselight.app/u/kaggle/dataset/katehighnam_beth_dataset)
- **NGIDS-DS (UNSW Canberra, 2017)**
  - "Although the newer NGIDS-DS of 2017 contains thread information, both parameters and more accurate timestamps are missing" — [Grimmer et al. 2019](https://dbs.uni-leipzig.de/file/BSI-LID-DS.pdf)
  - Dataset page — [UNSWorks NGIDS-DS](https://unsworks.unsw.edu.au/entities/dataset/fa64cd6b-4a80-49bb-80fe-23549a60d695)
- **Cui & Umphress 2020 (container)**
  - Docker MySQL with 7 attack types, 10 traces each, and 20 benign traces. The format is not described in the source I read — [via arXiv 2306.14750](https://arxiv.org/pdf/2306.14750)
- **Fournier et al. 2023 (LTTng kernel traces)**
  - Over 2 million web requests under 7 behaviours, including misconfigurations and latency. Events carry a timestamp and context fields. Data are on Zenodo and code on GitHub. There are no attacks — [arXiv 2309.02206](https://arxiv.org/pdf/2309.02206); [Zenodo 7378420](https://zenodo.org/record/7378420)
- **Other container datasets found**
  - A Docker container-escape dataset with syscall traces and capability labels in CSV (PES University; details not read) — [IEEE DataPort](https://ieee-dataport.org/documents/docker-container-escape-attack-dataset-capabilities-and-system-call-traces)
  - A Kubernetes pod-level dataset with CPU, memory and disk metrics only, no syscalls — [IEEE DataPort](https://ieee-dataport.org/documents/pod-level-labelled-resource-utilization-dataset-intrusion-detection-kubernetes)
  - A search for 2024-2025 Kubernetes syscall attack datasets with timestamps found none.

**Fitness summary (my assessment from the cited formats)**

| Dataset | Wall-clock timestamps | PID/TID | Args | Container context | Attack type | Usable for 0.5 s per-container windows? |
|---|---|---|---|---|---|---|
| ADFA-LD 2013 | No (mocked in LID-DS loader) | No | No | No | 6 host attacks | No (sequence-only appendix at most) |
| LID-DS 2019 | Time of day | TID (+ process name) | Yes | Docker victim | CVE exploits | Yes (with date reconstruction) |
| LID-DS 2021 | Unix ns | PID + TID | Yes | Docker victim | 15 real-vuln scenarios | Yes (already used by Pulse) |
| CB-DS (scap) | Event time | TID | Yes | Container (per paper title) | Container attacks | Yes (already used by Pulse) |
| DongTing 2023 | Not documented | Not documented | Not documented | No | Kernel bug triggers | No for timing; sequence-only |
| BETH 2021 | Yes (eBPF) | Yes per field count (not verified) | Partial | Hosts (honeypot) | Real honeypot attacks | Partial: process/DNS events only, not full syscall counts |
| NGIDS-DS 2017 | Coarse | Threads | No | No | Cyber-range attacks | Weak |
| Fournier 2023 LTTng | Yes | Yes | Partial | No | No attacks (benign/perf novelties) | As a benign-novelty corpus only |

### Inferences
- For "novelty is not maliciousness", the publicly available hard negatives are thin. LID-DS and CB-DS benign traffic is workload-only and does not include new benign binaries being exec'd. Fournier 2023's novelties are performance changes, not new binaries. So Pulse's own benign-binary control suite is likely to be a contribution in its own right, and should be released (free and open) with timestamps, PID/TID and cgroup IDs.
- LID-DS 2021 and CB-DS are the right cross-dataset tests for the timing pipeline. DongTing and ADFA-LD can only test sequence modelling, not the kernel-to-alert path or per-container windows.

### Gaps
- Exact BETH field list (whether TID or mount namespace is present) and licence were not verified from the primary README.
- The DongTing per-sequence file format (whether names or numbers, any timing) is not documented in the README. The GitHub `Documents/Documentation.pdf` was not read.
- The CB-DS public download location and licence were not found in this session (the LID-DS README only names the format).
- LID-DS 2019's exact scenario count and size were not extracted.
- No 2024-2026 Kubernetes syscall attack dataset was found. Absence from search results is not proof of absence.
