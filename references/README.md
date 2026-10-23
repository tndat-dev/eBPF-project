# Tài liệu tham chiếu

[`catalog.json`](catalog.json) là danh mục mọi nguồn mà các báo cáo trích, cùng các tài liệu nền của phương pháp (ExtraTrees, Isolation Forest, STIDE, conformal, CUSUM, bootstrap, khoảng Wilson…). Tổng cộng 87 mục:

- **70 bài báo hoặc sách, mỗi mục có đúng một file PDF trong `pdf/`:**
  - 60 bản gốc: 53 do script tải, 7 do chủ đồ án tải tay;
  - 10 bản dựng lại;
- **17 mục là dataset, công cụ hoặc trang web,** chỉ lưu link.

Mỗi bài có thông tin thư mục (tiêu đề, tác giả, năm, nơi công bố, DOI hoặc arXiv), nguồn gốc file (`how`), kích thước và **SHA-256**.

## Tên file

`<năm>-<họ tác giả đầu>-<tiêu đề>.pdf`. Hậu tố `--reconstructed` đánh dấu bản dựng lại.

Thông tin thư mục lấy từ:
- DataCite (bài arXiv, vì arXiv API giới hạn tốc độ);
- Crossref (DOI);
- thẻ `citation_*` trên trang của nhà xuất bản;
- metadata ghi tay trong [`extra.json`](extra.json) (đã đối chiếu với trang đầu bài hoặc trang công bố). Metadata ghi tay luôn được ưu tiên.

## Bản dựng lại (không phải bản gốc)

Mười bài không có bản PDF hay toàn văn công khai, hoặc trang của nhà xuất bản chặn tải tự động. Mỗi bài có một bản PDF dựng lại, gồm:
- thông tin thư mục;
- tóm tắt công khai **nguyên văn kèm nguồn**;
- phần **đọc hiểu của người dựng**, ghi rõ là diễn giải;
- các câu trong báo cáo của đồ án đang trích bài;
- cách lấy bản gốc.

Mọi trang đều ghi "BẢN DỰNG LẠI — không phải bản gốc". Khi trích dẫn trong luận văn, dùng thông tin thư mục và đối chiếu với bản gốc. Nội dung dựng lại nằm trong [`reconstructions.json`](reconstructions.json).

| File | Bài | DOI / trang gốc |
|---|---|---|
| `pdf/1993-efron-an-introduction-to-the-bootstrap--reconstructed.pdf` | An Introduction to the Bootstrap | reconstructed |
| `pdf/2026-zheng-in-kernel-cnn-inference-for-edge-devices-an-ebpf-based--reconstructed.pdf` | In-Kernel CNN Inference for Edge Devices: An eBPF-Based Approach to Low-Latency and Resource-Efficient Processing | kept |
| `pdf/2026-rheey-toward-reliable-intrusion-monitoring-for-o-ran-based--reconstructed.pdf` | Toward Reliable Intrusion Monitoring for O-RAN Based Networks with Conformal False Alarm Control | reconstructed |
| `pdf/1927-wilson-probable-inference-the-law-of-succession-and-statistical--reconstructed.pdf` | Probable Inference, the Law of Succession, and Statistical Inference | kept |
| `pdf/1954-page-continuous-inspection-schemes--reconstructed.pdf` | Continuous Inspection Schemes | kept |
| `pdf/2019-tien-kubanomaly-anomaly-detection-for-the-docker-orchestration--reconstructed.pdf` | KubAnomaly: Anomaly detection for the Docker orchestration platform with neural network approaches | kept |
| `pdf/1996-forrest-a-sense-of-self-for-unix-processes--reconstructed.pdf` | A sense of self for Unix processes | reconstructed |
| `pdf/2025-he-on-the-practicability-of-deep-learning-based-anomaly--reconstructed.pdf` | On the Practicability of Deep Learning Based Anomaly Detection for Modern Online Software Systems: A Pre-Train-and-Align Framework | kept |
| `pdf/2005-vovk-algorithmic-learning-in-a-random-world--reconstructed.pdf` | Algorithmic Learning in a Random World | kept |
| `pdf/2020-lin-cdl-classified-distributed-learning-for-detecting-security--reconstructed.pdf` | CDL: Classified Distributed Learning for Detecting Security Attacks in Containerized Applications | kept |

## Lấy lại và kiểm tra

```bash
python3 scripts/fetch_references.py            # dựng lại danh mục; tải, đổi tên, dựng bản còn thiếu
python3 scripts/fetch_references.py --refresh-bib
```

- **Nhận diện file:** mọi PDF trong `pdf/`, kể cả file tải tay đặt tên bất kỳ, được gán cho đúng bài theo tiêu đề ở đầu trang 1 (đọc thêm trang 2 nếu trang 1 là bìa). Khi hai bài cùng khớp, bài có tiêu đề xuất hiện sớm nhất thắng.
- **Đổi tên an toàn:** file được chuyển qua tên tạm trước nên không bao giờ ghi đè nhau. Bản sao giống hệt từng byte thì chỉ giữ một.
- **Bản quét không có lớp chữ** (JSTOR) được ghép tay trong [`manual_matches.json`](manual_matches.json), có ghi căn cứ.
- **Một PDF chỉ được nhận** khi đủ (`%PDF` … `%%EOF`) và trang đầu mang đúng tiêu đề. Từng có một file lấy từ kho của trường hóa ra là tờ giới thiệu thư viện.
- **Bổ sung tay:** tải bằng trình duyệt, đặt vào `pdf/` với tên bất kỳ, chạy lại script; file được ghi `how = placed_by_hand`.

## Vì sao PDF không nằm trong git

Repo này **công khai**, và phần lớn bài báo không cho phép phát tán lại. Vì vậy:
- `pdf/` có trong `.gitignore`;
- bản PDF nằm ở thư mục này trên máy chủ đồ án và bản sao trên NFS `/mnt/sentinel-pulse-archive/references/pdf/`;
- SHA-256 trong danh mục cho phép kiểm bất kỳ bản sao nào.

## Bài và file

| File | Nơi công bố | Nguồn gốc |
|---|---|---|
| `pdf/1927-wilson-probable-inference-the-law-of-succession-and-statistical--reconstructed.pdf` | Journal of the American Statistical Association | kept |
| `pdf/1954-page-continuous-inspection-schemes--reconstructed.pdf` | Biometrika | kept |
| `pdf/1971-lorden-procedures-for-reacting-to-a-change-in-distribution.pdf` | The Annals of Mathematical Statistics | placed_by_hand |
| `pdf/1986-moustakides-optimal-stopping-times-for-detecting-changes-in.pdf` | The Annals of Statistics | placed_by_hand |
| `pdf/1993-efron-an-introduction-to-the-bootstrap--reconstructed.pdf` | Chapman & Hall/CRC | reconstructed |
| `pdf/1996-forrest-a-sense-of-self-for-unix-processes--reconstructed.pdf` | IEEE Symposium on Security and Privacy 1996 | reconstructed |
| `pdf/2002-wagner-mimicry-attacks-on-host-based-intrusion-detection-systems.pdf` | ACM CCS 2002 | script |
| `pdf/2005-vovk-algorithmic-learning-in-a-random-world--reconstructed.pdf` | Springer | kept |
| `pdf/2006-geurts-extremely-randomized-trees.pdf` | Machine Learning | script |
| `pdf/2008-liu-isolation-forest.pdf` | 2008 Eighth IEEE International Conference on Data Mining | script |
| `pdf/2009-moustakides-numerical-comparison-of-cusum-and-shiryaev-roberts.pdf` | arXiv | script |
| `pdf/2011-pedregosa-scikit-learn-machine-learning-in-python.pdf` | Journal of Machine Learning Research | script |
| `pdf/2012-day-condor-a-hybrid-ids-to-offer-improved-intrusion-detection.pdf` | IEEE TrustCom 2012 | script |
| `pdf/2016-abed-intrusion-detection-system-for-applications-using-linux.pdf` | arXiv | script |
| `pdf/2016-kim-lstm-based-system-call-language-modeling-and-robust-ensemble.pdf` | arXiv | script |
| `pdf/2018-liu-cauchy-combination-test-a-powerful-test-with-analytic-p.pdf` | arXiv | script |
| `pdf/2019-hassan-nodoze-combatting-threat-alert-fatigue-with-automated.pdf` | NDSS 2019 | script |
| `pdf/2019-tibshirani-conformal-prediction-under-covariate-shift.pdf` | arXiv | script |
| `pdf/2019-tien-kubanomaly-anomaly-detection-for-the-docker-orchestration--reconstructed.pdf` | Engineering Reports | kept |
| `pdf/2019-vovk-testing-randomness.pdf` | arXiv | script |
| `pdf/2019-wilson-the-harmonic-mean-p-value-for-combining-dependent-tests.pdf` | Proceedings of the National Academy of Sciences | script |
| `pdf/2020-arp-dos-and-don-ts-of-machine-learning-in-computer-security.pdf` | arXiv | script |
| `pdf/2020-barbero-transcending-transcend-revisiting-malware-classification-in.pdf` | arXiv | script |
| `pdf/2020-castanhel-sliding-window-the-impact-of-trace-size-in-anomaly-detection.pdf` | ERRC 2020 (SBC) | script |
| `pdf/2020-ghavamnia-confine-automated-system-call-policy-generation-for.pdf` | 23rd International Symposium on Research in Attacks, Intrusions and Defenses (RAID 2020) | script |
| `pdf/2020-ghavamnia-temporal-system-call-specialization-for-attack-surface.pdf` | 29th USENIX Security Symposium (USENIX Security 20) | script |
| `pdf/2020-lin-cdl-classified-distributed-learning-for-detecting-security--reconstructed.pdf` | Annual Computer Security Applications Conference | kept |
| `pdf/2020-nakandala-a-tensor-compiler-for-unified-machine-learning-prediction.pdf` | Symposium on Operating Systems Design and Implementation (OSDI) | script |
| `pdf/2021-bates-testing-for-outliers-with-conformal-p-values.pdf` | arXiv | script |
| `pdf/2021-fisher-online-false-discovery-rate-control-for-lord-amp-saffron.pdf` | arXiv | script |
| `pdf/2021-gibbs-adaptive-conformal-inference-under-distribution-shift.pdf` | arXiv | script |
| `pdf/2021-podkopaev-tracking-the-risk-of-a-deployed-model-and-detecting-harmful.pdf` | arXiv | script |
| `pdf/2021-rebjock-online-false-discovery-rate-control-for-anomaly-detection-in.pdf` | arXiv | script |
| `pdf/2021-yang-cade-detecting-and-explaining-concept-drift-samples-for.pdf` | 30th USENIX Security Symposium (USENIX Security 21) | script |
| `pdf/2022-alahmadi-99-false-positives-a-qualitative-study-of-soc-analysts.pdf` | 31st USENIX Security Symposium (USENIX Security 22) | script |
| `pdf/2022-barber-conformal-prediction-beyond-exchangeability.pdf` | arXiv | script |
| `pdf/2022-chen-robust-tests-for-combining-p-values-under-arbitrary.pdf` | Scientific Reports | script |
| `pdf/2022-grimmer-extended-abstract-lid-ds-2021.pdf` | CRITIS 2022 | script |
| `pdf/2022-khairi-contextualizing-system-calls-in-containers-for-anomaly-based.pdf` | Proceedings of the 2022 on Cloud Computing Security Workshop | placed_by_hand |
| `pdf/2022-zaffran-adaptive-conformal-predictions-for-time-series.pdf` | International Conference on Machine Learning | script |
| `pdf/2023-angelopoulos-conformal-pid-control-for-time-series-prediction.pdf` | arXiv | script |
| `pdf/2023-cheng-kairos-practical-intrusion-detection-and-investigation-using.pdf` | arXiv | script |
| `pdf/2023-goyal-sometimes-you-aren-t-what-you-do-mimicry-attacks-against.pdf` | NDSS 2023 | script |
| `pdf/2023-guan-a-comparison-of-decision-forest-inference-platforms-from-a.pdf` | arXiv | script |
| `pdf/2023-kronert-fdr-control-for-online-anomaly-detection.pdf` | arXiv | script |
| `pdf/2024-fernando-efficient-training-approaches-for-performance-anomaly.pdf` | arXiv | script |
| `pdf/2024-khairi-replicawatcher-training-less-anomaly-detection-in.pdf` | NDSS 2024 | script |
| `pdf/2024-li-nodlink-an-online-system-for-fine-grained-apt-attack.pdf` | NDSS 2024 | script |
| `pdf/2024-mehta-benchmarking-anomaly-detection-algorithms-deep-learning-and.pdf` | arXiv | script |
| `pdf/2024-oliver-carbon-filter-real-time-alert-triage-using-large-scale.pdf` | arXiv | script |
| `pdf/2024-osaki-dynamic-fixed-point-values-in-ebpf-a-case-for-fully-in.pdf` | Proceedings of the 19th Asian Internet Engineering Conference | placed_by_hand |
| `pdf/2025-bortolini-deteccao-eficiente-de-anomalias-em-hosts-usando-transformer.pdf` | Anais do XXV Simpósio Brasileiro de Cibersegurança (SBSeg 2025) | script |
| `pdf/2025-ghimire-ebpf-patrol-protective-agent-for-threat-recognition-and.pdf` | arXiv | script |
| `pdf/2025-he-on-the-practicability-of-deep-learning-based-anomaly--reconstructed.pdf` | ACM Transactions on Software Engineering and Methodology | kept |
| `pdf/2025-jiang-orthrus-achieving-high-quality-of-attribution-in-provenance.pdf` | USENIX Security 2025 | script |
| `pdf/2025-kim-detecting-cryptojacking-containers-using-ebpf-based-security.pdf` | Electronics | placed_by_hand |
| `pdf/2025-syairozi-comparative-analysis-of-ebpf-based-runtime-security.pdf` | Proceedings of the 1st International Conference on Research and Innovations in Information and Engineering Technology | script |
| `pdf/2025-wei-cortex-collaborative-llm-agents-for-high-stakes-alert-triage.pdf` | NeurIPS 2025 | script |
| `pdf/2025-ying-metanoia-a-lifelong-intrusion-detection-and-investigation.pdf` | arXiv | script |
| `pdf/2025-zehra-fedmon-federated-ebpf-monitoring-for-distributed-anomaly.pdf` | arXiv | script |
| `pdf/2025-zhang-e-gai-e-value-based-generalized-investing-for-online-false.pdf` | International Conference on Machine Learning | script |
| `pdf/2026-althani-class-conditional-conformal-prediction-for-reliable-anomaly.pdf` | Machine Learning and Knowledge Extraction 8, 190 | placed_by_hand |
| `pdf/2026-araz-conformal-calibration-and-look-elsewhere-effect-in-anomaly.pdf` | arXiv | script |
| `pdf/2026-begimher-sir-bench-evaluating-investigation-depth-in-security.pdf` | arXiv | script |
| `pdf/2026-bhattacharyya-change-detection-with-conformal-martingales-new-optimal.pdf` | arXiv | script |
| `pdf/2026-dasari-when-to-retrain-an-empirical-study-of-retraining-policies.pdf` | arXiv | script |
| `pdf/2026-jajodia-before-you-hand-over-the-wheel-evaluating-llms-for-security.pdf` | arXiv | script |
| `pdf/2026-rheey-toward-reliable-intrusion-monitoring-for-o-ran-based--reconstructed.pdf` | ICML 2026 | reconstructed |
| `pdf/2026-zheng-in-kernel-cnn-inference-for-edge-devices-an-ebpf-based--reconstructed.pdf` | Lecture Notes in Computer Science | kept |
| `pdf/2026-zhou-an-abnormal-file-access-detection-model-for-containers-based.pdf` | Mathematics 14(6), 991 | placed_by_hand |

## Dataset, công cụ, trang web (chỉ lưu link)

| Loại | Nguồn |
|---|---|
| web | [Báo cáo Aqua/Sysdig 2022 (tóm tắt)](https://www.scmagazine.com/news/cryptominers-still-preferred-in-cloud-attacks-but-the-use-of-other-malware-has-increased) |
| tool | [bảng ABI Linux x86-64 v6.8](https://raw.githubusercontent.com/torvalds/linux/v6.8/arch/x86/entry/syscalls/syscall_64.tbl) |
| tool | [DeepOD](https://github.com/xuhongzuo/DeepOD) |
| dataset | [Docker container escape dataset (IEEE DataPort)](https://ieee-dataport.org/documents/docker-container-escape-attack-dataset-capabilities-and-system-call-traces) |
| dataset | [DongTing dataset](https://zenodo.org/records/6627050) |
| tool | [Falco (tài liệu dự án)](https://falco.org/docs/) |
| web | [Falco drift detection (Sysdig blog)](https://www.sysdig.com/blog/container-drift-detection-with-falco) |
| dataset | [LID-DS (kịch bản)](https://github.com/LID-DS/LID-DS) |
| tool | [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/) |
| tool | [Mondrian conformal (MAPIE)](https://mapie.readthedocs.io/en/stable/theoretical_description_mondrian.html) |
| tool | [Prometheus Alertmanager (tài liệu)](https://prometheus.io/docs/alerting/latest/alertmanager/) |
| tool | [sentinel-ebpf](https://github.com/Murashidzi/sentinel-ebpf) |
| web | [Sysdig 2025 report](https://www.sysdig.com/2025-cloud-native-security-and-usage-report) |
| tool | [Tetragon (tài liệu dự án)](https://tetragon.io/docs/) |
| tool | [Threat Matrix for Kubernetes](https://github.com/microsoft/Threat-Matrix-for-Kubernetes) |
| web | [Training-less IDS in containerized microservices (Twente)](https://www.utwente.nl/en/eemcs/events/2025/11/654945/phd-defence-asbat-el-khairi-training-less-anomaly-based-intrusion-detection-in-containerized-microservices) |
| tool | [tài liệu Istio](https://istio.io/latest/docs/ambient/usage/networkpolicy/) |
