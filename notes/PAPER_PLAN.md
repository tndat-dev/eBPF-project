# Lộ trình lên tầm bài báo (lập 13/11/2026)

Bản ghi làm việc: mỗi điểm yếu, bằng chứng hiện có, thí nghiệm sẽ khép nó và tiêu chí. Số liệu chỉ lấy từ biên nhận; protocol đăng ký
trước khi chạy. Trạng thái từng bước: [STATE.md](STATE.md), nhật ký: [WORKLOG.md](WORKLOG.md).

## Luận điểm của bài

Một mô hình ngôn ngữ đếm trên token syscall dựng ngay trong kernel (eBPF), học chỉ từ normal, phát hiện exploit thật trong dưới 1 s trên
Kubernetes, với mọi lựa chọn thiết kế được kiểm bằng protocol đăng ký trước. Đóng góp cần chứng minh:

1. **Token trong kernel:** mã lỗi, cỡ trả về, thư mục đầu, theo thread, đếm 4-gram trong map; chi phí đo được.
2. **Mô hình và ngưỡng không nhãn** giữ kết quả trên LID-DS 2021 (97,40% / 0,33%), CB-DS, và live.
3. **Tách theo dòng dõi process** (mới, mục W1): process của dịch vụ và process đi vào qua runtime exec có mô hình riêng.
4. **Đánh giá trung thực:** development / official / live blind, kết quả âm được báo, mô phỏng kẻ tấn công chỉ dùng chuỗi đã thấy.

## Tài liệu đã rà (13/11) và hệ quả

- **Baseline trên LID-DS 2021:** kết quả công bố trên đủ 15 kịch bản chỉ có STIDE của tác giả dataset (Grimmer et al., CRITIS 2022; Dataset
  Report, Springer 2023). Bài 2026 dùng 3 kịch bản (TextRank + DL, Electronics 15(9):1856) hoặc 6 kịch bản (From CVE to CWE, arXiv
  2606.22581: detector một lớp theo kịch bản chỉ bắt được ít cửa sổ exploit nếu không chỉnh ngưỡng bằng nhãn). Hệ quả: bài phải tự chạy
  baseline theo cùng protocol (W4); ngưỡng không nhãn của ta là điểm khác biệt cần nêu.
- **Process vô hại mới:** không tìm thấy công trình học thuật nào tách `kubectl exec` vô hại khỏi tấn công; công cụ (Falco, Elastic, Splunk)
  dùng luật và danh sách ngoại lệ theo người dùng, công cụ. ReplicaWatcher (NDSS 2024) né việc học bằng cách so replica, precision 91,08%,
  recall 98,35%, không dùng được khi chỉ có một replica. Hệ quả: tách dòng dõi trong kernel là hướng chưa ai làm (W1).
- **Né tránh:** Wagner và Soto (CCS 2002), Tan et al. (2002), Kruegel et al. (TISSEC 2006: thêm tham số syscall tăng sức chống né), mimicry
  trên hệ provenance thành công 100% (Goyal et al., NDSS 2023). Hệ quả: phải có thí nghiệm né có chủ đích (W3).
- **Exploit thật:** mã nguồn 15 kịch bản LID-DS (victim, normal, exploit, mỗi vai một Dockerfile) công khai ở github.com/LID-DS/LID-DS; lab
  kéo được image (đã kiểm). Hệ quả: chạy chính các CVE đó live trên cụm dưới probe thật (W2).

## Điểm yếu, bằng chứng hiện có, việc sẽ làm

| | Điểm yếu | Hiện có | Thí nghiệm khép lại | Tiêu chí |
|---|---|---|---|---|
| W1 | Process vô hại mới bị gắn cờ (binary 314/314, lệnh quản trị 419/436) | Gate mất exploit LID-DS; B (học lệnh khác) 82,5% vẫn bị gắn cờ | B2, B3 (amendment 1): proxy dòng dõi trên dữ liệu v5 → thẻ dòng dõi trong probe → lượt live xác nhận | native ≤ 5% trên control/admin/benign; tool đã biết ≤ 20%; tấn công ≥ 95%; LID-DS giữ nguyên (mọi sự kiện là native) |
| W2 | Tấn công live là fixture tự viết, luôn bắt đầu bằng exec | A: bỏ gram khởi chạy vẫn 314/314 | Chạy kịch bản LID-DS (CVE thật, exploit trong process dịch vụ) trên cụm: thu normal bằng client của kịch bản, rồi exploit blind | recall ≥ 95% trên các kịch bản mà offline đạt 100%; p95 ≤ 3 s; báo nhầm trên normal của kịch bản |
| W3 | Kẻ tấn công thích nghi chưa đo; chỉ dùng chuỗi đã thấy thì mô hình 0/544 | D: tín hiệu tần suất 225/544, trượt tiêu chí một báo nhầm CB-DS | (a) fixture pha loãng: chèn syscall quen giữa thao tác tấn công, theo mức hiểu biết về detector; (b) đăng ký lại tín hiệu tần suất với cách chia α giữa hai nhánh | báo cả tỉ lệ bị bắt và tỉ lệ đạt mục tiêu của tấn công |
| W4 | Chưa có baseline cùng protocol | Luật đếm 4-gram chưa thấy (development); cây + support | STIDE theo thread, bag-of-syscalls + Isolation Forest, LSTM LM, Transformer LM, autoencoder n-gram; cùng split, cùng quy tắc ngưỡng, một lần official mỗi baseline; Falco mặc định trên campaign live | bảng so sánh ở cùng ngân sách báo nhầm |
| W5 | Official không hoàn toàn chưa nhìn | CB-DS 891/891 | LID-DS 2019 đúng một lần, sau khi W1–W4 chốt hệ thống | protocol `lidds2019-confirmation-v1` |
| W6 | Chi phí: chưa có request thật, chưa có điểm map đầy | microbenchmark; lượt v5 dùng tối đa 2,6% map | Tải HTTP vào api-gateway, bật/tắt probe xen kẽ; fixture stress tới khi `insert_fail` > 0 | báo p50/p99 độ trễ request và ngưỡng tải |
| W7 | RCA: thứ tự có lợi, đua exec | 467/522, hạng 1 99,4% | Thứ tự ngẫu nhiên trong trial; đo `follow_up_recheck_seconds` | cùng lượt live của W1/W2 |
| W8 | Ngưỡng không giữ mức thiết kế | C: phân vị thực nghiệm bị loại | Giữ Gumbel, báo như núm chỉnh; không làm thêm | đã khép |

## Thứ tự làm

1. **B2, B3** trên dữ liệu v5 (đang chạy 13/11). Đạt thì viết thẻ dòng dõi vào probe (`pulse_task_state.lineage`, bit trong
   `pulse_gram_key.pad`), loader và worker ghi hai dòng; proof trên 3 worker.
2. **Baseline (W4)** song song trên `.234`, dùng lại cache development; không cần cụm.
3. **Kịch bản LID-DS trên cụm (W2):** dựng image victim/normal/exploit, namespace riêng trong allow-list, thu normal, fit.
4. **Một lượt live `pulse-live-v6`:** AIMS + kịch bản LID-DS, thẻ dòng dõi, thứ tự ngẫu nhiên, lệnh quản trị mới, fixture pha loãng, RCA
   recheck. Trước và sau lượt: W6.
5. **Rule (phần E)** trên dữ liệu v6: R2 drift cho binary lạ; so sánh có và không có rule.
6. **LID-DS 2019** một lần; viết bài.

## Nguồn

- Grimmer et al., Extended Abstract: LID-DS 2021 (CRITIS 2022): https://dbs.uni-leipzig.de/file/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf
- Grimmer et al., Dataset Report: LID-DS 2021 (Springer 2023): https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf
- From CVE to CWE: Syscall-Based HIDS Generalisation (arXiv 2606.22581): https://arxiv.org/abs/2606.22581
- TextRank-based system call preprocessing and deep learning models (Electronics 2026): https://doi.org/10.3390/electronics15091856
- ReplicaWatcher (NDSS 2024): https://www.ndss-symposium.org/ndss-paper/replicawatcher-training-less-anomaly-detection-in-containerized-microservices
- Wagner, Soto, Mimicry attacks on host-based intrusion detection systems (CCS 2002): https://www.cs.purdue.edu/homes/ninghui/readings/AccessControl/wagner_soto_ccs02.pdf
- Kruegel et al., Anomalous system call detection (TISSEC 2006): https://www.auto.tuwien.ac.at/~chris/research/doc/tissec06_syscall.pdf
- LID-DS, mã nguồn kịch bản: https://github.com/LID-DS/LID-DS
