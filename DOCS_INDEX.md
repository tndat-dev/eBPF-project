# Danh mục tài liệu

## Báo cáo hiện hành (cập nhật liên tục, mỗi file có nhật ký làm việc riêng)

1. [SENTINEL_PULSE_STATUS.md](SENTINEL_PULSE_STATUS.md) — Pulse (phát hiện ML): tóm tắt, trạng thái cụm và job,
   thuật ngữ, kết quả các lượt (soak 48 giờ, pulse-attack-dev, hiệu chỉnh lại, 5 lượt live tới lượt cuối
   pulse-peer-discount-confirm), luật chọn chính sách, biên Pareto, baseline ML (5.15), giảm gánh cảnh báo
   (5.22–5.27), ML stable cuối (5.27), hạ tầng chung, nhật ký. Chỉ số liệu ML, không có rule.
2. [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) — thí nghiệm chọn syscall:
   thiết kế syscall-arms, holdout, replay attack, so sánh ở cùng ngân sách cảnh báo, luật chọn, nhật ký.
3. [RCA_RUNTIME_STATUS.md](RCA_RUNTIME_STATUS.md) — RCA: subscriber, policy Tetragon, xếp hạng nghi phạm,
   độ phủ trong campaign, sự cố đã xử lý, nhật ký.
4. [RULE_INTEGRATION_STATUS.md](RULE_INTEGRATION_STATUS.md) — phần rule, tách riêng khỏi ML (22/10): Falco
   (framework có sẵn), tripwire A1, tầng triage probe sau ML, so sánh không có / có rule (R6) và hệ thống cuối
   ML + tripwire; nguyên tắc tách và nhật ký.
5. [TODO.md](TODO.md) — danh sách việc theo mức ưu tiên.
6. [RESEARCH_IDEAS.md](RESEARCH_IDEAS.md) — đánh giá tổng thể (điểm mạnh, khoảng cách G1–G9, đề xuất, % tiến độ),
   ý tưởng từ tài liệu (R1–R8, A1–D1), công trình liên quan và nguồn.
7. [README.md](README.md) gốc — hướng dẫn đọc repo: thứ tự đọc, cách đánh số mục, từ con số trong báo cáo tới biên nhận, script và luật đăng ký trước; những gì không nằm trong git.
8. [references/README.md](references/README.md) — danh mục bài báo và nguồn đã trích (`catalog.json`, SHA-256 của bản PDF đã tải).
   [references/KNOWLEDGE_SYNTHESIS.md](references/KNOWLEDGE_SYNTHESIS.md) — tri thức tổng hợp từ 70 bài theo chủ đề luận văn (CUSUM, conformal, gộp p-value/FDR, HIDS syscall, mô hình, provenance/RCA, eBPF, phương pháp đánh giá): bảo đảm lý thuyết, số liệu tác giả báo cáo, chỗ đồ án dùng, câu được nói và giới hạn.
9. README trong từng thư mục (`sentinel_pulse/`, `testbed/`, `validation-evidence/` và các thư mục `results-*`) — hướng dẫn code và nguồn gốc biên nhận, không phải báo cáo tiến độ.
   `docs/figures/README.md` — hình cho luận văn và paper, sinh lại từ biên nhận.
10. [docs/AUDIT.md](docs/AUDIT.md) — rà soát số liệu (25/10, mở rộng 29/10): số chủ chốt của báo cáo và luận văn tính lại từ biên nhận
   (`scripts/audit/headline_numbers.py`, chạy trong bộ test) và số trích từ tài liệu so với PDF (`scripts/audit/literature_numbers.py`).

## Luận văn

- [thesis/](thesis/README.md) — luận văn bằng LaTeX (từ 29/10; build: `cd thesis && tectonic main.tex`, PDF không đưa vào git).
  8 chương, tài liệu tham khảo sinh từ `references/catalog.json`, hình lấy từ `docs/figures/`. Số liệu chỉ lấy từ 4 báo cáo hiện hành.
  Bản nháp trên Claude Docs trước đó đã ngừng cập nhật.

## Nghiên cứu theo chủ đề

- [reports/Cải thiện Pulse trên LID DS.md](reports/Cải%20thiện%20Pulse%20trên%20LID%20DS.md) (29/10) — vì sao Pulse bỏ sót trên LID-DS 2021,
  kết quả đã công bố, kỹ thuật cải thiện và lộ trình 4 bậc; là cơ sở của protocol `lidds-evaluation-v2` (Pulse 5.32).
  Ghi chú nguồn từng phần: [research_notes/Cải thiện Pulse trên LID DS/](research_notes/Cải%20thiện%20Pulse%20trên%20LID%20DS/).
- [reports/Giảm gắn cờ binary vô hại.md](reports/Giảm%20gắn%20cờ%20binary%20vô%20hại.md) (30/10) — hướng giảm việc Pulse gắn cờ process vô hại mới
  (truy vết process, đặc trưng hành vi, thực hành của công cụ runtime, phương pháp học và đánh giá) và kế hoạch xếp hạng;
  ghi chú nguồn: [research_notes/Giảm gắn cờ binary vô hại/](research_notes/Giảm%20gắn%20cờ%20binary%20vô%20hại/).

## Báo cáo buổi họp (bản chụp tại ngày họp, không cập nhật)

- 16/10: `docs/Bao_cao_Sentinel_Pulse.docx`, `docs/Bao_cao_Thi_nghiem_Syscall_Feature.docx`, `docs/Bao_cao_RCA.docx`,
  `docs/Slide-runtime_security(16_10).pptx`.
- 23/10: `docs/Bao_cao_tien_do_16_10-23_10.docx` (tiến độ 16/10–23/10 của cả 3 thí nghiệm và phần rule, cùng định dạng
  với báo cáo 16/10; có chỉnh sửa của chủ đồ án; 5 hình: 4 hình từ `docs/figures` bản không CI và cây RCA ví dụ) và
  `docs/Slide-runtime_security(23_10).pptx` (19 slide, không có hình). Số liệu lấy từ 4 báo cáo hiện hành lúc 23/10 04:20;
  lượt xác nhận `pulse-stable-confirm` khi đó đang chạy.
- 30/10: `docs/Bao_cao_tien_do_23_10-30_10.docx` (21 trang, cùng mẫu với báo cáo 23/10; nội dung đi theo bản luận văn `thesis/`: bài toán, thiết kế, đánh giá theo 6 câu hỏi nghiên cứu, mục "Đọc đúng các con số" trả lời câu hỏi về overfitting, độ phủ 5 kịch bản, 5 chế độ tải, ADFA-LD, binary vô hại 89,5%, precision 1:1; hướng giảm gắn cờ binary vô hại theo nghiên cứu 30/10) và `docs/Slide-runtime_security(30_10).pptx` (19 slide). Số liệu lấy từ 4 báo cáo hiện hành và biên nhận lúc 30/10 01:40; lượt `pulse-live-recal-confirm` khi đó đang chạy.
- Báo cáo docx và slide **không ghi CI** (khoảng tin cậy, bootstrap); CI đầy đủ nằm trong 4 báo cáo `.md` (quyết định 23/10,
  áp dụng cả cho các báo cáo docx 16/10).

## Bằng chứng

`validation-evidence/` chứa biên nhận, checksum và kết quả nhỏ của từng lượt chạy
(`pulse/`, `syscall/`, `rca/`, `results-20261018/` … `results-20261029/`). Không sửa file đã niêm phong để chỉnh báo cáo;
dữ liệu lớn nằm trên NFS của cụm (`/mnt/sentinel-pulse-archive`).
