# Danh mục tài liệu

## Báo cáo hiện hành (cập nhật liên tục, mỗi file có nhật ký làm việc riêng)

1. [SENTINEL_PULSE_STATUS.md](SENTINEL_PULSE_STATUS.md) — Pulse (phát hiện ML): tóm tắt, trạng thái cụm và job,
   thuật ngữ, kết quả các lượt (soak 48 giờ, pulse-attack-dev, hiệu chỉnh lại, live pulse-live-recalibrated,
   pulse-stable-candidate, pulse-stable-refreshed), luật chọn chính sách v2, biên Pareto, baseline ML (5.15),
   giảm gánh cảnh báo (5.22), hạ tầng chung, nhật ký. Chỉ số liệu ML, không có rule.
2. [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) — thí nghiệm chọn syscall:
   thiết kế syscall-arms, holdout, replay attack, so sánh ở cùng ngân sách cảnh báo, luật chọn, nhật ký.
3. [RCA_RUNTIME_STATUS.md](RCA_RUNTIME_STATUS.md) — RCA: subscriber, policy Tetragon, xếp hạng nghi phạm,
   độ phủ trong campaign, sự cố đã xử lý, nhật ký.
4. [RULE_INTEGRATION_STATUS.md](RULE_INTEGRATION_STATUS.md) — phần rule, tách riêng khỏi ML (22/10): Falco
   (framework có sẵn), tripwire A1, tầng triage probe sau ML, hệ thống gộp; nguyên tắc tách và nhật ký.
5. [TODO.md](TODO.md) — danh sách việc theo mức ưu tiên.
6. [RESEARCH_IDEAS.md](RESEARCH_IDEAS.md) — đánh giá tổng thể (điểm mạnh, khoảng cách G1–G9, đề xuất, % tiến độ),
   ý tưởng từ tài liệu (R1–R8, A1–D1), công trình liên quan và nguồn.
7. [README.md](README.md) gốc — hướng dẫn đọc repo: thứ tự đọc, cách đánh số mục, từ con số trong báo cáo tới biên nhận, script và luật đăng ký trước; những gì không nằm trong git.
8. [references/README.md](references/README.md) — danh mục bài báo và nguồn đã trích (`catalog.json`, SHA-256 của bản PDF đã tải).
9. README trong từng thư mục (`sentinel_pulse/`, `testbed/`, `validation-evidence/` và các thư mục `results-*`) — hướng dẫn code và nguồn gốc biên nhận, không phải báo cáo tiến độ.
   `docs/figures/README.md` — hình cho luận văn và paper, sinh lại từ biên nhận.

## Báo cáo buổi họp (bản chụp tại ngày họp, không cập nhật)

- 16/10: `docs/Bao_cao_Sentinel_Pulse.docx`, `docs/Bao_cao_Thi_nghiem_Syscall_Feature.docx`, `docs/Bao_cao_RCA.docx`,
  `docs/Slide-runtime_security(16_10).pptx`.
- 23/10: `docs/Bao_cao_tien_do_16_10-23_10.docx` (tiến độ 16/10–23/10 của cả 3 thí nghiệm và phần rule, cùng định dạng
  với báo cáo 16/10) và `docs/Slide-runtime_security(23_10).pptx` (18 slide). Số liệu lấy từ 4 báo cáo hiện hành lúc
  23/10 01:50; lượt xác nhận `pulse-stable-confirm` khi đó đang chạy.

## Bằng chứng

`validation-evidence/` chứa biên nhận, checksum và kết quả nhỏ của từng lượt chạy
(`pulse/`, `syscall/`, `rca/`, `results-20261018/`, `results-20261019/`, `results-20261021/`). Không sửa file đã niêm phong để chỉnh báo cáo;
dữ liệu lớn nằm trên NFS của cụm (`/mnt/sentinel-pulse-archive`).
