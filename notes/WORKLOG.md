# Nhật ký làm việc

Mỗi dòng: thời điểm (giờ Việt Nam, lấy từ `date`, dữ liệu hoặc giờ commit, không ước tính; các dòng 07/11 từng ghi sai giờ đã sửa theo commit và dữ liệu), việc, kết quả hoặc biên nhận. Trước 07/11 xem nhật ký trong các file trạng thái cũ
(`git show 8b1bc44:SENTINEL_PULSE_STATUS.md`, mục 11).

| Khi | Việc | Kết quả / biên nhận |
|---|---|---|
| 01/11 | Chủ đồ án: chỉ phát triển ML, luật để sau | v2–v4 thành đối chứng luật |
| 02/11 | `lidds-ml-v1` | Âm: 65,2% official |
| 05/11 | `lidds-ml-v2` official | 95,99% / 0,57% / p95 2,32 s (`results-20261105/lidds-ml-v2/`) |
| 06/11 | Bảng chữ token theo chi phí probe, kiểm kê syscall, biến thể token, LSTM lớn, bằng chứng ngưỡng | `results-20261105/ml-exploration/` |
| 06/11 | Báo cáo và slide buổi 06/11 | `docs/Bao_cao_tien_do_30_10-06_11.docx`, `docs/Slide-runtime_security(06_11).pptx` |
| 06/11 | Chủ đồ án nới giới hạn overhead cho probe token | `reports/Thiết kế probe token Pulse.md` mục 5 |
| 07/11 01:02 | `lidds-ml-v3` official (lần chấm thứ 2, đã khai báo) | 97,32% / 0,44% / p95 2,09 s (`results-20261107/lidds-ml-v3/`) |
| 07/11 01:04 | Bản LaTeX theo v3 | 75 trang |
| 07/11 01:12 | Kiểm offline 2: ngưỡng theo khối trên lượt live cuối | Recall cụm 52–78% với riêng cây + support (`results-20261107/ml-block-threshold-live/`) |
| 07/11 07:53 | Xoá 4 file trạng thái (nội dung còn ở git `8b1bc44`), thêm `notes/STATE.md` và `notes/WORKLOG.md`; audit bỏ các câu trong file trạng thái, thêm 5 câu cho bảng hệ thống cuối trong bản LaTeX (48/48 khớp); xoá 2 script lỗi thời (`lidds2019_fetch_after_live.sh`, `lidds_v2_after_live.sh`), file tạm cục bộ; `fetch_references.py` bỏ User-Agent giả trình duyệt | commit gộp |
| 07/11 07:56 | Kiểm offline 1 của probe (`probe1f`, token của syscall không có hook phát lúc vào): development 530/544 như `select1f`, báo nhầm 21 so với 19 (thêm ở EPS_CWE-434), CB-DS 0 so với 2 báo nhầm | `results-20261105/ml-exploration/probe-order.txt` |
| 07/11 07:56 | Dọn cụm: `.234` xoá dữ liệu phân tích đã có biên nhận (ml-scores, ml-v1, ml-teacher*, ml-variants, ml-alphabets, ml-select*, ml-inventory, ml-probe-order, v2, v3-window, v4, converted*, script tải dataset, js-diag, baselines/models, snapshot nguồn), unit của lượt `pulse-live-recal-confirm` trên `.234` và 3 worker; xoá bản cục bộ của lượt đó trên 3 worker (33 GB; NFS có đủ 48/48 segment mỗi worker, bản nén có niêm phong) | `/var/tmp/lid-ds-2021` còn archive, `ml-scores-allwin`, `ml-tokens`, `ml-v3-tokens`, `ml-links` |
| 07/11 07:57 | Ablation vòng 2 (3 seed): chọn 45/46 cấu hình theo luật protocol từ biên nhận vòng 1 (chỉ `drop_accept` không vào) | `results-20261107/syscall-loo-stage2/ARMS.json`, `scripts/syscall_loo_stage2.sh` |
| 07/11 09:40 | Viết probe token (`make tokens`): 39 `fexit`, `fentry/security_file_open` + `bpf_d_path`, token 32 bit, map 4-gram theo (cgroup, cửa sổ); loader `--tokens`; kiểm chức năng trên k8s-worker1: token đúng, gắn 40 hook khoảng 10 s | `reports/Thiết kế probe token Pulse.md` mục 7 |
| 07/11 09:46 | Overhead A–D (`token-probe-overhead-v1`, đăng ký trước khi đo) trên 3 worker cùng lúc, 5 vòng × 7 điều kiện × 5 chế độ | `results-20261107/token-probe-overhead/` |
| 07/11 10:00 | Worker: `tokens.jsonl` mỗi segment, chấm trực tuyến (`TokenBranch`); mô hình đếm = `TokenLM` offline (test); script proof, fit nhánh token, đo lưu lượng | 562 test qua (bỏ test cần torch) |
| 07/11 11:53 | Overhead lần 1 (`fexit`): getpid +32–39 ns so với A, futex +277–316, read 4 KiB +226–349, open + close +2,3–2,7 µs và +1,8–2,1 µs cho process không giám sát | `results-20261107/token-probe-overhead/overhead-run1-fexit.json` |
| 07/11 12:05 | Chẩn đoán: chi phí open tăng theo số trampoline, do kprobe Tetragon trên `__x64_sys_openat` đẩy hàm qua `ftrace_ops_list_func`; sửa: `--token-exit sys_exit` (mặc định), proof cả hai chế độ đạt (đúng 1 token/syscall) | `hookcost*.jsonl`, `proof-check-*.json`, amendment 1 |
| 07/11 12:09 | Overhead lần 2 (amendment 1, `sys_exit` và `fexit` cùng vòng) trên 3 worker | unit `token-probe-overhead-2` |
| 07/11 15:20 | Overhead lần 2: `sys_exit` so với A: getpid +101–131 ns, read +187–199, open + close +1,1–1,5 µs (fexit +2,3–3,1), futex +293–317 | `overhead-run2.json` |
| 07/11 15:23 | Chẩn đoán 3: `fentry/security_file_open` tốn khoảng 380 ns mỗi lần mở của mọi process; thay bằng đi ngược dentry từ fd lúc open trả về (`bpf_loop`), probe không còn ftrace_ops; proof cả hai chế độ đạt | `hookcost3.jsonl`, amendment 2 |
| 07/11 15:27 | Overhead lần 3 (bản đi ngược dentry) trên 3 worker | unit `token-probe-overhead-3` |
| 07/11 15:29 | Nhánh đếm v3 trong worker (`detector/v3_policy.py`, cfg `v3_counts`), `count_branch_fit.py`, planner `--token-build --token-models --v3-counts`; protocol `pulse-live-v3-v1` (thu normal 12 h rồi live blind 24 h) đăng ký trước mọi dữ liệu | `sentinel_pulse/protocol/pulse-live-v3-v1.json` |
| 07/11 16:10 | Overhead lần 3 (bản cuối, không ftrace_ops): so với A getpid +127–174 ns, read +210–229, open + close +0,94–1,23 µs, mmap + munmap +413–699, futex +216–298 | `overhead-run3.json` |
| 07/11 15:45 | Sơ đồ kiến trúc 5 trang bằng draw.io (tổng quan, probe, worker + ML v3, cảnh báo + RCA, học và đánh giá), sinh bằng script, xuất PNG/SVG/PDF | `docs/architecture/` |
| 07/11 16:15 | Build chính thức `/home/dat/pulse-tokens-20261107` trên 3 worker từ 46e9039, proof đạt cả 3; chạy 150 s trên allow-list production thật: dòng token 75–290 KB/s (gzip ~9x), rút map trung vị 2–6 ms, không chèn hỏng; thư mục đầu đúng góc nhìn container | `results-20261107/token-probe-build/` |
| 07/11 16:21 | Ablation vòng 2: dump của worker4 bị OOM kill lúc 09:12 (3 dump + 2 replay chạm trần 40 GB của unit; OOMPolicy=continue nên unit chạy tiếp thiếu worker4). Replay đã xong; dừng unit, xoá 3 segment dở (chỉ có file .partial, đúng segment sau `STATUS.last`), chạy lại cùng script với trần 42 GB: 3 dump đang chạy (worker1 12/49, worker3 38/49, worker4 1/49 segment xong) | unit `syscall-loo-stage2` |
