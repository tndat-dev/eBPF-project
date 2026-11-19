# Kiến trúc Sentinel Pulse (draw.io)

`sentinel-pulse-architecture.drawio`: 5 trang, trạng thái 19/11/2026: hệ thống của lượt live cuối `pulse-live-final-1119`
(`lidds-ml-v5-t3`: chỉ mô hình token, top 3, trim 0,5%, α′ 0,0003; thẻ dòng dõi từ `sched_process_fork`; cảnh báo khi map
gram đầy (D1); hàng đợi bền của bridge (D3); nhãn `stream` của cảnh báo; bộ ghi sự kiện Kubernetes).

`sentinel-pulse-overview-en.drawio`: một trang tiếng Anh, Figure 1 của paper (`export/overview-en.pdf`, `overview-en.png`).

**Mọi tài liệu chỉ dùng các hình draw.io này** (chủ đồ án, 19/11): đồ án chèn từng trang của
`export/sentinel-pulse-architecture.pdf` (Hình 4.1 = trang 1, 4.2 = trang 3, 4.3 = trang 4, 5.1 = trang 2, 6.1 = trang 5);
báo cáo và slide dùng `export/1-tong-quan.png`, `export/2-probe-ebpf.png`; paper dùng `export/overview-en.pdf`. Không còn
hình TikZ. Sửa hình thì sửa `make_architecture_drawio.py`, chạy lại, xuất lại, rồi dựng lại tài liệu.

1. Tổng quan hệ thống: cụm, node, NFS, đường dữ liệu từ kernel tới cảnh báo, thành phần chỉ dùng khi đánh giá.
2. Probe eBPF: các hook (`sys_enter`, `sys_exit`, `fexit/__seccomp_filter`), map, bố cục token 32 bit, loader, đầu ra JSON.
3. Worker và mô hình token: cửa sổ token, mô hình ngôn ngữ theo workload, điểm, ngưỡng, decision, khoá SHA, học mô hình.
4. Cảnh báo và RCA: bridge, Alertmanager, route, Tetragon, dựng case, xếp hạng nghi phạm, triage.
5. Học và đánh giá: LID-DS, CB-DS, lượt thu và lượt live, protocol, biên nhận.

File được sinh bởi `make_architecture_drawio.py` (sửa script rồi chạy lại, hoặc mở file bằng draw.io và sửa tay; sinh lại
sẽ ghi đè sửa tay). Xuất bằng draw.io desktop (`snap install drawio`):

```bash
python3 make_architecture_drawio.py
drawio -x -f png -p 1 -s 2 -b 20 -o export/1-tong-quan.png sentinel-pulse-architecture.drawio   # từng trang
drawio -x -f svg --embed-svg-fonts false -p 1 -b 20 -o export/1-tong-quan.svg sentinel-pulse-architecture.drawio
drawio -x -f pdf -a --crop -b 20 -o export/sentinel-pulse-architecture.pdf sentinel-pulse-architecture.drawio
drawio -x -f pdf --crop -b 10 -o export/overview-en.pdf sentinel-pulse-overview-en.drawio
drawio -x -f png -s 2 -b 10 -o export/overview-en.png sentinel-pulse-overview-en.drawio
```

Nội dung lấy từ `thesis/chapters/design.tex`, `implementation.tex`, `sentinel_pulse/ebpf/`, `pipeline/matched_worker.py`,
`ops/alert_bridge.py`, protocol `lidds-ml-v5`, `lidds2019-development-v1`, `improvement-round-v1`, `pulse-live-final-v1`; số liệu chỉ từ biên nhận đã ghi trong `notes/STATE.md`.

Mô tả từng thành phần trong hình và code tương ứng (file, hàm): `KIEN_TRUC.md` trong thư mục này.
