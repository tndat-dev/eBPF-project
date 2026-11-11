# Kiến trúc Sentinel Pulse (draw.io)

`sentinel-pulse-architecture.drawio`: 5 trang, trạng thái 11/11/2026 (hệ thống `lidds-ml-v5`: chỉ mô hình token;
bản LaTeX của đồ án có cùng nội dung dưới dạng sơ đồ TikZ trong `thesis/figures/tikz-*.tex`).

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
```

Nội dung lấy từ `thesis/chapters/design.tex`, `implementation.tex`, `sentinel_pulse/ebpf/`, `pipeline/matched_worker.py`,
protocol `lidds-ml-v5` và `pulse-live-v3-v1`; số liệu chỉ từ biên nhận đã ghi trong `notes/STATE.md`.
