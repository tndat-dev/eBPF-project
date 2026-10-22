# Ví dụ cây RCA thật (chép nguyên bản 23/10)

Hai case do dịch vụ RCA (`sentinel_pulse/rca/service.py`) dựng trên cụm, chép nguyên từ `.234`; SHA-256 khớp file gốc (`SHA256SUMS`). Mỗi case có ba file:

- `.json`: cây bằng chứng đầy đủ (nút, cạnh, nghi phạm, phạm vi thu, giới hạn). Đây là bằng chứng.
- `.md`: bản đọc nhanh do chính dịch vụ RCA viết lúc dựng case.
- `.svg`: hình vẽ để đọc, sinh lại bằng `python3 scripts/analysis/rca_case_graph.py <case>.json --output <case>.dot`. Hình không thêm suy luận nào.

| File | Lượt | Là gì |
|---|---|---|
| `attack-ptrace-api-gateway-2e6d889a740dd5b609786274.*` | `pulse-stable-refreshed` (21/10), case trong `/var/lib/sentinel-pulse-rca/rca-pulse-stable-refreshed/cases/` | Trial 21 của campaign, kịch bản `child_ptrace_handshake` trên `production/api-gateway:app` (worker1). Nghi phạm hạng 1 là đúng binary tấn công `/tmp/sentinel-runtime-attack-blind`, lý do `novel_binary`, `spawned_children`, `started_in_window`. Nó fork 16 tiến trình con, mỗi con gọi `ptrace` (hạng 2–17, lý do `security_operation`). Khớp biên nhận `results-20261021/pulse-stable-refreshed/rca-ranking-reranked.json` (trial `21:attack`, hạng 1) |
| `normal-probe-inventory-service-00a0b1e0f074049e0b62676c.*` | `pulse-stable-confirm` (23/10, đang chạy lúc chép) | Cảnh báo trên dữ liệu bình thường của `production/inventory-service:app` (worker3). Trong cửa sổ có 8 exec, cả 8 đều là exec probe Kubernetes khai báo trong pod spec (`python`, do `runc` khởi chạy, nối vào loopback), nên `triage.probe_only = true`. Nhãn này chỉ là chú thích, không ẩn case (Pulse 5.18) |

## Cách đọc một case JSON

- **Trigger (`nodes[kind=signal].trigger`):** dòng decision của Pulse đã khớp hash model và chính sách đóng băng (`candidate_manifest_sha256`, `policy_sha256`), có `window_end` và `joint_p`. `trigger_kind = candidate_alert_preview`: đây là cảnh báo thử (shadow).
- **Ghép bằng chứng:** chỉ theo định danh chính xác (node, pod UID, container) và khoảng thời gian 30 s trước đến 5 s sau trigger. Không ghép theo PID, tên pod hay IP (`join`).
- **Nút:**
  - `process` / `process_parent`: process có `exec_id` của Tetragon, kèm binary, PID, cwd;
  - `runtime_event`: exec, fork, ptrace, exit, mở/ghi file nhạy cảm…; `target_object` trỏ tới đối tượng như `executable`, `fork_child`, `ptrace_target`;
  - `connect_attempt` / `active_flow`: `connect()` và luồng TCP được lấy mẫu, mỗi process tối đa 10 s một lần;
  - `destination`: IP:port, kèm `kubernetes` nếu ánh xạ được.
- **`suspects` / `suspect_ranking`:** thứ tự để người điều tra xem trước, theo luật (binary mới hoặc chưa biết, tạo tiến trình con, thao tác bảo mật, bắt đầu trong cửa sổ…). `method = heuristic_triage_order_not_probability`: đây không phải xác suất.
- **Giới hạn ghi ngay trong case:**
  - `causal_root_confirmed = false`, `automatic_response = false`, `application_payload_captured = false`;
  - `limitations` liệt kê: anomaly tổng hợp không chứng minh process nào gây ra; chi tiết file được lấy mẫu; syscall bị seccomp chặn trước kprobe thì không thấy.

## Lưu ý về ánh xạ IP trong hai case này

Hai case dựng **trước** bản sửa ngày 23/10 (`connect.py`, RCA mục 5.13). Vì vậy một số đích là IP node (`10.1.16.238`, `10.1.16.239`, cổng tạm) bị ghi là pod `node-exporter`. Thực ra đó là IP node, dùng chung bởi các pod `hostNetwork` và bởi lưu lượng đã qua SNAT; peer thật không xác định được.

Từ lượt RCA sau, các địa chỉ này được ánh xạ thành `Node` kèm `ambiguous: true`. File gốc ở đây giữ nguyên, không sửa.
