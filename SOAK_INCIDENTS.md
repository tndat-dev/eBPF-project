# Sentinel Pulse — lỗi và alert trong soak đang chạy

## Trạng thái hiện hành

Kiểm tra trực tiếp bằng SSH ngày **06/10/2026 lúc 21:21 ICT (UTC+7)**. Campaign: `pulse-observation-c1-20261006`, control plane `dat@10.1.16.234`.

**Campaign vẫn active; không bị dừng/reset trong lần kiểm tra này.** MainPID `528252`, NRestarts `1` không đổi. Restart duy nhất này thuộc lần chuyển controller trước đó, không phải sự cố mới. Đợt đang thu là `s0025`; collector và detector trên cả ba worker active, detector NRestarts `0` tại kiểm tra trực tiếp. Registration SHA-256 giữ nguyên: `10457f3f7f3823293258bf9fc8fcd1c14907cc29db68c232aca935f1a1be186f`.

Snapshot kiểm chứng: [inspection.json](validation-evidence/soak-inspection-20261006/inspection.json). Đây là trạng thái đang chạy, không phải terminal report hay formal PASS.

| Chỉ số tại snapshot | Giá trị đo được |
|---|---:|
| Wall time từ registration | Khoảng 12,21 giờ |
| Đợt đã ghi vào journal | 24; không phải 24 đợt đều đủ 30 phút |
| Exposure hợp lệ trong `STATUS.json` | 9,61–10,02 giờ/workload, 21 workload |
| Decision trong các receipt đã audit, gồm correction s0024 | 5.191.787 |
| Alert giữ lại trong các receipt | 1, Redis |
| Alert thuộc exposure normal được admission | 0 |
| Precision/recall đã adjudication | Chưa có; `null` |

`STATUS.json` chưa nhập correction s0024 tại thời điểm snapshot; vì vậy exposure trong bảng chưa gồm phần được khôi phục của đợt đó. Coordinator sẽ nhập correction khi kết thúc đợt đang chạy. Không dùng thời gian wall hoặc tổng decision thay cho scored exposure. Không suy ra false-positive rate bằng 0 từ việc chưa có alert được admission.

## Danh sách sự cố và cách xử lý

| Sự cố | Bằng chứng đã xác minh | Tác động và xử lý hiện hành |
|---|---|---|
| Lỗi audit cgroup ID ban đầu, s0001–s0014 | Feature dùng số nguyên, decision dùng chuỗi; 14 correction receipts và journal backfill | Đã kiểm chứng lại toàn bộ 14 đợt. Backfill service kết thúc `Result=success`. Raw/journal gốc không sửa; thời gian tốt được giữ. |
| s0010: worker đang seal nhưng vượt thời gian quan sát trạng thái unknown | Supervision lúc **14:27:05 ICT**: `worker connectivity unknown beyond bound: 10.1.16.237`; reply `.237` là `unavailable`, reason `worker_sealing` | Đợt con bị kết thúc; audit giữ được prefix hợp lệ trên ba worker. Campaign tiếp tục đợt sau. Cần cải thiện phân biệt sealing và mất kết nối sau phép đo; chưa đủ bằng chứng gọi đây là lỗi mạng. |
| s0018: preflight không thành công trên `.237` | `segments.jsonl`: `worker preflight failed: 10.1.16.237` | Không có worker audit cho đợt này, không cộng exposure. Campaign đã tự thử đợt tiếp theo. Log generic hiện không đủ để xác định chính xác nguyên nhân; không tự gán thành thiếu tài nguyên hay lỗi SSH. |
| s0019: stream telemetry ngừng tiến triển trên `.237` | Worker journal lúc **18:17:35 ICT**: `stream stalled beyond registered recovery gap budget`; worker terminal `exit_code=1` lúc khoảng **18:17:40 ICT** | Đợt con bị seal và kết thúc; prefix tốt vẫn được audit, campaign thu tiếp. Detector được shutdown trong cleanup, không có bằng chứng model inference crash. Nguyên nhân sâu của stream stall chưa xác định. |
| s0024: audit ban đầu trả RuntimeError trên cả ba worker | Journal gốc giữ ba lỗi generic; kiểm tra lại raw seals và audit đều thành công trên cả ba worker | Đã ghi correction receipt lúc **21:20:45 ICT**, không dừng worker đang thu. Nguyên nhân lỗi ban đầu chưa xác định; không khẳng định do race/network khi chưa có traceback gốc. |
| Longhorn degraded trong một số khoảng | Dependency health ghi `longhorn_volume_unhealthy` ở s0006, s0008–s0013, s0015–s0017, s0019–s0020 | Campaign không dừng vì cảnh báo này. Khoảng health degraded vẫn được ghi và loại khỏi normal exposure theo contract. Snapshot health của s0025 không degraded/fatal. Chưa điều tra nguyên nhân từng volume degraded trong lần kiểm tra này. |

Các audit retry khác cũng được giữ trong `audit-recovery-errors.jsonl`: s0015, s0017, s0021. Các đợt này đã có correction thành công; không gọi mỗi lần retry là một lần campaign fail. Tại snapshot, phần thiếu audit trong `STATUS.json` là s0018 và s0024; s0024 đã có correction mới chờ nhập vào summary.

### Chi tiết s0019: không nhầm cleanup với lỗi model

Collector `.237` thực sự bắt đầu lúc `1791285165.1621163`. Journal còn ghi telemetry `ready`, sequence 506, maximum snapshot gap khoảng **0,518 giây** tại **18:17:01 ICT**. Sau đó health checker báo stream stalled lúc **18:17:35**.

Detector được systemd stop có chủ đích lúc **18:17:35–18:17:36**; collector được stop lúc **18:17:39**. Supervision thấy detector inactive lúc **18:17:40** và trả thêm các thông báo binding/lifecycle invalid. Thông báo này không giải thích đầy đủ nguyên nhân ban đầu; worker journal chỉ ra stream stall trước cleanup.

[Worker terminal đã lấy từ VM](validation-evidence/soak-inspection-20261006/s0019-worker-terminal.json) xác nhận exit code 1. Không sửa receipt thành thành công và không gọi thời gian bị thiếu là normal. Chưa có bằng chứng xác định stall do CPU, RAM, disk, resolver hoặc loader.

### Chi tiết s0024: khôi phục audit, không chạy lại capture

Kiểm tra `sha256sum --check --strict FORMAL_WORKER_SHA256SUMS` trên cả ba worker đều exit 0. Audit lại cùng raw streams, marker, model và health journal thành công:

| Worker | Decision được kiểm chứng | Alert |
|---|---:|---:|
| 10.1.16.237 | 73.533 | 0 |
| 10.1.16.238 | 87.096 | 0 |
| 10.1.16.239 | 74.118 | 0 |
| Tổng | 234.747 | 0 |

Receipt: [s0024-corrected-audit.json](validation-evidence/soak-inspection-20261006/s0024-corrected-audit.json). Correction bind checksum START và health journal gốc, có commit/checksum auditor. One-shot `sentinel-pulse-reconcile-s0024-20261006.service` kết thúc `Result=success`; không sửa `segments.jsonl`, không thay model/threshold, không relaunch collector.

## Alert Redis cần adjudication

Raw alert được giữ nguyên trong [redis-alert-s0012.jsonl](validation-evidence/soak-inspection-20261006/redis-alert-s0012.jsonl); checksum đã đối chiếu với receipt audit của `.237`.

| Trường | Giá trị từ raw alert |
|---|---|
| Thời điểm | **15:20:55,735 ngày 06/10 ICT** |
| Run/pod/node | s0012 / `aims-redis-0` / `k8s-worker1.local` |
| Workload | `production/aims-redis:aims-redis` |
| Score | 0,8183227556 |
| Conformal p | 0,0001873361 |
| Security mass | 58 |
| Nhóm trigger | `identity_transition`, observed 34, normal_max 19 |
| Security counts | socket 2, connect 4, clone3 5, setuid 16, setgid 16, capset 2, openat 13 |
| Temporal confirmation | Hai window liên tiếp |
| Inference | 26,82 ms |
| Window-end → alert | Khoảng 0,770 giây; **không phải kernel-to-alert** |

Telemetry/freshness của decision hợp lệ, nhưng thời điểm alert nằm trong khoảng health degraded của normal soak; receipt giữ `all_alerts=1`, `eligible_alerts=0`. **Bị loại khỏi mẫu normal hợp lệ không có nghĩa alert bị xóa hoặc được chứng minh đúng.** Trạng thái adjudication: **uncertain**. Cần đối chiếu probe/maintenance/process evidence trước khi kết luận TP/FP; exact counters không cho biết process nào thực hiện các syscall này.

Không chỉnh model hoặc policy dựa vào alert này khi campaign chưa kết thúc. Không tuyên bố precision 100%, false positive 0%, hoặc kernel-to-alert đạt 1–2 giây từ một alert không có attack injection timestamp.

## Tài nguyên và điều kiện hiện hành

Cả sáu node Ready; DiskPressure, MemoryPressure, PIDPressure đều False tại truy vấn API. Ba worker đang chạy collector/detector và còn dung lượng:

| Worker | Disk available, `df -h` | Disk used | RAM available, `free -m` |
|---|---:|---:|---:|
| .237 | 196 GiB | 66% | 30.288 MiB |
| .238 | 151 GiB | 74% | 31.891 MiB |
| .239 | 115 GiB | 80% | 32.976 MiB |

Đây là số đo tức thời, không cam kết đủ cho mọi tăng trưởng. `.239` cần tiếp tục theo dõi disk; lần kiểm tra này không xóa raw data, không scale workload và không dừng soak để dọn đĩa.

## Lệnh kiểm chứng và nguồn log trên VM

Trên `.234`:

```bash
systemctl show sentinel-pulse-observation-campaign.service \
  -p ActiveState -p MainPID -p NRestarts

cd /home/dat/sentinel-pulse-observation-campaigns/pulse-observation-c1-20261006
python3 -m json.tool STATUS.json
python3 -m json.tool pulse-observation-c1-20261006-s0024-corrected-audit.json
# Journal có thể rất dài: đọc bằng parser, không in toàn bộ interval ra terminal.
ls segments/*/TERMINAL.json
```

Trên `.237`, truy vấn s0019 (journal hiển thị UTC; báo cáo quy đổi UTC+7):

```bash
journalctl -u sentinel-pulse-recovery-worker-pulse-observation-c1-20261006-s0019.service \
  --since '2026-10-06 11:15:00 UTC' --until '2026-10-06 11:21:00 UTC' --no-pager

sudo cat /var/lib/sentinel-pulse-recovery-formal/pulse-observation-c1-20261006-s0019/WORKER_TERMINAL.json
sudo cat /var/lib/sentinel-pulse-500ms/runs/pulse-observation-c1-20261006-s0012/alerts.jsonl
```

Thư mục mỗi đợt trên `.234` chứa `dependency-health.jsonl`, `SUPERVISION.jsonl`, API snapshots và terminal nếu có. Raw streams và seals trên worker nằm dưới `/var/lib/sentinel-pulse-500ms/runs/<run-id>/`. Giữ nguyên chứng cứ, thu tiếp sau phục hồi và chỉ đánh giá chất lượng khi kết thúc campaign. Mốc 24 giờ wall time là khoảng **09:10 ngày 07/10**; có thể thu bù exposure đến hạn đã đăng ký, không reset từ đầu.
