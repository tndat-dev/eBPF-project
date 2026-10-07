# Sentinel Pulse — lỗi và alert trong campaign soak hiện hành

## Trạng thái hiện hành

Kiểm tra trực tiếp bằng SSH ngày **07/10/2026 lúc 13:24 ICT (UTC+7)**. Campaign: `pulse-observation-c1-20261006`, control plane `dat@10.1.16.234`. Cập nhật trạng thái hiện hành, không bổ sung checkpoint lịch sử.

**Campaign đã hoàn thành lúc 12:42:20 ngày 07/10.** MainPID `0`, `active/exited`, Result `success`, NRestarts `1`. Restart duy nhất thuộc lần chuyển controller trước đó, không phải sự cố mới. Không còn active segment và không relaunch soak. Registration SHA-256 giữ nguyên: `10457f3f7f3823293258bf9fc8fcd1c14907cc29db68c232aca935f1a1be186f`.

Snapshot cuối kỳ: [inspection.json](validation-evidence/soak-completion-20261007/inspection.json), [terminal report](validation-evidence/soak-completion-20261007/TERMINAL.json). Raw receipts trước đó vẫn giữ để truy nguyên. Đây là observation campaign completed, không phải formal PASS của protocol legacy hoặc chứng minh model không có false positive.

| Chỉ số tại snapshot | Giá trị đo được |
|---|---:|
| Wall time từ registration đến terminal | 27,55 giờ |
| Đợt đã ghi vào journal | 54; không phải mọi đợt đều đủ 30 phút |
| Exposure hợp lệ trong `STATUS.json` | 24,17–25,08 giờ/workload, 100% mục tiêu cho 21 workload |
| Decision trong các receipt đã audit | 12.223.588 |
| Alert giữ lại trong các receipt | 1, Redis |
| Alert thuộc exposure normal được admission | 0 |
| Precision/recall đã adjudication | Chưa có; `null` |

`STATUS.json` đã nhập correction/retry, gồm s0048/s0050/s0053. Đợt preflight lỗi s0018 vẫn không có dữ liệu để cộng. Không dùng wall time hoặc tổng decision thay cho scored exposure; không suy FPR bằng 0 từ việc chưa có alert được admission.

Snapshot lúc giữa hai đợt có thể không có `active_segments`, dù service vẫn active để audit/repair receipts. Đây là gián đoạn scoring giữa các đợt, không được claim detector chạy liên tục không gián đoạn. Mọi gap vẫn phải thể hiện trong exposure/availability; không chỉ dựa vào `ActiveState=active` để kết luận telemetry khỏe.

## Danh sách sự cố và cách xử lý

| Sự cố | Bằng chứng đã xác minh | Tác động và xử lý hiện hành |
|---|---|---|
| Lỗi audit cgroup ID ban đầu, s0001–s0014 | Feature dùng số nguyên, decision dùng chuỗi; 14 correction receipts và journal backfill | Đã kiểm chứng lại toàn bộ 14 đợt. Backfill service kết thúc `Result=success`. Raw/journal gốc không sửa; thời gian tốt được giữ. |
| s0010: worker đang seal nhưng vượt thời gian quan sát trạng thái unknown | Supervision lúc **14:27:05 ICT**: `worker connectivity unknown beyond bound: 10.1.16.237`; reply `.237` là `unavailable`, reason `worker_sealing` | Đợt con bị kết thúc; audit giữ được prefix hợp lệ trên ba worker. Campaign tiếp tục đợt sau. Cần cải thiện phân biệt sealing và mất kết nối sau phép đo; chưa đủ bằng chứng gọi đây là lỗi mạng. |
| s0018: preflight không thành công trên `.237` | `segments.jsonl`: `worker preflight failed: 10.1.16.237` | Không có worker audit cho đợt này, không cộng exposure. Campaign đã tự thử đợt tiếp theo. Log generic hiện không đủ để xác định chính xác nguyên nhân; không tự gán thành thiếu tài nguyên hay lỗi SSH. |
| s0019: stream telemetry ngừng tiến triển trên `.237` | Worker journal lúc **18:17:35 ICT**: `stream stalled beyond registered recovery gap budget`; worker terminal `exit_code=1` lúc khoảng **18:17:40 ICT** | Đợt con bị seal và kết thúc; prefix tốt vẫn được audit, campaign thu tiếp. Detector được shutdown trong cleanup, không có bằng chứng model inference crash. Nguyên nhân sâu của stream stall chưa xác định. |
| s0024: audit ban đầu trả RuntimeError trên cả ba worker | Journal gốc giữ ba lỗi generic; kiểm tra lại raw seals và audit đều thành công trên cả ba worker | Đã ghi correction receipt lúc **21:20:45 ICT**, không dừng worker đang thu. Nguyên nhân lỗi ban đầu chưa xác định; không khẳng định do race/network khi chưa có traceback gốc. |
| s0027/s0028: audit ban đầu trả RuntimeError | Receipt gốc giữ lỗi, sau đó cả hai đợt có correction thành công trên ba worker | Phục hồi tự động đã cộng lại exposure, không chạy lại capture hoặc reset campaign. Lỗi generic chưa đủ xác định nguyên nhân; không tự gọi là data corruption. |
| s0048/s0050/s0053: audit ban đầu trả RuntimeError | Receipt gốc giữ lỗi; correction cuối kỳ có ba worker audit thành công | Exposure tốt được phục hồi mà không rerun capture; chưa xác định nguyên nhân sâu của lỗi generic. |
| Longhorn degraded trong một số khoảng | Dependency health ghi `longhorn_volume_unhealthy`, gồm các đợt s0030/s0031/s0038/s0048 trong snapshot mới | Campaign không dừng vì cảnh báo này. Khoảng health degraded vẫn được ghi và loại khỏi normal exposure theo contract. Snapshot health của s0049 không degraded/fatal. Chưa điều tra nguyên nhân từng volume degraded trong lần kiểm tra này. |

Các audit retry khác giữ trong `audit-recovery-errors.jsonl`, gồm s0031/s0033/s0036/s0039/s0041/s0046; đã có ba worker audit thành công. Không gọi mỗi retry là một campaign fail. Phần thiếu cuối kỳ chỉ còn s0018 do preflight không có capture. Chưa có bằng chứng về nguyên nhân sâu của các RuntimeError generic.

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

Receipt: [s0024-corrected-audit.json](validation-evidence/soak-inspection-20261006/s0024-corrected-audit.json). Correction bind checksum START và health journal gốc, có commit/checksum auditor, đã được nhập vào summary hiện hành. One-shot `sentinel-pulse-reconcile-s0024-20261006.service` kết thúc `Result=success`; không sửa `segments.jsonl`, không thay model/threshold, không relaunch collector.

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

Cả sáu node Ready; DiskPressure, MemoryPressure, PIDPressure đều False tại truy vấn API đã ghi ở lần kiểm tra trước. Sau terminal, cả ba worker có collector/detector `inactive/dead`, Result `success`, MainPID `0`: cleanup bình thường, không phải đang thu liên tục. Bảng tài nguyên bên dưới là **số đo cũ ngày 06/10**, disk lúc 23:05 và RAM lúc 21:21, không phải số đo mới ngày 07/10:

| Worker | Disk available, `df -h` | Disk used | RAM available, `free -m` |
|---|---:|---:|---:|
| .237 | 194 GiB | 66% | 30.288 MiB |
| .238 | 149 GiB | 74% | 31.891 MiB |
| .239 | 112 GiB | 81% | 32.976 MiB |

Đây là số đo tức thời, không cam kết đủ cho mọi tăng trưởng. `.239` cần tiếp tục theo dõi disk; không xóa raw data, không scale workload hoặc relaunch soak đã hoàn thành.

## Lệnh kiểm chứng và nguồn log trên VM

Review chỉ đọc trên Host, không thay gates và không audit raw seals:

```bash
python3 -m sentinel_pulse.review_observation \
  --inspection validation-evidence/soak-inspection-20261007/inspection.json
```

Review ghi cả tổng một alert và một alert ngoài admission; khoảng 0,0408 alert/giờ wall time trên toàn campaign. Đây **không phải FPR/precision** và không dùng làm ngân sách alert/workload-hour. Công cụ không có ground truth; các chỉ số TP/FP/precision/recall vẫn chưa đo.

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
