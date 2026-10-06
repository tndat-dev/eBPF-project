# Soak quan sát có phục hồi — trạng thái hiện hành

Cập nhật ngày 06/10/2026, múi giờ Asia/Bangkok. Đây là tài liệu trạng thái hiện hành; không bổ sung checkpoint lịch sử. Các biên bản đã kết thúc của hệ thống cũ giữ nguyên kết luận đã đăng ký.

## Trạng thái triển khai đã xác minh

Campaign `pulse-observation-c1-20261006` chạy bằng systemd trên `.234`, bắt đầu **09:09:24 ngày 06/10 ICT**. Tối thiểu 24 giờ wall time tới khoảng **09:10 ngày 07/10**; còn có thể kéo dài để đủ exposure từng workload, tối đa khoảng 09:10 ngày 08/10. Đây là thời hạn thiết kế, không phải cam kết sẽ đạt mọi tiêu chí chất lượng.

Tại kiểm tra live **16:45 ngày 06/10**, service active, đang thu đợt `s0015`; 14 đợt trước đã kết thúc và raw data được giữ. Cả ba worker báo detector active, can-score, không có lỗi supervision. Số đợt hoàn thành **không tương đương** số giờ normal hợp lệ.

Audit ban đầu bị lỗi đối chiếu `cgroup_id`: feature lưu số nguyên, decision lưu chuỗi. Bản sửa chuẩn hóa cách biểu diễn nhưng vẫn kiểm tra đúng identity/window/model/policy. Không sửa raw capture hay model. Audit thử lại `s0014` thành công ở cả ba worker: **234.702 decision, 0 alert trong riêng đợt này**; các row telemetry-degraded/warming vẫn loại khỏi scored exposure. Bằng chứng: [current-segment-corrected-audit.json](validation-evidence/syscall-analysis-20261006/current-segment-corrected-audit.json). Không suy rộng thành FPR = 0 hoặc precision = 100% cho toàn campaign.

Kiểm chứng lại các đợt đã seal đang chạy bằng `sentinel-pulse-audit-backfill-r3-20261006.service`. Report sửa được ghi thành `*-corrected-audit.json`; journal gốc không bị ghi đè. `BACKFILL_STATUS.json` là tổng hợp kiểm chứng bổ sung; coordinator nhập các receipt này khi hoàn thành đợt đang chạy rồi cập nhật `STATUS.json`. Trong thời gian backfill chưa xong, tổng exposure của `STATUS.json` có thể chưa phản ánh dữ liệu đã thu; không coi giá trị 0 cũ là bằng chứng không có telemetry.

Runtime worker giữ nguyên checkout **a3cdbfb** tại `/home/dat/eBPF-project-observation-r2-20261006`; controller/auditor dùng checkout **529d207** tại `/home/dat/eBPF-project-observation-audit-r3-20261006`. Khi chuyển controller, checksum `START.json` vẫn là `10457f3f7f3823293258bf9fc8fcd1c14907cc29db68c232aca935f1a1be186f`; PID và InvocationID của cả ba collector không đổi. Model, policy, protocol và thời điểm bắt đầu không đổi. Resume được ghi trong `RESUME.jsonl`, nguồn controller/auditor trong `CONTROLLER_BINDINGS.jsonl` và `CONTROLLER_EXECUTION.jsonl`.

Toàn bộ test Sentinel Pulse đã qua **661 test và 20 subtest**, gồm các kiểm tra recovery/audit/features và model. Phân tích syscall và 171 fit ablation đã hoàn thành; kết quả và giới hạn tại [syscall_analysis.md](syscall_analysis.md). Chưa có precision/recall end-to-end được adjudication hoặc phép đo blind kernel-to-alert mới cho campaign này.

## Mục tiêu và tiêu chí đã đăng ký

Campaign thu tối thiểu 24 giờ thực tế và hướng tới 24 giờ **được score hợp lệ cho từng workload**. Thời gian tối đa 48 giờ. Nếu chưa đủ khi hết hạn, xuất kết quả `completed_with_insufficient_coverage` cùng phần thiếu; không tự chạy lại từ đầu. Thời lượng là thiết kế thí nghiệm để quan sát chu kỳ vận hành, không phải yêu cầu bắt buộc của ExtraTrees.

Protocol: `sentinel_pulse/protocol/observation-campaign-v1.json`.

Ngân sách ban đầu: trung bình tối đa 0,01 alert/workload-hour, và tối đa 0,05 alert/hour cho từng workload. Đây là mục tiêu chất lượng được đánh giá cuối kỳ; vượt ngân sách vẫn tiếp tục thu và giữ mọi alert. Alert cần được đối chiếu ground truth trước khi gọi là false positive.

Benchmark cân bằng dự kiến có 200 interval normal và 200 interval attack, cùng định nghĩa đơn vị đánh giá:

| Ground truth | Có phát hiện | Không phát hiện |
|---|---:|---:|
| Attack | TP kỳ vọng 190 | FN kỳ vọng 10 |
| Normal | FP kỳ vọng 10 | TN kỳ vọng 190 |

Precision kỳ vọng 95%, recall kỳ vọng 95%, FPR kỳ vọng 5% **trên benchmark này**. Recall tối thiểu mục tiêu 90%. Những giá trị này chưa phải số đo và không tương đương ngân sách alert theo giờ trong production. Precision thực tế còn phụ thuộc tần suất attack. Normal soak riêng không cung cấp TP/FN nên không thể tính precision/recall; report để `null`.

## Cách tiếp tục sau lỗi

`observation_campaign.py` điều phối các đợt thu có biên bản và checksum riêng, dài tối đa 30 phút. Giới hạn này tái sử dụng launcher hiện hữu; mỗi lần chuyển đợt cần khởi động và warm-up lại. Campaign giữ tổng thời gian hợp lệ của tất cả các đợt, không xóa dữ liệu.

1. Đăng ký nguồn code, model, policy, protocol trước thu; khóa một writer cho cả fleet.
2. Thu snapshot và decision. Giữ mọi alert, kể cả trong khoảng hạ tầng bất ổn.
3. DiskPressure, rollout, Longhorn degraded hoặc thiếu health probe được ghi trong journal/API snapshot. Khoảng không đủ chứng cứ bị loại khỏi exposure normal hợp lệ.
4. Khi detector/collector ngừng hoặc telemetry mất tính toàn vẹn, kết thúc và seal đợt thu đó. Audit độc lập giữ các khoảng tốt trước sự cố; đợi rồi thử đợt mới sau phục hồi. Campaign tiếp tục, không reset tổng exposure.
5. Hợp nhất interval giữa replica/node trước cộng workload-hour để không đếm trùng.
6. Đến hạn hoặc đủ exposure, xuất kết quả dù không đạt ngân sách alert. Sau đó mới phân tích alert và thiết kế candidate cải thiện trên dữ liệu phát triển riêng.

Launcher vẫn có giới hạn startup 120 giây và giới hạn gap 30 giây **cho một đợt thu**. Các giới hạn này không phải tiêu chí chấm dứt campaign. Gap dài làm lịch sử temporal không còn liền kề; đợt mới xây dựng lại history. Dữ liệu bị thiếu không được gán thành normal/TN. Revision mới chưa có baseline được ghi thiếu coverage, không tự nhận là bình thường.

Audit kiểm tra seal raw, replay recovery snapshot và freshness, identity/model/policy/revision, exact counts, thứ tự nguồn và nội dung alert. Đợt thiếu seal hoặc sai binding được ghi thiếu audit; không cộng exposure. Biên bản raw vẫn giữ để điều tra. Campaign có hạn thời gian nên không mắc kẹt chờ vô hạn.

Hiện implementation dùng các đợt thu chung cho ba worker. Lỗi khiến một đợt kết thúc có thể làm hai worker khỏe phải chuyển đợt theo; đây là overhead vận hành cần đo. Không tuyên bố thu liên tục tuyệt đối hoặc formal PASS của protocol cũ.

## Sự cố đã xác minh trực tiếp trên VM

Run `pulse-recovery-formal-c1-20261005` kết thúc ngày 05/10 lúc 10:01:17 ICT sau khoảng 55 phút. Worker `.238` có snapshot sequence 6378 healthy, tiếp theo sequence 6379 fatal: khoảng snapshot **30,63884949684143 giây**, snapshot read **13,102009535 giây**, reason `single gap exceeds recovery budget`. Các counter integrity được ghi trong snapshot đều bằng 0. Chưa xác định nguyên nhân làm snapshot chậm chỉ từ các số này.

Detector ghi `ValueError: fatal telemetry recovery journal`; supervisor sau đó báo `worker did not complete startup within 120 seconds`. Nhánh thông báo đã được sửa để phân biệt detector ngừng trong runtime với cài đặt chưa xong. Đây là lỗi diễn đạt chẩn đoán; không phải bằng chứng worker khởi động mất 55 phút.

Nguồn kiểm chứng: `/home/dat/sentinel-pulse-recovery-coordinator-runs/pulse-recovery-formal-c1-20261005/{START.json,SUPERVISION.jsonl,TERMINAL.json}` trên `.234`; `/var/lib/sentinel-pulse-500ms/runs/pulse-recovery-formal-c1-20261005/features.jsonl` và journal detector trên `.238`.

## Model và cụm đã kiểm tra

Cả sáu node Ready, Kubernetes v1.34.10. Control plane `.234/.235/.236`, worker `.237/.238/.239`. Hostname `.238` hiện là `k8s-worker4.local`; không đổi tên trong thí nghiệm.

Bundle R10C1: 21 workload/container, ExtraTrees, 249 feature/window, history 3 → input 996 chiều, window 500 ms, alpha **0,001**. Manifest ghi năm regime: steady, toolmix, peak, burst, recovery. Dataset train/calibration gồm 391.454 feature rows. Đây là thông tin manifest đã đọc, không phải kết quả normal soak mới hoặc blind recall mới.

Manifest SHA-256: `6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21`. Policy SHA-256: `602165bd48d81f549d3bfb65e5bdb319a11252678cbf484d739afcf2e5bc8143`.

## Vận hành

Trên control plane `.234`:

```bash
systemctl status sentinel-pulse-observation-campaign.service --no-pager
systemctl status sentinel-pulse-audit-backfill-r3-20261006.service --no-pager
journalctl -u sentinel-pulse-observation-campaign.service -n 30 --no-pager

cd /home/dat/sentinel-pulse-observation-campaigns/pulse-observation-c1-20261006
python3 -m json.tool STATUS.json
python3 -m json.tool BACKFILL_STATUS.json
test ! -f TERMINAL.json || python3 -m json.tool TERMINAL.json
```

Service enabled và restart khi process lỗi. Config: `/home/dat/pulse-observation-config-20261006.json`; biến môi trường: `/etc/sentinel-pulse/observation-campaign.env`. `PULSE_SOURCE` là runtime frozen R2; `PULSE_CONTROLLER_SOURCE` và `PULSE_AUDITOR_SOURCE` là R3 đã kiểm chứng. Credential ở `/home/dat/.pulse-recovery-credential-20261005`, mode 0600, không trong Git/config/command arguments.

Không chạy thêm một coordinator thủ công song song service. Restart tiếp tục registration hiện hữu nếu chưa terminal và binding khớp. SIGTERM chủ động dừng đợt worker để seal; không dùng restart tùy tiện giữa đợt. Nếu phải thay controller trong campaign quan sát, đăng ký nguồn code mới riêng và xác minh worker không bị relaunch; không áp dụng cách này cho formal legacy.

Giữ `START.json`, raw seals, health journals, `segments.jsonl`, correction receipts, `recovery-events.jsonl` và `TERMINAL.json`. Không thay nguồn runtime/model/protocol đã đăng ký giữa phép đo; không tự promote chỉ vì service chạy đủ ngày.
