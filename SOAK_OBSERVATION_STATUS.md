# Soak quan sát có phục hồi — trạng thái hiện hành

Cập nhật ngày 06/10/2026, múi giờ Asia/Bangkok. Đây là tài liệu cho campaign quan sát mới. Các biên bản đã kết thúc của hệ thống cũ giữ nguyên kết luận đã đăng ký.

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

```bash
python -m sentinel_pulse.observation_campaign \
  --config /home/dat/pulse-observation-config-20261006.json \
  --password-file /home/dat/.config/sentinel-pulse/ssh-password \
  --protocol /home/dat/eBPF-project-observation-20261006/sentinel_pulse/protocol/observation-campaign-v1.json \
  --output-root /home/dat/sentinel-pulse-observation-campaigns \
  --run-id pulse-observation-c1-20261006
```

Credential phải là file riêng mode 0600; không lưu trong config/Git/command arguments. Đọc `STATUS.json`, `segments.jsonl`, `recovery-events.jsonl` và `TERMINAL.json` trong thư mục campaign. Cùng lệnh tự tiếp tục registration cũ nếu chưa terminal và binding vẫn khớp. Không thay nguồn/model/protocol khi đang đo.

Trạng thái deploy và kiểm tra live sẽ được cập nhật tại đây sau kiểm chứng; các lệnh trên chưa tự chứng minh dịch vụ đã chạy.
