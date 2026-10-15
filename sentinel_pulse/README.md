# Sentinel Pulse — hướng dẫn tra code

README này là điểm vào source, không phải báo cáo tiến độ. Trạng thái runtime,
số liệu và việc còn lại chỉ cập nhật trong ba file:

- [Sentinel Pulse](../SENTINEL_PULSE_STATUS.md).
- [Chọn feature/syscall](../SYSCALL_FEATURE_EXPERIMENT_STATUS.md).
- [RCA](../RCA_RUNTIME_STATUS.md).

[Báo cáo tổng hợp giữ nguyên](../SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md)
là tài liệu tham khảo, không thay thế timestamp của ba báo cáo trên.

## Nhánh telemetry và ML

| Bước | Source |
|---|---|
| Pod/container → cgroup/revision | [cgroup_resolver.py](cgroup_resolver.py) |
| Kernel counters/transition | [ebpf/pulse_counter.bpf.c](ebpf/pulse_counter.bpf.c) |
| Feature 249 chiều | [features.py](features.py), [encoding.py](encoding.py) |
| Extended/idle capture | [extended_capture.py](extended_capture.py) |
| Temporal ExtraTrees | [model.py](model.py), [extended_reference_experiment.py](extended_reference_experiment.py) |
| Normal support branch | [support_model.py](support_model.py) |
| Manifest/artifact loading | [idle_candidate.py](idle_candidate.py), [integrity.py](integrity.py) |
| History, batch, preview policy | [candidate_shadow.py](candidate_shadow.py), [idle_batch.py](idle_batch.py), [candidate_policy.py](candidate_policy.py) |
| Matched 500 ms worker | [matched_worker.py](matched_worker.py) |
| Paired development evaluation | [preview_campaign.py](preview_campaign.py), [preview_evaluation.py](preview_evaluation.py) |

## Nhánh nghiên cứu feature/syscall

- [matched_study.py](matched_study.py): selection có seal, split/embargo,
  explicit additions/group ablation, nhiều seed và artifact theo arm.
- [syscall_frequency_report.py](syscall_frequency_report.py): frequency
  descriptive, không tự chứng minh utility hoặc feature tối ưu.
- [syscall_addition_experiment.py](syscall_addition_experiment.py):
  exploratory entry-only generation; không nhầm observable với matched worker.
- [protocol v2](protocol/syscall-selection-evaluation-v2.json): metric,
  ngân sách false alert và yêu cầu validation prospective.

## Nhánh RCA

- [rca_connect.py](rca_connect.py): normalize process/parent/socket/destination.
- [rca_tree.py](rca_tree.py): identity/time join và graph bằng chứng.
- [rca_service.py](rca_service.py): subscriber, local context, case/cursor
  checkpoint và bounded retention.
- [systemd expanded subscriber](systemd/pulse-rca-runtime-events.service): đọc
  policy+lifecycle events, không enforce. `pulse-rca-context.service` là
  connect-only legacy unit và hiện được giữ làm artifact nhưng không chạy.

## Kiểm thử và contract

Chạy từ repo root bằng Python environment tương ứng với manifest/source
cần kiểm chứng; không trộn sklearn/NumPy khác generation rồi gọi là replay
đồng nhất. Ví dụ test RCA chỉ cần standard library và pytest:

    PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests/test_sentinel_pulse_rca_tree.py tests/test_sentinel_pulse_rca_connect.py

Các entrypoint/module khác nhau có thể thuộc generation khác. Trước deploy
phải kiểm tra source/model/policy/schema/kernel binding; không chạy toàn bộ
installer trong thư mục như một pipeline duy nhất. JSON protocol kỳ vọng
không phải số đo; preview không phải operational alert; connect entry
không chứng minh thành công hoặc nội dung L7.

Không sửa raw/seal hay xóa miss/unknown để làm đẹp báo cáo. Dữ liệu và receipt
ở ../validation-evidence/ là hồ sơ thí nghiệm, được giữ độc lập với việc
dọn Markdown tiến độ.
