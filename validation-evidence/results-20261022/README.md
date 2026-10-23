# Biên nhận 22–23/10 (chép về repo ngày 23/10)

Các file dưới đây là output của job chạy trên cụm, chép nguyên từ NFS (`A=/mnt/sentinel-pulse-archive`) hoặc đĩa local của `.234`. Mỗi job là một script trong `scripts/`; dòng đầu của script ghi giao thức, đầu vào và cách chạy. Code chạy là snapshot git ghi trong biên nhận hoặc tên thư mục `runtime-<commit>-<ngày>/source`.

| File | Kết quả cho | Script / lệnh | Bản gốc trên cụm |
|---|---|---|---|
| `pulse/stable-selection-kofn.json`, `pulse/stable-selection-cusum-3-6.json` | Pulse 5.19: chọn luật thời gian của ML stable (bản đầu, trước bổ sung `cap`) | `scripts/stable_selection_replay.sh` (`sentinel_pulse.attack.rolling_recalibration … --temporal kofn` hoặc `cusum-3-6`) | `$A/pulse-stable-refreshed/analysis/` |
| `pulse/burden-levers.json` | Pulse 5.22: 1.414 cấu hình giảm gánh cảnh báo × 2 lượt development, luật chọn đăng ký trước (`burden-reduction-v1`) | `scripts/burden_levers.sh` → `scripts/analysis/burden_levers.py` | `$A/pulse-stable-refreshed/analysis/burden-levers.json` (= `/var/tmp/burden-levers/BURDEN-LEVERS.json` trên `.234`) |
| `pulse/rolling-recalibration-k2of2-soak48h-RESULTS.json` | Pulse 5.7d: chiến lược làm mới calibration trên soak 48 giờ | `scripts/pulse_57d.sh` | `$A/confirmation-study-20261018/rolling-recalibration-k2of2-20261021/RESULTS.json` |
| `syscall/syscall-arms-cusum-keep/*` | Syscall 5C bản `keep`: 11 cấu hình dưới CUSUM drift 3 | `scripts/syscall_cusum.sh` (bước 2, trước bổ sung 1) | `$A/matched-parallel-r4-20261015/syscall-arms-cusum/` |
| `syscall/syscall-arms-cusum-cap/*` | Syscall 5C bản `cap` (luật ML stable) | `scripts/syscall_cusum.sh` bước 2 | `$A/matched-parallel-r4-20261015/syscall-arms-cusum-cap/` |
| `syscall/feature-groups-primary/{RESULTS,BOOTSTRAP,arm-scenarios}-*.json` | Syscall 5B.3: nhóm feature trên holdout chính, luật v1 k2of2 | `scripts/feature_groups_primary.sh` | `$A/matched-parallel-r4-20261015/feature-groups/` |
| `syscall/feature-groups-primary/VERDICT.json` | Áp luật từng thành phần cho holdout chính; sinh lại ngày 23/10 từ hai file ở trên, khớp cột "Holdout chính" của 5B.3 | `python3 scripts/analysis/feature_group_verdict.py --set pulse-attack-dev=RESULTS-pulse-attack-dev.json,BOOTSTRAP-pulse-attack-dev.json --set pulse-live-recalibrated=… --output VERDICT.json` | (sinh tại repo) |
| `syscall/feature-groups-branches/*` | Syscall 5B.3: hai biến thể p-value (chỉ nhánh tree / chỉ nhánh support), cả hai **cần** | `scripts/feature_groups_branches.sh`, rồi `feature_group_verdict.py` | `$A/matched-parallel-r4-20261015/feature-groups/branches/` |
| `syscall/feature-groups-cusum-cap/*` (+ `VERDICT.json` sinh tại repo) | Syscall 5C: nhóm feature dưới CUSUM `cap`; không đổi kết luận nào của 5B.3 | `scripts/syscall_cusum.sh` bước 3, rồi `feature_group_verdict.py` | `$A/matched-parallel-r4-20261015/feature-groups/cusum-cap/` (tên file `CUSUM-CAP-BOOTSTRAP-*`, `cusum-cap-arm-scenarios-*` đổi thành `BOOTSTRAP-*`, `arm-scenarios-*`) |
| `rca/rca-baseline-seed-20261022.json` | RCA 5.12: 59 binary đã biết, mang từ khoảng normal của 2 lượt trước sang lượt `pulse-stable-confirm` | `python3 -m sentinel_pulse.rca.baseline_seed --run db=…,campaign=… --output …` (đầu vào: database RCA và campaign của 2 lượt trước; RCA 5.12) | `$A/pulse-next-run-model/rca-baseline-seed-20261022.json` |

Kết quả của lượt xác nhận `pulse-stable-confirm` nằm ở [`../results-20261023/`](../results-20261023/README.md): giai đoạn campaign và độ trễ của đường cảnh báo vận hành đã có; giai đoạn final thêm sau lượt.

Không đưa vào git: dữ liệu thô (`features.jsonl`, `decisions.jsonl`, score dump, bảng cửa sổ `.npz`). Một lượt 24 giờ chiếm vài chục GB, vượt giới hạn của GitHub. Chúng nằm trên NFS, đường dẫn ghi trong biên nhận; `.gitignore` liệt kê các mẫu bị loại.
