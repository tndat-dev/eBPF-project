# Release evidence `20260801T153648Z`

Đây là bản sao read-only của evidence dùng để promote model V7 lên production
ngày 01-08-2026. Nguồn gốc là `/home/dat/ml-service` trên control plane
`10.1.16.234`.

| File | Vai trò |
|---|---|
| `normal_validation_report.json` | Bốn normal regime, zero false-positive gate |
| `attack_validation_report.json` | Aggregate 15/15 real-kernel attack trials |
| `promotion_manifest.json` | Kết quả atomic promotion và file hashes |
| `release_manifest.json` | Manifest đang nằm trong model production |
| `paper_statistics.json` | Confusion metrics, Wilson 95% CI, latency CDF và bootstrap CI |
| `paper_statistics.md` | Bảng thống kê rút gọn có ghi rõ sample unit/giới hạn |

Kiểm tra integrity:

```bash
sha256sum validation-evidence/20260801T153648Z/*.json
```

Tái tạo hai file thống kê từ report gốc:

```bash
python3 ml-service/paper_statistics.py \
  --normal validation-evidence/20260801T153648Z/normal_validation_report.json \
  --attack validation-evidence/20260801T153648Z/attack_validation_report.json \
  --output validation-evidence/20260801T153648Z/paper_statistics.json
```

Fast path là early-warning telemetry; ML path là quyết định xác nhận. Production
service vẫn chạy `--dry-run`, chưa tự động cô lập pod.
