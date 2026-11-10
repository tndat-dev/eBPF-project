# Bản build probe token sau audit (10/11/2026)

Commit đã chạy: a01b843. Build `make tokens` trên từng worker tại `/home/dat/pulse-tokens-20261110/build`, proof bằng
`scripts/token_probe_proof.py` sau khi lượt `pulse-live-v4-1109` dừng.

- Proof đạt trên cả 3 worker (`proof-*.json`): đường seccomp, đúng một token mỗi syscall, token mong đợi, không mất sự kiện.
- So với bản build của 46e9039 (dùng cho lượt thu và lượt 1109), build trên `.234` cùng header kernel: bốn section chương trình
  (`raw_tp/sys_enter`, `raw_tp/sys_exit`, `fexit/__seccomp_filter`, `.text`) giống từng byte; khác biệt là mất 39 section `fexit`
  của biến thể đã loại. Bản `matched`: mọi section giống hệt, loader sau `strip` giống từng byte.
