# Sealed compression of the 1121 and 1124 captures (26/11)

`scripts/compress_raw_frames.py --worker <node>` on each worker (unit `compress-diurnal-1126`), gzip level 1, every
segment's SHA-256 checked against its TERMINAL.json seal before the plain file is removed. Marker files written by unit
`compress-done-1126` when the compression unit ended: unit result, then one totals line per run (capture 1124, then 1121).

| worker | 1124 files | 1124 saved | 1121 files | 1121 saved | mismatched |
|---|---|---|---|---|---|
| k8s-worker1 | 384 | 121.8 GB | 192 | 51.8 GB | none |
| k8s-worker3 | 384 | 122.1 GB | 192 | 52.0 GB | none |
| k8s-worker4 | 384 | 114.7 GB | 192 | 48.9 GB | none |

Total saved 511.2 GB. NFS `/mnt/sentinel-pulse-archive` after compression: 176 GB used, 510 GB free (26/11 17:10 UTC).
