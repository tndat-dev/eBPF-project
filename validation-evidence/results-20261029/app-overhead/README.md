# G7: application latency with and without the Pulse probe (Pulse 5.30)

Protocol `sentinel_pulse/protocol/app-overhead-v1.json` + amendment 1, measured 29/10 09:52–11:56 (UTC+7) by unit
`app-overhead-ab` on k8s-master (`scripts/app_overhead_ab.py`, code `576790c`).

| File | What |
|---|---|
| `requests.jsonl.gz` | every request of the open-loop client (59,394): endpoint, worker IP, scheduled / sent / done time, status |
| `blocks.jsonl` | run events and the 24 blocks (round, condition, start, end, probe CPU ns per worker, /proc/stat deltas, MemAvailable) |
| `APP-OVERHEAD.json` | `python3 scripts/analysis/app_overhead.py <dir> --output APP-OVERHEAD.json` (re-run on the host from these two files: identical) |

Raw files on `.234` (`/var/tmp/app-overhead/`) were deleted after the copy.
