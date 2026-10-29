# LID-DS 2021 evaluation (Pulse 5.32, protocol `lidds-evaluation-v1`)

Run on `.234` 29/10 09:10–15:01 (UTC+7): `lid-ds-convert` (code `3790d91`, `sentinel_pulse/lidds/convert.py`, 4 scenarios in
parallel) then `lid-ds-evaluate` (code `045c484`, `scripts/analysis/lidds_evaluate.py`). Archives: the 15 zips of the public
Proton Drive share linked from github.com/LID-DS/LID-DS, downloaded 25/10, in `/var/tmp/lid-ds-2021/` on `.234`.

| File | What |
|---|---|
| `lidds-evaluation.json` | per scenario (fit, recordings, arms ML / tripwire / system / STIDE) and pooled, with Wilson CI and the scenario bootstrap of system - ML, system - STIDE, ML - STIDE |
| `convert.log` | one line per scenario: windows per split and the syscall names left unmapped |
| `evaluate.log` | per-scenario summary lines as the job printed them |

Known after the run (amendment 1, `sentinel_pulse/protocol/lidds-evaluation-v1-amendment-1.json`): `convert.log` shows that
`pread`, `pwrite`, `sigreturn` and `prlimit` (sysdig spellings of pread64, pwrite64, rt_sigreturn, prlimit64) were dropped as
unmapped in 12 of 15 scenarios. A sensitivity re-run with the alias table goes into a separate directory after the next live run.
