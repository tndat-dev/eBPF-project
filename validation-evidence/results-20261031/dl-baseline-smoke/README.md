# lidds-dl-baseline-v1, smoke run on CVE-2014-0160 (31/10)

`check-mlp.json`, `check-lstm.json`: `scripts/analysis/lidds_dl_baselines.py --library-check` (commit `3db5ee7`) on the
smallest LID-DS 2021 scenario, `.234`, venv `/var/tmp/dl-baseline/venv` (torch 2.15 CPU), LID-DS library `5b8e414`.
Our per-recording outcomes agree with the library's own serial `IDS.detect()` (`library_check`): MLP 0/120 detected,
1 false-alarm recording (library: 1 false-alarm episode); LSTM 120/120, 32 false-alarm recordings out of 758
(library: 33 episodes, counted by episode, not by recording). Not part of the comparison: the full run rescores this
scenario with training CPU-hours recorded.
