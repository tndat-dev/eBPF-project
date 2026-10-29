# CB-DS: archive build for cbds-confirmation-v1 (Pulse 5.32)

Protocol `sentinel_pulse/protocol/cbds-confirmation-v1.json` (registered 29/10 22:22, before any attack recording was
decoded) and amendment 1 (22:33, counts only). Built on the host 29/10 22:22–22:32 with `sentinel_pulse/lidds/cbds.py`
(code `3ea182f`; sysdig image `sysdig/sysdig@sha256:740a122b…`, no network, read-only input) from the owner's download
`CB-DS.zip` (sha256 `f47a792e…`).

| File | What |
|---|---|
| `CB-DS.zip.SUMMARY.json.gz` | release hash, split seed, sysdig image digest, counts per split, per recording: release entry, split, main container id, kept events, events outside the main container |
| `build.log` | progress of the build (324 batches) and its summary |

The archive itself (`CB-DS.zip` in the LID-DS 2021 layout, 681 MB, sha256 `235f06a9…`) is on `.234` at
`/var/tmp/cb-ds/archives/` and in the session scratch space of the host; it is not in git (derived from the
dataset). Results of the evaluation are added here after `scripts/cbds_after_live.sh` has run.
