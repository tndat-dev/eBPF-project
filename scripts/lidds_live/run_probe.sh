#!/usr/bin/env bash
# Run the lineage token probe on the pinned worker for a lidds-live capture/live run (protocol pulse-live-lidds-v1).
# As root. Keeps the resolver allow-list (lidds-live only) fresh so the loader picks up each victim, and records every
# token window to tokens.jsonl plus timestamped resolver metadata to meta.jsonl (for cgroup -> victim mapping offline).
#   run_probe.sh BUILD_DIR OUT_DIR SOURCE_DIR
set -uo pipefail
BUILD=${1:?build dir}; OUT=${2:?out dir}; SRC=${3:?source repo for the resolver}
mkdir -p "$OUT"
ALLOW="$OUT/allow"; META="$OUT/meta.json"
: > "$OUT/meta.jsonl"
# resolver loop: refresh allow-list + metadata every 5 s; append a timestamped metadata snapshot for the scorer
( while true; do
    PYTHONPATH="$SRC" python3 -m sentinel_pulse.collector.cgroup_resolver --namespace lidds-live \
        --allow-file "$ALLOW" --metadata-file "$META" --once >/dev/null 2>>"$OUT/resolver.err" || true
    [ -s "$META" ] && python3 -c "import json,time,sys;d=json.load(open('$META'));print(json.dumps(dict(at=time.time(),cgroups=d['cgroups'])))" >> "$OUT/meta.jsonl" 2>/dev/null
    sleep 5
  done ) &
RLOOP=$!
echo "$RLOOP" > "$OUT/resolver.pid"
# wait for a non-empty allow-list (a victim must be up) before the loader, which stops fail-closed on empty
for _ in $(seq 1 60); do [ -s "$ALLOW" ] && break; sleep 2; done
if [ ! -s "$ALLOW" ]; then echo "no lidds-live cgroups in allow-list; is a victim running?" >&2; kill "$RLOOP"; exit 1; fi
echo "loader starting; targets=$(wc -l < "$ALLOW")" >&2
"$BUILD/pulse_counter_tokens_loader" --object "$BUILD/pulse_counter_tokens.bpf.o" \
    --allow-cgroup-file "$ALLOW" --interval-ms 500 --tokens grams > "$OUT/tokens.jsonl" 2>"$OUT/loader.err"
kill "$RLOOP" 2>/dev/null
