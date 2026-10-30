#!/usr/bin/env bash
# Pulse eBPF overhead A/B on one worker (protocol overhead-ab-v1), as root, only when no live run is active.
#   BENCH=/path/syscall_bench LOADER=.../pulse_counter_extended_loader OBJECT=.../pulse_counter_extended.bpf.o \
#   OUT=/var/tmp/overhead-ab/<node>.jsonl [ROUNDS=5] [SECONDS_PER_MODE=10] bash overhead_ab.sh
#   [LOADER2=... OBJECT2=...]  adds a fourth condition, monitored2, with a second probe build (exec-intent-v1 P1)
# Conditions, rotated each round to cancel drift:
#   off        - no Pulse probe attached on the node;
#   filtered   - Pulse loader attached, the benchmark's cgroup is NOT in its allow list (cost every unmonitored
#                process on the node pays: raw_tp/sys_enter + cgroup lookup miss);
#   monitored  - the benchmark's cgroup is in the allow list (full counting path: per-cgroup counters, bins,
#                per-thread last-syscall for transitions).
# Tetragon and everything else on the node stay as they are in all three conditions.
set -euo pipefail
BENCH=${BENCH:?benchmark binary}; LOADER=${LOADER:?loader}; OBJECT=${OBJECT:?bpf object}; OUT=${OUT:?output}
ROUNDS=${ROUNDS:-5}; SECS=${SECONDS_PER_MODE:-10}
MODES=(getpid read4k openclose mmapunmap)
for u in $(systemctl list-units --no-legend --plain --state=active 'pulse-matched-worker-*' 'sentinel-pulse-collector*' | awk '{print $1}'); do
  echo "refusing: $u is active (live run or collector); overhead needs a quiet probe-free node" >&2; exit 3
done
# match the process name, not command lines: a shell that merely mentions the loader path must not count
if ps -eo comm= | grep -q '^pulse_counter'; then echo "refusing: a Pulse loader is already attached" >&2; exit 3; fi
CG=/sys/fs/cgroup/pulse-bench
mkdir -p "$CG"; CGID=$(stat -c %i "$CG")
ALLOW_MON=$(mktemp); ALLOW_NONE=$(mktemp)
echo "$CGID" > "$ALLOW_MON"; echo 1 > "$ALLOW_NONE"        # id 1 never matches a leaf cgroup
mkdir -p "$(dirname "$OUT")"; : > "$OUT"
loader_pid=
stop_loader() { [ -n "$loader_pid" ] && kill "$loader_pid" 2>/dev/null && wait "$loader_pid" 2>/dev/null; loader_pid=; }
trap 'stop_loader; rm -f "$ALLOW_MON" "$ALLOW_NONE"; rmdir "$CG" 2>/dev/null || true' EXIT
CONDS=(off filtered monitored)
[ -n "${LOADER2:-}" ] && CONDS+=(monitored2)
for round in $(seq 1 "$ROUNDS"); do
  shift_by=$(( (round - 1) % ${#CONDS[@]} ))
  order=("${CONDS[@]:$shift_by}" "${CONDS[@]:0:$shift_by}")
  for cond in "${order[@]}"; do
    case $cond in
      off) ;;
      filtered) "$LOADER" --object "$OBJECT" --allow-cgroup-file "$ALLOW_NONE" --interval-ms 500 >/dev/null 2>&1 & loader_pid=$!; sleep 3 ;;
      monitored) "$LOADER" --object "$OBJECT" --allow-cgroup-file "$ALLOW_MON" --interval-ms 500 >/dev/null 2>&1 & loader_pid=$!; sleep 3 ;;
      monitored2) "$LOADER2" --object "$OBJECT2" --allow-cgroup-file "$ALLOW_MON" --interval-ms 500 > "$OUT.monitored2-r$round.jsonl" 2>&1 & loader_pid=$!; sleep 3
                  kill -0 "$loader_pid" 2>/dev/null || { echo "second probe failed to load: $(tail -3 "$OUT.monitored2-r$round.jsonl")" >&2; exit 4; } ;;
    esac
    for mode in "${MODES[@]}"; do
      line=$(sh -c "echo \$\$ > $CG/cgroup.procs && exec $BENCH $mode $SECS")
      python3 -c "import json,sys,time; d=json.loads(sys.argv[1]); d.update(round=int(sys.argv[2]), condition=sys.argv[3], node=sys.argv[4], at=time.time()); print(json.dumps(d))" \
        "$line" "$round" "$cond" "$(hostname)" >> "$OUT"
    done
    stop_loader
  done
done
echo "done $(wc -l < "$OUT") rows -> $OUT"
