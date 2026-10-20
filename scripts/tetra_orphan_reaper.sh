#!/usr/bin/env bash
# Kill orphaned `tetra getevents` processes inside Tetragon containers (run on each worker by a timer).
# Every legitimate stream is started as `timeout <=900 tetra getevents ...`. When the kubectl exec session
# closes, the in-container `timeout` gets SIGKILL (not forwardable), its tetra child is reparented to the
# container init, ignores SIGTERM and keeps pulling events nobody reads (seen 19-20/10: 9-10 per node, up to 29 h).
# Rule: tetra getevents older than 1000 s whose parent is not `timeout` -> SIGKILL. Logs what it kills.
set -u
for pid in $(ps -eo pid,etimes,args | awk '$3=="tetra" && $4=="getevents" && $2>1000 {print $1}'); do
  parent=$(ps -o comm= -p "$(ps -o ppid= -p "$pid" | tr -d ' ')" 2>/dev/null)
  [ "$parent" = timeout ] && continue
  echo "reaping tetra getevents pid=$pid age=$(ps -o etimes= -p "$pid" | tr -d ' ')s parent=${parent:-?}"
  kill -9 "$pid" 2>/dev/null
done
