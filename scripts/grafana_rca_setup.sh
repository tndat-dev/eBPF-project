#!/usr/bin/env bash
# One-time setup of the RCA views (30/10), run on .234 as root after a live run, never during one (Grafana restarts):
# - Graphviz, so the alert bridge can draw the evidence tree of a case as SVG (scripts/analysis/rca_case_graph.py);
# - the free Grafana plugin yesoreyeram-infinity-datasource (RCA case table), through the kube-prometheus-stack
#   release when helm is available, otherwise through GF_INSTALL_PLUGINS on the Grafana deployment.
#   sudo bash scripts/grafana_rca_setup.sh
set -euo pipefail
PLUGIN=yesoreyeram-infinity-datasource
kc() { sudo -u dat kubectl "$@"; }
command -v dot >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q graphviz
dot -V
if sudo -u dat helm -n monitoring status monitoring >/dev/null 2>&1; then
  chart=$(sudo -u dat helm -n monitoring list -o json | python3 -c "import json,sys; print([r['chart'] for r in json.load(sys.stdin) if r['name']=='monitoring'][0])")
  echo "helm release monitoring: $chart"
  sudo -u dat helm -n monitoring upgrade monitoring prometheus-community/kube-prometheus-stack --version "${chart##*-}" \
    --reuse-values --set "grafana.plugins[0]=$PLUGIN"
else
  kc -n monitoring set env deploy/monitoring-grafana -c grafana GF_INSTALL_PLUGINS=$PLUGIN
fi
kc -n monitoring rollout status deploy/monitoring-grafana --timeout=300s
kc -n monitoring exec deploy/monitoring-grafana -c grafana -- grafana cli plugins ls | grep -i infinity
