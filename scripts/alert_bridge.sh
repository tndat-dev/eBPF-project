#!/usr/bin/env bash
# Operational alert path test (sentinel_pulse/ops/alert_bridge.py): Pulse previews of a live run -> Alertmanager /
# Prometheus / Grafana of the cluster. Read-only towards Pulse and RCA. Run on .234 as root:
#   sudo bash scripts/alert_bridge.sh RUN        (RUN = live run whose RCA config names workers and frozen hashes)
# Stop: systemctl stop pulse-alert-bridge-RUN; kubectl delete -f testbed/k8s/monitoring/sentinel-pulse-alerting.yaml
set -euo pipefail
RUN=${1:?run name, e.g. pulse-stable-confirm}
REPO=/home/dat/eBPF-project
BASE=/var/lib/sentinel-pulse-alert-bridge
COMMIT=$(git -C $REPO rev-parse --short HEAD)
SRC=$BASE/source-$COMMIT
OUT=$BASE/$RUN
kc() { sudo -u dat kubectl "$@"; }   # root has no kubeconfig on .234
install -d -o dat -g dat $BASE $OUT
[ -d $SRC/.git ] || sudo -u dat git clone -q $REPO $SRC
sudo -u dat git -C $SRC checkout -q $COMMIT
# workers, decision-stream transport and frozen hashes come from the run's RCA config (credential path only)
python3 - /etc/sentinel-pulse-rca/rca-$RUN.json $OUT <<'EOF'
import json, sys
rca, out = json.load(open(sys.argv[1])), sys.argv[2]
cfg = dict(run=sys.argv[1].split('rca-', 1)[1][:-5], workers=rca['workers'],
           ssh=dict(credential=rca['decision_stream']['credential'], user=rca['decision_stream'].get('user', 'dat'),
                    rotate_seconds=3600),
           model_hash=rca['model_hash'], policy_hash=rca['policy_hash'],
           alertmanager_url='http://monitoring-kube-prometheus-alertmanager.monitoring.svc:9093',
           listen=['0.0.0.0', 9478], resolve_after_seconds=3, refresh_seconds=5, output=out)
open(out + '/config.json', 'w').write(json.dumps(cfg, indent=1))
EOF
chown dat:dat $OUT/config.json
# the bridge runs on the host, not in a pod: resolve the Alertmanager service to its ClusterIP
AM=$(kc -n monitoring get svc monitoring-kube-prometheus-alertmanager -o jsonpath='{.spec.clusterIP}')
sed -i "s#monitoring-kube-prometheus-alertmanager.monitoring.svc#$AM#" $OUT/config.json
systemd-run --unit pulse-alert-bridge-$RUN --uid dat --gid dat -p Nice=10 -p MemoryMax=512M \
  --setenv=PYTHONPATH=$SRC --setenv=PYTHONDONTWRITEBYTECODE=1 --setenv=CODE_COMMIT=$COMMIT \
  /usr/bin/python3 -u -m sentinel_pulse.ops.alert_bridge --config $OUT/config.json
kc apply -f $SRC/testbed/k8s/monitoring/sentinel-pulse-alerting.yaml
kc -n sentinel-pulse create configmap sentinel-pulse-dashboard \
  --from-file=sentinel-pulse-alerts.json=$SRC/testbed/k8s/monitoring/sentinel-pulse-dashboard.json \
  --dry-run=client -o yaml | kc label --local -f - grafana_dashboard=1 -o yaml | kc apply -f -
echo "bridge pulse-alert-bridge-$RUN from $COMMIT, output $OUT"
