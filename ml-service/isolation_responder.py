"""
isolation_responder.py
----------------------
Tự động cách ly pod khi AnomalyDetector phát hiện attack.

4 bước isolation (theo đồ án):
  Step 1: Cordon node        — ngăn pod mới schedule lên node bị nhiễm
  Step 2: Evict pod          — terminate pod bị nhiễm gracefully
  Step 3: Quarantine label   — patch label quarantine=true lên pod
  Step 4: CiliumNetworkPolicy — deny all ingress/egress cho pod bị nhiễm

Cách dùng:
  from isolation_responder import IsolationResponder
  responder = IsolationResponder()
  # Dùng làm on_alert callback trong AnomalyDetector
  detector = AnomalyDetector(model_manager, on_alert=responder.respond)
"""

import logging
import threading
import time
import json
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("isolation_responder")

# ─────────────────────────────────────────────
# Kubernetes Client Setup
# ─────────────────────────────────────────────

def get_k8s_clients():
    """
    Khởi tạo Kubernetes API clients.
    Tự động detect: trong cluster (ServiceAccount) hoặc ngoài (kubeconfig).
    """
    from kubernetes import client, config
    try:
        config.load_incluster_config()
        logger.info("K8s config: in-cluster mode")
    except Exception:
        config.load_kube_config()
        logger.info("K8s config: kubeconfig mode")

    return {
        "core":   client.CoreV1Api(),
        "policy": client.PolicyV1Api(),
        "custom": client.CustomObjectsApi(),
    }


# ─────────────────────────────────────────────
# IsolationResult — kết quả sau isolation
# ─────────────────────────────────────────────

class IsolationResult:
    def __init__(self, pod_key: str):
        self.pod_key    = pod_key
        self.started_at = time.time()
        self.steps      = []   # list of {step, status, latency_ms, error}
        self.success    = False

    def add_step(self, step: str, status: str,
                 latency_ms: float, error: str = ""):
        self.steps.append({
            "step":       step,
            "status":     status,
            "latency_ms": round(latency_ms, 1),
            "error":      error,
        })
        icon = "✅" if status == "ok" else "❌"
        logger.info(
            f"  {icon} Step {len(self.steps)}: {step} "
            f"[{latency_ms:.0f}ms] "
            f"{'ERROR: ' + error if error else ''}"
        )

    def total_latency_ms(self) -> float:
        return (time.time() - self.started_at) * 1000

    def to_dict(self) -> dict:
        return {
            "pod_key":          self.pod_key,
            "success":          self.success,
            "total_latency_ms": round(self.total_latency_ms(), 1),
            "steps":            self.steps,
        }


# ─────────────────────────────────────────────
# IsolationResponder
# ─────────────────────────────────────────────

class IsolationResponder:
    """
    Thực hiện 4-step isolation khi nhận AnomalyAlert.
    Thread-safe, không block detector thread.
    """

    def __init__(self, dry_run: bool = False):
        """
        Args:
            dry_run: nếu True → chỉ log, không thực sự gọi K8s API
        """
        self.dry_run = dry_run
        self._clients = None
        self._lock    = threading.Lock()
        self._history = []   # list of IsolationResult

        if not dry_run:
            try:
                self._clients = get_k8s_clients()
                logger.info("K8s clients khởi tạo thành công")
            except Exception as e:
                logger.error(f"Không kết nối được K8s API: {e}")
                logger.warning("Chuyển sang dry_run mode")
                self.dry_run = True

        mode = "DRY RUN" if self.dry_run else "LIVE"
        logger.info(f"IsolationResponder khởi động [{mode}]")

    # ── Public API ───────────────────────────

    def respond(self, alert) -> IsolationResult:
        """
        Callback cho AnomalyDetector.on_alert.
        Chạy trong background thread để không block detector.
        """
        result = IsolationResult(alert.pod_key)
        thread = threading.Thread(
            target=self._execute_isolation,
            args=(alert, result),
            daemon=True,
            name=f"isolate-{alert.pod_name}",
        )
        thread.start()
        return result

    # ── Internal ─────────────────────────────

    def _execute_isolation(self, alert, result: IsolationResult):
        """Thực hiện 4 bước isolation tuần tự."""
        logger.warning(
            f"\n{'='*55}\n"
            f"🔒 BẮT ĐẦU ISOLATION: {alert.pod_key}\n"
            f"   Score: {alert.ensemble_score:.4f}\n"
            f"   Node:  {alert.node_name}\n"
            f"{'='*55}"
        )

        # Lấy thông tin pod trước khi evict
        pod_name  = alert.pod_name
        namespace = alert.pod_namespace
        node_name = alert.node_name

        errors = []

        # Step 1: Cordon node
        self._step_cordon(node_name, result)

        # Step 2: Patch quarantine label (TRƯỚC khi evict)
        # Quan trọng: label phải được patch trước để Cilium kịp enforce
        self._step_quarantine_label(pod_name, namespace, result)

        # Step 3: Apply CiliumNetworkPolicy deny-all
        self._step_cilium_policy(pod_name, namespace, result)

        # Step 4: Evict pod (sau khi network đã bị block)
        self._step_evict(pod_name, namespace, result)

        # Lưu SecurityIncident
        self._save_incident(alert, result)

        result.success = all(s["status"] == "ok" for s in result.steps)
        total_ms = result.total_latency_ms()

        logger.warning(
            f"\n{'='*55}\n"
            f"{'✅' if result.success else '⚠️'} ISOLATION HOÀN THÀNH: {alert.pod_key}\n"
            f"   Total latency: {total_ms:.0f}ms ({total_ms/1000:.2f}s)\n"
            f"   Steps: {len(result.steps)}\n"
            f"{'='*55}"
        )

        with self._lock:
            self._history.append(result)

    def _step_cordon(self, node_name: str, result: IsolationResult):
        """Step 1: Cordon node — ngăn pod mới schedule."""
        t0 = time.time()
        step_name = f"cordon_node({node_name})"
        try:
            if self.dry_run:
                logger.info(f"[DRY RUN] kubectl cordon {node_name}")
                time.sleep(0.1)
            else:
                from kubernetes import client
                body = {"spec": {"unschedulable": True}}
                self._clients["core"].patch_node(node_name, body)

            latency = (time.time() - t0) * 1000
            result.add_step(step_name, "ok", latency)

        except Exception as e:
            latency = (time.time() - t0) * 1000
            result.add_step(step_name, "error", latency, str(e))

    def _step_quarantine_label(self, pod_name: str,
                                namespace: str,
                                result: IsolationResult):
        """Step 2: Patch label quarantine=true lên pod."""
        t0 = time.time()
        step_name = f"quarantine_label({namespace}/{pod_name})"
        try:
            if self.dry_run:
                logger.info(
                    f"[DRY RUN] kubectl label pod {pod_name} "
                    f"-n {namespace} quarantine=true"
                )
                time.sleep(0.1)
            else:
                body = {"metadata": {"labels": {"quarantine": "true"}}}
                self._clients["core"].patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body=body,
                )

            latency = (time.time() - t0) * 1000
            result.add_step(step_name, "ok", latency)

        except Exception as e:
            latency = (time.time() - t0) * 1000
            result.add_step(step_name, "error", latency, str(e))

    def _step_cilium_policy(self, pod_name: str,
                             namespace: str,
                             result: IsolationResult):
        """Step 3: Tạo CiliumNetworkPolicy deny-all cho pod bị quarantine."""
        t0 = time.time()
        policy_name = f"quarantine-{pod_name}"
        step_name   = f"cilium_deny_all({policy_name})"

        # CiliumNetworkPolicy spec
        cnp = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name":      policy_name,
                "namespace": namespace,
                "labels": {
                    "managed-by": "security-operator",
                    "pod-name":   pod_name,
                },
            },
            "spec": {
                "endpointSelector": {
                    "matchLabels": {"quarantine": "true"}
                },
                "ingress": [],  # empty = deny all ingress
                "egress":  [],  # empty = deny all egress
            },
        }

        try:
            if self.dry_run:
                logger.info(
                    f"[DRY RUN] kubectl apply CiliumNetworkPolicy "
                    f"{policy_name} (deny all) -n {namespace}"
                )
                time.sleep(0.1)
            else:
                # Xóa policy cũ nếu có
                try:
                    self._clients["custom"].delete_namespaced_custom_object(
                        group="cilium.io", version="v2",
                        namespace=namespace,
                        plural="ciliumnetworkpolicies",
                        name=policy_name,
                    )
                except Exception:
                    pass  # Không có → bỏ qua

                # Tạo policy mới
                self._clients["custom"].create_namespaced_custom_object(
                    group="cilium.io", version="v2",
                    namespace=namespace,
                    plural="ciliumnetworkpolicies",
                    body=cnp,
                )

            latency = (time.time() - t0) * 1000
            result.add_step(step_name, "ok", latency)

        except Exception as e:
            latency = (time.time() - t0) * 1000
            result.add_step(step_name, "error", latency, str(e))

    def _step_evict(self, pod_name: str,
                    namespace: str,
                    result: IsolationResult):
        """Step 4: Evict pod."""
        t0 = time.time()
        step_name = f"evict_pod({namespace}/{pod_name})"
        try:
            if self.dry_run:
                logger.info(
                    f"[DRY RUN] kubectl delete pod {pod_name} "
                    f"-n {namespace} --grace-period=10"
                )
                time.sleep(0.2)
            else:
                from kubernetes import client
                eviction = client.V1Eviction(
                    metadata=client.V1ObjectMeta(
                        name=pod_name,
                        namespace=namespace,
                    ),
                    delete_options=client.V1DeleteOptions(
                        grace_period_seconds=10,
                    ),
                )
                self._clients["core"].create_namespaced_pod_eviction(
                    name=pod_name,
                    namespace=namespace,
                    body=eviction,
                )

            latency = (time.time() - t0) * 1000
            result.add_step(step_name, "ok", latency)

        except Exception as e:
            # 404 = pod đã bị xóa → coi như thành công
            if "404" in str(e) or "Not Found" in str(e):
                latency = (time.time() - t0) * 1000
                result.add_step(step_name, "ok", latency,
                                "pod đã terminate trước")
            else:
                latency = (time.time() - t0) * 1000
                result.add_step(step_name, "error", latency, str(e))

    def _save_incident(self, alert, result: IsolationResult):
        """Lưu SecurityIncident ra file JSON."""
        os.makedirs("incidents", exist_ok=True)
        ts = int(alert.window_start)
        fname = (
            f"incidents/{alert.pod_namespace}__{alert.pod_name}_{ts}.json"
        )
        incident = {
            "apiVersion": "security.thesis/v1",
            "kind":       "SecurityIncident",
            "metadata": {
                "pod_name":      alert.pod_name,
                "pod_namespace": alert.pod_namespace,
                "node_name":     alert.node_name,
                "detected_at":   alert.detected_at,
            },
            "spec": {
                "anomaly_score":     alert.ensemble_score,
                "lstm_score":        alert.lstm_score,
                "if_score":          alert.if_score,
                "threshold":         alert.threshold,
                "top_syscalls":      alert.top_syscalls,
                "isolation_result":  result.to_dict(),
                "mitre_mapping":     self._map_mitre(alert.top_syscalls),
            },
        }
        with open(fname, "w") as f:
            json.dump(incident, f, indent=2)
        logger.info(f"SecurityIncident saved: {fname}")

    def _map_mitre(self, top_syscalls: list) -> list:
        """
        Map syscall pattern → MITRE ATT&CK for Containers technique.
        """
        syscall_names = [s["name"] for s in top_syscalls]
        matches = []

        rules = [
            {
                "id":   "T1059",
                "name": "Command and Scripting Interpreter",
                "check": lambda s: "execve" in s,
                "confidence": "high",
            },
            {
                "id":   "T1611",
                "name": "Escape to Host",
                "check": lambda s: any(x in s for x in
                                       ["unshare", "mount", "pivot_root"]),
                "confidence": "high",
            },
            {
                "id":   "T1046",
                "name": "Network Service Discovery",
                "check": lambda s: s.count("connect") > 0,
                "confidence": "medium",
            },
            {
                "id":   "T1548",
                "name": "Abuse Elevation Control Mechanism",
                "check": lambda s: any(x in s for x in
                                       ["setuid", "setgid", "capset"]),
                "confidence": "high",
            },
            {
                "id":   "T1496",
                "name": "Resource Hijacking (Cryptomining)",
                "check": lambda s: s.count("clone") > 0,
                "confidence": "medium",
            },
            {
                "id":   "T1041",
                "name": "Exfiltration Over C2 Channel",
                "check": lambda s: "connect" in s and "openat" in s,
                "confidence": "medium",
            },
        ]

        for rule in rules:
            if rule["check"](syscall_names):
                matches.append({
                    "technique_id":   rule["id"],
                    "technique_name": rule["name"],
                    "confidence":     rule["confidence"],
                })

        return matches

    def get_history(self) -> list:
        with self._lock:
            return [r.to_dict() for r in self._history]


# ─────────────────────────────────────────────
# Test standalone
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Giả lập AnomalyAlert
    sys.path.insert(0, ".")
    from anomaly_detector import AnomalyAlert

    alert = AnomalyAlert(
        pod_name="nginx-56fcf95486-r6n7g",
        pod_namespace="production",
        node_name="synthetic-node",
        detected_at=datetime.now(timezone.utc).isoformat(),
        ensemble_score=1.0,
        lstm_score=1.0,
        if_score=1.0,
        threshold=0.80,
        top_syscalls=[
            {"name": "execve",  "freq": 0.487, "count": 291},
            {"name": "connect", "freq": 0.361, "count": 216},
            {"name": "read",    "freq": 0.117, "count": 70},
        ],
        window_start=time.time() - 30,
        window_end=time.time(),
    )

    print("=" * 55)
    print("Test IsolationResponder (dry_run=True)")
    print("=" * 55)

    responder = IsolationResponder(dry_run=True)
    result = responder.respond(alert)

    # Đợi isolation thread hoàn thành
    time.sleep(2)

    history = responder.get_history()
    if history:
        r = history[0]
        print(f"\nKết quả:")
        print(f"  Success:       {r['success']}")
        print(f"  Total latency: {r['total_latency_ms']:.0f}ms")
        print(f"  Steps:")
        for s in r["steps"]:
            icon = "✅" if s["status"] == "ok" else "❌"
            print(f"    {icon} {s['step']} [{s['latency_ms']:.0f}ms]")
