"""
evaluation.py
-------------
Chạy 5 attack scenarios và đo metrics theo đồ án:
  - Detection Rate (Recall)
  - False Positive Rate
  - Detection Latency
  - Response Latency
  - MITRE ATT&CK mapping accuracy

Chạy:
  python evaluation.py --runs 5 --window 10 --attack-delay 60
"""

import argparse
import json
import logging
import os
import pickle
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("evaluation.log"),
    ]
)
logger = logging.getLogger("evaluation")


# ─────────────────────────────────────────────
# Kết quả 1 lần chạy
# ─────────────────────────────────────────────

@dataclass
class RunResult:
    scenario:          str
    run_id:            int
    detected:          bool    = False
    detection_latency: float   = 0.0   # giây từ lúc inject → alert
    response_latency:  float   = 0.0   # giây từ alert → isolation xong
    ensemble_score:    float   = 0.0
    mitre_mapped:      bool    = False
    mitre_techniques:  list    = field(default_factory=list)
    error:             str     = ""


@dataclass
class ScenarioResult:
    scenario:          str
    runs:              List[RunResult] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        if not self.runs: return 0.0
        return sum(1 for r in self.runs if r.detected) / len(self.runs)

    @property
    def avg_detection_latency(self) -> float:
        detected = [r.detection_latency for r in self.runs if r.detected]
        return np.mean(detected) if detected else 0.0

    @property
    def std_detection_latency(self) -> float:
        detected = [r.detection_latency for r in self.runs if r.detected]
        return np.std(detected) if detected else 0.0

    @property
    def avg_response_latency(self) -> float:
        detected = [r.response_latency for r in self.runs if r.detected]
        return np.mean(detected) if detected else 0.0

    @property
    def mitre_accuracy(self) -> float:
        detected = [r for r in self.runs if r.detected]
        if not detected: return 0.0
        return sum(1 for r in detected if r.mitre_mapped) / len(detected)


# ─────────────────────────────────────────────
# Evaluator
# ─────────────────────────────────────────────

class Evaluator:
    """
    Chạy từng scenario N lần, thu thập metrics.
    """

    SCENARIOS = {
        "S1_reverse_shell": {
            "attack_type": "reverse_shell",
            "description": "Reverse Shell — execve(/bin/sh) + connect(external)",
            "mitre_expected": ["T1059"],
            "profile": {
                "execve": 0.50, "connect": 0.35,
                "read": 0.10, "write": 0.05,
            },
        },
        "S2_container_escape": {
            "attack_type": "container_escape",
            "description": "Container Escape — unshare + mount + clone",
            "mitre_expected": ["T1611"],
            "profile": {
                "unshare": 0.30, "mount": 0.30, "clone": 0.20,
                "execve": 0.15, "openat": 0.05,
            },
        },
        "S3_cryptomining": {
            "attack_type": "cryptomining",
            "description": "Cryptomining — clone threads burst",
            "mitre_expected": ["T1496"],
            "profile": {
                "clone": 0.60, "read": 0.20,
                "write": 0.15, "execve": 0.05,
            },
        },
        "S4_privilege_escalation": {
            "attack_type": "privilege_escalation",
            "description": "Privilege Escalation — setuid/setgid/capset",
            "mitre_expected": ["T1548"],
            "profile": {
                "setuid": 0.35, "setgid": 0.25, "capset": 0.20,
                "execve": 0.15, "openat": 0.05,
            },
        },
        "S5_data_exfiltration": {
            "attack_type": "data_exfiltration",
            "description": "Data Exfiltration — mass file read + connect",
            "mitre_expected": ["T1041"],
            "profile": {
                "openat": 0.40, "read": 0.30, "connect": 0.20,
                "write": 0.05, "execve": 0.05,
            },
        },
    }

    def __init__(self, target_pod_key: str, window_seconds: int = 30,
                 attack_delay: int = 60, attack_duration: int = 60,
                 threshold: float = 0.80, runs_per_scenario: int = 5,
                 dry_run: bool = True):
        self.target_pod_key    = target_pod_key
        self.window_seconds    = window_seconds
        self.attack_delay      = attack_delay
        self.attack_duration   = attack_duration
        self.threshold         = threshold
        self.runs_per_scenario = runs_per_scenario
        self.dry_run           = dry_run

        # Load vocab và models
        with open("vocab.pkl", "rb") as f:
            self.vocab = pickle.load(f)

        sys.path.insert(0, ".")
        from ml_models import ModelManager
        self.manager = ModelManager(model_dir="models", vocab_path="vocab.pkl")
        self.manager.load_all()
        logger.info(f"Models loaded: {self.manager.list_models()}")

    def run_all(self) -> dict:
        """Chạy tất cả 5 scenarios."""
        results = {}
        fp_count, total_normal_windows = 0, 0

        print("\n" + "="*65)
        print("🔬 BẮT ĐẦU EVALUATION — 5 Attack Scenarios")
        print(f"   Target pod:  {self.target_pod_key}")
        print(f"   Runs/scenario: {self.runs_per_scenario}")
        print(f"   Window: {self.window_seconds}s | Threshold: {self.threshold}")
        print("="*65 + "\n")

        for scenario_id, scenario_cfg in self.SCENARIOS.items():
            print(f"\n{'─'*65}")
            print(f"📋 {scenario_id}: {scenario_cfg['description']}")
            print(f"{'─'*65}")

            scenario_result = ScenarioResult(scenario=scenario_id)

            for run_id in range(1, self.runs_per_scenario + 1):
                print(f"\n  Run {run_id}/{self.runs_per_scenario}...")
                result = self._run_one(
                    scenario_id=scenario_id,
                    scenario_cfg=scenario_cfg,
                    run_id=run_id,
                )
                scenario_result.runs.append(result)
                fp_count += self._count_fp_in_run(result)
                total_normal_windows += self.attack_delay // self.window_seconds

                status = "✅ DETECTED" if result.detected else "❌ MISSED"
                print(
                    f"  {status} | "
                    f"detect_latency={result.detection_latency:.1f}s | "
                    f"response_latency={result.response_latency:.3f}s | "
                    f"score={result.ensemble_score:.4f}"
                )
                if result.error:
                    print(f"  ⚠️  Error: {result.error}")

                # Cleanup sau mỗi run
                self._cleanup(run_id)
                time.sleep(5)

            results[scenario_id] = scenario_result
            self._print_scenario_summary(scenario_result)

        # Tính overall metrics
        fp_rate = fp_count / max(1, total_normal_windows)
        self._print_final_report(results, fp_rate)
        self._save_report(results, fp_rate)
        return results

    def _run_one(self, scenario_id: str, scenario_cfg: dict,
                 run_id: int) -> RunResult:
        """Chạy 1 lần cho 1 scenario."""
        result = RunResult(scenario=scenario_id, run_id=run_id)

        # Events để track timing
        attack_start_time   = [0.0]
        alert_received_time = [0.0]
        isolation_done_time = [0.0]

        # Import modules
        from feature_engineering import WindowManager
        from anomaly_detector import AnomalyDetector, AnomalyAlert
        from isolation_responder import IsolationResponder

        # Alert callback
        def on_alert(alert: AnomalyAlert):
            if alert.pod_key == self.target_pod_key:
                alert_received_time[0] = time.time()
                result.detected       = True
                result.ensemble_score = alert.ensemble_score

                # Response latency
                from isolation_responder import IsolationResponder as IR
                resp = IR(dry_run=self.dry_run)
                t0 = time.time()
                resp.respond(alert)
                time.sleep(0.5)  # đợi isolation thread
                isolation_done_time[0] = time.time()
                result.response_latency = isolation_done_time[0] - t0

                # MITRE mapping
                from isolation_responder import IsolationResponder as IR2
                ir_tmp = IR2.__new__(IR2)
                mitre = ir_tmp._map_mitre(alert.top_syscalls)
                result.mitre_techniques = [m["technique_id"] for m in mitre]
                expected = scenario_cfg["mitre_expected"]
                result.mitre_mapped = any(
                    t in result.mitre_techniques for t in expected
                )

        # Setup pipeline
        window_mgr = WindowManager(
            window_seconds=self.window_seconds,
            vocab=self.vocab,
            on_feature_vector=self._make_detector(on_alert),
        )

        # Phase 1: Normal baseline (attack_delay giây)
        logger.info(f"  Phase 1: Normal ({self.attack_delay}s)...")
        normal_start = time.time()
        stop_normal  = threading.Event()

        def run_normal():
            while not stop_normal.is_set():
                self._inject_normal(window_mgr)
                time.sleep(0.1)

        normal_thread = threading.Thread(target=run_normal, daemon=True)
        normal_thread.start()
        time.sleep(self.attack_delay)
        stop_normal.set()

        # Phase 2: Attack injection
        logger.info(f"  Phase 2: Inject {scenario_cfg['attack_type']}...")
        attack_start_time[0] = time.time()
        self._inject_attack(window_mgr, scenario_cfg["profile"],
                            self.attack_duration)

        # Đợi thêm 1 window để detector kịp score
        time.sleep(self.window_seconds + 5)

        # Tính detection latency
        if result.detected and attack_start_time[0] > 0:
            result.detection_latency = (
                alert_received_time[0] - attack_start_time[0]
            )

        return result

    def _make_detector(self, on_alert_cb):
        """Tạo closure kết nối WindowManager → ML → Alert."""
        from anomaly_detector import AnomalyDetector

        detector = AnomalyDetector(
            model_manager=self.manager,
            on_alert=on_alert_cb,
            threshold=self.threshold,
            cooldown_seconds=30,
        )
        return detector.handle_feature_vector

    def _inject_normal(self, window_mgr, n_events: int = 5):
        """Inject normal syscall events."""
        import random
        normal_profile = {
            "read": 0.40, "write": 0.35, "close": 0.15,
            "connect": 0.05, "openat": 0.05,
        }
        ns, name = self.target_pod_key.split("/", 1)
        syscalls = list(normal_profile.keys())
        weights  = list(normal_profile.values())

        class FakePod:
            def __init__(self): self.name=name; self.namespace=ns; self.uid=""
        class FakeProc:
            def __init__(self): self.pid=1; self.uid=1000; self.binary="/usr/sbin/nginx"; self.arguments=""; self.parent_exec_id=""; self.exec_id=""
        class FakeEvent:
            def __init__(self, sc):
                self.pod=FakePod(); self.process=FakeProc()
                self.syscall_name=sc; self.node_name="synthetic-node"
                self.event_type="process_kprobe"; self.timestamp=""

        for _ in range(n_events):
            sc = random.choices(syscalls, weights=weights)[0]
            window_mgr.handle_event(FakeEvent(sc))

    def _inject_attack(self, window_mgr, profile: dict,
                       duration: int):
        """Inject attack events trong duration giây."""
        import random
        ns, name = self.target_pod_key.split("/", 1)
        syscalls = list(profile.keys())
        weights  = [profile[s] for s in syscalls]
        total_w  = sum(weights)
        weights  = [w/total_w for w in weights]

        class FakePod:
            def __init__(self): self.name=name; self.namespace=ns; self.uid=""
        class FakeProc:
            def __init__(self): self.pid=9999; self.uid=0; self.binary="/bin/sh"; self.arguments="-c bash -i"; self.parent_exec_id=""; self.exec_id=""
        class FakeEvent:
            def __init__(self, sc):
                self.pod=FakePod(); self.process=FakeProc()
                self.syscall_name=sc; self.node_name="synthetic-node"
                self.event_type="process_kprobe"; self.timestamp=""

        start = time.time()
        while time.time() - start < duration:
            sc = random.choices(syscalls, weights=weights)[0]
            window_mgr.handle_event(FakeEvent(sc))
            time.sleep(0.05)

    def _count_fp_in_run(self, result: RunResult) -> int:
        """FP = alert trong phase normal (không có attack)."""
        # Nếu detection_latency < attack_delay → alert trước attack → FP
        if result.detected and result.detection_latency < 0:
            return 1
        return 0

    def _cleanup(self, run_id: int):
        """Cleanup K8s resources sau mỗi run."""
        import subprocess
        ns, name = self.target_pod_key.split("/", 1)
        try:
            # Never uncordon a hard-coded cluster node. A real live-response
            # evaluation must opt in and record its target explicitly.
            cleanup_node = os.environ.get("EVALUATION_CLEANUP_NODE", "").strip()
            if cleanup_node:
                subprocess.run(
                    ["kubectl", "uncordon", cleanup_node],
                    capture_output=True,
                )
            # Xóa quarantine label
            subprocess.run(
                ["kubectl", "label", "pod", "-n", ns,
                 "-l", f"app={name.split('-')[0]}", "quarantine-"],
                capture_output=True
            )
            # Xóa CiliumNetworkPolicy
            subprocess.run(
                ["kubectl", "delete", "ciliumnetworkpolicy",
                 "-n", ns, "--selector=managed-by=security-operator"],
                capture_output=True
            )
        except Exception as e:
            logger.debug(f"Cleanup error (ok): {e}")

    def _print_scenario_summary(self, sr: ScenarioResult):
        print(f"\n  📊 {sr.scenario} Summary:")
        print(f"     Detection Rate:       {sr.detection_rate*100:.0f}%"
              f" ({sum(1 for r in sr.runs if r.detected)}/{len(sr.runs)})")
        print(f"     Detect Latency:       {sr.avg_detection_latency:.1f}s"
              f" ± {sr.std_detection_latency:.1f}s")
        print(f"     Response Latency:     {sr.avg_response_latency*1000:.0f}ms")
        print(f"     MITRE Accuracy:       {sr.mitre_accuracy*100:.0f}%")

    def _print_final_report(self, results: dict, fp_rate: float):
        print("\n\n" + "="*65)
        print("📈 FINAL EVALUATION REPORT")
        print("="*65)
        print(f"{'Scenario':<28} {'DR':>6} {'Det.Lat':>10} {'Resp.Lat':>10} {'MITRE':>7}")
        print("─"*65)

        all_dr, all_dl, all_rl = [], [], []
        for sid, sr in results.items():
            dr = sr.detection_rate * 100
            dl = sr.avg_detection_latency
            rl = sr.avg_response_latency * 1000
            mt = sr.mitre_accuracy * 100
            print(f"  {sid:<26} {dr:>5.0f}% {dl:>8.1f}s {rl:>8.0f}ms {mt:>6.0f}%")
            all_dr.append(dr); all_dl.append(dl); all_rl.append(rl)

        print("─"*65)
        print(
            f"  {'OVERALL':<26} "
            f"{np.mean(all_dr):>5.0f}% "
            f"{np.mean(all_dl):>8.1f}s "
            f"{np.mean(all_rl):>8.0f}ms"
        )
        print(f"\n  False Positive Rate: {fp_rate*100:.2f}%")
        print(f"\n  NFR Targets:")
        print(f"    Detection Rate  ≥ 90%:  "
              f"{'✅' if np.mean(all_dr) >= 90 else '❌'} {np.mean(all_dr):.0f}%")
        print(f"    Response Latency < 5s:  "
              f"{'✅' if np.mean(all_rl)/1000 < 5 else '❌'} {np.mean(all_rl)/1000:.2f}s")
        print(f"    FP Rate < 10%:          "
              f"{'✅' if fp_rate < 0.10 else '❌'} {fp_rate*100:.2f}%")
        print("="*65)

    def _save_report(self, results: dict, fp_rate: float):
        os.makedirs("evaluation", exist_ok=True)
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "config": {
                "target_pod":    self.target_pod_key,
                "window_seconds": self.window_seconds,
                "threshold":     self.threshold,
                "runs":          self.runs_per_scenario,
            },
            "false_positive_rate": fp_rate,
            "scenarios": {},
        }
        for sid, sr in results.items():
            report["scenarios"][sid] = {
                "detection_rate":      sr.detection_rate,
                "avg_detect_latency":  sr.avg_detection_latency,
                "std_detect_latency":  sr.std_detection_latency,
                "avg_response_latency": sr.avg_response_latency,
                "mitre_accuracy":      sr.mitre_accuracy,
                "runs": [
                    {
                        "run_id":            r.run_id,
                        "detected":          r.detected,
                        "detection_latency": r.detection_latency,
                        "response_latency":  r.response_latency,
                        "ensemble_score":    r.ensemble_score,
                        "mitre_mapped":      r.mitre_mapped,
                        "mitre_techniques":  r.mitre_techniques,
                    }
                    for r in sr.runs
                ],
            }

        fname = f"evaluation/report_{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report saved: {fname}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluation — 5 Attack Scenarios")
    parser.add_argument("--target", default="production/nginx",
                        help="Pod key để inject attack")
    parser.add_argument("--runs", type=int, default=5,
                        help="Số lần chạy mỗi scenario (mặc định 5)")
    parser.add_argument("--window", type=int,
                        default=int(os.environ.get("SENTINEL_WINDOW_SECONDS", "10")))
    parser.add_argument("--attack-delay", type=int, default=60,
                        help="Giây normal trước khi inject attack")
    parser.add_argument("--attack-duration", type=int, default=60)
    parser.add_argument("--threshold", type=float, default=0.80)
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--live-response", action="store_true",
                        help="Explicitly allow response actions; dry-run is the default")
    parser.add_argument("--quick", action="store_true", default=False,
                        help="Chạy nhanh: 1 run/scenario, delay=30s")
    args = parser.parse_args()

    if args.live_response:
        args.dry_run = False

    if args.quick:
        args.runs = 1
        args.attack_delay = 30
        args.attack_duration = 30
        logger.info("Quick mode: 1 run/scenario, delay=30s")

    evaluator = Evaluator(
        target_pod_key=args.target,
        window_seconds=args.window,
        attack_delay=args.attack_delay,
        attack_duration=args.attack_duration,
        threshold=args.threshold,
        runs_per_scenario=args.runs,
        dry_run=args.dry_run,
    )

    evaluator.run_all()
