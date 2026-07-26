import importlib.util
from pathlib import Path
import sys


HERE = Path(__file__).resolve()
MODULE_PATH = next(path for path in (
    HERE.with_name("run_kernel_regression.py"),  # flat VM deployment
    HERE.parents[1] / "ml-service" / "run_kernel_regression.py",
) if path.is_file())
sys.path.insert(0, str(MODULE_PATH.parent))
spec = importlib.util.spec_from_file_location("run_kernel_regression", MODULE_PATH)
run_kernel_regression = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_kernel_regression)


def pod(name, phase="Running", ready=True, deleting=False, created="2026-01-01T00:00:00Z"):
    metadata = {"name": name, "creationTimestamp": created}
    if deleting:
        metadata["deletionTimestamp"] = "2026-01-01T00:01:00Z"
    return {
        "metadata": metadata,
        "status": {
            "phase": phase,
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "containerStatuses": [{"name": "app", "ready": ready}],
        },
    }


def test_ready_pod_names_excludes_completed_unready_and_terminating_pods():
    payload = {
        "items": [
            pod("completed", phase="Succeeded", created="2026-04-01T00:00:00Z"),
            pod("unready", ready=False, created="2026-05-01T00:00:00Z"),
            pod("terminating", deleting=True, created="2026-06-01T00:00:00Z"),
            pod("ready-old", created="2026-02-01T00:00:00Z"),
            pod("ready-new", created="2026-03-01T00:00:00Z"),
        ]
    }

    assert run_kernel_regression.ready_pod_names(payload) == [
        "ready-new", "ready-old",
    ]


def test_ready_pod_names_requires_all_containers_ready():
    candidate = pod("partially-ready")
    candidate["status"]["containerStatuses"].append(
        {"name": "sidecar", "ready": False}
    )

    assert run_kernel_regression.ready_pod_names({"items": [candidate]}) == []
