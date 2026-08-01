"""Conservative Kubernetes workload identity helpers.

This root copy mirrors ``ml-service/workload_identity.py`` because the detector
supports both repository-root and deployed ML-service entrypoints.
"""


def get_deployment_key(pod_key: str) -> str:
    """Resolve ``namespace/pod`` to ``namespace/workload`` when unambiguous."""
    try:
        namespace, pod_name = pod_key.split("/", 1)
    except ValueError:
        return pod_key

    parts = pod_name.rsplit("-", 2)
    if (
        len(parts) == 3
        and 8 <= len(parts[1]) <= 10
        and len(parts[2]) == 5
        and parts[1].isalnum()
        and parts[2].isalnum()
    ):
        return f"{namespace}/{parts[0]}"
    if len(parts) >= 2 and parts[-1].isdigit():
        return f"{namespace}/{'-'.join(parts[:-1])}"
    return pod_key


get_deploy_key = get_deployment_key
