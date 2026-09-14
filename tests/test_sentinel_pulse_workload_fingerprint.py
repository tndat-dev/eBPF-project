from sentinel_pulse.workload_fingerprint import fingerprint


def test_fingerprint_tracks_template_not_pod_uid_and_excludes_load_generators():
    payload = {"items": [
        {"metadata": {"namespace": "production", "name": "cart-service-a1b2c3d4-x1y2z", "labels": {
            "app.kubernetes.io/name": "cart-service", "rollouts-pod-template-hash": "a1b2c3d4"}},
         "status": {"phase": "Running"}},
        {"metadata": {"namespace": "production", "name": "cart-service-a1b2c3d4-z9y8x", "labels": {
            "app.kubernetes.io/name": "cart-service", "rollouts-pod-template-hash": "a1b2c3d4"}},
         "status": {"phase": "Running"}},
        {"metadata": {"namespace": "production", "name": "cart-loadgen-123", "labels": {}},
         "status": {"phase": "Running"}},
    ]}
    assert fingerprint(payload) == {
        "schema": "sentinel-pulse-workload-fingerprint-v1",
        "workloads": {"production/cart-service": ["a1b2c3d4"]},
    }
