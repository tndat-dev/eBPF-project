from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_deployments():
    path = ROOT / "sentinel/k8s/aims-sentinel-loadgen.yaml"
    return {doc["metadata"]["name"]: doc for doc in yaml.safe_load_all(path.read_text())}


def container_script(deployment):
    return deployment["spec"]["template"]["spec"]["containers"][0]["args"][0]


def test_north_south_and_east_west_load_are_separate():
    deployments = load_deployments()
    east_west = deployments["aims-sentinel-loadgen"]
    ingress = deployments["aims-sentinel-ingress-loadgen"]

    assert "aims-ingress-istio" not in container_script(east_west)
    assert 'services="api-gateway auth-service' in container_script(east_west)
    assert 'http://$service:8000/api/health/' in container_script(east_west)
    assert ingress["spec"]["template"]["metadata"]["labels"][
        "istio.io/dataplane-mode"
    ] == "none"
    assert "aims-ingress-istio" in container_script(ingress)


def test_all_ingress_clients_opt_out_of_ambient_hairpin():
    deployments = load_deployments()
    for name in ("aims-sentinel-ingress-loadgen", "aims-sentinel-readmix-loadgen"):
        assert deployments[name]["spec"]["template"]["metadata"]["labels"][
            "istio.io/dataplane-mode"
        ] == "none"


def test_regime_and_capture_scripts_bind_the_ingress_generator():
    regime = (ROOT / "ml-service/set_aims_traffic_regime.sh").read_text()
    capture = (ROOT / "sentinel_pulse/run_500ms_dataset_campaign.sh").read_text()
    assert regime.count("deployment/aims-sentinel-ingress-loadgen") >= 3
    assert "aims-sentinel-ingress-loadgen" in capture
