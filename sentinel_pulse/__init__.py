"""Sentinel Pulse: eBPF syscall-counter anomaly detection for Kubernetes containers."""

__all__ = ["PulseFeature", "PulseFeatureBuilder", "PulseSnapshot"]


def __getattr__(name: str):
    """Keep scheduler/integrity CLIs independent of NumPy and sklearn.

    Feature classes remain available through the package API, but importing a
    standard-library-only command such as ``prepare_contract`` no longer pulls
    the training stack into a control-plane process.
    """
    if name in __all__:
        from .collector import features

        return getattr(features, name)
    raise AttributeError(name)
