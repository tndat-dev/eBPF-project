"""Monotonic timing primitives for long baseline captures."""

import time
from collections.abc import Callable


def wait_until(
    deadline: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    maximum_sleep: float = 1.0,
) -> None:
    """Sleep until a monotonic deadline, tolerating early wake-ups."""
    if maximum_sleep <= 0:
        raise ValueError("maximum_sleep must be positive")
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            return
        sleeper(min(maximum_sleep, remaining))


def minimum_duration_satisfied(actual: float, minimum: float, tolerance=2.0) -> bool:
    """Allow only a small shutdown/scheduling tolerance, never minute collapse."""
    if actual < 0 or minimum < 0 or tolerance < 0:
        raise ValueError("durations must be non-negative")
    return actual >= max(0.0, minimum - tolerance)
