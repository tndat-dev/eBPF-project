"""Resolve capacity settings without silently weakening a registered soak."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def resolve(marker: dict, minimum: str | None = None, maximum: str | None = None) -> tuple[int, int]:
    names = ("minimum_root_available_bytes", "maximum_root_used_percent")
    registered = [name in marker for name in names]
    if any(registered) and not all(registered):
        raise ValueError("incomplete registered capacity contract")
    if not all(registered):
        raise ValueError("missing registered capacity contract")
    values = tuple(marker[name] for name in names)
    if any(type(value) is not int for value in values):
        raise ValueError("capacity values must be integers")
    if values[0] < 0 or not 1 <= values[1] <= 99:
        raise ValueError("invalid registered capacity contract")
    for override, registered_value in zip((minimum, maximum), values):
        if override is not None:
            if not override.isascii() or not override.isdigit():
                raise ValueError("invalid capacity override")
            if int(override) != registered_value:
                raise ValueError("capacity override differs from registered contract")
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--minimum")
    parser.add_argument("--maximum")
    args = parser.parse_args()
    try:
        minimum, maximum = resolve(json.loads(args.marker.read_text()), args.minimum, args.maximum)
    except (ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    print(minimum, maximum)


if __name__ == "__main__":
    main()
