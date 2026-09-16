"""Compare stable logical flights from two Phantom QUIC packet summaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .quic_flight import (
    LogicalFlight,
    compare_logical_flights,
    parse_logical_flight_summary,
)


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    mapping: dict[str, object] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError(f"duplicate JSON key {key!r}")
        mapping[key] = value
    return mapping


def load_logical_flight(path: Path) -> LogicalFlight:
    """Loads one strict packet-summary document."""

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"could not read {path}: {error}") from error
    try:
        return parse_logical_flight_summary(value)
    except ValueError as error:
        raise ValueError(f"invalid packet summary {path}: {error}") from error


def main() -> None:
    parser = argparse.ArgumentParser(
        description="compare packetization-independent QUIC request flights"
    )
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    args = parser.parse_args()

    try:
        left = load_logical_flight(args.left)
        right = load_logical_flight(args.right)
    except ValueError as error:
        parser.error(str(error))
    differences = compare_logical_flights(left, right)
    if differences:
        for difference in differences:
            print(difference)
        raise SystemExit(1)
    print("logical QUIC flights match")


if __name__ == "__main__":
    main()
