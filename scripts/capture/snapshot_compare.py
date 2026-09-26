"""Compare a fingerprint snapshot with a browser's retained fixtures.

Values that change on every connection are normalized first: GREASE code
points, the QUIC initial source connection ID, reserved versions, HTTP/3
GREASE settings, and the port in `:authority`. Chromium permutes its TLS
extensions per connection, so an extension list that differs only in order
is reported as a permutation, not a difference; so is its QUIC transport
parameter order. The HTTP/3 request a snapshot records is a script navigation
after `Accept-CH`, while the retained startup fixtures record a first
command-line navigation, so their field lists are expected to differ.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .http3_wire import (
    INITIAL_SOURCE_CONNECTION_ID,
    VERSION_INFORMATION,
    is_h3_grease,
    is_quic_grease,
    parse_parameters,
    parse_settings,
)
from .quic_resumption import RESERVED_VERSION_SENTINEL, is_reserved_version
from .snapshot import TLS_GREASE, HelloSummary, summary_lines

TLS_LIST_FIELDS = (
    "legacy_version",
    "cipher_suites",
    "supported_groups",
    "ec_point_formats",
    "signature_algorithms",
    "alpn_protocols_hex",
    "supported_versions",
    "key_share_groups",
    "server_name_hex",
)
HTTP2_FIELDS = ("initial_settings", "connection_window_update", "frame_count")


def fields(text: str, prefix: str = "") -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        key, separator, value = line.rstrip("\r").partition("=")
        if separator and key.startswith(prefix):
            values[key[len(prefix) :]] = value
    return values


def degrease(value: str) -> str:
    """Replace TLS GREASE code points in a comma-separated `0x` list."""
    items = []
    for item in value.split(","):
        try:
            number = int(item, 16)
        except ValueError:
            items.append(item)
            continue
        items.append("GREASE" if number in TLS_GREASE else item)
    return ",".join(items)


def compare_tls(label: str, snapshot: dict[str, str], retained: dict[str, str]):
    differences = []
    for name in TLS_LIST_FIELDS:
        new, old = degrease(snapshot.get(name, "")), degrease(retained.get(name, ""))
        if new != old:
            differences.append(f"{label}.{name}: retained {old!r}, snapshot {new!r}")
    new = degrease(snapshot.get("extension_types", "")).split(",")
    old = degrease(retained.get("extension_types", "")).split(",")
    if new != old:
        if sorted(new) == sorted(old):
            differences.append(f"{label}.extension_types: same set, order permuted")
        else:
            added = sorted(set(new) - set(old))
            removed = sorted(set(old) - set(new))
            differences.append(
                f"{label}.extension_types: added {added or 'none'}, "
                f"removed {removed or 'none'}"
            )
    return differences


def hello_fields(handshake_hex: str) -> dict[str, str]:
    return fields(
        "\n".join(summary_lines(HelloSummary.parse(bytes.fromhex(handshake_hex))))
    )


def transport_parameters(value_hex: str) -> list[str]:
    items = []
    for parameter in parse_parameters(bytes.fromhex(value_hex)):
        value = parameter.value
        if is_quic_grease(parameter.identifier):
            items.append("GREASE")
            continue
        if parameter.identifier == INITIAL_SOURCE_CONNECTION_ID:
            items.append(f"{parameter.identifier}:<{len(value)} bytes>")
            continue
        if parameter.identifier == VERSION_INFORMATION:
            # Chosen version, then the available ones; Chromium places its
            # reserved version at a random position among them.
            versions = [
                RESERVED_VERSION_SENTINEL
                if is_reserved_version(value[i : i + 4])
                else value[i : i + 4]
                for i in range(0, len(value), 4)
            ]
            value = b"".join(versions[:1] + sorted(versions[1:]))
        items.append(f"{parameter.identifier}:{value.hex()}")
    return items


def settings(payload_hex: str) -> list[str]:
    """SETTINGS in wire order; a GREASE setting's id, value, and widths vary."""
    return [
        "GREASE"
        if is_h3_grease(identifier)
        else f"{identifier}:{value}(widths {id_width},{value_width})"
        for identifier, id_width, value, value_width in parse_settings(
            bytes.fromhex(payload_hex)
        )
    ]


def request_headers(values: dict[str, str]) -> list[tuple[str, str]]:
    headers = []
    for index in range(int(values.get("request_header_count", "0"))):
        name_hex, _, value_hex = values[f"request_header_{index}"].partition(":")
        name = bytes.fromhex(name_hex).decode("latin-1")
        value = bytes.fromhex(value_hex).decode("latin-1")
        if name == ":authority":
            value = value.rsplit(":", 1)[0] + ":<port>"
        if name == ":path":
            value = "<path>"
        headers.append((name, value))
    return headers


def compare_order(label: str, new: list[str], old: list[str]) -> list[str]:
    if new == old:
        return []
    if sorted(new) == sorted(old):
        return [f"{label}: same set, order permuted"]
    return [f"{label}: retained {old}, snapshot {new}"]


def compare_http3(snapshot: dict[str, str], retained: dict[str, str]) -> list[str]:
    differences = compare_order(
        "h3.transport_parameters",
        transport_parameters(snapshot["transport_parameters_hex"]),
        transport_parameters(retained["transport_parameters_hex"]),
    )
    new_settings = settings(snapshot["settings_payload_normalized_hex"])
    old_settings = settings(retained["settings_payload_normalized_hex"])
    if new_settings != old_settings:
        differences.append(
            f"h3.settings: retained {old_settings}, snapshot {new_settings}"
        )
    new_headers, old_headers = request_headers(snapshot), request_headers(retained)
    new_names = [name for name, _ in new_headers]
    old_names = [name for name, _ in old_headers]
    added = [name for name in new_names if name not in old_names]
    removed = [name for name in old_names if name not in new_names]
    if added or removed:
        differences.append(
            f"h3.request_fields: added {added or 'none'}, removed {removed or 'none'}"
        )
    common = [name for name in new_names if name in old_names]
    if common != [name for name in old_names if name in new_names]:
        differences.append(f"h3.request_field_order: shared fields reordered: {common}")
    old_values = dict(old_headers)
    for name, value in new_headers:
        if name in old_values and old_values[name] != value:
            differences.append(
                f"h3.request_header {name}: retained {old_values[name]!r}, "
                f"snapshot {value!r}"
            )
    return differences


def newest(root: Path, area: str, browser: str) -> Path | None:
    """The retained fixture directory of the newest version for `browser`."""
    versions = sorted(
        (path for path in (root / area / browser).glob("*/*") if path.is_dir()),
        key=lambda path: tuple(
            int(part) if part.isdigit() else -1 for part in path.parent.name.split(".")
        ),
    )
    return versions[-1] if versions else None


def compare(text: str, root: Path, browser: str) -> list[str]:
    """Return one line per compared file, then one line per difference."""
    report = []
    snapshot = fields(text)

    def section(area: str, name: str) -> dict[str, str] | None:
        directory = newest(root, area, browser)
        path = None if directory is None else directory / name
        if path is None or not path.exists():
            report.append(f"no retained {area}/{browser}/.../{name}")
            return None
        report.append(f"compared with {path.relative_to(root).as_posix()}")
        return fields(path.read_text(encoding="utf-8"))

    retained = section("tls", "client-hello.txt")
    if retained is not None and "tls.format" in snapshot:
        report.extend(compare_tls("tls", fields(text, "tls."), retained))
    retained = section("http2", "client-startup.txt")
    if retained is not None and "h2.frame_count" in snapshot:
        new = fields(text, "h2.")
        for name in HTTP2_FIELDS:
            if new.get(name) != retained.get(name):
                report.append(
                    f"h2.{name}: retained {retained.get(name)!r}, "
                    f"snapshot {new.get(name)!r}"
                )
        count = int(new.get("frame_count", "0"))
        for index in range(count):
            key = f"frame_{index}_hex"
            if new.get(key) != retained.get(key):
                report.append(
                    f"h2.{key}: retained {retained.get(key)}, snapshot {new.get(key)}"
                )
    retained = section("http3", "client-startup.txt")
    if retained is not None and "h3_startup.format" in snapshot:
        report.extend(compare_http3(fields(text, "h3_startup."), retained))
    retained = section("http3", "quic-client-hello-1.txt")
    if retained is not None and "quic_client_hello.handshake_hex" in snapshot:
        report.extend(
            compare_tls(
                "quic_tls",
                hello_fields(snapshot["quic_client_hello.handshake_hex"]),
                hello_fields(retained["handshake_hex"]),
            )
        )
    retained = section("client-hints", "navigation.txt")
    if retained is not None:
        new = [snapshot.get(f"hint_{i}") for i in range(int(snapshot["hint_count"]))]
        old = [retained.get(f"hint_{i}") for i in range(int(retained["hint_count"]))]
        if new != old:
            report.append(f"client_hints: retained {old}, snapshot {new}")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--browser", required=True, help="fixture directory name")
    parser.add_argument("--fixtures", type=Path, default=Path("fixtures"))
    args = parser.parse_args(argv)
    text = args.snapshot.read_text(encoding="utf-8")
    for line in compare(text, args.fixtures, args.browser):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
