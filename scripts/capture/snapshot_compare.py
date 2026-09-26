"""Compare a fingerprint snapshot with a browser's retained fixtures.

For each layer the tool reads the newest retained fixture of the browser
recorded on the snapshot's operating system, and prints `compared <path>`,
then one `differs ...` line per difference. A layer the snapshot lacks, or
a retained fixture that is missing, is a difference too. The exit status is
1 when any difference was printed.

Compared, after normalizing GREASE, key shares, ECH payloads, and QUIC
connection IDs and reserved versions:

- TCP ClientHello: legacy version, cipher suites, extension order, and each
  extension body;
- HTTP/2: the frames before the first HEADERS, and the first navigation's
  field order, HEADERS flags, and priority;
- QUIC ClientHello: the same as TCP, transport parameters included;
- HTTP/3 SETTINGS;
- client hints.

Chromium permutes its TLS extensions and QUIC transport parameters per
connection, so for Chromium browsers a list that differs only in order is
not a difference. For Firefox it is.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .browser_launch import CHROMIUM_BROWSERS
from .http3_wire import (
    INITIAL_SOURCE_CONNECTION_ID,
    VERSION_INFORMATION,
    is_h3_grease,
    is_quic_grease,
    parse_parameters,
    parse_settings,
)
from .quic_resumption import (
    ECH,
    KEY_SHARE,
    PRE_SHARED_KEY,
    QUIC_TRANSPORT_PARAMETERS,
    RESERVED_VERSION_SENTINEL,
    is_reserved_version,
    is_tls_grease,
    parse_client_hello,
)
from .snapshot import hello_message

PADDING = 0x0015
TRUST_ANCHORS = 0xCA34
# Bodies that are length-prefixed lists of u16 code points after `n` bytes.
U16_LISTS = {0x000A: 2, 0x000D: 2, 0x002B: 1}


def fields(text: str, prefix: str = "") -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        key, separator, value = line.rstrip("\r").partition("=")
        if separator and key.startswith(prefix):
            values[key[len(prefix) :]] = value
    return values


def code(value: int) -> str:
    return "GREASE" if is_tls_grease(value) else f"0x{value:04x}"


def transport_parameters(body: bytes, permuted: bool) -> str:
    items = []
    for parameter in parse_parameters(body):
        value = parameter.value
        if is_quic_grease(parameter.identifier):
            items.append("GREASE")
            continue
        if parameter.identifier == INITIAL_SOURCE_CONNECTION_ID:
            value = f"<{len(value)} bytes>".encode()
        elif parameter.identifier == VERSION_INFORMATION:
            # The chosen version, then the available ones; Chromium puts its
            # reserved version at a random position among them.
            versions = [
                RESERVED_VERSION_SENTINEL
                if is_reserved_version(value[i : i + 4])
                else value[i : i + 4]
                for i in range(0, len(value), 4)
            ]
            value = b"".join(versions[:1] + sorted(versions[1:]))
        items.append(f"{parameter.identifier}:{value.hex()}")
    return ",".join(sorted(items) if permuted else items)


def extension_body(kind: int, body: bytes, permuted: bool) -> str:
    """One extension body with its per-connection randomness replaced."""
    if kind in U16_LISTS:
        start = U16_LISTS[kind]
        values = [
            int.from_bytes(body[i : i + 2], "big")
            for i in range(start, len(body) - 1, 2)
        ]
        return ",".join(code(value) for value in values)
    if kind == KEY_SHARE:
        shares, offset = [], 2
        while offset + 4 <= len(body):
            length = int.from_bytes(body[offset + 2 : offset + 4], "big")
            shares.append(
                f"{code(int.from_bytes(body[offset : offset + 2], 'big'))}/{length}"
            )
            offset += 4 + length
        return ",".join(shares)
    if kind == ECH and len(body) >= 8 and body[0] == 0:
        # Outer ECH: type, cipher suite, and enc length. The config ID, enc,
        # and payload are random, and Chromium's GREASE payload length varies
        # per connection (144 to 240 bytes in the Windows captures).
        return f"outer,suite:{body[1:5].hex()},enc:{int.from_bytes(body[6:8], 'big')}"
    if kind == PADDING:
        return f"<{len(body)} bytes>"
    if kind == QUIC_TRANSPORT_PARAMETERS:
        return transport_parameters(body, permuted)
    if kind == TRUST_ANCHORS and permuted:
        items, offset = [], 2
        while offset < len(body):
            items.append(body[offset : offset + 1 + body[offset]].hex())
            offset += 1 + body[offset]
        return ",".join(sorted(items))
    return body.hex()


def compare_hello(label: str, new: bytes, old: bytes, permuted: bool) -> list[str]:
    """Differences between two ClientHello handshake messages."""
    differences = []
    new_shape, old_shape = parse_client_hello(new), parse_client_hello(old)
    if new[4:6] != old[4:6]:
        differences.append(
            f"{label}.legacy_version: retained {old[4:6].hex()}, snapshot {new[4:6].hex()}"
        )
    new_suites = [code(v) for v in new_shape.cipher_suites]
    old_suites = [code(v) for v in old_shape.cipher_suites]
    if new_suites != old_suites:
        differences.append(
            f"{label}.cipher_suites: retained {old_suites}, snapshot {new_suites}"
        )
    new_types = [code(v) for v in new_shape.extension_types]
    old_types = [code(v) for v in old_shape.extension_types]
    if new_types != old_types and not (
        permuted and sorted(new_types) == sorted(old_types)
    ):
        differences.append(
            f"{label}.extension_types: retained {old_types}, snapshot {new_types}"
        )
    old_bodies = dict(old_shape.extensions)
    for kind, body in new_shape.extensions:
        if is_tls_grease(kind) or kind == PRE_SHARED_KEY or kind not in old_bodies:
            continue
        new_body = extension_body(kind, body, permuted)
        old_body = extension_body(kind, old_bodies[kind], permuted)
        if new_body != old_body:
            differences.append(
                f"{label}.extension 0x{kind:04x}: retained {old_body}, snapshot {new_body}"
            )
    return differences


def settings(payload_hex: str) -> list[str]:
    """SETTINGS in wire order; a GREASE setting's id, value, and widths vary."""
    return [
        "GREASE"
        if is_h3_grease(identifier)
        else f"{identifier}:{value}/{id_width},{value_width}"
        for identifier, id_width, value, value_width in parse_settings(
            bytes.fromhex(payload_hex)
        )
    ]


def tls_message(values: dict[str, str]) -> bytes:
    count = int(values["record_count"])
    return hello_message(
        [bytes.fromhex(values[f"record_{i}_hex"]) for i in range(count)]
    )


def navigation(values: dict[str, str], key: str, header: str) -> tuple[str, str, str]:
    """Field order, HEADERS flags, and priority of one recorded HEADERS block."""
    flags = header.split("flags:", 1)[1].split(",", 1)[0]
    return values[f"{key}_field_order"], flags, header.split("priority:", 1)[1]


def newest(root: Path, area: str, browser: str, name: str, system: str) -> Path | None:
    """The newest retained `name` for `browser` recorded on `system`."""
    candidates = []
    for path in (root / area / browser).glob(f"*/*/{name}"):
        if fields(path.read_text(encoding="utf-8")).get("operating_system") == system:
            version = tuple(
                int(p) if p.isdigit() else -1
                for p in path.parent.parent.name.split(".")
            )
            candidates.append((version, path))
    return max(candidates)[1] if candidates else None


def compare(text: str, root: Path, browser: str) -> list[str]:
    snapshot = fields(text)
    system = snapshot.get("operating_system", "")
    permuted = browser in CHROMIUM_BROWSERS
    report: list[str] = []

    def retained(
        area: str, name: str, layer: str, present: bool
    ) -> dict[str, str] | None:
        path = newest(root, area, browser, name, system)
        if path is None:
            report.append(
                f"differs {layer}: no retained {area}/{browser}/*/*/{name} for {system!r}"
            )
            return None
        if not present:
            error = snapshot.get(f"{layer}_error", "not recorded")
            report.append(f"differs {layer}: missing from the snapshot ({error})")
            return None
        report.append(f"compared {path.relative_to(root).as_posix()}")
        return fields(path.read_text(encoding="utf-8"))

    def differs(lines: Sequence[str]) -> None:
        report.extend(f"differs {line}" for line in lines)

    old = retained("tls", "client-hello.txt", "tls", "tls.format" in snapshot)
    if old is not None:
        differs(
            compare_hello(
                "tls", tls_message(fields(text, "tls.")), tls_message(old), permuted
            )
        )

    old = retained("http2", "client-startup.txt", "h2", "h2.frame_count" in snapshot)
    if old is not None:
        new = fields(text, "h2.")
        for key in ("frame_count", "initial_settings", "connection_window_update"):
            if new.get(key) != old.get(key):
                differs([f"h2.{key}: retained {old.get(key)}, snapshot {new.get(key)}"])
        for index in range(int(new.get("frame_count", "0"))):
            key = f"frame_{index}_hex"
            if new.get(key) != old.get(key):
                differs([f"h2.{key}: retained {old.get(key)}, snapshot {new.get(key)}"])

    first = next(
        (
            key
            for key, value in snapshot.items()
            if key.startswith("request_")
            and key.count("_") == 1
            and value.startswith("protocol:h2,")
            and ",kind:start," in value
        ),
        None,
    )
    # The retained WebSocket sessions start with a command-line navigation.
    old = retained(
        "websocket", "accept.txt", "h2_navigation", f"{first}_headers" in snapshot
    )
    if old is not None:
        new_nav = navigation(snapshot, str(first), snapshot[f"{first}_headers"])
        connection = min(
            int(key.split("_")[3])
            for key in old
            if key.startswith("run_0_connection_") and key.endswith("_headers_0")
        )
        key = f"run_0_connection_{connection}_headers_0"
        old_nav = navigation(old, key, old[key])
        for part, new_value, old_value in zip(
            ("field_order", "flags", "priority"), new_nav, old_nav, strict=True
        ):
            if new_value != old_value:
                differs(
                    [
                        f"h2_navigation.{part}: retained {old_value}, snapshot {new_value}"
                    ]
                )

    old = retained(
        "http3",
        "quic-client-hello-1.txt",
        "quic_client_hello",
        "quic_client_hello.handshake_hex" in snapshot,
    )
    if old is not None:
        differs(
            compare_hello(
                "quic_tls",
                bytes.fromhex(snapshot["quic_client_hello.handshake_hex"]),
                bytes.fromhex(old["handshake_hex"]),
                permuted,
            )
        )

    old = retained(
        "http3",
        "client-startup.txt",
        "h3",
        "h3.settings_payload_normalized_hex" in snapshot,
    )
    if old is not None:
        new_settings = settings(snapshot["h3.settings_payload_normalized_hex"])
        old_settings = settings(old["settings_payload_normalized_hex"])
        if new_settings != old_settings:
            differs([f"h3.settings: retained {old_settings}, snapshot {new_settings}"])

    old = retained("client-hints", "navigation.txt", "hints", "hint_count" in snapshot)
    if old is not None:
        new = [
            snapshot.get(f"hint_{i}")
            for i in range(int(snapshot.get("hint_count", "0")))
        ]
        hints = [old.get(f"hint_{i}") for i in range(int(old.get("hint_count", "0")))]
        if new != hints:
            differs([f"client_hints: retained {hints}, snapshot {new}"])
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--browser", required=True, help="fixture directory name")
    parser.add_argument("--fixtures", type=Path, default=Path("fixtures"))
    args = parser.parse_args(argv)
    report = compare(
        args.snapshot.read_text(encoding="utf-8"), args.fixtures, args.browser
    )
    print("\n".join(report))
    return 1 if any(line.startswith("differs ") for line in report) else 0


if __name__ == "__main__":
    sys.exit(main())
