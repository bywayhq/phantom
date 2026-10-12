"""Record a Chromium browser's socket calls and host lookups with Frida hooks.

A wire capture cannot show socket options, the order of connection attempts
before one succeeds, or host lookups answered from a cache. This tool attaches
the Frida agent in `socket_hooks.js` to the browser's network service process
and records its Winsock and resolver calls while the browser loads a page from
a loopback HTTP/1.1 origin. The origin also records the connections it
accepted, so each run has wire evidence beside the hook evidence.

Windows only: the agent hooks `ws2_32.dll` and `dnsapi.dll`.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import ipaddress
import json
import platform
import queue
import re
import shlex
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .browser_failures import raise_browser_failures
from .browser_launch import (
    CLIENT_NAMES,
    DESKTOP_CHROMIUM_BROWSERS,
    PROFILE_PLACEHOLDER,
    chromium_arguments,
    recorded_arguments,
    terminate_profile_processes,
)
from .fixture_file import write_text_fixture

FORMAT = "phantom-socket-hooks-v1"
AGENT = Path(__file__).with_name("socket_hooks.js")
NETWORK_SERVICE_SWITCH = "--utility-sub-type=network.mojom.NetworkService"
MAX_REQUEST_HEAD = 64 * 1024
# Existing profile cleanup permits two 60-second commands and a 5-second join.
_RUN_CLEANUP_SECONDS = 150.0
_HOOK_CHILD_LIMIT = 64
_HOOK_REPORT_LIMIT = 100_000
_HOOK_READY_SECONDS = 10.0
_HOOK_NATIVE_CLEANUP_SECONDS = 15.0
_PROCESS_TERMINATE = 0x0001
# A name that public DNS resolves to 127.0.0.1, so a lookup leaves the
# browser's resolver while the connection stays on loopback.
LOOKUP_HOST = "127.0.0.1.nip.io"
SLOW_RESPONSE_SECONDS = 1.5
PARALLEL_REQUESTS = 10
LOOKUP_INTERVAL_SECONDS = 10
# Chromium 154 keeps a used idle socket for 300 s
# (`net/socket/client_socket_pool.cc:42`).
IDLE_REUSE_SECONDS = 290
IDLE_CLOSE_SECONDS = 600
LOOKUP_COUNT = 13

# Winsock constants (winsock2.h, ws2def.h, mstcpip.h).
AF_INET = 2
AF_INET6 = 23
SOCK_STREAM = 1
SOCK_DGRAM = 2
SOL_SOCKET = 0xFFFF
IPPROTO_IP = 0
IPPROTO_IPV6 = 41
IPPROTO_TCP = 6
SIO_KEEPALIVE_VALS = 0x98000004
SIO_TCP_INITIAL_RTO = 0x98000011
SOCKET_OPTIONS = {
    (SOL_SOCKET, 0x0004): "SO_REUSEADDR",
    (SOL_SOCKET, 0x0008): "SO_KEEPALIVE",
    (SOL_SOCKET, 0x0020): "SO_BROADCAST",
    (SOL_SOCKET, 0x0080): "SO_LINGER",
    (SOL_SOCKET, 0x1001): "SO_SNDBUF",
    (SOL_SOCKET, 0x1002): "SO_RCVBUF",
    (SOL_SOCKET, 0x3005): "SO_RANDOMIZE_PORT",
    (SOL_SOCKET, 0x3006): "SO_PORT_SCALABILITY",
    (SOL_SOCKET, 0x3007): "SO_REUSE_UNICASTPORT",
    (SOL_SOCKET, -5): "SO_EXCLUSIVEADDRUSE",
    (SOL_SOCKET, 0x700B): "SO_UPDATE_CONNECT_CONTEXT",
    (IPPROTO_TCP, 0x0001): "TCP_NODELAY",
    (IPPROTO_TCP, 0x0003): "TCP_KEEPALIVE",
    (IPPROTO_TCP, 0x000F): "TCP_FASTOPEN",
    (IPPROTO_TCP, 0x0010): "TCP_KEEPCNT",
    (IPPROTO_TCP, 0x0011): "TCP_KEEPINTVL",
    (IPPROTO_IP, 3): "IP_TOS",
    (IPPROTO_IP, 14): "IP_DONTFRAGMENT",
    (IPPROTO_IP, 19): "IP_PKTINFO",
    (IPPROTO_IP, 40): "IP_RECVTOS",
    (IPPROTO_IP, 50): "IP_RECVECN",
    (IPPROTO_IP, 71): "IP_MTU_DISCOVER",
    (IPPROTO_IPV6, 14): "IPV6_DONTFRAG",
    (IPPROTO_IPV6, 19): "IPV6_PKTINFO",
    (IPPROTO_IPV6, 27): "IPV6_V6ONLY",
    (IPPROTO_IPV6, 40): "IPV6_RECVTCLASS",
    (IPPROTO_IPV6, 50): "IPV6_RECVECN",
    (IPPROTO_IPV6, 71): "IPV6_MTU_DISCOVER",
}
IOCTL_NAMES = {
    SIO_KEEPALIVE_VALS: "SIO_KEEPALIVE_VALS",
    SIO_TCP_INITIAL_RTO: "SIO_TCP_INITIAL_RTO",
    0xC8000006: "SIO_GET_EXTENSION_FUNCTION_POINTER",
    0x9800000C: "SIO_UDP_CONNRESET",
    0x9800000F: "SIO_UDP_NETRESET",
    0x98000010: "SIO_LOOPBACK_FAST_PATH",
    0x4004747F: "FIONREAD",
    0x8004667E: "FIONBIO",
}
SYSTEM_RESOLVER_MODULES = {"ws2_32.dll", "dnsapi.dll", "mswsock.dll"}
DNS_TYPES = {
    1: "A",
    28: "AAAA",
    65: "HTTPS",
    5: "CNAME",
    12: "PTR",
    16: "TXT",
    33: "SRV",
}


@dataclass(frozen=True)
class Scenario:
    """One page load, and what the hooks should show for it."""

    name: str
    question: str
    limit_seconds: float
    disabled_features: tuple[str, ...] = ()
    # When set, the page on 127.0.0.1 fetches this host on a second loopback
    # port, which only that fetch uses, so startup preconnects to the page
    # do not mix with the attempts the scenario measures.
    target_host: str | None = None
    # Make a refused [::1] connect take Windows' SYN retransmissions (about
    # two seconds) by failing the browser's SIO_TCP_INITIAL_RTO call on IPv6
    # sockets. The fixture names this intervention.
    slow_ipv6_refusal: bool = False

    @property
    def intervention(self) -> str:
        if self.slow_ipv6_refusal:
            return "SIO_TCP_INITIAL_RTO fails on IPv6 sockets"
        return "none"


SCENARIOS = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "single",
            "Options on the socket of one navigation and fetch",
            30,
        ),
        Scenario(
            "parallel",
            f"How many connections {PARALLEL_REQUESTS} parallel requests to one origin open",
            60,
        ),
        Scenario(
            "idle",
            f"Whether a used connection idle {IDLE_REUSE_SECONDS} s is reused and "
            f"one idle {IDLE_CLOSE_SECONDS - IDLE_REUSE_SECONDS} s is replaced",
            IDLE_CLOSE_SECONDS + 60,
        ),
        Scenario(
            "lookups",
            f"Lookups of {LOOKUP_HOST} for fetches {LOOKUP_INTERVAL_SECONDS} s apart "
            "on new connections",
            LOOKUP_INTERVAL_SECONDS * LOOKUP_COUNT + 60,
        ),
        Scenario(
            "lookups-system",
            "The lookups scenario with the system resolver (AsyncDns disabled)",
            LOOKUP_INTERVAL_SECONDS * LOOKUP_COUNT + 60,
            ("AsyncDns",),
        ),
        Scenario(
            "happy-eyeballs",
            "Connection attempts to localhost when only 127.0.0.1 listens",
            30,
            target_host="localhost",
        ),
        Scenario(
            "happy-eyeballs-slow",
            "Connection attempts to localhost when only 127.0.0.1 listens and a "
            "refused [::1] connect takes about two seconds",
            30,
            target_host="localhost",
            slow_ipv6_refusal=True,
        ),
    )
}


# Decoding of the agent's raw bytes. These functions are pure and tested.


def decode_sockaddr(text: str) -> str:
    """Render a hex `sockaddr_in` or `sockaddr_in6` as `address:port`.

    A non-loopback address is replaced by `<external>`, so a retained log
    names no machine outside the capture host.
    """
    data = bytes.fromhex(text)
    if len(data) < 4:
        return "<none>"
    family = int.from_bytes(data[0:2], "little")
    port = int.from_bytes(data[2:4], "big")
    if family == AF_INET and len(data) >= 8:
        address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv4Address(
            data[4:8]
        )
        rendered = str(address)
    elif family == AF_INET6 and len(data) >= 24:
        address = ipaddress.IPv6Address(data[8:24])
        rendered = f"[{address}]"
    else:
        return f"<family {family}>:{port}"
    if not (address.is_loopback or address.is_unspecified):
        rendered = "<external>" if family == AF_INET else "[<external>]"
    return f"{rendered}:{port}"


def decode_option(level: int, option: int, value: str) -> tuple[str, str]:
    """Name a `setsockopt` call and render its value as an integer."""
    name = SOCKET_OPTIONS.get((level, option), f"level_{level}_option_{option}")
    data = bytes.fromhex(value)
    if name == "SO_LINGER" and len(data) == 4:
        on = int.from_bytes(data[0:2], "little")
        seconds = int.from_bytes(data[2:4], "little")
        return name, f"{on}/{seconds}"
    if 1 <= len(data) <= 8:
        return name, str(int.from_bytes(data, "little", signed=True))
    return name, data.hex()


def decode_keepalive(value: str) -> str:
    """Render `struct tcp_keepalive` as `onoff/keepalivetime_ms/interval_ms`."""
    data = bytes.fromhex(value)
    if len(data) != 12:
        return data.hex()
    fields = [int.from_bytes(data[i : i + 4], "little") for i in (0, 4, 8)]
    return "/".join(str(field) for field in fields)


def decode_initial_rto(value: str) -> str:
    """Render `TCP_INITIAL_RTO_PARAMETERS` as `rtt_ms/max_syn_retransmissions`.

    `0xffff/0xff` (`TCP_INITIAL_RTO_UNSPECIFIED_RTT` and
    `TCP_INITIAL_RTO_UNSPECIFIED_MAX_SYN_RETRANSMISSIONS`) keeps the system
    value.
    """
    data = bytes.fromhex(value)
    if len(data) < 3:
        return data.hex()
    return f"{int.from_bytes(data[0:2], 'little')}/{data[2]}"


def dns_question(payload: str) -> tuple[str, str] | None:
    """Return the first question's name and type in a DNS query message."""
    data = bytes.fromhex(payload)
    if len(data) < 12 or int.from_bytes(data[4:6], "big") == 0:
        return None
    labels = []
    offset = 12
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(data):
            return None
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 2 > len(data):
        return None
    kind = int.from_bytes(data[offset : offset + 2], "big")
    return ".".join(labels), DNS_TYPES.get(kind, str(kind))


@dataclass
class SocketRecord:
    family: int = 0
    kind: int = 0
    options: list[str] = field(default_factory=list)
    peers: list[str] = field(default_factory=list)
    callers: set[str] = field(default_factory=set)


def decode_events(raw: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn agent reports into fixture events.

    Socket handles become `s<n>` in order of first use, times become
    milliseconds from the first report, and byte arguments are decoded. Agent
    bookkeeping reports and return values that say nothing beyond their call
    are dropped.
    """
    if not raw:
        return []
    start = raw[0]["time_ms"]
    # Windows hands a closed socket's handle value to the next new socket, so
    # a handle names one socket from its creation to its close.
    handles: dict[str, str] = {}
    count = 0

    def name(handle: str, created: bool) -> str:
        nonlocal count
        if created or handle not in handles:
            handles[handle] = f"s{count}"
            count += 1
        return handles[handle]

    events = []
    for report in raw:
        kind = report["kind"]
        event: dict[str, Any] = {"t": report["time_ms"] - start, "kind": kind}
        if "socket" in report:
            event["socket"] = name(report["socket"], kind == "socket")
            if kind == "close":
                del handles[report["socket"]]
        if kind == "socket":
            event.update(
                function=report["function"],
                family=report["family"],
                type=report["type"],
                protocol=report["protocol"],
            )
        elif kind in ("connect", "bind"):
            if "function" in report:
                event["function"] = report["function"]
            event["address"] = decode_sockaddr(report["address"])
        elif kind == "connect-return":
            event.update(result=report["result"], error=report.get("error"))
        elif kind == "setsockopt":
            option, value = decode_option(
                report["level"], report["option"], report["value"]
            )
            event.update(option=option, value=value)
        elif kind == "setsockopt-return":
            if report["result"] == 0:
                continue
            event["result"] = report["result"]
        elif kind == "wsaioctl":
            code = report["code"]
            event["code"] = IOCTL_NAMES.get(code, f"0x{code:08x}")
            if code == SIO_KEEPALIVE_VALS:
                event["value"] = decode_keepalive(report["input"])
            elif code == SIO_TCP_INITIAL_RTO:
                event["value"] = decode_initial_rto(report["input"])
        elif kind == "wsaioctl-return":
            if report["result"] == 0:
                continue
            code = report["code"]
            event.update(
                code=IOCTL_NAMES.get(code, f"0x{code:08x}"), result=report["result"]
            )
        elif kind == "ioctlsocket":
            command = report["command"]
            event.update(
                command=IOCTL_NAMES.get(command, f"0x{command:08x}"),
                value=int.from_bytes(bytes.fromhex(report["value"] or "00"), "little"),
            )
        elif kind == "dns-send":
            question = dns_question(report["payload"])
            event["function"] = report["function"]
            if report["address"]:
                event["address"] = decode_sockaddr(report["address"])
            if question is not None:
                event.update(host=question[0], query_type=question[1])
        elif kind == "resolve":
            event.update(function=report["function"], host=report["host"])
            if "query_type" in report:
                kind_number = report["query_type"]
                event["query_type"] = DNS_TYPES.get(kind_number, str(kind_number))
        elif kind == "resolve-return":
            event.update(
                function=report["function"],
                host=report["host"],
                result=report["result"],
                answers=[decode_sockaddr(answer) for answer in report["answers"]],
            )
        elif kind == "wsaioctl-suppressed":
            code = report["code"]
            event["code"] = IOCTL_NAMES.get(code, f"0x{code:08x}")
        elif kind in ("close", "config"):
            if kind == "config":
                event["slow_ipv6_refusal"] = report["slow_ipv6_refusal"]
        else:
            continue
        if "caller" in report:
            event["caller"] = report["caller"]
        events.append(event)
    return events


def socket_records(events: Sequence[dict[str, Any]]) -> dict[str, SocketRecord]:
    """Group the options and peers of each socket, in call order."""
    records: dict[str, SocketRecord] = {}
    for event in events:
        handle = event.get("socket")
        if handle is None:
            continue
        record = records.setdefault(handle, SocketRecord())
        kind = event["kind"]
        if kind in ("setsockopt", "wsaioctl") and "caller" in event:
            record.callers.add(event["caller"])
        if kind == "socket":
            record.family = event["family"]
            record.kind = event["type"]
        elif kind == "setsockopt":
            record.options.append(f"{event['option']}={event['value']}")
        elif kind == "wsaioctl" and "value" in event:
            record.options.append(f"{event['code']}={event['value']}")
        elif kind == "connect":
            record.peers.append(event["address"])
    return records


def summarize(
    events: Sequence[dict[str, Any]], origin_port: int
) -> list[tuple[str, str]]:
    """Summary lines for one run: option sets, attempts, and lookups."""
    records = socket_records(events)
    tcp = [record for record in records.values() if record.kind == SOCK_STREAM]
    origin = [
        record
        for record in tcp
        if any(peer.endswith(f":{origin_port}") for peer in record.peers)
    ]
    option_sets: dict[str, int] = {}
    for record in origin:
        key = ",".join(record.options) or "<none>"
        option_sets[key] = option_sets.get(key, 0) + 1
    callers = sorted({name for record in origin for name in record.callers})
    lines = [
        ("origin_tcp_socket_count", str(len(origin))),
        ("origin_tcp_option_callers", ",".join(callers) or "<none>"),
    ]
    for index, (options, count) in enumerate(sorted(option_sets.items())):
        lines.append((f"origin_tcp_option_set_{index}", f"{count}x {options}"))
    attempts = [
        f"{event['t']}:{event['address']}"
        for event in events
        if event["kind"] == "connect" and event["address"].endswith(f":{origin_port}")
    ]
    lines.append(("origin_connect_attempts", " ".join(attempts) or "<none>"))
    lines.append(("origin_ipv4_after_ipv6_ms", ipv4_after_ipv6(events, origin_port)))
    udp_sets: dict[str, int] = {}
    for record in records.values():
        if record.kind == SOCK_DGRAM:
            key = ",".join(record.options) or "<none>"
            udp_sets[key] = udp_sets.get(key, 0) + 1
    for index, (options, count) in enumerate(sorted(udp_sets.items())):
        lines.append((f"udp_option_set_{index}", f"{count}x {options}"))
    lookups = [
        f"{event['t']}:{event['function']}:{event.get('query_type', '-')}:{event['host']}"
        for event in events
        if event["kind"] in ("resolve", "dns-send")
        and is_lookup_host(event.get("host"))
        # Calls Winsock or the DNS client library make inside a browser's
        # resolver call are not lookups of their own.
        and event.get("caller", "").lower() not in SYSTEM_RESOLVER_MODULES
    ]
    lines.append(("lookup_host", LOOKUP_HOST))
    lines.append(("lookup_count", str(len(lookups))))
    lines.append(("lookups", " ".join(lookups) or "<none>"))
    return lines


def is_lookup_host(host: str | None) -> bool:
    """The lookup host, or a name under it such as an HTTPS-record query's."""
    return host is not None and (
        host == LOOKUP_HOST or host.endswith("." + LOOKUP_HOST)
    )


def ipv4_after_ipv6(events: Sequence[dict[str, Any]], origin_port: int) -> str:
    """Milliseconds from each IPv6 attempt to the IPv4 attempt paired with it.

    Each connect job of a Chromium browser tries `[::1]` first and
    `127.0.0.1` second, and jobs start in order, so the n-th IPv4 attempt to
    the port pairs with the n-th IPv6 attempt. `-` when no IPv4 attempt
    follows an IPv6 one.
    """
    ipv6: list[int] = []
    delays: list[str] = []
    for event in events:
        if event["kind"] != "connect" or not event["address"].endswith(
            f":{origin_port}"
        ):
            continue
        if event["address"].startswith("["):
            ipv6.append(event["t"])
        elif len(delays) < len(ipv6):
            delays.append(str(event["t"] - ipv6[len(delays)]))
    return ",".join(delays) or "-"


# The loopback origin.


@dataclass
class OriginConnection:
    peer: str
    accepted_ms: int
    requests: list[tuple[int, str, str]] = field(default_factory=list)
    closed_ms: int | None = None
    last_response_ms: int | None = None


@dataclass
class Origin:
    scenario: Scenario
    port: int = 0
    target_port: int = 0
    connections: list[OriginConnection] = field(default_factory=list)
    open_count: int = 0
    max_open: int = 0
    done: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def measured_port(self) -> int:
        """The port whose connections the summary lines describe."""
        return self.target_port or self.port

    def page(self) -> bytes:
        name = self.scenario.name
        if name == "parallel":
            script = (
                f"Promise.all([...Array({PARALLEL_REQUESTS}).keys()].map(i => "
                "fetch('/slow?i=' + i, {cache: 'no-store'}).then(r => r.text())))"
                ".then(() => fetch('/done'));"
            )
        elif name == "idle":
            # Chromium closes an idle used socket only when a later request
            # to its pool finds it idle for its timeout, so the page asks
            # again before and after IDLE_REUSE_SECONDS and IDLE_CLOSE_SECONDS.
            script = (
                "const get = (i) => fetch('/fast?i=' + i, {cache: 'no-store'})"
                ".then(r => r.text());"
                "get(0);"
                f"setTimeout(() => get(1), {IDLE_REUSE_SECONDS * 1000});"
                f"setTimeout(() => get(2).then(() => fetch('/done')), "
                f"{IDLE_CLOSE_SECONDS * 1000});"
            )
        elif name.startswith("lookups"):
            script = (
                "let i = 0;"
                "const step = () => {"
                f"  if (i === {LOOKUP_COUNT}) {{ fetch('/done'); return; }}"
                f"  fetch('http://{LOOKUP_HOST}:{self.port}/close?i=' + i,"
                "    {mode: 'no-cors', cache: 'no-store'}).catch(() => {});"
                f"  i += 1; setTimeout(step, {LOOKUP_INTERVAL_SECONDS * 1000});"
                "};"
                "step();"
            )
        elif self.scenario.target_host is not None:
            script = (
                f"fetch('http://{self.scenario.target_host}:{self.target_port}/done',"
                " {mode: 'no-cors', cache: 'no-store'});"
            )
        else:
            script = "fetch('/done', {cache: 'no-store'});"
        return (
            "<!doctype html><meta charset=utf-8><link rel=icon href='data:,'>"
            f"<script>{script}</script>\n"
        ).encode()

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        connection = OriginConnection(f"{peer[0]}:{peer[1]}", now_ms())
        self.connections.append(connection)
        self.open_count += 1
        self.max_open = max(self.max_open, self.open_count)
        try:
            while True:
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                    break
                line = head.split(b"\r\n", 1)[0].decode("latin-1")
                parts = line.split(" ")
                target = parts[1] if len(parts) > 1 else "/"
                host = ""
                for field_line in head.split(b"\r\n")[1:]:
                    key, _, value = field_line.partition(b":")
                    if key.strip().lower() == b"host":
                        host = value.strip().decode("latin-1")
                connection.requests.append((now_ms(), host, target))
                close = await self.respond(writer, urlsplit(target))
                connection.last_response_ms = now_ms()
                if close:
                    break
        except (ConnectionError, OSError):
            pass
        finally:
            connection.closed_ms = now_ms()
            self.open_count -= 1
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def respond(self, writer: asyncio.StreamWriter, target: Any) -> bool:
        path = target.path
        close = path == "/close"
        if path == "/":
            body, kind = self.page(), "text/html"
        else:
            body, kind = b"ok\n", "text/plain"
        if path == "/slow":
            await asyncio.sleep(SLOW_RESPONSE_SECONDS)
        fields = [
            "HTTP/1.1 200 OK",
            f"Content-Type: {kind}",
            f"Content-Length: {len(body)}",
            "Cache-Control: no-store",
            "Access-Control-Allow-Origin: *",
            "Connection: close" if close else "Connection: keep-alive",
        ]
        writer.write(("\r\n".join(fields) + "\r\n\r\n").encode() + body)
        await writer.drain()
        if path == "/done":
            self.done.set()
        return close


def now_ms() -> int:
    return int(time.time() * 1000)


# The hooked browser.


def merged_disabled_features(arguments: list[str], extra: Sequence[str]) -> list[str]:
    """Add features to the launch's one `--disable-features` switch.

    Chromium reads only the last copy of a repeated switch, so a second
    `--disable-features` would re-enable what the first one disabled.
    """
    if not extra:
        return arguments
    prefix = "--disable-features="
    merged = []
    found = False
    for argument in arguments:
        if argument.startswith(prefix) and not found:
            names = [name for name in argument[len(prefix) :].split(",") if name]
            names.extend(name for name in extra if name not in names)
            merged.append(prefix + ",".join(names))
            found = True
        else:
            merged.append(argument)
    if not found:
        merged.insert(len(merged) - 1, prefix + ",".join(extra))
    return merged


def is_network_service(argv: Sequence[str] | None) -> bool:
    return bool(argv) and NETWORK_SERVICE_SWITCH in argv


def _socket_hook_switches(extra: Sequence[str]) -> tuple[str, ...]:
    """Keep the disposable profile and page URL under the run's ownership."""
    switches = tuple(extra)
    for switch in switches:
        if not isinstance(switch, str) or any(char in switch for char in "\x00\r\n"):
            raise ValueError("browser-switch must use --name or --name=value")

        name = switch.partition("=")[0]
        if re.fullmatch(r"--[a-zA-Z][a-zA-Z0-9-]*", name) is None:
            raise ValueError("browser-switch must use --name or --name=value")

        # Chromium's Windows command-line parser lowercases switch names.
        if name.lower() in ("--user-data-dir", "--single-argument"):
            raise ValueError(
                "browser-switch cannot replace the managed profile or page"
            )

    return switches


class HookedBrowser:
    """A browser spawned under Frida with child gating, on a fresh profile.

    The spawned browser's direct children are held until resumed. The network
    service must acknowledge configuration and installed hooks before resume.
    The agent requires Windows x64 and already loaded Winsock and DNS modules.
    Shutdown retains native sessions, pending children and unfinished workers.
    """

    def __init__(
        self,
        executable: Path,
        arguments: list[str],
        profile: Path,
        config: dict[str, Any],
    ) -> None:
        self.config = config
        self.executable = executable
        self.arguments = arguments
        self.profile = profile
        self.reports: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.network_service_argv: list[str] | None = None
        self.frida_version = ""
        self._children: queue.Queue[Any] = queue.Queue()
        self._lock = threading.Lock()
        self._sessions: dict[int, Any] = {}
        self._pid: int | None = None
        self._processes: dict[int, _SocketHookProcess] = {}
        self._retired_pids: set[int] = set()
        self._network_pid: int | None = None
        self._device: Any = None
        self._worker: threading.Thread | None = None
        self._stopping = threading.Event()
        self._ready = threading.Event()
        self._frida: Any = None
        self._cancellable: Any = None
        self._accepting = False
        self._subscribed = False
        self._child_count = 0
        self._children_by_pid: dict[int, Any] = {}
        self._scripts: dict[int, Any] = {}
        self._pending_children: tuple[Any, ...] = ()
        self._failure: BaseException | None = None
        self._failure_notifier: Callable[[BaseException], None] | None = None
        self._cleanup_failures: list[BaseException] = []
        self._stopped = False
        self._profile_retired = False

    def start(self) -> None:
        import frida  # noqa: PLC0415 - only a capture needs Frida

        self._frida = frida
        self.frida_version = frida.__version__
        with self._lock:
            self._cancellable = frida.Cancellable()
            if self._stopping.is_set():
                self._cancellable.cancel()

        with self._cancellable:
            self._device = frida.get_local_device()
            self._subscribed = True
            self._device.on("child-added", self._on_child_added)
            with self._lock:
                self._accepting = not self._stopping.is_set()

            self._worker = threading.Thread(target=self._gate_children, daemon=False)
            self._worker.start()
            self._pid = self._device.spawn([str(self.executable), *self.arguments])
            self._processes[self._pid] = _SocketHookProcess(self._pid)
            session = self._device.attach(self._pid)
            with self._lock:
                self._sessions[self._pid] = session

            session.enable_child_gating()
            self._device.resume(self._pid)

        deadline = time.monotonic() + _HOOK_READY_SECONDS
        while not self._ready.wait(0.1):
            if self._stopping.is_set():
                with self._lock:
                    failure = self._failure

                if failure is not None:
                    raise failure

                raise RuntimeError("socket hook startup was stopped before readiness")

            if time.monotonic() >= deadline:
                raise TimeoutError("socket hook configuration readiness deadline elapsed")

    def _on_child_added(self, child: Any) -> None:
        try:
            with self._lock:
                if child.parent_pid != self._pid:
                    return

                if not self._accepting:
                    return

                if child.pid in self._children_by_pid:
                    raise _SocketHookIdentityUnknown(self, (child,))

                if self._child_count >= _HOOK_CHILD_LIMIT:
                    raise _SocketHookChildLimit(self, child)

                self._child_count += 1
                self._children_by_pid[child.pid] = child
                self._children.put_nowait(child)
        except BaseException as error:
            self._retain_failure(error)

    def request_stop(self) -> None:
        with self._lock:
            self._accepting = False
            self._stopping.set()
            cancellable = self._cancellable

        if cancellable is not None:
            cancellable.cancel()

    def _retain_failure(self, error: BaseException) -> None:
        with self._lock:
            notifier = None
            if self._failure is None:
                self._failure = error
                notifier = self._failure_notifier

        if notifier is not None:
            try:
                notifier(error)
            except BaseException as notify_error:
                with self._lock:
                    self._cleanup_failures.append(notify_error)

        try:
            self.request_stop()
        except BaseException as stop_error:
            with self._lock:
                if not self._cleanup_failures:
                    self._cleanup_failures.append(stop_error)

    def _gate_children(self) -> None:
        try:
            source = AGENT.read_text(encoding="utf-8")
            while not self._stopping.is_set():
                try:
                    child = self._children.get(timeout=0.2)
                except queue.Empty:
                    continue

                with self._cancellable:
                    self._instrument_child(child, source)
        except BaseException as error:
            locally_cancelled = (
                self._stopping.is_set()
                and isinstance(error, self._frida.OperationCancelledError)
                and self._cancellable.is_cancelled
            )
            if not locally_cancelled:
                self._retain_failure(error)

    def _instrument_child(self, child: Any, source: str) -> None:
        if self._stopping.is_set():
            return

        process = _SocketHookProcess(child.pid)
        with self._lock:
            self._processes[child.pid] = process

        if is_network_service(child.argv):
            if self.network_service_argv is not None:
                raise RuntimeError("socket hook network service restarted during capture")

            self.network_service_argv = list(child.argv)
            self._network_pid = child.pid
            session = self._device.attach(child.pid)
            with self._lock:
                self._sessions[child.pid] = session

            if self._stopping.is_set():
                return

            script = session.create_script(source)
            with self._lock:
                stopped = self._stopping.is_set()
                if not stopped:
                    self._scripts[child.pid] = script
                    script.on("message", self._on_message)

            if stopped:
                return

            script.load()
            script.post({"type": "config", **self.config})
            deadline = time.monotonic() + _HOOK_READY_SECONDS
            while not self._ready.wait(0.1):
                if self._stopping.is_set():
                    return

                if time.monotonic() >= deadline:
                    raise TimeoutError("socket hook child readiness deadline elapsed")

        if not self._stopping.is_set():
            self._device.resume(child.pid)

    def _on_message(self, message: dict[str, Any], _data: object) -> None:
        try:
            with self._lock:
                if self._failure is not None:
                    return

                if message.get("type") != "send":
                    raise _SocketHookAgentFailure(message)

                payload = message["payload"]
                if payload["kind"] in ("hook-missing", "hook-failure"):
                    raise _SocketHookAgentFailure(message)

                if self._stopped:
                    return

                if len(self.reports) >= _HOOK_REPORT_LIMIT:
                    raise RuntimeError("socket hook report limit exceeded")

                self.reports.append(payload)
                if payload["kind"] == "ready":
                    if (
                        payload.get("arch") != "x64"
                        or payload.get("pid") != self._network_pid
                        or payload.get("platform") != "windows"
                        or payload.get("modules") != ["ws2_32.dll", "dnsapi.dll"]
                        or payload.get("slow_ipv6_refusal")
                        is not self.config.get("slow_ipv6_refusal", False)
                    ):
                        raise _SocketHookAgentFailure(message)

                    self._ready.set()
        except BaseException as error:
            self._retain_failure(error)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            failures = (self._failure, *self._cleanup_failures)
            stopped = self._stopped
            reports = list(self.reports)

        raise_browser_failures(None, tuple(error for error in failures if error is not None))
        if not stopped or (self._worker is not None and self._worker.is_alive()):
            raise _SocketHookChildrenPending(self)

        if not self._ready.is_set():
            raise RuntimeError("socket hook capture has no acknowledged network service")

        return reports

    def stop(self) -> None:
        failures = []
        try:
            self.request_stop()
        except BaseException as error:
            failures.append(error)

        if self._subscribed:
            try:
                self._device.off("child-added", self._on_child_added)
                self._subscribed = False
            except BaseException as error:
                failures.append(error)

        deadline = time.monotonic() + _HOOK_NATIVE_CLEANUP_SECONDS
        if self._pid in self._processes:
            failures.extend(self._retire_process(self._pid, deadline))

        roster_known = self._device is None
        if self._device is not None:
            pending, error = self._cleanup_native(self._device.enumerate_pending_children, deadline)
            if error is not None:
                failures.append(error)
            else:
                roster_known = True
                with self._lock:
                    self._pending_children = tuple(
                        child for child in pending
                        if child.parent_pid == self._pid
                        or child.parent_pid in self._children_by_pid
                    )

        if self._worker is not None:
            try:
                self._worker.join(timeout=5)
            except BaseException as error:
                failures.append(error)

            if self._worker.is_alive():
                failures.append(_SocketHookChildrenPending(self))

        worker_finished = self._worker is None or not self._worker.is_alive()
        with self._lock:
            processes = dict(self._processes)
            sessions = tuple(self._sessions.items())
            scripts = tuple(self._scripts.items())
            children = dict(self._children_by_pid)
            children.update((child.pid, child) for child in self._pending_children)
            failure = self._failure
            if isinstance(failure, _SocketHookChildLimit):
                children[failure.child.pid] = failure.child

        for pid in processes:
            if pid != self._pid:
                failures.extend(self._retire_process(pid, deadline))

        unknown = tuple(child for pid, child in children.items() if pid not in processes)
        if isinstance(failure, _SocketHookIdentityUnknown):
            unknown += failure.children

        if unknown or (self._pid is not None and self._pid not in processes):
            failures.append(_SocketHookIdentityUnknown(self, unknown))

        retired = (
            roster_known
            and worker_finished
            and not unknown
            and (self._pid is None or self._pid in self._retired_pids)
            and all(pid in self._retired_pids for pid in processes)
        )
        detached = set()
        for pid, session in sessions:
            if pid not in self._retired_pids or (pid == self._pid and not retired):
                continue

            _, error = self._cleanup_native(session.detach, deadline)
            if error is not None:
                failures.append(error)
            else:
                detached.add(pid)

        # Local Frida message dispatch and synchronous detach use one native
        # main context. Successful detach removes scripts before completing;
        # removing a Python callback alone does not fence selected callbacks.
        for pid, script in scripts:
            if pid not in detached:
                continue

            try:
                script.off("message", self._on_message)
            except BaseException as error:
                failures.append(error)

        for pid in processes:
            if pid not in self._retired_pids:
                continue

            try:
                self._processes[pid].close()
            except BaseException as error:
                failures.append(error)

        try:
            terminate_profile_processes(self.profile)
        except BaseException as error:
            failures.append(error)

        with self._lock:
            self._stopped = retired
            self._cleanup_failures.extend(failures)
            self._profile_retired = self._stopped and not self._cleanup_failures
            failures = [self._failure, *self._cleanup_failures]

        if self._cleanup_failures:
            failures.append(_SocketHookCleanupIncomplete(self))

        raise_browser_failures(None, tuple(error for error in failures if error is not None))

    def _retire_process(self, pid: int, deadline: float) -> tuple[BaseException, ...]:
        if pid in self._retired_pids:
            return ()

        process = self._processes[pid]
        failures = []
        retired = False
        try:
            retired = process.wait(time.monotonic())
        except BaseException as error:
            failures.append(error)

        if not retired:
            try:
                process.terminate()
            except BaseException as error:
                failures.append(error)

            try:
                retired = process.wait(deadline)
            except BaseException as error:
                failures.append(error)

        if retired:
            self._retired_pids.add(pid)
        else:
            failures.append(_SocketHookProcessPending(self, pid, process))

        return tuple(failures)

    def _cleanup_native(
        self, operation: Any, deadline: float, *arguments: Any
    ) -> tuple[Any, BaseException | None]:
        try:
            cancellable = self._frida.Cancellable()
        except BaseException as error:
            return None, error

        cancellation_failures = []
        expired = threading.Event()

        def cancel() -> None:
            expired.set()
            try:
                cancellable.cancel()
            except BaseException as error:
                cancellation_failures.append(error)

        remaining = min(1.0, max(0.0, deadline - time.monotonic()))
        timer = threading.Timer(remaining, cancel)
        timer.daemon = False
        error = None
        result = None
        try:
            if remaining == 0:
                cancel()
            else:
                timer.start()

            result = operation(*arguments, cancellable=cancellable)
        except BaseException as failure:
            error = failure
        finally:
            try:
                timer.cancel()
            except BaseException as failure:
                cancellation_failures.append(failure)

            if timer.ident is not None:
                try:
                    timer.join(timeout=1)
                except BaseException as failure:
                    cancellation_failures.append(failure)

        if timer.is_alive():
            pending = _SocketHookCleanupPending(self, timer, cancellable, operation, arguments)
            cancellation_failures.append(pending)

        if expired.is_set():
            cancellation_failures.append(TimeoutError("socket hook native cleanup deadline elapsed"))

        try:
            raise_browser_failures(error, tuple(cancellation_failures))
        except BaseException as failure:
            return result, failure

        return result, None


class _SocketHookProcess:
    """Own a suspended process's kernel handle until its exit is observed."""

    def __init__(self, pid: int) -> None:
        import _winapi  # noqa: PLC0415 - the socket hooks require Windows

        self._api = _winapi
        access = _winapi.SYNCHRONIZE | _PROCESS_TERMINATE
        self.handle: int | None = _winapi.OpenProcess(access, False, pid)

    def wait(self, deadline: float) -> bool:
        remaining = min(_HOOK_NATIVE_CLEANUP_SECONDS, max(0.0, deadline - time.monotonic()))
        result = self._api.WaitForSingleObject(self.handle, int(remaining * 1000))
        if result == self._api.WAIT_OBJECT_0:
            return True

        if result == self._api.WAIT_TIMEOUT:
            return False

        raise RuntimeError("socket hook process wait returned an unsupported status")

    def terminate(self) -> None:
        self._api.TerminateProcess(self.handle, 0xDEADBEEF)

    def close(self) -> None:
        if self.handle is not None:
            self._api.CloseHandle(self.handle)
            self.handle = None


class _SocketHookAgentFailure(RuntimeError):
    def __init__(self, message: dict[str, Any]) -> None:
        self.message = message
        super().__init__("socket hook agent failed readiness or execution")


class _SocketHookChildLimit(RuntimeError):
    def __init__(self, owner: HookedBrowser, child: Any) -> None:
        self.owner = owner
        self.child = child
        super().__init__("socket hook child limit exceeded")


class _SocketHookChildrenPending(RuntimeError):
    def __init__(self, owner: HookedBrowser) -> None:
        self.owner = owner
        super().__init__("socket hook child worker has not finished cleanup")


class _SocketHookCleanupIncomplete(RuntimeError):
    def __init__(self, owner: HookedBrowser) -> None:
        self.owner = owner
        super().__init__("socket hook browser retains failed cleanup owners")


class _SocketHookProcessPending(RuntimeError):
    def __init__(self, owner: HookedBrowser, pid: int, process: _SocketHookProcess) -> None:
        self.owner = owner
        self.pid = pid
        self.process = process
        super().__init__("socket hook process exit is unconfirmed and its owners are retained")


class _SocketHookIdentityUnknown(RuntimeError):
    def __init__(self, owner: HookedBrowser, children: tuple[Any, ...]) -> None:
        self.owner = owner
        self.children = children
        super().__init__("socket hook process identity is unconfirmed and its owners are retained")


class _SocketHookCleanupPending(RuntimeError):
    def __init__(
        self,
        owner: HookedBrowser,
        timer: threading.Timer,
        cancellable: Any,
        operation: Any,
        arguments: tuple[Any, ...],
    ) -> None:
        self.owner = owner
        self.timer = timer
        self.cancellable = cancellable
        self.operation = operation
        self.arguments = arguments
        super().__init__("socket hook native cleanup cancellation has not finished")


@dataclass
class RunResult:
    reports: list[dict[str, Any]]
    origin: Origin
    errors: list[str]
    network_service_argv: list[str] | None
    timed_out: bool
    frida_version: str


def localhost_ipv6_free(port: int) -> bool:
    """Whether nothing listens on [::1] at `port`, which the scenario needs."""
    probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        probe.bind(("::1", port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


async def run_once(
    scenario: Scenario, executable: Path, extra: Sequence[str]
) -> tuple[RunResult, list[str]]:
    extra = _socket_hook_switches(extra)
    origin = Origin(scenario)
    server = None
    target = None
    profile = None
    worker = None
    done_waiter = None
    primary = None
    cleanup = []
    timed_out = False

    try:
        server = await asyncio.start_server(
            origin.handle, "127.0.0.1", 0, limit=MAX_REQUEST_HEAD, start_serving=False
        )
        origin.port = server.sockets[0].getsockname()[1]
        await server.start_serving()

        if scenario.target_host is not None:
            target = await asyncio.start_server(
                origin.handle,
                "127.0.0.1",
                0,
                limit=MAX_REQUEST_HEAD,
                start_serving=False,
            )
            origin.target_port = target.sockets[0].getsockname()[1]
            await target.start_serving()

            if not localhost_ipv6_free(origin.target_port):
                raise RuntimeError(f"[::1]:{origin.target_port} is in use")

        url = f"http://127.0.0.1:{origin.port}/"
        profile = Path(tempfile.mkdtemp(prefix="phantom-capture-profile-"))
        arguments = chromium_arguments(profile, url, headless=True, extra=extra)
        arguments = merged_disabled_features(arguments, scenario.disabled_features)
        config = {"slow_ipv6_refusal": scenario.slow_ipv6_refusal}
        browser = HookedBrowser(executable, arguments, profile, config)
        worker = _SocketHookBrowserOwner(browser, profile)
        await worker.start()

        done_waiter = asyncio.create_task(origin.done.wait())
        completed, _ = await asyncio.wait(
            (done_waiter, worker.failed),
            timeout=scenario.limit_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if worker.failed.done():
            raise worker.failed.result()

        if done_waiter in completed:
            done_waiter.result()
        else:
            timed_out = True

        await asyncio.sleep(1.0)
        if worker.failed.done():
            raise worker.failed.result()
    except BaseException as error:
        primary = error

    deadline = asyncio.get_running_loop().time() + _RUN_CLEANUP_SECONDS
    if done_waiter is not None:
        requested = not done_waiter.done() and done_waiter.cancel()
        try:
            await asyncio.wait((done_waiter,), timeout=0)
        except BaseException as error:
            cleanup.append(error)

        if done_waiter.done():
            try:
                done_waiter.result()
            except asyncio.CancelledError as error:
                if not requested:
                    cleanup.append(error)
            except BaseException as error:
                cleanup.append(error)
        else:
            cleanup.append(_SocketHookDonePending(done_waiter, requested))

    if worker is not None:
        worker.stop_requested.set()
        try:
            worker.browser.request_stop()
        except BaseException as error:
            cleanup.append(error)

    listeners = [listener for listener in (target, server) if listener is not None]
    for listener in listeners:
        try:
            listener.close()
        except BaseException as error:
            cleanup.append(error)

    for listener in listeners:
        operation = None
        try:
            operation = listener.wait_closed()
            waiter = asyncio.create_task(operation)
        except BaseException as error:
            cleanup.append(error)
            if operation is not None:
                try:
                    operation.close()
                except BaseException as close_error:
                    cleanup.append(close_error)
            continue

        requested = False
        while not waiter.done():
            remaining = max(0.0, deadline - asyncio.get_running_loop().time())
            try:
                _, pending = await asyncio.wait((waiter,), timeout=remaining)
            except BaseException as error:
                interrupted = isinstance(
                    error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
                )
                if primary is None and interrupted:
                    primary = error
                else:
                    cleanup.append(error)

                if interrupted and asyncio.get_running_loop().time() < deadline:
                    continue

                requested = not waiter.done() and waiter.cancel()
                break

            if pending:
                cleanup.append(
                    asyncio.TimeoutError(
                        "socket hook listener cleanup deadline elapsed"
                    )
                )
                requested = not waiter.done() and waiter.cancel()
                break

        if requested and not waiter.done():
            try:
                await asyncio.wait((waiter,), timeout=0)
            except BaseException as error:
                if primary is None and isinstance(
                    error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
                ):
                    primary = error
                else:
                    cleanup.append(error)

        if not waiter.done():
            cleanup.append(
                _SocketHookListenerPending(listener, waiter, requested, primary)
            )
            continue

        try:
            waiter.result()
        except asyncio.CancelledError as error:
            if not requested:
                cleanup.append(error)
        except BaseException as error:
            cleanup.append(error)

    if worker is not None and worker.future is not None:
        cleanup.extend(await worker.finish(deadline, primary))
    elif profile is not None:
        try:
            shutil.rmtree(profile)
        except BaseException as error:
            cleanup.append(error)

    raise_browser_failures(primary, tuple(cleanup))

    result = RunResult(
        browser.snapshot(),
        origin,
        list(browser.errors),
        browser.network_service_argv,
        timed_out,
        browser.frida_version,
    )
    return result, arguments


class _SocketHookListenerPending(RuntimeError):
    def __init__(
        self,
        listener: asyncio.Server,
        waiter: asyncio.Task[None],
        requested: bool,
        primary: BaseException | None,
    ) -> None:
        self.listener = listener
        self.waiter = waiter
        self.requested = requested
        self.primary = primary
        self.error: BaseException | None = None
        waiter.add_done_callback(self._finished)
        super().__init__("socket hook listener waiter has not finished cleanup")

    def _finished(self, completed: asyncio.Task[None]) -> None:
        try:
            completed.result()
        except asyncio.CancelledError as error:
            if not self.requested:
                self.error = error
        except BaseException as error:
            self.error = error

        if self.error is not None:
            completed.get_loop().call_exception_handler(
                {
                    "message": "socket hook listener cleanup failed after caller exit",
                    "exception": self.error,
                    "primary": self.primary,
                    "future": completed,
                    "owner": self,
                }
            )


class _SocketHookDonePending(RuntimeError):
    def __init__(self, waiter: asyncio.Task[bool], requested: bool) -> None:
        self.waiter = waiter
        self.requested = requested
        waiter.add_done_callback(self._finished)
        super().__init__("socket hook scenario waiter has not finished cleanup")

    def _finished(self, completed: asyncio.Task[bool]) -> None:
        try:
            completed.result()
        except asyncio.CancelledError as error:
            if self.requested:
                return

            failure = error
        except BaseException as error:
            failure = error
        else:
            return

        completed.get_loop().call_exception_handler(
            {
                "message": "socket hook scenario waiter failed after caller exit",
                "exception": failure,
                "future": completed,
                "owner": self,
            }
        )


class _SocketHookBrowserOwner:
    """Keep blocking start, stop and profile removal in one owned worker."""

    def __init__(self, browser: HookedBrowser, profile: Path) -> None:
        self.browser = browser
        self.profile = profile
        self.loop = asyncio.get_running_loop()
        self.started = self.loop.create_future()
        self.failed = self.loop.create_future()
        self.stop_requested = threading.Event()
        self.future: asyncio.Future[None] | None = None
        self.start_error: BaseException | None = None
        self.notification_error: BaseException | None = None
        self.stop_error: BaseException | None = None
        self.profile_error: BaseException | None = None
        browser._failure_notifier = self._notify_failure

    def _notify_failure(self, error: BaseException) -> None:
        self.stop_requested.set()
        self.loop.call_soon_threadsafe(self._publish_failure, error)

    def _publish_failure(self, error: BaseException) -> None:
        if not self.failed.done():
            self.failed.set_result(error)

    async def start(self) -> None:
        self.future = self.loop.run_in_executor(None, self._run)
        await asyncio.wait(
            (self.started, self.future), return_when=asyncio.FIRST_COMPLETED
        )
        if self.start_error is not None:
            raise self.start_error

        if self.notification_error is not None:
            raise self.notification_error

        if self.future.done():
            self.future.result()

    def _run(self) -> None:
        try:
            try:
                self.browser.start()
            except BaseException as error:
                self.start_error = error

            try:
                self.loop.call_soon_threadsafe(self.started.set_result, None)
            except BaseException as error:
                self.notification_error = error

            if self.start_error is None and self.notification_error is None:
                self.stop_requested.wait()
        finally:
            try:
                self.browser.stop()
            except BaseException as error:
                self.stop_error = error

            if self.browser._profile_retired:
                try:
                    shutil.rmtree(self.profile)
                except BaseException as error:
                    self.profile_error = error

    def failures(self, primary: BaseException | None) -> tuple[BaseException, ...]:
        errors = [
            self.start_error,
            self.notification_error,
            self.stop_error,
            self.profile_error,
        ]

        try:
            self.future.result()
        except BaseException as error:
            errors.append(error)

        return tuple(
            error for error in errors if error is not None and error is not primary
        )

    async def finish(
        self, deadline: float, primary: BaseException | None
    ) -> tuple[BaseException, ...]:
        try:
            remaining = max(0.0, deadline - self.loop.time())
            _, pending = await asyncio.wait((self.future,), timeout=remaining)
        except BaseException as error:
            if self.future.done():
                failures = self.failures(primary)
                if error is not primary and all(
                    error is not failure for failure in failures
                ):
                    return (*failures, error)

                return failures

            return self._retain_pending(error, primary)

        if pending:
            error = asyncio.TimeoutError("socket hook browser cleanup deadline elapsed")
            return self._retain_pending(error, primary)

        return self.failures(primary)

    def _retain_pending(
        self, error: BaseException, primary: BaseException | None
    ) -> tuple[BaseException, ...]:
        pending = _SocketHookWorkerPending(self, error)
        interrupted = isinstance(
            error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
        )
        initiating = primary
        if initiating is None and interrupted:
            initiating = error

        self.future.add_done_callback(
            lambda completed: self._report_late_failure(completed, initiating)
        )
        if interrupted and error is not primary:
            return (error, pending)

        return (pending,)

    def _report_late_failure(
        self, completed: asyncio.Future[None], primary: BaseException | None
    ) -> None:
        failures = self.failures(primary)
        if failures:
            self.loop.call_exception_handler(
                {
                    "message": "socket hook browser cleanup failed after caller exit",
                    "exception": failures[0],
                    "failures": failures,
                    "primary": primary,
                    "future": completed,
                    "owner": self,
                }
            )


class _SocketHookWorkerPending(RuntimeError):
    def __init__(self, owner: _SocketHookBrowserOwner, error: BaseException) -> None:
        self.owner = owner
        self.__cause__ = error
        super().__init__("socket hook browser worker has not finished cleanup")


def portable_argv(argv: Sequence[str] | None, profile_text: str) -> str:
    """The network service command line without run-specific values."""
    if not argv:
        return "<none>"
    kept = []
    for argument in argv[1:]:
        name, separator, _ = argument.partition("=")
        if separator and name.endswith("-handle"):
            argument = f"{name}=<handle>"
        kept.append(argument.replace(profile_text, PROFILE_PLACEHOLDER))
    return shlex.join(kept)


def render_run(index: int, result: RunResult, profile_text: str) -> list[str]:
    prefix = f"run_{index}_"
    events = decode_events(result.reports)
    lines = [
        f"{prefix}timed_out={'true' if result.timed_out else 'false'}",
        f"{prefix}origin_port={result.origin.port}",
        f"{prefix}measured_port={result.origin.measured_port}",
        f"{prefix}network_service_arguments="
        + portable_argv(result.network_service_argv, profile_text),
        f"{prefix}hook_error_count={len(result.errors)}",
    ]
    lines.extend(
        f"{prefix}hook_error_{i}={error}" for i, error in enumerate(result.errors)
    )
    lines.extend(
        f"{prefix}{key}={value}"
        for key, value in summarize(events, result.origin.measured_port)
    )
    connections = result.origin.connections
    start = result.reports[0]["time_ms"] if result.reports else 0
    lines.append(f"{prefix}server_connection_count={len(connections)}")
    lines.append(f"{prefix}server_max_open_connections={result.origin.max_open}")
    for i, connection in enumerate(connections):
        requests = " ".join(
            f"{t - start}:{host}{path}" for t, host, path in connection.requests
        )
        closed = (
            "open"
            if connection.closed_ms is None
            else str(connection.closed_ms - start)
        )
        idle = (
            "-"
            if connection.closed_ms is None or connection.last_response_ms is None
            else str(connection.closed_ms - connection.last_response_ms)
        )
        lines.append(
            f"{prefix}server_connection_{i}=accepted:{connection.accepted_ms - start}"
            f",closed:{closed},idle_before_close_ms:{idle},requests:{requests or '-'}"
        )
    lines.append(f"{prefix}event_count={len(events)}")
    lines.extend(
        f"{prefix}event_{i}={json.dumps(event, sort_keys=True, separators=(',', ':'))}"
        for i, event in enumerate(events)
    )
    return lines


def file_digest(path: Path) -> str:
    """SHA-256 of a source file with LF line endings.

    A Windows checkout with `core.autocrlf` has CRLF endings, so the digest
    is taken of the text as Git stores it.
    """
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def render_fixture(
    *,
    browser: str,
    client_version: str,
    operating_system: str,
    frida_version: str,
    launch_arguments: str,
    scenario: Scenario,
    runs: Sequence[Sequence[str]],
) -> str:
    """The fixture text: provenance header first, then each run."""
    header = [
        f"format={FORMAT}",
        "evidence=hook",
        f"captured_at_unix={int(time.time())}",
        f"browser={CLIENT_NAMES[browser]}",
        f"browser_version={client_version}",
        f"operating_system={operating_system}",
        f"hook_tool=frida {frida_version}",
        f"hook_agent=scripts/capture/{AGENT.name}",
        f"hook_agent_sha256={file_digest(AGENT)}",
        f"capture_tool_sha256={file_digest(Path(__file__))}",
        f"hooked_process={NETWORK_SERVICE_SWITCH}",
        "launch_mode=headless",
        f"launch_arguments={launch_arguments}",
        f"scenario={scenario.name}",
        f"question={scenario.question}",
        f"hook_intervention={scenario.intervention}",
        f"run_count={len(runs)}",
    ]
    return "\n".join([*header, *(line for run in runs for line in run)]) + "\n"


async def capture(args: argparse.Namespace, scenario: Scenario) -> tuple[str, bool]:
    extra = _socket_hook_switches(args.browser_switch)
    runs = []
    recorded = ""
    frida_version = ""
    failed = False
    for index in range(args.repeat):
        result, arguments = await run_once(scenario, args.browser_path, extra)
        profile = next(
            argument.split("=", 1)[1]
            for argument in arguments
            if argument.startswith("--user-data-dir=")
        )
        recorded = recorded_arguments(arguments, Path(profile))
        runs.append(render_run(index, result, profile))
        frida_version = result.frida_version or frida_version
        if args.raw_dir is not None:
            args.raw_dir.mkdir(parents=True, exist_ok=True)
            raw = args.raw_dir / f"{args.browser}-{scenario.name}-{index}.json"
            raw.write_text(json.dumps(result.reports), encoding="utf-8")
        if result.timed_out or not result.reports or result.errors:
            failed = True
            print(
                f"{scenario.name} run {index}: timed_out={result.timed_out} "
                f"reports={len(result.reports)} errors={result.errors}",
                file=sys.stderr,
            )
    text = render_fixture(
        browser=args.browser,
        client_version=args.client_version,
        operating_system=args.operating_system,
        frida_version=frida_version,
        launch_arguments=recorded,
        scenario=scenario,
        runs=runs,
    )
    return text, failed


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--browser", choices=DESKTOP_CHROMIUM_BROWSERS, required=True)
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument(
        "--scenario", nargs="+", choices=[*SCENARIOS, "all"], required=True
    )
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument(
        "--browser-switch",
        action="append",
        default=[],
        metavar="SWITCH",
        help="append --name or --name=value; the managed profile and page stay fixed",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--raw-dir",
        type=Path,
        help="also write each run's undecoded agent reports here, for diagnosis",
    )
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("the agent hooks Winsock, so this tool runs on Windows only")
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")

    try:
        _socket_hook_switches(args.browser_switch)
    except ValueError as error:
        parser.error(str(error))

    names = list(SCENARIOS) if "all" in args.scenario else args.scenario
    args.output_dir.mkdir(parents=True, exist_ok=True)
    failed = False
    for name in names:
        text, run_failed = asyncio.run(capture(args, SCENARIOS[name]))
        write_text_fixture(args.output_dir / f"hooks-{name}.txt", text)
        failed = failed or run_failed
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
