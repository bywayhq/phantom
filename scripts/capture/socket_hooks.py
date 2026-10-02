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
import shlex
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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


class HookedBrowser:
    """A browser spawned under Frida with child gating, on a fresh profile.

    The browser process and every child it starts are held until resumed.
    The network service child gets the agent before it resumes, so the hooks
    see its first socket. Only the processes this object spawned are ended:
    the spawned browser by its process ID, then any process whose command
    line names this run's temporary profile.
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
        self._sessions: list[Any] = []
        self._pid: int | None = None
        self._device: Any = None
        self._worker: threading.Thread | None = None
        self._stopping = threading.Event()

    def start(self) -> None:
        import frida  # noqa: PLC0415 - only a capture needs Frida

        self.frida_version = frida.__version__
        self._device = frida.get_local_device()
        self._device.on("child-added", self._on_child_added)
        self._worker = threading.Thread(target=self._gate_children, daemon=True)
        self._worker.start()
        self._pid = self._device.spawn([str(self.executable), *self.arguments])
        session = self._device.attach(self._pid)
        self._sessions.append(session)
        session.enable_child_gating()
        self._device.resume(self._pid)

    def _on_child_added(self, child: Any) -> None:
        self._children.put(child)

    def _gate_children(self) -> None:
        source = AGENT.read_text(encoding="utf-8")
        while not self._stopping.is_set():
            try:
                child = self._children.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                if is_network_service(child.argv) and self.network_service_argv is None:
                    self.network_service_argv = list(child.argv)
                    session = self._device.attach(child.pid)
                    self._sessions.append(session)
                    script = session.create_script(source)
                    script.on("message", self._on_message)
                    script.load()
                    script.post({"type": "config", **self.config})
                self._device.resume(child.pid)
            except Exception as error:  # noqa: BLE001 - recorded; the fixture shows it
                self.errors.append(f"child {child.pid}: {error}")
                with contextlib.suppress(Exception):
                    self._device.resume(child.pid)

    def _on_message(self, message: dict[str, Any], _data: object) -> None:
        with self._lock:
            if message.get("type") == "send":
                self.reports.append(message["payload"])
            else:
                self.errors.append(json.dumps(message, sort_keys=True))

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.reports)

    def stop(self) -> None:
        self._stopping.set()
        for session in self._sessions:
            with contextlib.suppress(Exception):
                session.detach()
        if self._pid is not None and self._device is not None:
            with contextlib.suppress(Exception):
                self._device.kill(self._pid)
        terminate_profile_processes(self.profile)
        if self._worker is not None:
            self._worker.join(timeout=5)


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
    origin = Origin(scenario)
    server = await asyncio.start_server(
        origin.handle, "127.0.0.1", 0, limit=MAX_REQUEST_HEAD
    )
    origin.port = server.sockets[0].getsockname()[1]
    target = None
    if scenario.target_host is not None:
        target = await asyncio.start_server(
            origin.handle, "127.0.0.1", 0, limit=MAX_REQUEST_HEAD
        )
        origin.target_port = target.sockets[0].getsockname()[1]
        if not localhost_ipv6_free(origin.target_port):
            server.close()
            target.close()
            raise RuntimeError(f"[::1]:{origin.target_port} is in use")
    url = f"http://127.0.0.1:{origin.port}/"
    profile = Path(tempfile.mkdtemp(prefix="phantom-capture-profile-"))
    arguments = chromium_arguments(profile, url, headless=True, extra=extra)
    arguments = merged_disabled_features(arguments, scenario.disabled_features)
    config = {"slow_ipv6_refusal": scenario.slow_ipv6_refusal}
    browser = HookedBrowser(executable, arguments, profile, config)
    timed_out = False
    try:
        async with server:
            await asyncio.to_thread(browser.start)
            try:
                await asyncio.wait_for(origin.done.wait(), scenario.limit_seconds)
            except asyncio.TimeoutError:
                timed_out = True
            await asyncio.sleep(1.0)
    finally:
        await asyncio.to_thread(browser.stop)
        shutil.rmtree(profile, ignore_errors=True)
        if target is not None:
            target.close()
            await target.wait_closed()
    result = RunResult(
        browser.snapshot(),
        origin,
        list(browser.errors),
        browser.network_service_argv,
        timed_out,
        browser.frida_version,
    )
    return result, arguments


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
    runs = []
    recorded = ""
    frida_version = ""
    failed = False
    for index in range(args.repeat):
        result, arguments = await run_once(
            scenario, args.browser_path, args.browser_switch
        )
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
        help="append a Chromium switch to the launch; the fixture records it",
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
