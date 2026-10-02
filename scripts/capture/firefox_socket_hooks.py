"""Record Firefox's socket calls, host lookups, and MOZ_LOG lines with Frida hooks.

`socket_hooks.py` records a Chromium browser's network service. Firefox opens
its HTTP connections in its parent process instead, and changes their
keepalive while they live, so this tool attaches the same agent
(`socket_hooks.js`) and a Firefox extension of it (`firefox_socket_hooks.js`)
to the running parent process. The launch itself is the ordinary one of
`browser_launch.py`: Firefox's launcher process records a failed start in the
registry when it runs under Frida, so the hooks attach after the first page
request instead of at spawn. The page then waits until the hooks are in place
before it reaches the measured origin on a second loopback port.

Firefox's own MOZ_LOG (`nsSocketTransport`, `nsHttp`, `nsHostResolver`, and
`GetAddrInfo`) runs beside the hooks as a cross-check; the lines about the
measured origin are retained.

Windows only: the agents hook `ws2_32.dll` and `dnsapi.dll`.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import datetime
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import socket_hooks
from .browser_launch import (
    CLIENT_NAMES,
    LaunchedBrowser,
    LaunchPlan,
)
from .fixture_file import write_text_fixture
from .socket_hooks import (
    IOCTL_NAMES,
    SIO_KEEPALIVE_VALS,
    SYSTEM_RESOLVER_MODULES,
    decode_keepalive,
    decode_option,
    decode_sockaddr,
    dns_question,
    file_digest,
    localhost_ipv6_free,
)

FORMAT = socket_hooks.FORMAT
AGENT = socket_hooks.AGENT
EXTENSION = Path(__file__).with_name("firefox_socket_hooks.js")
DECODER = Path(socket_hooks.__file__)
# A name that public DNS resolves to 127.0.0.1, so a lookup leaves the
# browser's resolver while the connection stays on loopback.
TARGET_HOST = socket_hooks.LOOKUP_HOST
MOZ_LOG_MODULES = (
    "timestamp,sync,nsSocketTransport:5,nsHttp:5,nsHostResolver:5,GetAddrInfo:5"
)
MAX_REQUEST_HEAD = 64 * 1024
ATTACH_LIMIT_SECONDS = 30.0
# The address the `backup` scenario's lookups return: Windows answers
# `localhost` with [::1] first, then 127.0.0.1.
REWRITE_TO = "localhost"
TRICKLE_CHUNKS = 17
SLOW_RESPONSE_SECONDS = 3
TRICKLE_INTERVAL_SECONDS = 5
WEBSOCKET_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

AI_FLAGS = (
    (0x1, "AI_PASSIVE"),
    (0x2, "AI_CANONNAME"),
    (0x4, "AI_NUMERICHOST"),
    (0x100, "AI_ALL"),
    (0x400, "AI_ADDRCONFIG"),
    (0x800, "AI_V4MAPPED"),
    (0x4000, "AI_NON_AUTHORITATIVE"),
    (0x8000, "AI_SECURE"),
    (0x10000, "AI_RETURN_PREFERRED_NAMES"),
    (0x20000, "AI_FQDN"),
    (0x40000, "AI_FILESERVER"),
)
DNS_SECTIONS = {0: "question", 1: "answer", 2: "authority", 3: "additional"}
SHUTDOWN_HOW = {0: "SD_RECEIVE", 1: "SD_SEND", 2: "SD_BOTH"}


@dataclass(frozen=True)
class Scenario:
    """What the page does once the hooks are in place, and why."""

    name: str
    question: str
    limit_seconds: float
    # "http1", "h2" (TLS with ALPN h2 only), or "websocket" (HTTP/1.1).
    target: str
    script: str
    # Answer the lookup of TARGET_HOST as REWRITE_TO does.
    rewrite_lookup: bool = False

    @property
    def scheme(self) -> str:
        return {"http1": "http", "h2": "https", "websocket": "ws"}[self.target]

    @property
    def intervention(self) -> str:
        if self.rewrite_lookup:
            return (
                f"getaddrinfo({TARGET_HOST}) resolves {REWRITE_TO} instead "
                "([::1] then 127.0.0.1) and returns no canonical name"
            )
        return "none"


def _get(path: str) -> str:
    return f"fetch(T + '{path}', {{mode: 'no-cors', cache: 'no-store'}}).then(r => r.text())"


def _at(seconds: float, body: str) -> str:
    return f"setTimeout(() => {{ {body}; }}, {int(seconds * 1000)});"


DONE = "fetch('/done', {cache: 'no-store'})"

SCENARIOS = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "http1-idle",
            "Keepalive on an HTTP/1.1 connection that carries a request, idles past "
            "the short-lived period, carries a second request, and idles until "
            "Firefox closes it",
            260,
            "http1",
            _get("/fast?i=0") + ";" + _at(90, _get("/fast?i=1")) + _at(225, DONE),
        ),
        Scenario(
            "http1-long",
            f"Keepalive on an HTTP/1.1 connection whose response takes "
            f"{TRICKLE_CHUNKS * TRICKLE_INTERVAL_SECONDS} s",
            130,
            "http1",
            _get("/trickle") + f".then(() => {DONE})",
        ),
        Scenario(
            "h2",
            "Keepalive on an HTTP/2 connection before and after ALPN",
            60,
            "h2",
            _get("/fast?i=0") + ";" + _at(15, _get("/fast?i=1")) + _at(20, DONE),
        ),
        Scenario(
            "websocket",
            "Keepalive on an HTTP/1.1 connection upgraded to WebSocket",
            60,
            "websocket",
            "const ws = new WebSocket(T + '/ws');"
            "ws.onopen = () => setTimeout(() => ws.close(1000), 20000);"
            f"ws.onclose = () => setTimeout(() => {DONE}, 2000);",
        ),
        Scenario(
            "backup",
            "Connection attempts when the name resolves to [::1] then 127.0.0.1 "
            "and only 127.0.0.1 listens; then for a third concurrent request while "
            "the origin has connections, and for a request after the origin closed "
            "them all",
            40,
            "http1",
            _get("/fast?i=0")
            + ";"
            + _at(5, ";".join(_get(f"/slow?i={i}") for i in (1, 2, 3)))
            + _at(10, "fetch('/drop', {cache: 'no-store'})")
            + _at(12, _get("/fast?i=4"))
            + _at(16, DONE),
            rewrite_lookup=True,
        ),
        Scenario(
            "dns-cache",
            f"Lookups of {TARGET_HOST} for new connections 0, 30, 65, and 95 s "
            "after the first",
            140,
            "http1",
            _get("/close?i=0")
            + ";"
            + _at(30, _get("/close?i=1"))
            + _at(65, _get("/close?i=2"))
            + _at(95, _get("/close?i=3"))
            + _at(100, DONE),
        ),
    )
}


# Decoding of the agents' raw reports. These functions are pure and tested.


def decode_ai_flags(flags: int) -> str:
    """Name the bits of an `addrinfo.ai_flags` value, `0` when none is set."""
    names = [name for bit, name in AI_FLAGS if flags & bit]
    rest = flags & ~sum(bit for bit, _ in AI_FLAGS)
    if rest:
        names.append(f"0x{rest:x}")
    return "|".join(names) or "0"


def decode_events(raw: Sequence[dict[str, Any]], start_ms: int) -> list[dict[str, Any]]:
    """Turn agent reports into fixture events, as `socket_hooks.decode_events`.

    Times are milliseconds from `start_ms`. Sockets that existed before the
    hooks attached get a name at their first report.
    """
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
        event: dict[str, Any] = {"t": report["time_ms"] - start_ms, "kind": kind}
        if "socket" in report:
            event["socket"] = name(report["socket"], kind == "socket")
            if kind == "close":
                handles.pop(report["socket"], None)
        if kind == "socket":
            event.update(family=report["family"], type=report["type"])
        elif kind in ("connect", "bind"):
            event["address"] = decode_sockaddr(report["address"])
        elif kind == "connect-return":
            if report["result"] == 0:
                continue
            event.update(result=report["result"], error=report.get("error"))
        elif kind == "setsockopt":
            option, value = decode_option(
                report["level"], report["option"], report["value"]
            )
            event.update(option=option, value=value)
        elif kind in ("setsockopt-return", "wsaioctl-return"):
            if report["result"] == 0:
                continue
            event["result"] = report["result"]
            if "code" in report:
                event["code"] = IOCTL_NAMES.get(
                    report["code"], f"0x{report['code']:08x}"
                )
        elif kind == "wsaioctl":
            code = report["code"]
            event["code"] = IOCTL_NAMES.get(code, f"0x{code:08x}")
            if code == SIO_KEEPALIVE_VALS:
                event["value"] = decode_keepalive(report["input"])
        elif kind == "ioctlsocket":
            command = report["command"]
            event.update(
                command=IOCTL_NAMES.get(command, f"0x{command:08x}"),
                value=int.from_bytes(bytes.fromhex(report["value"] or "00"), "little"),
            )
        elif kind == "shutdown":
            event["how"] = SHUTDOWN_HOW.get(report["how"], str(report["how"]))
        elif kind == "socket-error":
            event["value"] = report["value"]
        elif kind == "dns-send":
            question = dns_question(report["payload"])
            if question is not None:
                event.update(host=question[0], query_type=question[1])
        elif kind == "resolve":
            event.update(function=report["function"], host=report["host"])
            if "query_type" in report:
                event["query_type"] = socket_hooks.DNS_TYPES.get(
                    report["query_type"], str(report["query_type"])
                )
        elif kind == "resolve-return":
            event.update(
                function=report["function"],
                host=report["host"],
                result=report["result"],
                answers=[decode_sockaddr(answer) for answer in report["answers"]],
            )
        elif kind == "resolve-hints":
            event.update(function=report["function"], host=report["host"])
            if "flags" in report:
                event.update(
                    flags=decode_ai_flags(report["flags"]),
                    family=report["family"],
                    socktype=report["socktype"],
                    protocol=report["protocol"],
                )
        elif kind == "resolve-rewritten":
            event.update(host=report["host"], to=report["to"])
        elif kind == "dnsquery":
            event.update(
                host=report["host"],
                query_type=socket_hooks.DNS_TYPES.get(
                    report["query_type"], str(report["query_type"])
                ),
                options=f"0x{report['options']:x}",
            )
        elif kind == "dnsquery-return":
            event.update(
                host=report["host"],
                query_type=socket_hooks.DNS_TYPES.get(
                    report["query_type"], str(report["query_type"])
                ),
                status=report["status"],
                records=[
                    f"{socket_hooks.DNS_TYPES.get(kind_, str(kind_))}/"
                    f"{DNS_SECTIONS.get(section, str(section))}/{ttl}"
                    for kind_, section, ttl in report["records"]
                ],
            )
        elif kind == "firefox-config":
            event.update(
                rewrite_host=report["rewrite_host"], rewrite_to=report["rewrite_to"]
            )
        elif kind != "close":
            continue
        if "caller" in report:
            event["caller"] = report["caller"]
        events.append(event)
    return events


def option_text(event: dict[str, Any]) -> str:
    if event["kind"] == "setsockopt":
        return f"{event['option']}={event['value']}"
    if event["kind"] == "wsaioctl":
        return f"{event['code']}={event.get('value', '-')}"
    return f"shutdown={event['how']}"


@dataclass
class OriginSocket:
    """One TCP socket that connected to the measured port, in call order."""

    address: str = ""
    connect_ms: int = 0
    before_connect: list[str] = field(default_factory=list)
    after_connect: list[str] = field(default_factory=list)
    # NSPR reads SO_ERROR only when a connect fails: the error and when.
    failed: str = "-"
    closed: str = "open"


def origin_sockets(events: Sequence[dict[str, Any]], port: int) -> list[OriginSocket]:
    """The sockets that connected to `port`, with their options over time.

    Options set before `connect` are listed as they were set; each later
    option, keepalive change, and `shutdown` is `+ms:` after the connect.
    `failed` is the error NSPR read from `SO_ERROR` and when, or `-`.
    """
    pending: dict[str, list[str]] = {}
    sockets: dict[str, OriginSocket] = {}
    order: list[OriginSocket] = []
    for event in events:
        handle = event.get("socket")
        if handle is None:
            continue
        kind = event["kind"]
        if kind == "socket":
            pending[handle] = []
            sockets.pop(handle, None)
            continue
        record = sockets.get(handle)
        if kind == "connect":
            if not event["address"].endswith(f":{port}"):
                continue
            record = OriginSocket(event["address"], event["t"], pending.pop(handle, []))
            sockets[handle] = record
            order.append(record)
            continue
        if kind in ("setsockopt", "wsaioctl", "shutdown"):
            if kind == "wsaioctl" and "value" not in event:
                continue
            if record is None:
                pending.setdefault(handle, []).append(option_text(event))
            else:
                record.after_connect.append(
                    f"+{event['t'] - record.connect_ms}:{option_text(event)}"
                )
        elif kind == "socket-error" and record is not None and record.failed == "-":
            record.failed = f"{event['value']}+{event['t'] - record.connect_ms}"
        elif kind == "close":
            if record is not None:
                record.closed = f"+{event['t'] - record.connect_ms}"
            pending.pop(handle, None)
            sockets.pop(handle, None)
    return order


def is_target(host: str | None) -> bool:
    return host is not None and (
        host == TARGET_HOST or host.endswith("." + TARGET_HOST)
    )


def summarize(events: Sequence[dict[str, Any]], port: int) -> list[tuple[str, str]]:
    """Summary lines for one run: each origin socket, attempts, and lookups."""
    lines: list[tuple[str, str]] = []
    sockets = origin_sockets(events, port)
    lines.append(("origin_tcp_socket_count", str(len(sockets))))
    for index, record in enumerate(sockets):
        lines.append(
            (
                f"origin_socket_{index}",
                f"address:{record.address},connect_ms:{record.connect_ms},"
                f"failed:{record.failed},closed:{record.closed},"
                f"before_connect:{';'.join(record.before_connect) or '-'},"
                f"after_connect:{';'.join(record.after_connect) or '-'}",
            )
        )
    lines.append(
        (
            "origin_connect_attempts",
            " ".join(f"{record.connect_ms}:{record.address}" for record in sockets)
            or "<none>",
        )
    )
    lookups = []
    for event in events:
        if not is_target(event.get("host")):
            continue
        if event.get("caller", "").lower() in SYSTEM_RESOLVER_MODULES:
            continue
        if event["kind"] == "resolve-hints":
            lookups.append(
                f"{event['t']}:{event['function']}:flags={event.get('flags', '-')}"
                f":family={event.get('family', '-')}"
            )
        elif event["kind"] == "resolve-return" and event["function"] == "getaddrinfo":
            lookups.append(f"{event['t']}:answers={'|'.join(event['answers']) or '-'}")
        elif event["kind"] == "resolve-rewritten":
            lookups.append(f"{event['t']}:rewritten={event['to']}")
        elif event["kind"] == "dnsquery-return":
            answers = [record for record in event["records"] if "/answer/" in record]
            lookups.append(
                f"{event['t']}:DnsQuery_A:{event['query_type']}:status={event['status']}"
                f":{'|'.join(answers) or '-'}"
            )
    lines.append(("lookup_host", TARGET_HOST))
    lines.append(("lookup_calls", " ".join(lookups) or "<none>"))
    return lines


# MOZ_LOG lines about the measured origin.

MOZ_LOG_LINE = re.compile(
    r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) UTC - \[[^\]]*\]: \w/(\w+) (.*)$"
)
POINTER = re.compile(r"(?<![0-9A-Za-z])(?:0x)?[0-9a-f]{9,16}(?![0-9A-Za-z])")
MOZ_LOG_KEEP = (
    "SetKeepaliveVals",
    "SetKeepaliveEnabled",
    "StartShortLivedTCPKeepalives",
    "StartLongLivedTCPKeepalives",
    "DisableTCPKeepalives",
    "TakeTransport",
    "nsHttpConnection::Init",
    "Creating DnsAndConnectSocket",
    "SetupDnsFlags flags=",
    "SetupBackupTimer",
    "trying address",
    "nsSocketTransport::ResolveHost",
    "Caching host [",
    "Using cached record",
    "starting async renewal",
    "Issuing second async lookup",
    "Resolving ",
    "Getting TTL",
    "Got TTL",
    "Could not get TTL",
    "ConnectionEntry::ConnectionEntry",
    "IPFamilyPreference",
    "prefer ipv4=",
)


def moz_log_time(stamp: str) -> int:
    moment = datetime.datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S.%f")
    return int(moment.replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)


def anchors_origin_object(
    message: str, pointers: Sequence[str], origin: str, objects: set[str]
) -> bool:
    """Whether the line's first object serves `origin`; see `moz_log_lines`."""
    if "nsHttpConnection::Init" in message:
        return bool(objects.intersection(pointers[1:2]))
    return origin in message and (
        "nsSocketTransport::ResolveHost" in message
        or "Creating DnsAndConnectSocket" in message
        or "ConnectionEntry::ConnectionEntry" in message
    )


def moz_log_lines(text: str, port: int, start_ms: int) -> list[str]:
    """Retained MOZ_LOG lines about TARGET_HOST and the objects serving `port`.

    A socket transport belongs to the origin when its `ResolveHost` line names
    `TARGET_HOST:port`; an HTTP connection when its `Init` line names such a
    transport; a connection setup or a connection entry when its
    `Creating DnsAndConnectSocket` or `ConnectionEntry` line names the origin.
    A line is kept when it matches `MOZ_LOG_KEEP` and
    names one of those objects or `TARGET_HOST`. Object addresses become
    `p<n>` in order of first appearance, and times are milliseconds from
    `start_ms`.
    """
    origin = f"{TARGET_HOST}:{port}"
    objects: set[str] = set()
    kept: list[tuple[int, str, str]] = []
    for line in text.splitlines():
        match = MOZ_LOG_LINE.match(line)
        if match is None:
            continue
        stamp, module, message = match.groups()
        pointers = POINTER.findall(message)
        if anchors_origin_object(message, pointers, origin, objects):
            objects.update(pointers[:1])
        if not any(marker in message for marker in MOZ_LOG_KEEP):
            continue
        if not (objects.intersection(pointers) or TARGET_HOST in message):
            continue
        kept.append((moz_log_time(stamp) - start_ms, module, message.strip()))
    names: dict[str, str] = {}

    def rename(match: re.Match[str]) -> str:
        return names.setdefault(match.group(0), f"p{len(names)}")

    return [
        f"{t} {module} {POINTER.sub(rename, message)}" for t, module, message in kept
    ]


def parent_moz_log(directory: Path) -> str:
    """The parent process's MOZ_LOG text; child process files are skipped."""
    texts = [
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(directory.glob("moz*"))
        if ".child-" not in path.name
    ]
    return "\n".join(texts)


# The loopback origins.


@dataclass
class ServerConnection:
    peer: str
    accepted_ms: int
    requests: list[tuple[int, str]] = field(default_factory=list)
    closed_ms: int | None = None
    last_response_ms: int | None = None
    # "fin" when the client's close arrived as end of stream, "reset" when it
    # arrived as a reset, "server" when the origin closed first.
    close_kind: str = "-"


@dataclass
class Origins:
    """The page origin on 127.0.0.1 and the measured origin on TARGET_HOST."""

    scenario: Scenario
    certificate: Any = None
    page_port: int = 0
    port: int = 0
    connections: list[ServerConnection] = field(default_factory=list)
    open: list[tuple[ServerConnection, asyncio.StreamWriter]] = field(
        default_factory=list
    )
    page_requested: asyncio.Event = field(default_factory=asyncio.Event)
    go: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def target_url(self) -> str:
        return f"{self.scenario.scheme}://{TARGET_HOST}:{self.port}"

    def page(self) -> bytes:
        script = (
            f"const T = '{self.target_url}';"
            "fetch('/go', {cache: 'no-store'}).then(() => {"
            f"{self.scenario.script}"
            "});"
        )
        return (
            "<!doctype html><meta charset=utf-8><link rel=icon href='data:,'>"
            f"<script>{script}</script>\n"
        ).encode()

    async def handle_page(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                head = await read_head(reader)
                if head is None:
                    break
                path = urlsplit(request_target(head)).path
                if path == "/":
                    self.page_requested.set()
                    body, kind = self.page(), "text/html"
                else:
                    body, kind = b"ok\n", "text/plain"
                if path == "/go":
                    await self.go.wait()
                elif path == "/drop":
                    for connection, target in list(self.open):
                        connection.close_kind = "server"
                        target.close()
                await write_response(writer, body, kind, close=False)
                if path == "/done":
                    self.done.set()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def handle_target(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        connection = ServerConnection(f"{peer[0]}:{peer[1]}", now_ms())
        self.connections.append(connection)
        self.open.append((connection, writer))
        try:
            if self.scenario.target == "h2":
                await self.serve_h2(reader, writer, connection)
            else:
                await self.serve_http1(reader, writer, connection)
        except ConnectionResetError:
            connection.close_kind = "reset"
        except (ConnectionError, OSError):
            pass
        finally:
            connection.closed_ms = now_ms()
            self.open.remove((connection, writer))
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def serve_http1(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        connection: ServerConnection,
    ) -> None:
        while True:
            try:
                head = await read_head(reader)
            except ConnectionResetError:
                connection.close_kind = "reset"
                return
            if head is None:
                if connection.close_kind == "-":
                    connection.close_kind = "fin"
                return
            target = request_target(head)
            connection.requests.append((now_ms(), target))
            path = urlsplit(target).path
            if path == "/ws":
                await serve_websocket(reader, writer, head)
                connection.last_response_ms = now_ms()
                connection.close_kind = "websocket"
                return
            if path == "/slow":
                await asyncio.sleep(SLOW_RESPONSE_SECONDS)
            if path == "/trickle":
                await trickle(writer)
            else:
                await write_response(
                    writer, b"ok\n", "text/plain", close=path == "/close"
                )
            connection.last_response_ms = now_ms()
            if path == "/close":
                connection.close_kind = "server"
                return

    async def serve_h2(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        connection: ServerConnection,
    ) -> None:
        import h2.config  # noqa: PLC0415 - only the h2 scenario needs it
        import h2.connection  # noqa: PLC0415
        import h2.events  # noqa: PLC0415

        session = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        session.initiate_connection()
        writer.write(session.data_to_send())
        await writer.drain()
        while True:
            data = await reader.read(65536)
            if not data:
                if connection.close_kind == "-":
                    connection.close_kind = "fin"
                return
            for event in session.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    fields = dict(event.headers)
                    connection.requests.append((now_ms(), fields.get(":path", "")))
                    session.send_headers(
                        event.stream_id,
                        [
                            (":status", "200"),
                            ("content-type", "text/plain"),
                            ("content-length", "3"),
                            ("cache-control", "no-store"),
                            ("access-control-allow-origin", "*"),
                        ],
                    )
                    session.send_data(event.stream_id, b"ok\n", end_stream=True)
                    connection.last_response_ms = now_ms()
                elif isinstance(event, h2.events.ConnectionTerminated):
                    connection.close_kind = "goaway"
            writer.write(session.data_to_send())
            await writer.drain()


async def read_head(reader: asyncio.StreamReader) -> bytes | None:
    try:
        return await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as error:
        if error.partial:
            raise ConnectionError("request head cut short") from error
        return None
    except asyncio.LimitOverrunError as error:
        raise ConnectionError("request head too long") from error


def request_target(head: bytes) -> str:
    parts = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
    return parts[1] if len(parts) > 1 else "/"


def header_value(head: bytes, name: bytes) -> bytes:
    for line in head.split(b"\r\n")[1:]:
        key, _, value = line.partition(b":")
        if key.strip().lower() == name:
            return value.strip()
    return b""


async def write_response(
    writer: asyncio.StreamWriter, body: bytes, kind: str, *, close: bool
) -> None:
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


async def trickle(writer: asyncio.StreamWriter) -> None:
    """A chunked response with one chunk every TRICKLE_INTERVAL_SECONDS."""
    writer.write(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\n"
        b"Access-Control-Allow-Origin: *\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    for _ in range(TRICKLE_CHUNKS):
        writer.write(b"2\r\nx\n\r\n")
        await writer.drain()
        await asyncio.sleep(TRICKLE_INTERVAL_SECONDS)
    writer.write(b"0\r\n\r\n")
    await writer.drain()


def websocket_accept(key: bytes) -> str:
    return base64.b64encode(hashlib.sha1(key + WEBSOCKET_GUID).digest()).decode()


async def serve_websocket(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, head: bytes
) -> None:
    """Accept the upgrade, send a text frame every five seconds, echo a close."""
    accept = websocket_accept(header_value(head, b"sec-websocket-key"))
    writer.write(
        (
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode()
    )
    await writer.drain()

    async def tick() -> None:
        while True:
            await asyncio.sleep(5)
            writer.write(b"\x81\x04tick")
            await writer.drain()

    ticker = asyncio.create_task(tick())
    try:
        while True:
            first = await reader.readexactly(2)
            length = first[1] & 0x7F
            if length == 126:
                length = int.from_bytes(await reader.readexactly(2), "big")
            elif length == 127:
                length = int.from_bytes(await reader.readexactly(8), "big")
            mask = await reader.readexactly(4) if first[1] & 0x80 else b""
            payload = await reader.readexactly(length)
            if first[0] & 0x0F == 0x8:
                if mask:
                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                writer.write(bytes([0x88, len(payload)]) + payload)
                await writer.drain()
                return
    except asyncio.IncompleteReadError:
        return
    finally:
        ticker.cancel()


def now_ms() -> int:
    return int(time.time() * 1000)


def firefox_cert_override(host: str, port: int, fingerprint: str) -> str:
    """Trust the throwaway leaf inside one disposable Firefox profile only."""
    return (
        "# PSM Certificate Override Settings file\n"
        "# This is a generated file!  Do not edit.\n"
        f"{host}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t{fingerprint}\t\n"
    )


# The hooked browser.


def browser_process(listing: Sequence[dict[str, Any]]) -> int | None:
    """The Firefox parent process among the processes of one profile.

    `listing` holds `ProcessId`, `ParentProcessId`, and `CommandLine` of every
    process whose command line names the run's profile. Content processes
    carry `-contentproc`. With the launcher process, the parent process is
    the launcher's child; without it, the launched process is the parent.
    """
    candidates = [
        entry
        for entry in listing
        if "-contentproc" not in (entry.get("CommandLine") or "").split()
    ]
    ids = {entry["ProcessId"] for entry in candidates}
    children = [entry for entry in candidates if entry["ParentProcessId"] in ids]
    if len(children) == 1:
        return int(children[0]["ProcessId"])
    if len(candidates) == 1:
        return int(candidates[0]["ProcessId"])
    return None


def profile_processes(profile: Path) -> list[dict[str, Any]]:
    # The profile path is a mkdtemp name without quotes, so it is safe to embed.
    script = (
        "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and "
        f"$_.CommandLine.Contains('{profile}') }} | "
        "Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress"
    )
    output = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        check=False,
        timeout=60,
    ).stdout.decode(errors="replace")
    if not output.strip():
        return []
    listing = json.loads(output)
    return listing if isinstance(listing, list) else [listing]


class Hooks:
    """Both agents, loaded as one script into a running process."""

    def __init__(self, pid: int, config: dict[str, Any]) -> None:
        self.pid = pid
        self.config = config
        self.reports: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.frida_version = ""
        self.ready = threading.Event()
        self._lock = threading.Lock()
        self._session: Any = None

    def attach(self) -> None:
        import frida  # noqa: PLC0415 - only a capture needs Frida

        self.frida_version = frida.__version__
        source = (
            AGENT.read_text(encoding="utf-8")
            + "\n"
            + EXTENSION.read_text(encoding="utf-8")
        )
        self._session = frida.get_local_device().attach(self.pid)
        script = self._session.create_script(source)
        script.on("message", self._on_message)
        script.load()
        script.post({"type": "config", "slow_ipv6_refusal": False})
        script.post({"type": "firefox-config", **self.config})

    def _on_message(self, message: dict[str, Any], _data: object) -> None:
        with self._lock:
            if message.get("type") == "send":
                self.reports.append(message["payload"])
                if message["payload"]["kind"] == "firefox-config":
                    self.ready.set()
            else:
                self.errors.append(json.dumps(message, sort_keys=True))

    def snapshot(self) -> tuple[list[dict[str, Any]], list[str]]:
        with self._lock:
            return list(self.reports), list(self.errors)

    def detach(self) -> None:
        if self._session is not None:
            with contextlib.suppress(Exception):
                self._session.detach()


@dataclass
class RunResult:
    reports: list[dict[str, Any]]
    errors: list[str]
    origins: Origins
    timed_out: bool
    frida_version: str
    launcher_process: bool
    moz_log: list[str]
    start_ms: int
    # The whole parent process log, kept only for --raw-dir.
    moz_log_text: str = ""


async def run_once(scenario: Scenario, executable: Path) -> tuple[RunResult, str]:
    origins = Origins(scenario)
    page = await asyncio.start_server(
        origins.handle_page, "127.0.0.1", 0, limit=MAX_REQUEST_HEAD
    )
    origins.page_port = page.sockets[0].getsockname()[1]
    context = None
    files: tuple[tuple[str, str], ...] = ()
    if scenario.target == "h2":
        from .http2_session import generate_certificate, server_context  # noqa: PLC0415

        certificate = generate_certificate(TARGET_HOST)
        context = server_context(certificate)
        context.set_alpn_protocols(["h2"])
    target = await asyncio.start_server(
        origins.handle_target, "127.0.0.1", 0, limit=MAX_REQUEST_HEAD, ssl=context
    )
    origins.port = target.sockets[0].getsockname()[1]
    if scenario.target == "h2":
        files = (
            (
                "cert_override.txt",
                firefox_cert_override(
                    TARGET_HOST, origins.port, certificate.sha256_fingerprint
                ),
            ),
        )
    if scenario.rewrite_lookup and not localhost_ipv6_free(origins.port):
        page.close()
        target.close()
        raise RuntimeError(f"[::1]:{origins.port} is in use")
    url = f"http://127.0.0.1:{origins.page_port}/"
    plan = LaunchPlan(
        browser="firefox", executable=executable, headless=True, profile_files=files
    )
    log_directory = Path(tempfile.mkdtemp(prefix="phantom-capture-moz-log-"))
    config = (
        {"rewrite_host": TARGET_HOST, "rewrite_to": REWRITE_TO}
        if scenario.rewrite_lookup
        else {}
    )
    hooks: Hooks | None = None
    timed_out = False
    launcher = False
    errors: list[str] = []
    environment = {
        "MOZ_LOG": MOZ_LOG_MODULES,
        "MOZ_LOG_FILE": str(log_directory / "moz"),
    }
    try:
        with patched_environment(environment):
            browser = LaunchedBrowser(plan, url)
            await asyncio.to_thread(browser.__enter__)
        try:
            await asyncio.wait_for(origins.page_requested.wait(), ATTACH_LIMIT_SECONDS)
            assert browser.profile is not None
            listing = await asyncio.to_thread(profile_processes, browser.profile)
            pid = browser_process(listing)
            if pid is None:
                raise RuntimeError(f"no Firefox parent process among {listing}")
            launcher = browser.process is not None and pid != browser.process.pid
            hooks = Hooks(pid, config)
            await asyncio.to_thread(hooks.attach)
            if not await asyncio.to_thread(hooks.ready.wait, ATTACH_LIMIT_SECONDS):
                raise RuntimeError("the agents did not report ready")
            origins.go.set()
            try:
                await asyncio.wait_for(origins.done.wait(), scenario.limit_seconds)
            except asyncio.TimeoutError:
                timed_out = True
            await asyncio.sleep(1.0)
        finally:
            if hooks is not None:
                await asyncio.to_thread(hooks.detach)
            await asyncio.to_thread(browser.__exit__, None, None, None)
    except asyncio.TimeoutError:
        timed_out = True
        errors.append("the page was not requested")
    finally:
        page.close()
        target.close()
    reports, hook_errors = hooks.snapshot() if hooks is not None else ([], [])
    start_ms = reports[0]["time_ms"] if reports else now_ms()
    moz_log_text = parent_moz_log(log_directory)
    moz_log = moz_log_lines(moz_log_text, origins.port, start_ms)
    shutil.rmtree(log_directory, ignore_errors=True)
    result = RunResult(
        reports,
        [*errors, *hook_errors],
        origins,
        timed_out,
        hooks.frida_version if hooks is not None else "",
        launcher,
        moz_log,
        start_ms,
        moz_log_text,
    )
    return result, plan.recorded_arguments(url)


@contextlib.contextmanager
def patched_environment(values: dict[str, str]):  # noqa: ANN201 - a context manager
    """Set environment variables for a child launched inside the block."""
    import os  # noqa: PLC0415

    saved = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def render_run(index: int, result: RunResult) -> list[str]:
    prefix = f"run_{index}_"
    events = decode_events(result.reports, result.start_ms)
    start = result.start_ms
    lines = [
        f"{prefix}timed_out={'true' if result.timed_out else 'false'}",
        f"{prefix}launcher_process={'true' if result.launcher_process else 'false'}",
        f"{prefix}origin_port={result.origins.port}",
        f"{prefix}hook_error_count={len(result.errors)}",
    ]
    lines.extend(
        f"{prefix}hook_error_{i}={error}" for i, error in enumerate(result.errors)
    )
    lines.extend(
        f"{prefix}{key}={value}"
        for key, value in summarize(events, result.origins.port)
    )
    connections = result.origins.connections
    lines.append(f"{prefix}server_connection_count={len(connections)}")
    for i, connection in enumerate(connections):
        requests = " ".join(f"{t - start}:{path}" for t, path in connection.requests)
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
        family = "ipv6" if connection.peer.startswith("::") else "ipv4"
        lines.append(
            f"{prefix}server_connection_{i}=family:{family},"
            f"accepted:{connection.accepted_ms - start},closed:{closed},"
            f"close:{connection.close_kind},idle_before_close_ms:{idle},"
            f"requests:{requests or '-'}"
        )
    lines.append(f"{prefix}moz_log_count={len(result.moz_log)}")
    lines.extend(f"{prefix}moz_log_{i}={line}" for i, line in enumerate(result.moz_log))
    lines.append(f"{prefix}event_count={len(events)}")
    lines.extend(
        f"{prefix}event_{i}={json.dumps(event, sort_keys=True, separators=(',', ':'))}"
        for i, event in enumerate(events)
    )
    return [line.encode("ascii", "backslashreplace").decode("ascii") for line in lines]


def installed_build(executable: Path) -> tuple[str, str]:
    """`Version` and `BuildID` from the `application.ini` beside `executable`."""
    fields = {}
    for line in (
        (executable.parent / "application.ini").read_text(encoding="utf-8").splitlines()
    ):
        key, separator, value = line.partition("=")
        if separator:
            fields.setdefault(key.strip(), value.strip())
    return fields.get("Version", ""), fields.get("BuildID", "")


def render_fixture(
    *,
    client_version: str,
    build_id: str,
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
        f"browser={CLIENT_NAMES['firefox']}",
        f"browser_version={client_version}",
        f"browser_build_id={build_id}",
        f"operating_system={operating_system}",
        f"hook_tool=frida {frida_version}",
        f"hook_agent=scripts/capture/{AGENT.name}",
        f"hook_agent_sha256={file_digest(AGENT)}",
        f"hook_agent_extension=scripts/capture/{EXTENSION.name}",
        f"hook_agent_extension_sha256={file_digest(EXTENSION)}",
        f"capture_tool=scripts/capture/{Path(__file__).name}",
        f"capture_tool_sha256={file_digest(Path(__file__))}",
        f"decoder_sha256={file_digest(DECODER)}",
        "hooked_process=parent process, attached after the first page request",
        f"moz_log={MOZ_LOG_MODULES}",
        "launch_mode=headless",
        f"launch_arguments={launch_arguments}",
        f"target={TARGET_HOST}",
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
        result, arguments = await run_once(scenario, args.browser_path)
        recorded = arguments
        runs.append(render_run(index, result))
        frida_version = result.frida_version or frida_version
        if args.raw_dir is not None:
            args.raw_dir.mkdir(parents=True, exist_ok=True)
            raw = args.raw_dir / f"firefox-{scenario.name}-{index}.json"
            raw.write_text(json.dumps(result.reports), encoding="utf-8")
            raw.with_suffix(".moz_log").write_text(
                result.moz_log_text, encoding="utf-8"
            )
        if result.timed_out or not result.reports or result.errors:
            failed = True
            print(
                f"{scenario.name} run {index}: timed_out={result.timed_out} "
                f"reports={len(result.reports)} errors={result.errors}",
                file=sys.stderr,
            )
    version, build_id = installed_build(args.browser_path)
    if version != args.client_version:
        raise RuntimeError(f"Firefox changed to {version} during the capture")
    text = render_fixture(
        client_version=args.client_version,
        build_id=build_id,
        operating_system=args.operating_system,
        frida_version=frida_version,
        launch_arguments=recorded_arguments_placeholder(recorded),
        scenario=scenario,
        runs=runs,
    )
    return text, failed


def recorded_arguments_placeholder(arguments: str) -> str:
    """Launch arguments with the run's port numbers replaced."""
    return re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:<port>", arguments)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument(
        "--scenario", nargs="+", choices=[*SCENARIOS, "all"], required=True
    )
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--raw-dir",
        type=Path,
        help="also write each run's undecoded agent reports here, for diagnosis",
    )
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("the agents hook Winsock, so this tool runs on Windows only")
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    version, _ = installed_build(args.browser_path)
    if version != args.client_version:
        parser.error(f"the installed Firefox is {version}, not {args.client_version}")
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
