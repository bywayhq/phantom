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
import errno
import hashlib
import ipaddress
import json
import math
import ntpath
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import socket_hooks
from .browser_failures import BrowserLaunchFailures, raise_browser_failures
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
NATIVE_HTTPS_HOST = "server.phantom.test"
MOZ_LOG_MODULES = (
    "timestamp,sync,nsSocketTransport:5,nsHttp:5,nsHostResolver:5,GetAddrInfo:5"
)
MAX_REQUEST_HEAD = 64 * 1024
ATTACH_LIMIT_SECONDS = 30.0
MAX_ACTIVE_PEERS = 32
MAX_CONNECTIONS = 128
MAX_REQUESTS = 512
MAX_HOOK_REPORTS = 100_000
MAX_HOOK_MESSAGE_BYTES = 16 * 1024
MAX_MOZ_LOG_BYTES = 64 * 1024 * 1024
MAX_MOZ_LOG_FILES = 64
MAX_FAILURE_REPORT_BYTES = 64 * 1024 * 1024
MAX_WEBSOCKET_FRAME = 64 * 1024
PEER_CLEANUP_SECONDS = 5.0
# A pending lookup takes at most 60 s, then browser cleanup has two 60 s
# commands and a 5 s process join. Native calls cannot be preempted by asyncio.
NATIVE_CLEANUP_SECONDS = 200.0
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
    # Proxy targets use H1 TLS through the named physical proxy.
    target: str
    script: str
    # Answer the lookup of TARGET_HOST as REWRITE_TO does.
    rewrite_lookup: bool = False

    @property
    def scheme(self) -> str:
        return {
            "http1": "http",
            "h2": "https",
            "websocket": "ws",
            "wss": "wss",
            "https-connect": "https",
            "https-proxy-connect": "https",
            "https-h2-proxy-connect": "https",
            "wss-https-h2-proxy": "wss",
            "https-socks5": "https",
        }[self.target]

    @property
    def proxy_mode(self) -> str | None:
        return {
            "https-connect": "http",
            "https-proxy-connect": "https",
            "https-h2-proxy-connect": "https",
            "wss-https-h2-proxy": "https",
            "https-socks5": "socks5",
        }.get(self.target)

    @property
    def proxy_alpn(self) -> str:
        return (
            "h2"
            if self.target in ("https-h2-proxy-connect", "wss-https-h2-proxy")
            else "h1"
        )

    @property
    def hostname(self) -> str:
        if self.proxy_mode is not None:
            from .http2_session import HOSTNAME  # noqa: PLC0415

            return HOSTNAME
        return TARGET_HOST

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


def _readable_get(path: str) -> str:
    return (
        f"fetch(T + '{path}', {{mode: 'cors', cache: 'no-store'}})"
        ".then(r => { if (!r.ok) throw new Error('target HTTP status ' + r.status); "
        "return r.text(); })"
    )


def _proxy_backup_script() -> str:
    return (
        _readable_get("/fast?i=0")
        + ".then(() => Promise.all(["
        + ",".join(_readable_get(f"/slow?i={i}") for i in (1, 2, 3))
        + "]))"
        + ".then(() => fetch('/drop', {cache: 'no-store'}))"
        + f".then(() => {_readable_get('/fast?i=4')})"
        + f".then(() => {DONE})"
    )


def _at(seconds: float, body: str) -> str:
    return f"setTimeout(() => {{ {body}; }}, {int(seconds * 1000)});"


DONE = "fetch('/done', {cache: 'no-store'})"


def _websocket_backup_script(scheme: str) -> str:
    http_scheme = "https" if scheme == "wss" else "http"
    return (
        "const sockets = [];"
        "const opened = i => new Promise((resolve, reject) => {"
        "const ws = new WebSocket(T + '/ws?i=' + i);"
        "sockets.push(ws);"
        "ws.onopen = () => resolve(ws);"
        "ws.onerror = () => reject(new Error('WebSocket opening failed'));"
        "ws.onclose = () => reject(new Error('WebSocket closed before opening'));"
        "});"
        "const message = ws => new Promise((resolve, reject) => {"
        "ws.onmessage = event => event.data === 'tick' ? resolve() : "
        "reject(new Error('unexpected WebSocket message'));"
        "ws.onclose = () => reject(new Error('WebSocket closed before its message'));"
        "ws.onerror = () => reject(new Error('WebSocket message failed'));"
        "});"
        "const closed = ws => new Promise((resolve, reject) => {"
        "ws.onclose = event => event.wasClean && event.code === 1000 ? "
        "resolve() : reject(new Error('WebSocket close failed'));"
        "ws.onerror = () => reject(new Error('WebSocket close failed'));"
        "ws.close(1000);"
        "});"
        f"const H = T.replace('{scheme}:', '{http_scheme}:');"
        "const get = i => fetch(H + '/fast?i=' + i, "
        "{mode: 'cors', cache: 'no-store'}).then(r => {"
        "if (!r.ok) throw new Error('target HTTP status ' + r.status);"
        "return r.text(); });"
        "opened(0).then(message).then(() => opened(1))"
        ".then(() => Promise.all(sockets.map(closed)))"
        ".then(() => get(2)).then(() => get(3))"
        f".then(() => {DONE})"
    )


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
            "websocket-backup",
            "Direct WebSocket connection attempts with [::1] then 127.0.0.1, "
            "a second upgrade while the first is active, and HTTP reuse after "
            "both WebSockets close",
            40,
            "websocket",
            _websocket_backup_script("ws"),
            rewrite_lookup=True,
        ),
        Scenario(
            "wss-backup",
            "Direct TLS WebSocket attempts with [::1] then 127.0.0.1, "
            "a second upgrade while the first is active, and HTTPS reuse "
            "after both WebSockets close; HTTP/1.1 only",
            40,
            "wss",
            _websocket_backup_script("wss"),
            rewrite_lookup=True,
        ),
        Scenario(
            "wss-https-h2-proxy-backup",
            "Fresh WSS through an HTTPS/H2 proxy with [::1] then 127.0.0.1; "
            "a second upgrade while the first is active, clean closes and "
            "subsequent HTTPS reuse; inner HTTP/1.1 only",
            40,
            "wss-https-h2-proxy",
            _websocket_backup_script("wss"),
            rewrite_lookup=True,
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
            "h2-backup",
            "HTTP/2 connection attempts with [::1] then 127.0.0.1, reuse, "
            "and a new request after the origin closes its connections",
            40,
            "h2",
            _readable_get("/fast?i=0")
            + f".then(() => {_readable_get('/fast?i=1')})"
            + ".then(() => fetch('/drop', {cache: 'no-store'}))"
            + f".then(() => {_readable_get('/fast?i=2')})"
            + f".then(() => {DONE})",
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
        Scenario(
            "http-connect-backup",
            "HTTP CONNECT proxy attempts with [::1] then 127.0.0.1, "
            "concurrent H1 TLS requests and a new request after origin disconnect",
            40,
            "https-connect",
            _proxy_backup_script(),
            rewrite_lookup=True,
        ),
        Scenario(
            "https-connect-backup",
            "HTTPS proxy attempts with [::1] then 127.0.0.1, outer H1 CONNECT, "
            "concurrent inner H1 TLS requests and origin disconnect",
            40,
            "https-proxy-connect",
            _proxy_backup_script(),
            rewrite_lookup=True,
        ),
        Scenario(
            "https-h2-connect-backup",
            "HTTPS proxy attempts with [::1] then 127.0.0.1, outer H2 CONNECT "
            "streams, concurrent inner H1 TLS requests and origin disconnect",
            40,
            "https-h2-proxy-connect",
            _proxy_backup_script(),
            rewrite_lookup=True,
        ),
        Scenario(
            "socks5-backup",
            "SOCKS5 proxy attempts with [::1] then 127.0.0.1, remote origin "
            "names, concurrent H1 TLS requests and origin disconnect",
            40,
            "https-socks5",
            _proxy_backup_script(),
            rewrite_lookup=True,
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


def moz_log_lines(
    text: str,
    port: int,
    start_ms: int,
    *,
    endpoints: Sequence[tuple[str, int]] = (),
) -> list[str]:
    """Retained MOZ_LOG lines about TARGET_HOST and the objects serving `port`.

    A socket transport belongs to the origin when its `ResolveHost` line names
    `TARGET_HOST:port`; an HTTP connection when its `Init` line names such a
    transport; a connection setup or a connection entry when its
    `Creating DnsAndConnectSocket` or `ConnectionEntry` line names the origin.
    Additional endpoints retain the proxy and origin in one object namespace.
    A line is kept when it matches `MOZ_LOG_KEEP` and
    names one of those objects or endpoint hosts. Object addresses become
    `p<n>` in order of first appearance, and times are milliseconds from
    `start_ms`.
    """
    origins = [f"{host}:{number}" for host, number in ((TARGET_HOST, port), *endpoints)]
    hosts = [TARGET_HOST, *(host for host, _ in endpoints)]
    objects: set[str] = set()
    kept: list[tuple[int, str, str]] = []
    for line in text.splitlines():
        match = MOZ_LOG_LINE.match(line)
        if match is None:
            continue
        stamp, module, message = match.groups()
        pointers = POINTER.findall(message)
        if any(
            anchors_origin_object(message, pointers, origin, objects)
            for origin in origins
        ):
            objects.update(pointers[:1])
        if not any(marker in message for marker in MOZ_LOG_KEEP):
            continue
        if not (
            objects.intersection(pointers) or any(host in message for host in hosts)
        ):
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
    paths = []
    for path in directory.glob("moz*"):
        if ".child-" in path.name:
            continue
        if len(paths) >= MAX_MOZ_LOG_FILES:
            raise ValueError("Firefox parent log file limit exceeded")
        paths.append(path)

    texts = []
    remaining = MAX_MOZ_LOG_BYTES
    for path in sorted(paths):
        with path.open("rb") as source:
            raw = source.read(remaining + 1)
        if len(raw) > remaining:
            raise ValueError("Firefox parent log byte limit exceeded")
        remaining -= len(raw)
        texts.append(raw.decode("utf-8", errors="replace"))
    return "\n".join(texts)


# The loopback origins.


@dataclass
class WebSocketResult:
    ticks_sent: int = 0
    close_code: int | None = None


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
    alpn: str | None = None
    websocket: WebSocketResult | None = None
    local: str | None = None


@dataclass
class Origins:
    """The page origin on 127.0.0.1 and the measured origin on TARGET_HOST."""

    scenario: Scenario
    certificate: Any = None
    page_port: int = 0
    port: int = 0
    external_https_origin: str | None = None
    connections: list[ServerConnection] = field(default_factory=list)
    open: list[tuple[ServerConnection, asyncio.StreamWriter]] = field(
        default_factory=list
    )
    page_requested: asyncio.Event = field(default_factory=asyncio.Event)
    go: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    peers: dict[asyncio.Task, tuple[asyncio.StreamWriter, bool]] = field(
        default_factory=dict
    )
    writers: set[asyncio.StreamWriter] = field(default_factory=set)
    listeners: list[asyncio.Server] = field(default_factory=list)
    failures: list[BaseException] = field(default_factory=list)
    failed: asyncio.Event = field(default_factory=asyncio.Event)
    stopping: bool = False
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    accepted: int = 0
    request_count: int = 0
    proxy: Any = None
    request_order: list[str] = field(default_factory=list)

    def remember_failure(self, error: BaseException) -> None:
        if all(error is not previous for previous in self.failures):
            self.failures.append(error)
        self.failed.set()
        self.changed.set()
        for listener in self.listeners:
            try:
                listener.close()
            except BaseException as close_error:
                if all(close_error is not old for old in self.failures):
                    self.failures.append(close_error)

    def accept_page(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.accept(reader, writer, page=True)

    def accept_target(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.accept(reader, writer, page=False)

    def accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, page: bool
    ) -> None:
        self.writers.add(writer)
        self.accepted += 1
        over_limit = (
            self.stopping
            or len(self.peers) >= MAX_ACTIVE_PEERS
            or self.accepted > MAX_CONNECTIONS
        )
        work = (
            self.close_rejected(writer)
            if over_limit
            else self.handle_page(reader, writer)
            if page
            else self.handle_target(reader, writer)
        )
        task = asyncio.create_task(work)
        self.peers[task] = (writer, False)
        task.add_done_callback(self.completed)
        self.changed.set()
        if over_limit:
            self.remember_failure(ValueError("Firefox origin peer limit exceeded"))

    async def close_rejected(self, writer: asyncio.StreamWriter) -> None:
        await close_writer(writer, None)

    def completed(self, task: asyncio.Task) -> None:
        _, requested = self.peers.pop(task)
        try:
            task.result()
        except asyncio.CancelledError as error:
            if not requested or isinstance(error.__cause__, BrowserLaunchFailures):
                self.remember_failure(error)
        except BaseException as error:
            self.remember_failure(error)

    def record_request(self) -> None:
        self.request_count += 1
        if self.request_count > MAX_REQUESTS:
            raise ValueError("Firefox origin request limit exceeded")

    async def shutdown(self) -> None:
        self.stopping = True
        if self.proxy is not None:
            try:
                await self.proxy.close()
            except BaseException as error:
                self.remember_failure(error)
        for listener in self.listeners:
            try:
                listener.close()
            except BaseException as error:
                self.remember_failure(error)
        for task, (writer, _) in tuple(self.peers.items()):
            # Close wakes reads, and cancellation wakes /go, slow responses and ticks.
            try:
                writer.close()
            except BaseException as error:
                self.remember_failure(error)
            self.peers[task] = (writer, task.cancel())

        for listener in self.listeners:
            try:
                await listener.wait_closed()
            except BaseException as error:
                self.remember_failure(error)
        if self.peers:
            await asyncio.wait(tuple(self.peers))
        # Task done callbacks retire each peer and observe its original outcome.
        await asyncio.sleep(0)
        # Retain failed close attempts until this explicit collection succeeds.
        for writer in tuple(self.writers):
            try:
                await close_writer(writer, None)
            except BaseException as error:
                self.remember_failure(error)
            else:
                self.writers.remove(writer)

    @property
    def target_url(self) -> str:
        if self.external_https_origin is not None:
            return self.external_https_origin
        return f"{self.scenario.scheme}://{self.scenario.hostname}:{self.port}"

    def cleanup_pending(self) -> bool:
        proxy = self.proxy
        return bool(
            self.peers
            or self.writers
            or (
                proxy is not None
                and (
                    proxy.servers
                    or proxy.handlers
                    or proxy.writers
                    or proxy.writer_waits
                    or proxy.listener_waits
                    or proxy.protocol_waits
                    or proxy.protocols
                )
            )
        )

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
        primary = None
        try:
            while True:
                head = await read_head(reader)
                if head is None:
                    break
                self.record_request()
                path = urlsplit(request_target(head)).path
                if path == "/":
                    self.page_requested.set()
                    self.changed.set()
                    body, kind = self.page(), "text/html"
                elif path == "/proxy.pac" and self.proxy is not None:
                    body, kind = connect_pac(self), "application/x-ns-proxy-autoconfig"
                else:
                    body, kind = b"ok\n", "text/plain"
                if path == "/go":
                    await self.go.wait()
                elif path == "/drop":
                    targets = list(self.open)
                    closing = [
                        task
                        for task, (writer, _) in self.peers.items()
                        if any(writer is target for _, target in targets)
                    ]
                    for connection, target in targets:
                        connection.close_kind = "server"
                        if (
                            self.scenario.name == "h2-backup"
                            or self.scenario.proxy_mode is not None
                        ):
                            target.transport.abort()
                        else:
                            target.close()
                    if (
                        self.scenario.name == "h2-backup"
                        or self.scenario.proxy_mode is not None
                    ):
                        if len(closing) != len(targets):
                            raise RuntimeError(
                                "Firefox target close has no owning peer"
                            )
                        outcomes = await asyncio.gather(
                            *(asyncio.shield(task) for task in closing),
                            return_exceptions=True,
                        )
                        raise_browser_failures(
                            None,
                            tuple(
                                outcome
                                for outcome in outcomes
                                if isinstance(outcome, BaseException)
                            ),
                        )
                await write_response(writer, body, kind, close=False)
                if path == "/done":
                    self.done.set()
                    self.changed.set()
        except BaseException as error:
            if not peer_gone(error):
                primary = error
        finally:
            await close_writer(writer, primary)

    async def handle_target(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        connection = None
        primary = None
        try:
            peer = writer.get_extra_info("peername")
            connection = ServerConnection(f"{peer[0]}:{peer[1]}", now_ms())
            local = writer.get_extra_info("sockname")
            connection.local = f"{local[0]}:{local[1]}"
            self.connections.append(connection)
            self.open.append((connection, writer))
            if self.scenario.target == "wss" or self.scenario.proxy_mode is not None:
                tls = writer.get_extra_info("ssl_object")
                if tls is None:
                    raise ValueError(
                        "Firefox CONNECT origin requires TLS"
                        if self.scenario.proxy_mode is not None
                        else "Firefox WSS origin requires TLS"
                    )
                connection.alpn = tls.selected_alpn_protocol()
                if self.scenario.proxy_mode is not None:
                    if connection.alpn != "http/1.1":
                        raise ValueError(
                            "Firefox CONNECT origin requires HTTP/1.1 ALPN"
                        )
                elif connection.alpn not in (None, "http/1.1"):
                    raise ValueError("Firefox WSS origin requires HTTP/1.1")
            if self.scenario.target == "h2":
                await self.serve_h2(reader, writer, connection)
            else:
                await self.serve_http1(reader, writer, connection)
        except ConnectionResetError as error:
            if not peer_gone(error):
                primary = error
            elif connection is not None:
                connection.close_kind = "reset"
        except BaseException as error:
            if not peer_gone(error):
                primary = error
        finally:
            if connection is not None:
                connection.closed_ms = now_ms()
                self.open.remove((connection, writer))
            await close_writer(writer, primary)

    async def serve_http1(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        connection: ServerConnection,
    ) -> None:
        while True:
            try:
                head = await read_head(reader)
            except ConnectionResetError as error:
                if not peer_gone(error):
                    raise
                connection.close_kind = "reset"
                return
            if head is None:
                if connection.close_kind == "-":
                    connection.close_kind = "fin"
                return
            target = request_target(head)
            self.record_request()
            connection.requests.append((now_ms(), target))
            path = urlsplit(target).path
            if self.scenario.target == "wss-https-h2-proxy":
                self.request_order.append(target)
                if path == "/fast":
                    websockets = proxy_websocket_connections(self)
                    if len(websockets) != 2 or any(
                        item.websocket is None or item.websocket.close_code != 1000
                        for item in websockets
                    ):
                        raise ValueError(
                            "Firefox proxy WSS sent HTTPS before its WebSockets closed"
                        )
            if path == "/ws":
                if self.scenario.target == "wss-https-h2-proxy":
                    connection.websocket = WebSocketResult()
                await serve_websocket(reader, writer, head, connection.websocket)
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
                    self.record_request()
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


def peer_gone(error: BaseException) -> bool:
    if isinstance(error.__cause__, BrowserLaunchFailures):
        return False
    return isinstance(
        error, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)
    ) or (
        isinstance(error, OSError)
        and error.errno in (errno.EPIPE, errno.ECONNRESET, errno.ECONNABORTED)
    )


async def close_writer(
    writer: asyncio.StreamWriter, primary: BaseException | None
) -> None:
    failures = []
    try:
        writer.close()
    except BaseException as error:
        if not peer_gone(error):
            failures.append(error)
    try:
        await writer.wait_closed()
    except BaseException as error:
        if not peer_gone(error):
            failures.append(error)
    raise_browser_failures(primary, tuple(failures))


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
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    head: bytes,
    result: WebSocketResult | None = None,
) -> WebSocketResult:
    """Accept the upgrade, send a text frame every five seconds, echo a close."""
    accept = websocket_accept(header_value(head, b"sec-websocket-key"))
    writer.write(
        (
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode()
    )
    await writer.drain()

    if result is None:
        result = WebSocketResult()

    async def tick() -> None:
        while True:
            await asyncio.sleep(5)
            writer.write(b"\x81\x04tick")
            await writer.drain()
            result.ticks_sent += 1

    ticker = asyncio.create_task(tick())
    primary = None
    try:
        while True:
            first = await reader.readexactly(2)
            opcode = first[0] & 0x0F
            length = first[1] & 0x7F
            if length == 126:
                length = int.from_bytes(await reader.readexactly(2), "big")
            elif length == 127:
                length = int.from_bytes(await reader.readexactly(8), "big")
            if length > MAX_WEBSOCKET_FRAME or (opcode >= 8 and length > 125):
                raise ValueError("Firefox WebSocket frame exceeds its byte limit")
            if opcode >= 8 and not first[0] & 0x80:
                raise ValueError("Firefox WebSocket control frame is fragmented")
            if not first[1] & 0x80:
                raise ValueError("Firefox WebSocket client frame is not masked")
            mask = await reader.readexactly(4) if first[1] & 0x80 else b""
            payload = await reader.readexactly(length)
            if opcode == 0x8:
                if mask:
                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                writer.write(bytes([0x88, len(payload)]) + payload)
                await writer.drain()
                if len(payload) >= 2:
                    result.close_code = int.from_bytes(payload[:2], "big")
                break
    except asyncio.IncompleteReadError:
        pass
    except BaseException as error:
        primary = error
    finally:
        requested = ticker.cancel()
        failures = []
        try:
            _, pending = await asyncio.wait((ticker,), timeout=PEER_CLEANUP_SECONDS)
            if pending:
                failures.append(_FirefoxTickerPending(ticker))
            else:
                try:
                    ticker.result()
                except asyncio.CancelledError as error:
                    if not requested or isinstance(
                        error.__cause__, BrowserLaunchFailures
                    ):
                        failures.append(error)
                except BaseException as error:
                    failures.append(error)
        except BaseException as error:
            failures.extend((error, _FirefoxTickerPending(ticker)))
        raise_browser_failures(primary, tuple(failures))
    return result


class _FirefoxTickerPending(RuntimeError):
    def __init__(self, task: asyncio.Task) -> None:
        self.task = task
        super().__init__("Firefox WebSocket ticker has not stopped")

    async def finish(self) -> None:
        # The task was explicitly asked to stop before this pending owner formed.
        try:
            await asyncio.shield(self.task)
        except asyncio.CancelledError as error:
            if not self.task.done() or isinstance(
                error.__cause__, BrowserLaunchFailures
            ):
                raise


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


def browser_process(
    listing: Sequence[dict[str, Any]], *, executable: Path, launcher_pid: int | None
) -> int | None:
    """Find the owned Firefox parent, with or without its launcher.

    The profile listing also contains the Python ownership bootstrap. Only
    the exact browser executable at the confirmed launch PID, or its single
    non-content child, can be the parent. Ambiguous ancestry fails closed.
    """
    executable_path = ntpath.normcase(ntpath.normpath(str(executable.resolve())))
    candidates = [
        entry
        for entry in listing
        if entry.get("ExecutablePath")
        and ntpath.normcase(ntpath.normpath(entry["ExecutablePath"])) == executable_path
        and "-contentproc" not in (entry.get("CommandLine") or "").split()
    ]
    ids = {entry["ProcessId"] for entry in candidates}
    if launcher_pid not in ids or len(ids) != len(candidates):
        return None

    children = [
        entry for entry in candidates if entry["ParentProcessId"] == launcher_pid
    ]
    if not children:
        return launcher_pid
    if len(children) != 1:
        return None

    parent_pid = int(children[0]["ProcessId"])
    if any(entry["ParentProcessId"] == parent_pid for entry in candidates):
        return None
    return parent_pid


def profile_processes(profile: Path) -> list[dict[str, Any]]:
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding; "
        "$profile = [Environment]::GetEnvironmentVariable('PHANTOM_FIREFOX_PROFILE'); "
        "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and "
        "$_.CommandLine.Contains($profile) } | "
        "Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | "
        "ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        env={**os.environ, "PHANTOM_FIREFOX_PROFILE": str(profile)},
        capture_output=True,
        check=False,
        timeout=60,
    )
    result.check_returncode()
    output = result.stdout.decode("utf-8", errors="strict")
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
        self._script: Any = None
        self.failure: BaseException | None = None
        self._detaching = False

    def attach(self) -> None:
        import frida  # noqa: PLC0415 - only a capture needs Frida

        self.frida_version = frida.__version__
        source = (
            AGENT.read_text(encoding="utf-8")
            + "\n"
            + EXTENSION.read_text(encoding="utf-8")
        )
        self._session = frida.get_local_device().attach(self.pid)
        self._session.on("detached", self._on_detached)
        script = self._session.create_script(source)
        self._script = script
        script.on("message", self._on_message)
        script.load()
        script.post({"type": "config", "slow_ipv6_refusal": False})
        script.post({"type": "firefox-config", **self.config})

    def _on_message(self, message: dict[str, Any], _data: object) -> None:
        with self._lock:
            try:
                if self.failure is not None:
                    return
                if not isinstance(message, dict):
                    raise ValueError("Firefox hook message must be an object")
                encoded = json.dumps(message, allow_nan=False).encode("utf-8")
                if len(encoded) > MAX_HOOK_MESSAGE_BYTES:
                    raise ValueError("Firefox hook message exceeds its byte limit")
                if len(self.reports) + len(self.errors) >= MAX_HOOK_REPORTS:
                    raise ValueError("Firefox hook report limit exceeded")
                if message.get("type") == "send":
                    report = message["payload"]
                    if not isinstance(report, dict) or not isinstance(
                        report.get("kind"), str
                    ):
                        raise ValueError("Firefox hook report must name its kind")
                    if type(report.get("time_ms")) is not int:
                        raise ValueError("Firefox hook report must name its time")
                    self.reports.append(report)
                    if report["kind"] == "firefox-config":
                        self.ready.set()
                else:
                    self.errors.append(json.dumps(message, sort_keys=True))
                    raise _FirefoxAgentFailure(message)
            except BaseException as error:
                self.failure = error
                self.ready.set()

    def _on_detached(self, reason: str, crash: object) -> None:
        with self._lock:
            if self._detaching and reason == "application-requested":
                return
            if self.failure is None:
                self.failure = _FirefoxSessionDetached(reason, crash)
            self.ready.set()

    def snapshot(self) -> tuple[list[dict[str, Any]], list[str]]:
        with self._lock:
            if self.failure is not None:
                raise self.failure
            return list(self.reports), list(self.errors)

    def detach(self) -> None:
        if self._session is not None:
            self._detaching = True
            try:
                self._session.detach()
            finally:
                self._detaching = False
            self._session = None
            self._script = None


class _FirefoxAgentFailure(RuntimeError):
    def __init__(self, message: dict[str, Any]) -> None:
        self.message = message
        super().__init__("Firefox native hook reported an error")


class _FirefoxSessionDetached(RuntimeError):
    def __init__(self, reason: str, crash: object) -> None:
        self.reason = reason
        self.crash = crash
        super().__init__(f"Firefox hook session detached unexpectedly: {reason}")


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


class _FirefoxNative:
    """Serialize one browser launch, attachment and teardown in one worker.

    Cancelling the asyncio waiter cannot interrupt a blocking native call. A
    pending cleanup error retains this owner so the caller can collect it later.
    """

    def __init__(
        self,
        run: _FirefoxRun,
        plan: LaunchPlan,
        url: str,
        config: dict,
        *,
        browser_factory: Callable[[LaunchPlan, str], LaunchedBrowser] | None = None,
    ) -> None:
        self.run = run
        factory = LaunchedBrowser if browser_factory is None else browser_factory
        self.browser = factory(plan, url)
        self.hooks: Hooks | None = None
        self.config = config
        self.future: asyncio.Future | None = None
        self.started = asyncio.Event()
        self.attached = asyncio.Event()
        self.attach_requested = threading.Event()
        self.stop_requested = threading.Event()
        self.failures: list[BaseException] = []
        self.cleanup_failed = False
        self.launcher = False
        self.primary: BaseException | None = None

    def notify(self, event: asyncio.Event) -> None:
        self.run.loop.call_soon_threadsafe(event.set)
        self.run.loop.call_soon_threadsafe(self.run.changed.set)

    def remember(self, error: BaseException) -> None:
        if all(error is not old for old in self.failures):
            self.failures.append(error)
        try:
            self.run.loop.call_soon_threadsafe(self.run.changed.set)
        except BaseException as notification_error:
            if all(notification_error is not old for old in self.failures):
                self.failures.append(notification_error)
            self.stop_requested.set()
            self.attach_requested.set()

    def start(self) -> None:
        self.future = self.run.loop.run_in_executor(None, self.work)

    def work(self) -> None:
        try:
            if self.stop_requested.is_set():
                return
            with patched_environment(self.run.environment):
                self.browser.__enter__()
            self.notify(self.started)
            self.attach_requested.wait()
            if self.stop_requested.is_set():
                return

            profile = self.browser.profile
            if profile is None:
                raise RuntimeError("Firefox launch did not retain its profile")
            listing = profile_processes(profile)
            launcher_pid = self.browser.launcher_pid
            pid = browser_process(
                listing,
                executable=self.browser.plan.executable,
                launcher_pid=launcher_pid,
            )
            if pid is None:
                diagnostic = {
                    "profile": str(profile),
                    "executable": str(self.browser.plan.executable),
                    "launcher_pid": launcher_pid,
                    "processes": [
                        {
                            "pid": entry["ProcessId"],
                            "parent_pid": entry["ParentProcessId"],
                            "executable": entry.get("ExecutablePath"),
                            "content_process": "-contentproc"
                            in (entry.get("CommandLine") or "").split(),
                        }
                        for entry in listing
                    ],
                }
                raise RuntimeError(
                    "no Firefox parent process for the capture profile: "
                    + json.dumps(diagnostic)
                )
            self.launcher = launcher_pid is not None and pid != launcher_pid
            self.hooks = Hooks(pid, self.config)
            self.hooks.attach()
            if not self.hooks.ready.wait(ATTACH_LIMIT_SECONDS):
                raise RuntimeError("Firefox agents did not report ready")
            if self.hooks.failure is not None:
                raise self.hooks.failure
            self.notify(self.attached)
            while not self.stop_requested.wait(0.1):
                if self.hooks.failure is not None:
                    raise self.hooks.failure
        except BaseException as error:
            self.remember(error)
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        self.cleanup_failed = False
        if self.hooks is not None:
            try:
                self.hooks.detach()
            except BaseException as error:
                self.cleanup_failed = True
                self.remember(error)
            if self.hooks.failure is not None:
                self.remember(self.hooks.failure)

        try:
            self.browser.__exit__(None, self.primary, None)
        except BaseException as error:
            self.cleanup_failed = True
            self.remember(error)

    def stop(self, primary: BaseException | None) -> None:
        self.primary = primary
        self.stop_requested.set()
        self.attach_requested.set()

    async def collect(self) -> None:
        if self.future is not None:
            await asyncio.shield(self.future)

    async def retry_cleanup(self) -> None:
        # Explicit caller retry after the previous worker finished, never overlap.
        await self.collect()
        if self.cleanup_failed:
            self.future = self.run.loop.run_in_executor(None, self.cleanup)
            await self.collect()


class _FirefoxRun:
    """Own listeners, peers, the native worker and temporary log publication."""

    def __init__(self, scenario: Scenario) -> None:
        self.loop = asyncio.get_running_loop()
        self.changed = asyncio.Event()
        self.origins = Origins(scenario)
        self.origins.changed = self.changed
        self.native: _FirefoxNative | None = None
        self.log_directory: Path | None = None
        self.environment: dict[str, str] = {}
        self.cleanup: asyncio.Task | None = None
        self.origin_cleanup: asyncio.Task[None] | None = None
        self.primary: BaseException | None = None
        self.collection_abandoned = False
        self.cleanup_failures: tuple[BaseException, ...] = ()

    async def wait(self, event: asyncio.Event, seconds: float) -> None:
        deadline = self.loop.time() + seconds
        while True:
            self.changed.clear()
            if self.origins.failures:
                raise self.origins.failures[0]
            if self.native is not None and self.native.failures:
                raise self.native.failures[0]
            if event.is_set():
                return
            await asyncio.wait_for(
                self.changed.wait(), max(0.0, deadline - self.loop.time())
            )

    async def cleanup_work(self, *, retry: bool = False) -> tuple[BaseException, ...]:
        failures = []
        for listener in self.origins.listeners:
            try:
                listener.close()
            except BaseException as error:
                self.origins.remember_failure(error)
        if self.primary is not None or self.known_failures():
            self.start_origin_cleanup(retry=retry)
        if self.native is not None:
            self.native.stop(self.primary)
            try:
                await self.native.collect()
                if retry:
                    await self.native.retry_cleanup()
            except BaseException as error:
                failures.append(error)
            failures.extend(self.native.failures)
            if self.native.cleanup_failed:
                failures.append(_FirefoxCapturePending(self, "native cleanup failed"))

        try:
            await asyncio.shield(self.start_origin_cleanup(retry=retry))
        except BaseException as error:
            failures.append(error)
        if self.origins.cleanup_pending():
            failures.append(
                _FirefoxCapturePending(self, "origin cleanup has not completed")
            )
        failures.extend(self.origins.failures)
        return tuple(error for error in failures if error is not self.primary)

    def start_origin_cleanup(self, *, retry: bool = False) -> asyncio.Task[None]:
        if self.origin_cleanup is None or (
            retry and self.origin_cleanup.done() and self.origins.cleanup_pending()
        ):
            self.origin_cleanup = asyncio.create_task(self.origins.shutdown())
            self.origin_cleanup.add_done_callback(self.observe_origin_cleanup)
        return self.origin_cleanup

    def observe_origin_cleanup(self, task: asyncio.Task[None]) -> None:
        try:
            task.result()
        except BaseException as error:
            self.origins.remember_failure(error)

    async def collect_pending_origins(self) -> tuple[BaseException, ...]:
        # Healthy captures observe browser FIN before origin retirement. Once
        # collection fails, a blocked native worker must not hold loopback peers.
        task = self.start_origin_cleanup()
        try:
            _, pending = await asyncio.wait((task,), timeout=PEER_CLEANUP_SECONDS)
        except BaseException as error:
            self.origins.remember_failure(error)
            return (
                _FirefoxCapturePending(self, "origin cleanup collection interrupted"),
            )
        if pending:
            return (_FirefoxCapturePending(self, "origin cleanup timed out"),)
        self.observe_origin_cleanup(task)
        return ()

    async def finish(
        self, primary: BaseException | None = None
    ) -> tuple[BaseException, ...]:
        self.primary = primary
        self.collection_abandoned = False
        if self.native is not None:
            self.native.stop(primary)
        if (
            self.cleanup is not None
            and self.cleanup.done()
            and (
                self.origins.cleanup_pending()
                or (self.native is not None and self.native.cleanup_failed)
            )
        ):
            self.cleanup = asyncio.create_task(self.cleanup_work(retry=True))
            self.cleanup.add_done_callback(self.observe_cleanup)
        elif self.cleanup is None:
            self.cleanup = asyncio.create_task(self.cleanup_work())
            self.cleanup.add_done_callback(self.observe_cleanup)
        try:
            _, pending = await asyncio.wait(
                (self.cleanup,), timeout=NATIVE_CLEANUP_SECONDS
            )
        except BaseException as error:
            self.collection_abandoned = True
            origin_failures = await self.collect_pending_origins()
            return (
                error,
                *self.known_failures(),
                *origin_failures,
                _FirefoxCapturePending(self, "cleanup collection interrupted"),
            )
        if pending:
            self.collection_abandoned = True
            origin_failures = await self.collect_pending_origins()
            return (
                *self.known_failures(),
                *origin_failures,
                _FirefoxCapturePending(self, "cleanup collection timed out"),
            )
        try:
            return self.cleanup.result()
        except BaseException as error:
            return (error, _FirefoxCapturePending(self, "cleanup failed"))

    def observe_cleanup(self, task: asyncio.Task) -> None:
        try:
            self.cleanup_failures = task.result()
        except BaseException as error:
            self.cleanup_failures = (error,)
        if self.collection_abandoned and self.cleanup_failures:
            self.loop.call_exception_handler(
                {
                    "message": "Firefox capture cleanup failed after collection stopped",
                    "exception": self.cleanup_failures[0],
                    "failures": self.cleanup_failures,
                    "primary": self.primary,
                    "owner": self,
                    "task": task,
                }
            )

    def known_failures(self) -> tuple[BaseException, ...]:
        errors = [*self.origins.failures]
        if self.native is not None:
            errors.extend(self.native.failures)
        return tuple(error for error in errors if error is not self.primary)

    def remove_log(self) -> tuple[BaseException, ...]:
        if self.log_directory is None:
            return ()
        try:
            shutil.rmtree(self.log_directory)
        except BaseException as error:
            return (error, _FirefoxCapturePending(self, "log cleanup failed"))
        self.log_directory = None
        return ()


class _FirefoxCapturePending(RuntimeError):
    def __init__(self, owner: _FirefoxRun, message: str) -> None:
        self.owner = owner
        super().__init__(
            f"Firefox capture {message}; owner remains available for collection"
        )


async def start_connect_proxy(origins: Origins, certificate: Any) -> None:
    from .http2_session import CaptureRun, ServerPolicy  # noqa: PLC0415
    from .websocket_tunnel import TunnelServer  # noqa: PLC0415

    class ConnectProxy(TunnelServer):
        async def _opening(self, channel: Any, record: Any) -> Any:
            if self.mode == "https" and record.connection.alpn != "http/1.1":
                raise ValueError("Firefox HTTPS proxy requires HTTP/1.1 ALPN")
            return await super()._opening(channel, record)

        def failed(self, error: BaseException, run: CaptureRun | None) -> None:
            super().failed(error, run)
            origins.remember_failure(error)

    mode = origins.scenario.proxy_mode
    if mode is None:
        raise ValueError("Firefox proxy scenario is required")
    proxy = ConnectProxy(
        mode, certificate, ("127.0.0.1", origins.port), alpn=origins.scenario.proxy_alpn
    )
    # Retain ownership before either admission or listener startup can fail.
    origins.proxy = proxy
    proxy.begin_run(
        CaptureRun(
            {
                "http": "firefox-connect",
                "https": "firefox-https-connect",
                "socks5": "firefox-socks5",
            }[mode],
            ServerPolicy(),
            {},
            clock=lambda: now_ms() / 1000,
        )
    )
    await proxy.start()


def connect_pac(origins: Origins) -> bytes:
    if origins.proxy is None or origins.proxy.address is None:
        raise RuntimeError("Firefox CONNECT proxy has no listener")
    host = json.dumps(origins.scenario.hostname)
    # Firefox157's PAC SOCKS5 always requests remote-name resolution.
    kind = {"http": "PROXY", "https": "HTTPS", "socks5": "SOCKS5"}[
        origins.scenario.proxy_mode
    ]
    route = json.dumps(f"{kind} {TARGET_HOST}:{origins.proxy.address[1]}")
    origin = json.dumps(f"{origins.target_url}/")
    matching = f"url.indexOf({origin}) === 0"
    if origins.scenario.target == "wss-https-h2-proxy":
        https_origin = json.dumps(
            f"https://{origins.scenario.hostname}:{origins.port}/"
        )
        matching = f"({matching} || url.indexOf({https_origin}) === 0)"
    return (
        f"function FindProxyForURL(url, host) {{\n"
        f"  if (host === {host} && {matching}) return {route};\n"
        '  return "DIRECT";\n'
        "}\n"
    ).encode("ascii")


def connect_preferences(origins: Origins) -> tuple[tuple[str, bool | int | str], ...]:
    if origins.proxy is None or origins.proxy.address is None or not origins.page_port:
        raise RuntimeError("Firefox CONNECT proxy and PAC listeners are required")
    return (
        ("network.proxy.type", 2),
        (
            "network.proxy.autoconfig_url",
            f"http://127.0.0.1:{origins.page_port}/proxy.pac",
        ),
        ("network.proxy.failover_direct", False),
        ("network.proxy.allow_hijacking_localhost", True),
        ("network.proxy.no_proxies_on", ""),
    )


def native_https_port(origin: str) -> int:
    if not isinstance(origin, str) or len(origin) > 256:
        raise ValueError("external HTTPS origin requires a bounded origin URL")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as error:
        raise ValueError(
            "external HTTPS origin has an invalid port or hostname"
        ) from error
    if (
        port is None
        or port == 443
        or not 0 < port <= 65535
        or origin != f"https://{NATIVE_HTTPS_HOST}:{port}"
    ):
        raise ValueError(
            "external HTTPS origin must name server.phantom.test on a non-443 port"
        )
    return port


async def run_once(
    scenario: Scenario,
    executable: Path,
    *,
    headful: bool = False,
    failure_path: Path | None = None,
    prepared: _FirefoxRun | None = None,
    external_https_origin: str | None = None,
    browser_factory: Callable[[LaunchPlan, str], LaunchedBrowser] | None = None,
) -> tuple[RunResult, str]:
    """Capture one scene; the caller owns any external HTTPS peer and DNS policy."""
    owner = _FirefoxRun(scenario) if prepared is None else prepared
    origins = owner.origins
    primary = None
    result = None
    plan = None
    try:
        validate_waits(scenario)
        if external_https_origin is not None:
            if prepared is not None:
                raise ValueError("external HTTPS origin cannot use prepared listeners")
            if scenario.target != "http1" or scenario.rewrite_lookup:
                raise ValueError(
                    "external HTTPS origin requires a direct HTTP controller without lookup rewriting"
                )
            origins.port = native_https_port(external_https_origin)
            origins.external_https_origin = external_https_origin
        if prepared is not None and (
            owner.native is not None
            or owner.cleanup is not None
            or origins.scenario != scenario
            or scenario.target != "http1"
            or origins.page_port != 0
            or origins.stopping
            or origins.done.is_set()
            or not 0 < origins.port <= 65535
            or not origins.listeners
            or any(
                not listener.is_serving()
                or not listener.sockets
                or any(
                    sock.getsockname()[1] != origins.port
                    or not ipaddress.ip_address(sock.getsockname()[0]).is_loopback
                    for sock in listener.sockets
                )
                for listener in origins.listeners
            )
        ):
            raise ValueError(
                "prepared Firefox origins require matching live HTTP/1 listeners"
            )
        page = await asyncio.start_server(
            origins.accept_page, "127.0.0.1", 0, limit=MAX_REQUEST_HEAD
        )
        origins.listeners.append(page)
        origins.page_port = page.sockets[0].getsockname()[1]
        context = None
        files: tuple[tuple[str, str], ...] = ()
        if scenario.target in ("h2", "wss") or scenario.proxy_mode is not None:
            from .http2_session import (  # noqa: PLC0415
                generate_certificate,
                server_context,
            )

            certificate = generate_certificate(scenario.hostname)
            context = server_context(certificate)
            context.set_alpn_protocols(
                ["h2" if scenario.target == "h2" else "http/1.1"]
            )
        if origins.port == 0:
            target = await asyncio.start_server(
                origins.accept_target,
                "127.0.0.1",
                0,
                limit=MAX_REQUEST_HEAD,
                ssl=context,
            )
            origins.listeners.append(target)
            origins.port = target.sockets[0].getsockname()[1]
        if scenario.target in ("h2", "wss") or scenario.proxy_mode is not None:
            files = (
                (
                    "cert_override.txt",
                    firefox_cert_override(
                        scenario.hostname, origins.port, certificate.sha256_fingerprint
                    ),
                ),
            )
        preferences: tuple[tuple[str, bool | int | str], ...] = ()
        measured_port = origins.port
        if scenario.proxy_mode is not None:
            proxy_certificate = (
                generate_certificate(TARGET_HOST)
                if scenario.proxy_mode == "https"
                else certificate
            )
            await start_connect_proxy(origins, proxy_certificate)
            if scenario.proxy_mode == "https":
                files = (
                    (
                        "cert_override.txt",
                        files[0][1]
                        + firefox_cert_override(
                            TARGET_HOST,
                            origins.proxy.address[1],
                            proxy_certificate.sha256_fingerprint,
                        ),
                    ),
                )
            preferences = connect_preferences(origins)
            measured_port = origins.proxy.address[1]
        if scenario.rewrite_lookup and not localhost_ipv6_free(measured_port):
            raise RuntimeError(f"[::1]:{measured_port} is in use")

        url = f"http://127.0.0.1:{origins.page_port}/"
        plan = LaunchPlan(
            browser="firefox",
            executable=executable,
            headless=not headful,
            profile_files=files,
            firefox_preferences=preferences,
        )
        owner.log_directory = Path(tempfile.mkdtemp(prefix="phantom-capture-moz-log-"))
        owner.environment = {
            "MOZ_LOG": MOZ_LOG_MODULES,
            "MOZ_LOG_FILE": str(owner.log_directory / "moz"),
        }
        config = (
            {"rewrite_host": TARGET_HOST, "rewrite_to": REWRITE_TO}
            if scenario.rewrite_lookup
            else {}
        )
        if browser_factory is None:
            owner.native = _FirefoxNative(owner, plan, url, config)
        else:
            owner.native = _FirefoxNative(
                owner, plan, url, config, browser_factory=browser_factory
            )
        owner.native.start()
        await owner.wait(owner.native.started, ATTACH_LIMIT_SECONDS)
        await owner.wait(origins.page_requested, ATTACH_LIMIT_SECONDS)
        owner.native.attach_requested.set()
        await owner.wait(owner.native.attached, ATTACH_LIMIT_SECONDS)
        origins.go.set()
        timed_out = False
        try:
            await owner.wait(origins.done, scenario.limit_seconds)
        except asyncio.TimeoutError:
            timed_out = True
        if scenario.proxy_mode is not None and not timed_out:
            validate_connect_run(origins)
        await asyncio.sleep(1.0)
        result = timed_out
    except BaseException as error:
        primary = error

    cleanup = await owner.finish(primary)
    if primary is not None or cleanup:
        if failure_path is not None:
            try:
                write_failure_report(failure_path, owner, primary, cleanup)
            except BaseException as error:
                cleanup = (*cleanup, error)
        if (
            owner.cleanup is not None
            and owner.cleanup.done()
            and not (owner.native and owner.native.cleanup_failed)
            and not any(isinstance(error, _FirefoxCapturePending) for error in cleanup)
        ):
            cleanup = (*cleanup, *owner.remove_log())
        raise_browser_failures(primary, cleanup)

    try:
        native = owner.native
        hooks = native.hooks
        reports, errors = hooks.snapshot()
        start_ms = reports[0]["time_ms"] if reports else now_ms()
        moz_log_text = parent_moz_log(owner.log_directory)
        endpoints = ()
        if origins.proxy is not None:
            endpoints = (
                (scenario.hostname, origins.port),
                (TARGET_HOST, origins.proxy.address[1]),
            )
        elif external_https_origin is not None:
            endpoints = ((NATIVE_HTTPS_HOST, origins.port),)
        result = RunResult(
            reports,
            errors,
            origins,
            result,
            hooks.frida_version,
            native.launcher,
            moz_log_lines(
                moz_log_text,
                origins.port,
                start_ms,
                endpoints=endpoints,
            ),
            start_ms,
            moz_log_text,
        )
    except BaseException as error:
        primary = error
    raise_browser_failures(primary, owner.remove_log())
    return result, plan.recorded_arguments(url)


def write_failure_report(
    path: Path,
    owner: _FirefoxRun,
    primary: BaseException | None,
    cleanup: tuple[BaseException, ...],
) -> None:
    def failure(error: BaseException | None) -> dict | None:
        if error is None:
            return None
        return {
            "id": id(error),
            "type": type(error).__name__,
            "message": str(error),
            "primary": repr(error.primary)
            if isinstance(error, BrowserLaunchFailures)
            else None,
            "primary_id": id(error.primary)
            if isinstance(error, BrowserLaunchFailures) and error.primary is not None
            else None,
            "cleanup": [repr(item) for item in error.cleanup]
            if isinstance(error, BrowserLaunchFailures)
            else [],
            "cleanup_ids": [id(item) for item in error.cleanup]
            if isinstance(error, BrowserLaunchFailures)
            else [],
        }

    reports, errors = [], []
    native = owner.native
    if native is not None and native.hooks is not None:
        with native.hooks._lock:
            reports = list(native.hooks.reports)
            errors = list(native.hooks.errors)
    report = {
        "scenario": owner.origins.scenario.name,
        "origin_port": owner.origins.port,
        "primary": failure(primary),
        "cleanup": [failure(error) for error in cleanup],
        "native_failures": [failure(error) for error in native.failures]
        if native is not None
        else [],
        "origin_failures": [failure(error) for error in owner.origins.failures],
        "proxy_connections": connect_observations(owner.origins, 0),
        "reports": reports,
        "hook_errors": errors,
        "connections": [asdict(connection) for connection in owner.origins.connections],
        "done": owner.origins.done.is_set(),
        "moz_log": parent_moz_log(owner.log_directory)
        if owner.log_directory is not None
        else "",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    with path.open("w", encoding="utf-8") as output:
        for chunk in json.JSONEncoder().iterencode(report):
            size += len(chunk.encode("utf-8"))
            if size > MAX_FAILURE_REPORT_BYTES:
                raise ValueError("Firefox raw failure report exceeds its byte limit")
            output.write(chunk)


def validate_waits(scenario: Scenario) -> None:
    for name, value in (
        ("scenario limit", scenario.limit_seconds),
        ("attachment limit", ATTACH_LIMIT_SECONDS),
        ("peer cleanup", PEER_CLEANUP_SECONDS),
        ("native cleanup", NATIVE_CLEANUP_SECONDS),
    ):
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"Firefox {name} must be finite and positive")


def validate_metadata(name: str, value: str) -> None:
    if not isinstance(value, str) or any(
        ord(char) < 32 or ord(char) > 126 for char in value
    ):
        raise ValueError(f"Firefox {name} must be single-line printable ASCII")


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


def connect_observations(origins: Origins, start_ms: int) -> list[dict[str, Any]]:
    if origins.proxy is None or origins.proxy.tunnel_run is None:
        return []
    run = origins.proxy.tunnel_run
    offset = run.origin.started * 1000 - start_ms
    observations = []
    for opening in run.openings:
        upstream = opening.upstream
        matches = [
            index
            for index, connection in enumerate(origins.connections)
            if upstream is not None
            and connection.peer == f"{upstream[0]}:{upstream[1]}"
        ]
        if len(matches) > 1:
            raise ValueError("Firefox CONNECT upstream matches multiple origin sockets")
        observations.append(
            {
                "peer": opening.peer,
                "upstream": upstream,
                "origin_connection": matches[0] if matches else None,
                "accepted_ms": offset + opening.connection.accepted * 1000,
                "finished_ms": offset + opening.finished * 1000
                if opening.finished is not None
                else None,
                "opening_hex": opening.head.hex(),
                "reply_hex": opening.reply.hex(),
                "outcome": opening.outcome,
            }
        )
    if origins.scenario.proxy_mode == "https":
        for observation, opening in zip(observations, run.openings, strict=True):
            observation["alpn"] = opening.connection.alpn
            if origins.scenario.proxy_alpn == "h2":
                observation.update(
                    proxy_connection=opening.proxy_connection,
                    stream_id=opening.stream_id,
                    headers=[
                        [name.hex(), value.hex()] for name, value in opening.headers
                    ],
                    status=opening.status,
                )
    return observations


def validate_connect_run(origins: Origins) -> None:
    observations = connect_observations(origins, 0)
    if origins.scenario.proxy_alpn == "h2":
        run = origins.proxy.tunnel_run
        seen = set()
        for opening in run.openings:
            index = opening.proxy_connection
            if (
                index is None
                or not 0 <= index < len(run.proxy_connections)
                or opening.connection is not run.proxy_connections[index].connection
                or opening.connection.alpn != "h2"
                or opening.stream_id is None
                or opening.stream_id <= 0
                or opening.stream_id % 2 != 1
                or (index, opening.stream_id) in seen
            ):
                raise ValueError(
                    "Firefox H2 CONNECT lost its proxy connection or stream"
                )
            seen.add((index, opening.stream_id))
    if origins.scenario.proxy_mode == "socks5":
        host = origins.scenario.hostname.encode("ascii")
        expected = (
            b"\x05\x01\x00\x05\x01\x00\x03"
            + bytes((len(host),))
            + host
            + origins.port.to_bytes(2, "big")
        )
        if any(
            record["upstream"] is not None
            and bytes.fromhex(record["opening_hex"]) != expected
            for record in observations
        ):
            raise ValueError("Firefox SOCKS5 origin must use the remote hostname")
    linked = [
        record["origin_connection"]
        for record in observations
        if record["origin_connection"] is not None
    ]
    if sorted(linked) != list(range(len(origins.connections))):
        raise ValueError("Firefox origin connection bypassed its CONNECT relay")
    if origins.scenario.target == "wss-https-h2-proxy":
        validate_proxy_websockets(origins)
        return
    requests = sorted(
        path for connection in origins.connections for _, path in connection.requests
    )
    if requests != ["/fast?i=0", "/fast?i=4", "/slow?i=1", "/slow?i=2", "/slow?i=3"]:
        raise ValueError(
            "Firefox CONNECT scenario did not complete its labeled requests"
        )


def proxy_websocket_connections(origins: Origins) -> list[ServerConnection]:
    return sorted(
        (
            connection
            for connection in origins.connections
            if any(path.startswith("/ws?") for _, path in connection.requests)
        ),
        key=lambda connection: connection.requests[0][1],
    )


def validate_proxy_websockets(origins: Origins) -> None:
    expected = ["/ws?i=0", "/ws?i=1", "/fast?i=2", "/fast?i=3"]
    paths = [
        path for connection in origins.connections for _, path in connection.requests
    ]
    if origins.request_order != expected or sorted(paths) != sorted(expected):
        raise ValueError("Firefox proxy WSS did not complete its labeled requests")
    websockets = proxy_websocket_connections(origins)
    if len(websockets) != 2 or any(
        connection.websocket is None
        or connection.websocket.close_code != 1000
        or connection.closed_ms is None
        or any(connection is active for active, _ in origins.open)
        or any(
            f"{peer[0]}:{peer[1]}" == connection.peer
            for writer, _ in origins.peers.values()
            if (peer := writer.get_extra_info("peername")) is not None
        )
        for connection in websockets
    ):
        raise ValueError("Firefox proxy WSS did not cleanly close both WebSockets")
    if websockets[0].websocket.ticks_sent < 1:
        raise ValueError("Firefox proxy WSS did not send the first WebSocket tick")
    if not origins.done.is_set():
        raise ValueError("Firefox proxy WSS page did not complete")


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
    if result.origins.proxy is not None:
        port = result.origins.proxy.address[1]
        lines.append(f"{prefix}proxy_port={port}")
        lines.extend(
            f"{prefix}proxy_{key}={value}" for key, value in summarize(events, port)
        )
        observations = connect_observations(result.origins, start)
        kind = "connection"
        if result.origins.scenario.proxy_alpn == "h2":
            run = result.origins.proxy.tunnel_run
            physical = run.proxy_connections
            offset = run.origin.started * 1000 - start
            lines.append(f"{prefix}proxy_connection_count={len(physical)}")
            for i, opening in enumerate(physical):
                record = {
                    "peer": opening.peer,
                    "accepted_ms": offset + opening.connection.accepted * 1000,
                    "finished_ms": offset + opening.finished * 1000
                    if opening.finished is not None
                    else None,
                    "alpn": opening.connection.alpn,
                    "outcome": opening.outcome,
                }
                lines.append(
                    f"{prefix}proxy_connection_{i}="
                    + json.dumps(record, sort_keys=True, separators=(",", ":"))
                )
            kind = "tunnel"
        lines.append(f"{prefix}proxy_{kind}_count={len(observations)}")
        lines.extend(
            f"{prefix}proxy_{kind}_{i}="
            + json.dumps(record, sort_keys=True, separators=(",", ":"))
            for i, record in enumerate(observations)
        )
    connections = result.origins.connections
    if result.origins.scenario.target == "wss-https-h2-proxy":
        lines.append(
            f"{prefix}origin_request_order=" + " ".join(result.origins.request_order)
        )
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
        alpn = (
            f",alpn:{connection.alpn or '-'}"
            if (
                result.origins.scenario.target == "wss"
                or result.origins.scenario.proxy_mode is not None
            )
            else ""
        )
        lines.append(
            f"{prefix}server_connection_{i}=family:{family},"
            f"accepted:{connection.accepted_ms - start},closed:{closed},"
            f"close:{connection.close_kind},idle_before_close_ms:{idle},"
            f"requests:{requests or '-'}{alpn}"
        )
        if connection.websocket is not None:
            lines.extend(
                (
                    f"{prefix}server_connection_{i}_websocket_ticks_sent="
                    f"{connection.websocket.ticks_sent}",
                    f"{prefix}server_connection_{i}_websocket_close_code="
                    f"{connection.websocket.close_code if connection.websocket.close_code is not None else 'none'}",
                )
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
    headful: bool = False,
) -> str:
    """The fixture text: provenance header first, then each run."""
    for name, value in (
        ("version", client_version),
        ("build ID", build_id),
        ("operating system", operating_system),
        ("hook version", frida_version),
        ("launch arguments", launch_arguments),
        ("scenario", scenario.name),
        ("question", scenario.question),
        ("intervention", scenario.intervention),
    ):
        validate_metadata(name, value)
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
        f"launch_mode={'headful' if headful else 'headless'}",
        f"launch_arguments={launch_arguments}",
        f"target={scenario.hostname}",
        f"scenario={scenario.name}",
        f"question={scenario.question}",
        f"hook_intervention={scenario.intervention}",
        f"run_count={len(runs)}",
    ]
    if scenario.proxy_mode is not None:
        header.extend(
            (
                f"proxy_hostname={TARGET_HOST}",
                {
                    "http": "proxy_mode=http-connect",
                    "https": "proxy_mode=https-connect",
                    "socks5": "proxy_mode=socks5",
                }[scenario.proxy_mode],
                "proxy_configuration=PAC exact origin; other names direct; direct failover disabled",
                "origin_alpn_offer=http/1.1",
                "origin_trust=disposable-profile cert_override.txt",
            )
        )
        if scenario.proxy_mode == "socks5":
            header.append("proxy_dns=remote")
        elif scenario.proxy_mode == "https":
            header.extend(
                (
                    "proxy_transport=tls",
                    f"proxy_alpn_offer={'h2' if scenario.proxy_alpn == 'h2' else 'http/1.1'}",
                    "proxy_trust=separate disposable-profile cert_override.txt leaf",
                )
            )
    return "\n".join([*header, *(line for run in runs for line in run)]) + "\n"


async def capture(args: argparse.Namespace, scenario: Scenario) -> tuple[str, bool]:
    validate_metadata("version", args.client_version)
    validate_metadata("operating system", args.operating_system)
    validate_waits(scenario)
    if type(args.repeat) is not int or args.repeat < 1:
        raise ValueError("Firefox repeat count must be a positive integer")
    runs = []
    recorded = ""
    frida_version = ""
    failed = False
    for index in range(args.repeat):
        failure_path = (
            args.raw_dir / f"firefox-{scenario.name}-{index}-failed.json"
            if args.raw_dir is not None
            else None
        )
        result, arguments = await run_once(
            scenario,
            args.browser_path,
            headful=args.headful,
            failure_path=failure_path,
        )
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
        headful=args.headful,
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
    parser.add_argument(
        "--headful", action="store_true", help="show the browser window"
    )
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
    try:
        validate_metadata("version", args.client_version)
        validate_metadata("operating system", args.operating_system)
    except ValueError as error:
        parser.error(str(error))
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
