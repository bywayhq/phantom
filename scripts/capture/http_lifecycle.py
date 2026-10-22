"""Record how a browser revalidates, uploads, idles on, and ends its connections.

One run serves a scripted page over TLS on loopback and keeps, for every
connection the browser opens, how it ended (a TLS `close_notify`, a TCP end
without one, or a reset), its HTTP/2 client frames other than DATA, and each
request's field names in wire order with the values of the fields a scenario
asks about.

| Scenario | ALPN | What the page does |
| --- | --- | --- |
| `revalidate` | h2 | Fetches four cacheable resources twice each |
| `upload-h1`, `upload-h2` | http/1.1, h2 | POSTs a small body, 1 MiB bodies, a multipart `FormData`, and a form |
| `idle-ping` | h2 | Fetches, waits `--idle` seconds on the open connection, fetches again |
| `ping-unanswered` | h2 | Fetches, waits 11.5 s, fetches again; the server goes silent on that connection |
| `close` | h2 and http/1.1 | Fetches over both, aborts an HTTP/1.1 response, then the tool closes the browser over its remote protocol |
| `resources` | h2 (default), http/1.1 (explicit) | Loads one local script, stylesheet, image and font |
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import math
import platform
import secrets
import ssl
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .browser_launch import CHROMIUM_BROWSERS, BrowserDriver, LaunchPlan
from .browser_remote import (
    RemoteConnection,
    RemoteSocket,
    chromium_endpoint,
    firefox_endpoint,
    request_browser_close,
    wait_for_endpoint,
)
from .fixture_file import write_text_fixture
from .http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    Certificate,
    generate_certificate,
    peer_disconnected,
    server_context,
)
from .http2_session import (
    ConnectionRecord as RawConnectionRecord,
)
from .http_lifecycle_resources import ASSETS, ResourceCapture, resource_page

FORMAT = "phantom-http-lifecycle-v1"
SUPPORTED = {"h2": "4.4.1", "hpack": "4.2.0"}
SCENARIOS = (
    "revalidate",
    "upload-h1",
    "upload-h2",
    "idle-ping",
    "ping-unanswered",
    "close",
    "resources",
)
FRAME_TYPES = {
    0x1: "HEADERS",
    0x2: "PRIORITY",
    0x3: "RST_STREAM",
    0x4: "SETTINGS",
    0x6: "PING",
    0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE",
    0x9: "CONTINUATION",
}
# Field values worth keeping; every other field keeps only its name.
RECORDED_FIELDS = (
    "if-none-match",
    "if-modified-since",
    "cache-control",
    "pragma",
    "expect",
    "content-type",
    "content-length",
    "transfer-encoding",
)
READ_SIZE = 64 * 1024
MAX_FRAMES = 2000
MAX_REQUEST_HEAD = 64 * 1024
MAX_BODY = 8 * 1024 * 1024
MAX_CONNECTIONS = 32
MAX_REQUESTS = 256
MAX_STREAMS = 64
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_INPUT_FRAMES = 65_536
MAX_FRAME_PAYLOAD = 16_384
CLEANUP_SECONDS = 5.0
MAX_TIMER_MS = 2_147_483_647
HTTP_TOKEN_PUNCTUATION = frozenset("!#$%&'*+-.^_`|~")
LARGE_BODY = 1024 * 1024
UNANSWERED_WAIT_MS = 11_500
ETAG = '"phantom-v1"'
LAST_MODIFIED = "Tue, 01 Sep 2026 00:00:00 GMT"
HEURISTIC_LAST_MODIFIED = "Mon, 01 Sep 2025 00:00:00 GMT"
# Seconds the browser has to end its connections after the remote close.
CLOSE_GRACE = 10.0


# -- Pages -----------------------------------------------------------------


def scenario_script(scenario: str, token: str, h1_origin: str, idle_ms: int) -> str:
    query = f"?run={token}"
    if scenario == "revalidate":
        return (
            "for (const path of ['/etag', '/last-modified', '/both', '/heuristic']) {"
            "for (const round of [1, 2]) {"
            f"const r = await fetch(path + '{query}');"
            "results.push(`${path}:${round}:${r.status}:${await r.text()}`);"
            "}}"
        )
    if scenario in ("upload-h1", "upload-h2"):
        return (
            f"const big = 'x'.repeat({LARGE_BODY});"
            "const post = async (path, body) => {"
            f"const r = await fetch(path + '{query}', {{method: 'POST', body}});"
            "results.push(`${path}:${r.status}`);};"
            "await post('/post-small', 'x'.repeat(100));"
            "await post('/post-large', big);"
            "await post('/post-blob', new Blob([big]));"
            "const data = new FormData(); data.append('field', 'value');"
            "data.append('file', new Blob([big]), 'upload.bin');"
            "await post('/post-multipart', data);"
            "const frame = document.createElement('iframe'); frame.name = 'sink';"
            "document.body.append(frame);"
            "const form = document.createElement('form'); form.method = 'post';"
            "form.enctype = 'multipart/form-data'; form.target = 'sink';"
            f"form.action = '/form-upload{query}';"
            "const input = document.createElement('input'); input.type = 'file';"
            "input.name = 'file'; const files = new DataTransfer();"
            "files.items.add(new File([big], 'upload.bin')); input.files = files.files;"
            "form.append(input); document.body.append(form);"
            "const loaded = new Promise(done => frame.addEventListener('load', () => {"
            "if (frame.contentWindow.location.pathname === '/form-upload') done();"
            "}));"
            "form.submit(); await loaded; results.push('/form-upload:loaded');"
        )
    if scenario == "idle-ping":
        return (
            f"await fetch('/a{query}', {{cache: 'no-store'}});"
            f"await wait({idle_ms});"
            f"await fetch('/b{query}', {{cache: 'no-store'}});"
            "results.push('b:fetched');"
        )
    if scenario == "ping-unanswered":
        return (
            f"await fetch('/a{query}', {{cache: 'no-store'}});"
            f"await wait({UNANSWERED_WAIT_MS});"
            "const started = performance.now();"
            "try {"
            f"const r = await fetch('/b{query}', {{cache: 'no-store'}});"
            "results.push(`b:${r.status}:${await r.text()}`);"
            "} catch (error) { results.push(`b:${error.name}`); }"
            "results.push(`b_ms:${Math.round(performance.now() - started)}`);"
        )
    if scenario == "close":
        return (
            f"await fetch('/a{query}', {{cache: 'no-store'}});"
            "const abort = new AbortController();"
            f"const stall = fetch('{h1_origin}/stall{query}', "
            "{cache: 'no-store', signal: abort.signal}).then(r => r.text());"
            "setTimeout(() => abort.abort(), 1000);"
            "try { await stall; results.push('stall:read'); }"
            "catch (error) { results.push(`stall:${error.name}`); }"
            f"const r = await fetch('{h1_origin}/b{query}', {{cache: 'no-store'}});"
            "results.push(`b:${r.status}`);"
        )
    raise ValueError(f"unknown scenario {scenario}")


def page(scenario: str, token: str, h1_origin: str, idle_ms: int) -> bytes:
    if scenario == "resources":
        return resource_page(token)
    script = scenario_script(scenario, token, h1_origin, idle_ms)
    return (
        "<!doctype html><meta charset=utf-8>"
        '<link rel=icon href="data:,"><body><script>'
        "const wait = ms => new Promise(done => setTimeout(done, ms));"
        "const results = [];"
        "(async () => {"
        f"try {{ {script} }} catch (error) {{ results.push(`error:${{error.name}}`); }}"
        f"await fetch('/done?run={token}&result=' + "
        "encodeURIComponent(JSON.stringify(results)), {cache: 'no-store'});"
        "})();</script>\n"
    ).encode()


# -- Responses -------------------------------------------------------------


@dataclass(frozen=True)
class Reply:
    status: int
    fields: tuple[tuple[str, str], ...]
    body: bytes
    # Send the head and these bytes of the body, then nothing more.
    stall: bool = False


def reply_for(
    scenario: str, method: str, path: str, fields: dict[str, str], run
) -> Reply:
    """The response to one request; `fields` maps lowercase names to values."""
    plain = (("content-type", "text/plain"), ("access-control-allow-origin", "*"))
    if run.resources is not None:
        if path == "/start":
            content_type, body = "text/html; charset=utf-8", resource_page(run.token)
        elif path in ASSETS:
            content_type, body = run.resources.asset(path)
        elif path == "/done":
            content_type, body = "text/plain", b"ok"
        else:
            raise ValueError("resource response does not name an owned path")
        return Reply(
            200, (("content-type", content_type), ("cache-control", "no-store")), body
        )
    if path == "/start":
        body = page(scenario, run.token, run.h1_origin, run.idle_ms)
        return Reply(
            200,
            (
                ("content-type", "text/html; charset=utf-8"),
                ("cache-control", "no-store"),
            ),
            body,
        )
    validators: dict[str, tuple[tuple[str, str], ...]] = {
        "/etag": (("etag", ETAG), ("cache-control", "no-cache")),
        "/last-modified": (
            ("last-modified", LAST_MODIFIED),
            ("cache-control", "no-cache"),
        ),
        "/both": (
            ("etag", ETAG),
            ("last-modified", LAST_MODIFIED),
            ("cache-control", "no-cache"),
        ),
        "/heuristic": (("last-modified", HEURISTIC_LAST_MODIFIED),),
    }
    if path in validators:
        matched = fields.get("if-none-match") == ETAG or (
            "if-none-match" not in fields and "if-modified-since" in fields
        )
        if matched:
            return Reply(304, validators[path], b"")
        return Reply(200, (*plain, *validators[path]), b"v1")
    if path == "/stall":
        return Reply(
            200, (*plain, ("content-length", str(LARGE_BODY))), b"x" * 16, True
        )
    return Reply(200, (*plain, ("cache-control", "no-store")), b"ok")


# -- Records ---------------------------------------------------------------


@dataclass
class RequestRecord:
    connection: int
    stream: int | None
    milliseconds: float
    method: str
    path: str
    names: list[str]
    values: dict[str, str]
    body_bytes: int = 0
    status: int | None = None

    def line(self) -> str:
        items = [
            f"connection:{self.connection}",
            f"stream:{self.stream if self.stream is not None else 'none'}",
            f"ms:{self.milliseconds:.3f}",
            f"method:{self.method}",
            f"path:{self.path}",
            f"body_bytes:{self.body_bytes}",
            f"status:{self.status if self.status is not None else 'none'}",
            "fields:" + "|".join(self.names),
        ]
        items.extend(
            f"{name}:{json.dumps(self.values[name])}"
            for name in RECORDED_FIELDS
            if name in self.values
        )
        return ",".join(items)


@dataclass
class ConnectionRecord:
    index: int
    listener: str
    accepted: float
    alpn: str | None = None
    close_notify: float | None = None
    eof: float | None = None
    reset: float | None = None
    tls_error: str | None = None
    silenced: float | None = None
    frames: list[str] = field(default_factory=list)
    data_frames: int = 0
    # Expected native disconnects retain their original diagnostic outside the fixture.
    disconnects: list[BaseException] = field(default_factory=list, repr=False)
    resource_tap: RawConnectionRecord | None = field(default=None, repr=False)

    @property
    def ended(self) -> bool:
        return (
            self.eof is not None or self.reset is not None or self.tls_error is not None
        )

    def end(self) -> str:
        parts = []
        if self.close_notify is not None:
            parts.append("close_notify")
        if self.eof is not None:
            parts.append("eof")
        if self.reset is not None:
            parts.append("reset")
        if self.tls_error is not None:
            parts.append("tls_error")
        return "+".join(parts) or "open"

    def line(self) -> str:
        def ms(value: float | None) -> str:
            return "none" if value is None else f"{value * 1000:.3f}"

        items = [
            f"listener:{self.listener}",
            f"alpn:{self.alpn or 'none'}",
            f"accepted_ms:{ms(self.accepted)}",
            f"end:{self.end()}",
            f"close_notify_ms:{ms(self.close_notify)}",
            f"eof_ms:{ms(self.eof)}",
            f"reset_ms:{ms(self.reset)}",
            f"server_silent_from_ms:{ms(self.silenced)}",
            f"data_frames:{self.data_frames}",
        ]
        if self.tls_error is not None:
            items.append(f"tls_error:{self.tls_error}")
        return ",".join(items)


class FrameLog:
    """Splits a client's HTTP/2 bytes into frames; DATA frames are only counted."""

    def __init__(self, record: ConnectionRecord) -> None:
        self.record = record
        self.buffer = bytearray()
        self.preface_seen = False
        self.paths: dict[int, int] = {}
        self.count = 0

    def feed(self, data: bytes, milliseconds: float) -> None:
        self.buffer.extend(data)
        if not self.preface_seen:
            if len(self.buffer) < len(CONNECTION_PREFACE):
                return
            if bytes(self.buffer[: len(CONNECTION_PREFACE)]) != CONNECTION_PREFACE:
                raise ValueError("client sent an invalid HTTP/2 connection preface")
            del self.buffer[: len(CONNECTION_PREFACE)]
            self.preface_seen = True
        while len(self.buffer) >= 9:
            length = int.from_bytes(self.buffer[0:3], "big")
            if length > MAX_FRAME_PAYLOAD:
                raise ValueError("HTTP/2 frame exceeds the advertised capture limit")
            if len(self.buffer) < 9 + length:
                return
            kind, flags = self.buffer[3], self.buffer[4]
            stream = int.from_bytes(self.buffer[5:9], "big") & 0x7FFF_FFFF
            payload = bytes(self.buffer[9 : 9 + length])
            del self.buffer[: 9 + length]
            self.count += 1
            if self.count > MAX_INPUT_FRAMES:
                raise ValueError("connection exceeds the input frame limit")
            if kind == 0x0:
                self.record.data_frames += 1
                continue
            if len(self.record.frames) >= MAX_FRAMES:
                raise ValueError("connection exceeds the frame limit")
            self.record.frames.append(
                frame_line(milliseconds, kind, flags, stream, payload)
            )
            if kind == 0x1:
                self.paths[stream] = len(self.record.frames) - 1

    def name_request(self, stream: int, path: str) -> None:
        index = self.paths.pop(stream, None)
        if index is not None:
            self.record.frames[index] += f",path:{path}"


def frame_line(
    milliseconds: float, kind: int, flags: int, stream: int, payload: bytes
) -> str:
    items = [
        f"ms:{milliseconds:.3f}",
        f"type:{FRAME_TYPES.get(kind, f'0x{kind:02x}')}",
        f"flags:0x{flags:02x}",
        f"stream:{stream}",
        f"length:{len(payload)}",
    ]
    if kind == 0x6:
        items.append(f"payload:{payload.hex()}")
    elif kind == 0x3 and len(payload) == 4:
        items.append(f"error:{int.from_bytes(payload, 'big')}")
    elif kind == 0x7 and len(payload) >= 8:
        last = int.from_bytes(payload[0:4], "big") & 0x7FFF_FFFF
        items.append(f"last_stream:{last}")
        items.append(f"error:{int.from_bytes(payload[4:8], 'big')}")
        items.append(f"debug:{json.dumps(payload[8:].decode('latin-1'))}")
    return ",".join(items)


def request_path(target: str) -> str:
    """The path of `target` without its query, which holds the run token."""
    return target.split("?", 1)[0]


def recorded_values(fields: Sequence[tuple[str, str]]) -> dict[str, str]:
    values = {}
    for name, value in fields:
        lower = name.lower()
        if lower not in RECORDED_FIELDS or lower in values:
            continue
        if lower == "content-type" and "boundary=" in value:
            value = value.split("boundary=", 1)[0] + "boundary=<boundary>"
        values[lower] = value
    return values


def _http_token(value: str) -> bool:
    return bool(value) and all(
        (character.isascii() and character.isalnum())
        or character in HTTP_TOKEN_PUNCTUATION
        for character in value
    )


def _validate_request_record(
    method: str,
    target: str,
    fields: Sequence[tuple[str, str]],
    *,
    http2: bool = False,
) -> None:
    if not _http_token(method):
        raise ValueError("request method is not an ASCII HTTP token")
    if not target or any(not 0x21 <= ord(character) <= 0x7E for character in target):
        raise ValueError("request target must contain visible ASCII only")
    if "," in request_path(target):
        raise ValueError("request path contains the fixture field separator")
    for name, _ in fields:
        token = name[1:] if http2 and name.startswith(":") else name
        if not _http_token(token):
            raise ValueError("request header name is not an ASCII HTTP token")
        if "|" in name:
            raise ValueError("request header name contains the fixture name separator")


# -- Transport -------------------------------------------------------------


class Channel:
    """TLS over memory BIOs that tells a `close_notify` from a bare TCP end."""

    def __init__(
        self,
        context: ssl.SSLContext,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        record: ConnectionRecord,
        clock: Callable[[], float],
        run: Run | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.record = record
        self.clock = clock
        self.run = run
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)

    async def raw(self) -> bytes | None:
        try:
            data = await self.reader.read(READ_SIZE)
        except OSError as error:
            if peer_disconnected(error):
                if not any(previous is error for previous in self.record.disconnects):
                    self.record.disconnects.append(error)
                if self.run is None or not self.run.stopping:
                    self.record.reset = self.clock()
                return None
            raise
        if not data:
            if self.run is None or not self.run.stopping:
                self.record.eof = self.clock()
            return None
        if self.run is not None:
            self.run.retain(len(data))
        return data

    async def handshake(self) -> bool:
        while True:
            try:
                self.tls.do_handshake()
                await self.flush()
                self.record.alpn = self.tls.selected_alpn_protocol()
                return True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as error:
                self.record.tls_error = error.reason or type(error).__name__
                raise
            await self.flush()
            data = await self.raw()
            if data is None:
                return False
            self.incoming.write(data)

    async def flush(self) -> None:
        pending = self.outgoing.read()
        if pending and not self.writer.transport.is_closing():
            if self.run is not None:
                self.run.retain(len(pending))
            self.writer.write(pending)
            await self.writer.drain()

    async def read(self) -> bytes | None:
        """Decrypted bytes, or None once the client has ended the connection."""
        while True:
            try:
                data = self.tls.read(READ_SIZE)
                await self.flush()
                if data:
                    if self.run is not None and self.run.resources is not None:
                        self.run.resources.retain(
                            self.record.resource_tap, "client", self.run.now(), data
                        )
                    return data
                # `_ssl` returns no bytes, rather than raising, once it has
                # read the peer's close_notify.
                return await self.after_close_notify()
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLZeroReturnError:
                return await self.after_close_notify()
            except ssl.SSLError as error:
                self.record.tls_error = error.reason or type(error).__name__
                raise
            await self.flush()
            raw = await self.raw()
            if raw is None:
                return None
            self.incoming.write(raw)

    async def after_close_notify(self) -> None:
        """Record the close_notify, then wait for the TCP end that follows."""
        if self.run is None or not self.run.stopping:
            self.record.close_notify = self.clock()
        await self.flush()
        while await self.raw() is not None:
            pass
        return None

    async def write(self, data: bytes) -> None:
        if data and self.record.silenced is None:
            written = self.tls.write(data)
            if self.run is not None and self.run.resources is not None:
                if written != len(data):
                    raise ValueError(
                        "resource TLS write did not accept every peer byte"
                    )
                self.run.resources.retain(
                    self.record.resource_tap, "server", self.run.now(), data
                )
            await self.flush()


# -- Server ----------------------------------------------------------------


@dataclass
class Run:
    scenario: str
    token: str
    idle_ms: int
    h1_origin: str = ""
    started: float = field(default_factory=time.perf_counter)
    connections: list[ConnectionRecord] = field(default_factory=list)
    requests: list[RequestRecord] = field(default_factory=list)
    page_result: str | None = None
    page_connection: int | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    # Set each time a connection's handler returns.
    connection_ended: asyncio.Event = field(default_factory=asyncio.Event)
    failure_ready: asyncio.Event = field(default_factory=asyncio.Event)
    failure: BaseException | None = None
    completion: asyncio.TimerHandle | None = None
    stopping: bool = False
    retained_bytes: int = 0
    grace_timeout: asyncio.TimeoutError | None = None
    remote_disconnect: BaseException | None = None
    resources: ResourceCapture | None = None

    def now(self) -> float:
        return time.perf_counter() - self.started

    def retain(self, amount: int) -> None:
        if self.retained_bytes + amount > MAX_CAPTURE_BYTES:
            raise ValueError("run exceeds the aggregate capture byte limit")
        self.retained_bytes += amount

    def belongs(self, target: str) -> bool:
        # urlsplit normalizes controls before parsing; qualify the actual wire target.
        if (
            not target.startswith("/")
            or target.startswith("//")
            or any(
                ord(character) <= 0x20 or ord(character) == 0x7F for character in target
            )
            or "#" in target
        ):
            return False
        try:
            parts = urlsplit(target)
        except ValueError:
            return False
        return (
            not parts.scheme
            and not parts.netloc
            and parse_qs(parts.query, keep_blank_values=True).get("run") == [self.token]
        )

    def select(self, connection: int, target: str) -> None:
        if self.belongs(target) and self.page_connection in (None, connection):
            self.page_connection = connection

    def finish(self, target: str, connection: int) -> None:
        resource_connection = (
            self.resources is not None
            and self.resources.protocol == "h1"
            and any(
                request.connection == connection and request.path == "/done"
                for request in self.resources.requests
            )
        )
        if (
            self.stopping
            or not self.belongs(target)
            or (connection != self.page_connection and not resource_connection)
            or self.completion is not None
        ):
            return
        query = parse_qs(urlsplit(target).query, keep_blank_values=True)
        self.page_result = query.get("result", ["none"])[0]
        self.completion = asyncio.get_running_loop().call_later(0.5, self.done.set)

    def add_request(self, request: RequestRecord) -> None:
        if len(self.requests) >= MAX_REQUESTS:
            raise ValueError("run exceeds the request limit")
        self.requests.append(request)

    def silences(self, connection: int, path: str) -> bool:
        """Whether the server stops writing on `connection` at this request."""
        return (
            self.scenario == "ping-unanswered"
            and path == "/b"
            and connection == self.page_connection
        )


async def all_ended(run: Run) -> None:
    """Return once the browser has ended every connection it opened."""
    while not all(record.ended for record in run.connections):
        run.connection_ended.clear()
        await run.connection_ended.wait()


async def serve_h2(run: Run, channel: Channel, record: ConnectionRecord) -> None:
    import h2.events
    from h2.config import H2Configuration
    from h2.connection import H2Connection

    connection = H2Connection(
        H2Configuration(
            client_side=False,
            header_encoding=None,
            normalize_inbound_headers=run.resources is None,
        )
    )
    if run.resources is not None:
        record.resource_tap = run.resources.tap(
            record.index, record.listener, record.accepted
        )
    connection.initiate_connection()
    await channel.write(connection.data_to_send())
    log = FrameLog(record)
    streams: dict[int, RequestRecord] = {}
    targets: dict[int, str] = {}
    while True:
        data = await channel.read()
        if data is None:
            return
        log.feed(data, run.now() * 1000)
        for event in connection.receive_data(data):
            if isinstance(event, h2.events.RequestReceived):
                if run.resources is not None:
                    run.resources.observe(
                        record.index,
                        event.stream_id,
                        event.headers,
                        event.priority_updated,
                    )
                fields = [
                    (n.decode("latin-1"), v.decode("latin-1")) for n, v in event.headers
                ]
                head = dict(fields)
                _validate_request_record(
                    head.get(":method", ""), head.get(":path", ""), fields, http2=True
                )
                path = request_path(head.get(":path", ""))
                log.name_request(event.stream_id, path)
                request = RequestRecord(
                    record.index,
                    event.stream_id,
                    run.now() * 1000,
                    head.get(":method", ""),
                    path,
                    [name for name, _ in fields],
                    recorded_values(fields),
                )
                if len(streams) >= MAX_STREAMS:
                    raise ValueError("connection exceeds the active stream limit")
                run.add_request(request)
                streams[event.stream_id] = request
                targets[event.stream_id] = head.get(":path", "")
                if path == "/start":
                    run.select(record.index, targets[event.stream_id])
                if run.silences(record.index, path):
                    record.silenced = run.now()
            elif isinstance(event, h2.events.DataReceived):
                if run.resources is not None and event.data:
                    raise ValueError("resource GET contains an unexpected body")
                request = streams.get(event.stream_id)
                if request is not None:
                    request.body_bytes += len(event.data)
                    if request.body_bytes > MAX_BODY:
                        raise ValueError("request body exceeds the capture limit")
                connection.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            elif isinstance(event, h2.events.StreamEnded):
                request = streams.pop(event.stream_id, None)
                target = targets.pop(event.stream_id, "")
                if request is None or record.silenced is not None:
                    continue
                reply = reply_for(
                    run.scenario, request.method, request.path, request.values, run
                )
                request.status = reply.status
                headers = [(":status", str(reply.status)), *reply.fields]
                if reply.status != 304 and not reply.stall:
                    headers.append(("content-length", str(len(reply.body))))
                connection.send_headers(
                    event.stream_id,
                    [(n.encode(), v.encode()) for n, v in headers],
                    end_stream=not reply.body,
                )
                if reply.body:
                    if run.resources is not None and len(
                        reply.body
                    ) > connection.local_flow_control_window(event.stream_id):
                        raise ValueError(
                            "resource response exceeds the client receive window"
                        )
                    chunks = (
                        [reply.body]
                        if run.resources is None
                        else [
                            reply.body[i : i + connection.max_outbound_frame_size]
                            for i in range(
                                0, len(reply.body), connection.max_outbound_frame_size
                            )
                        ]
                    )
                    for i, chunk in enumerate(chunks):
                        connection.send_data(
                            event.stream_id,
                            chunk,
                            end_stream=not reply.stall and i == len(chunks) - 1,
                        )
                if run.resources is not None:
                    run.resources.responded.add(request.path)
                if request.path == "/done":
                    run.finish(target, record.index)
            elif isinstance(event, h2.events.StreamReset):
                streams.pop(event.stream_id, None)
                targets.pop(event.stream_id, None)
        await channel.write(connection.data_to_send())


async def serve_h1(run: Run, channel: Channel, record: ConnectionRecord) -> None:
    if run.resources is not None:
        record.resource_tap = run.resources.tap(
            record.index, record.listener, record.accepted
        )
    buffer = bytearray()
    while True:
        while b"\r\n\r\n" not in buffer:
            if len(buffer) > MAX_REQUEST_HEAD:
                raise ValueError("request head exceeds the capture limit")
            data = await channel.read()
            if data is None:
                if run.resources is not None and buffer:
                    raise EOFError("resource HTTP/1 request head is truncated")
                return
            buffer.extend(data)
        end = buffer.index(b"\r\n\r\n")
        if end + 4 > MAX_REQUEST_HEAD:
            raise ValueError("request head exceeds the capture limit")
        if run.resources is not None:
            run.resources.observe_h1(record.index, bytes(buffer[: end + 4]))
        lines = bytes(buffer[:end]).decode("latin-1").split("\r\n")
        del buffer[: end + 4]
        parts = lines[0].split(" ")
        if len(parts) != 3 or parts[2] not in {"HTTP/1.0", "HTTP/1.1"}:
            raise ValueError("invalid HTTP/1 request line")
        method, target, _ = parts
        fields = []
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if not separator:
                raise ValueError("invalid HTTP/1 header field")
            fields.append((name, value.strip()))
        _validate_request_record(method, target, fields)
        head = {name.lower(): value for name, value in fields}
        path = request_path(target)
        request = RequestRecord(
            record.index,
            None,
            run.now() * 1000,
            method,
            path,
            [name for name, _ in fields],
            recorded_values(fields),
        )
        if "chunked" in head.get("transfer-encoding", "").lower():
            raise ValueError("chunked request bodies are not supported")
        remaining = int(head.get("content-length", "0"))
        if not 0 <= remaining <= MAX_BODY:
            raise ValueError("request body length is outside the capture limit")
        run.add_request(request)
        if path == "/start":
            run.select(record.index, target)
        if head.get("expect", "").lower() == "100-continue":
            await channel.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        while remaining > 0:
            if not buffer:
                data = await channel.read()
                if data is None:
                    raise EOFError("client ended before completing the request body")
                buffer.extend(data)
            taken = min(remaining, len(buffer))
            del buffer[:taken]
            remaining -= taken
            request.body_bytes += taken
        reply = reply_for(run.scenario, method, path, head, run)
        request.status = reply.status
        reason = {200: "OK", 304: "Not Modified"}.get(reply.status, "Status")
        out = [
            f"HTTP/1.1 {reply.status} {reason}",
            *(f"{n}: {v}" for n, v in reply.fields),
        ]
        if not reply.stall:
            out.append(f"content-length: {len(reply.body)}")
        await channel.write(("\r\n".join(out) + "\r\n\r\n").encode() + reply.body)
        if run.resources is not None:
            run.resources.responded.add(path)
        if path == "/done":
            run.finish(target, record.index)


class LifecycleFailures(Exception):
    """Original operation errors and owners whose retirement needs retry."""

    def __init__(
        self,
        primary: BaseException | None,
        cleanup: Sequence[BaseException],
        owner: LifecycleServer | RemoteConnection | RemoteSocket,
    ) -> None:
        self.primary = primary
        self.cleanup = tuple(cleanup)
        self.owner = owner
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        self.interruption_cause = None
        self.interruption_context = None
        super().__init__("lifecycle capture cleanup failed")


def _raise_lifecycle_failures(
    primary: BaseException | None,
    cleanup: Sequence[BaseException],
    owner: LifecycleServer | RemoteConnection | RemoteSocket,
) -> None:
    cleanup = tuple(error for error in cleanup if error is not primary)
    if cleanup:
        combined = LifecycleFailures(primary, cleanup, owner)
        interruption = next(
            (
                error
                for error in (primary, *cleanup)
                if isinstance(
                    error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
                )
            ),
            None,
        )
        if interruption is not None:
            combined.interruption_cause = interruption.__cause__
            combined.interruption_context = interruption.__context__
            raise interruption from combined
        if primary is not None:
            raise primary from combined
        raise combined from cleanup[0]
    if primary is not None:
        raise primary


@dataclass
class LifecycleListener:
    server: asyncio.Server
    waiter: asyncio.Task[None] | None = None
    observed: bool = False


class LifecycleProtocol(asyncio.StreamReaderProtocol):
    """Retain the accepted stream before connection_made is queued."""

    def __init__(
        self, owner: LifecycleServer, context: ssl.SSLContext, listener: str
    ) -> None:
        self.owner = owner
        self.context = context
        self.listener = listener
        self.transport: asyncio.Transport | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.handler: asyncio.Task[None] | None = None
        self.waiter: asyncio.Task[None] | None = None
        self.record: ConnectionRecord | None = None
        self.closed = asyncio.get_running_loop().create_future()
        self.retired = False
        self.observed: set[asyncio.Task] = set()
        super().__init__(asyncio.StreamReader(limit=READ_SIZE), self.connected)
        self.stream_closed = self._get_close_waiter(None)
        self.closed_observed = False

    def connection_made(self, transport) -> None:
        self.transport = transport
        if self.owner.run.stopping:
            self.owner.stop_listeners()
        try:
            super().connection_made(transport)
        except BaseException as error:
            self.owner.failed(error)
            try:
                transport.abort()
            except BaseException as cleanup:
                self.owner.failed(cleanup)

    def connected(self, reader, writer) -> None:
        self.writer = writer
        self.owner.accept(reader, self)

    def connection_lost(self, error) -> None:
        if error is not None:
            self.owner.disconnected(self, error)
        try:
            super().connection_lost(error)
        except BaseException as cleanup:
            self.owner.failed(cleanup)
        finally:
            self.retired = True
            if not self.closed.done():
                self.closed.set_result(None)


class LifecycleServer:
    """The two listeners and every accepted stream through native retirement."""

    def __init__(self, run: Run) -> None:
        self.run = run
        self.listeners: list[LifecycleListener] = []
        self.protocols: set[LifecycleProtocol] = set()
        self.failures: list[BaseException] = []
        self.primary: BaseException | None = None
        self.lock = asyncio.Lock()
        self.event_tasks: set[asyncio.Task] = set()

    def remember(self, error: BaseException) -> None:
        if not any(previous is error for previous in self.failures):
            self.failures.append(error)
        if self.run.failure is None:
            self.run.failure = error
        self.run.failure_ready.set()

    def failed(self, error: BaseException) -> None:
        self.remember(error)
        self.run.stopping = True
        self.stop_listeners()

    def stop_listeners(self) -> None:
        for listener in self.listeners:
            try:
                listener.server.close()
            except BaseException as error:
                self.remember(error)

    def submit(self, operation) -> asyncio.Task:
        try:
            return asyncio.create_task(operation)
        except BaseException as primary:
            self.failed(primary)
            try:
                operation.close()
            except BaseException as cleanup:
                self.failed(cleanup)
            raise

    async def start(self, host: str, context: ssl.SSLContext, name: str) -> int:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the capture listener must be a loopback address")
        server = await asyncio.get_running_loop().create_server(
            lambda: self.new_protocol(context, name),
            host,
            0,
            start_serving=False,
        )
        listener = LifecycleListener(server)
        self.listeners.append(listener)
        ready = asyncio.Event()
        listener.waiter = self.submit(self.wait_listener(listener, ready))
        listener.waiter.add_done_callback(lambda _task: ready.set())
        await asyncio.wait_for(ready.wait(), CLEANUP_SECONDS)
        if listener.waiter.done():
            listener.observed = True
            listener.waiter.result()
        port = server.sockets[0].getsockname()[1]
        await server.start_serving()
        return port

    async def wait_listener(
        self, listener: LifecycleListener, ready: asyncio.Event
    ) -> None:
        # Register while the listener is open, before any accepted transport attaches.
        asyncio.get_running_loop().call_soon(ready.set)
        await listener.server.wait_closed()

    def new_protocol(self, context: ssl.SSLContext, name: str) -> LifecycleProtocol:
        try:
            protocol = LifecycleProtocol(self, context, name)
        except BaseException as error:
            self.failed(error)
            raise
        self.protocols.add(protocol)
        if len(self.run.connections) >= MAX_CONNECTIONS:
            # The backend still has to attach this protocol before closing listeners.
            self.remember(ValueError("run exceeds the connection limit"))
            self.run.stopping = True
        elif not self.run.stopping:
            try:
                protocol.record = ConnectionRecord(
                    len(self.run.connections), name, self.run.now()
                )
                self.run.connections.append(protocol.record)
            except BaseException as error:
                self.remember(error)
                self.run.stopping = True
        return protocol

    def disconnected(self, protocol: LifecycleProtocol, error: BaseException) -> None:
        if peer_disconnected(error) and protocol.record is not None:
            record = protocol.record
            if not any(previous is error for previous in record.disconnects):
                record.disconnects.append(error)
            if not self.run.stopping and record.reset is None:
                record.reset = self.run.now()
        else:
            self.failed(error)

    def observe(self, protocol: LifecycleProtocol, task: asyncio.Task[None]) -> None:
        if task in protocol.observed:
            return
        protocol.observed.add(task)
        try:
            task.result()
        except BaseException as error:
            self.failed(error)

    def accept(self, reader: asyncio.StreamReader, protocol: LifecycleProtocol) -> None:
        try:
            if self.run.stopping:
                protocol.transport.abort()
            else:
                protocol.handler = self.submit(self.handle(reader, protocol))
                protocol.handler.add_done_callback(
                    lambda task: self.observe(protocol, task)
                )
            protocol.waiter = self.submit(self.wait_writer(protocol))
            protocol.waiter.add_done_callback(lambda task: self.observe(protocol, task))
        except BaseException as error:
            self.failed(error)
            try:
                protocol.transport.abort()
            except BaseException as cleanup:
                self.failed(cleanup)

    async def handle(
        self, reader: asyncio.StreamReader, protocol: LifecycleProtocol
    ) -> None:
        record = protocol.record
        try:
            channel = Channel(
                protocol.context,
                reader,
                protocol.writer,
                record,
                self.run.now,
                self.run,
            )
            if await channel.handshake():
                if self.run.resources is not None:
                    required = (
                        "http/1.1" if self.run.resources.protocol == "h1" else "h2"
                    )
                    if record.alpn != required:
                        raise ValueError(
                            f"resource capture requires {required} negotiation"
                        )
                if record.alpn == "h2":
                    await serve_h2(self.run, channel, record)
                else:
                    await serve_h1(self.run, channel, record)
        except BaseException as error:
            if peer_disconnected(error):
                self.disconnected(protocol, error)
            else:
                self.failed(error)
        finally:
            try:
                protocol.writer.close()
            except BaseException as error:
                self.disconnected(protocol, error)
            self.run.connection_ended.set()

    async def wait_writer(self, protocol: LifecycleProtocol) -> None:
        try:
            await protocol.writer.wait_closed()
        except BaseException as error:
            self.disconnected(protocol, error)

    async def wait_done(self, budget: float) -> None:
        try:
            self.event_tasks.add(self.submit(self.run.done.wait()))
            self.event_tasks.add(self.submit(self.run.failure_ready.wait()))
            done, _ = await asyncio.wait(
                self.event_tasks, timeout=budget, return_when=asyncio.FIRST_COMPLETED
            )
            for task in tuple(self.event_tasks):
                if task in done:
                    self.event_tasks.remove(task)
                    try:
                        task.result()
                    except BaseException as error:
                        self.failed(error)
            if self.run.failure is not None:
                raise self.run.failure
            if not done:
                raise asyncio.TimeoutError("the lifecycle page did not finish")
        finally:
            # Retain the actual observers on the owner until close collects both outcomes.
            self.run.done.set()
            self.run.failure_ready.set()

    async def close(self, primary: BaseException | None = None) -> None:
        try:
            await self.lock.acquire()
        except BaseException as error:
            _raise_lifecycle_failures(primary, (error,), self)
        try:
            if self.primary is None:
                self.primary = primary
            elif primary is not None and primary is not self.primary:
                self.remember(primary)
            try:
                await self.collect()
            except BaseException as error:
                self.remember(error)
            failures, self.failures = self.failures, []
            original, self.primary = self.primary, None
            _raise_lifecycle_failures(original, failures, self)
        finally:
            self.lock.release()

    async def collect(self) -> None:
        self.run.stopping = True
        self.run.done.set()
        self.run.failure_ready.set()
        if self.run.completion is not None:
            self.run.completion.cancel()
        self.stop_listeners()
        deadline = asyncio.get_running_loop().time() + CLEANUP_SECONDS
        while True:
            for task in tuple(self.event_tasks):
                if task.done():
                    self.event_tasks.remove(task)
                    try:
                        task.result()
                    except BaseException as error:
                        self.remember(error)
            for protocol in tuple(self.protocols):
                if protocol.transport is not None and not protocol.retired:
                    try:
                        protocol.transport.abort()
                    except BaseException as error:
                        self.failed(error)
                if protocol.writer is not None and protocol.waiter is None:
                    try:
                        protocol.waiter = self.submit(self.wait_writer(protocol))
                    except BaseException as error:
                        self.failed(error)
                for task in (protocol.handler, protocol.waiter):
                    if task is not None and task.done():
                        self.observe(protocol, task)
                if protocol.stream_closed.done() and not protocol.closed_observed:
                    # Setup can fail before a writer exists; its original stream
                    # close future still carries the native connection_lost error.
                    protocol.closed_observed = True
                    try:
                        protocol.stream_closed.result()
                    except BaseException as error:
                        self.disconnected(protocol, error)
                if (
                    protocol.retired
                    and protocol.closed_observed
                    and (protocol.handler is None or protocol.handler.done())
                    and (
                        protocol.writer is None
                        or (protocol.waiter is not None and protocol.waiter.done())
                    )
                ):
                    self.protocols.remove(protocol)
            tasks = {
                task
                for protocol in self.protocols
                for task in (
                    protocol.handler,
                    protocol.waiter,
                    protocol.closed,
                    protocol.stream_closed,
                )
                if task is not None and not task.done()
            }
            tasks.update(self.event_tasks)
            for listener in self.listeners:
                if listener.waiter is None:
                    self.remember(
                        RuntimeError("listener retirement waiter was not registered")
                    )
                elif listener.waiter.done():
                    if not listener.observed:
                        listener.observed = True
                        try:
                            listener.waiter.result()
                        except BaseException as error:
                            self.failed(error)
                else:
                    tasks.add(listener.waiter)
            if not tasks:
                if self.protocols:
                    self.remember(RuntimeError("connection retirement is unobserved"))
                return
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                self.remember(TimeoutError("lifecycle capture peers did not stop"))
                return
            try:
                await asyncio.wait(
                    tasks, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                )
            except BaseException as error:
                self.remember(error)


# -- Capture ---------------------------------------------------------------


def capture_tool() -> str:
    versions = " ".join(
        f"{package} {metadata.version(package)}" for package in SUPPORTED
    )
    return f"python {platform.python_version()} {versions}"


def firefox_cert_override(ports: Sequence[int], certificate: Certificate) -> str:
    """Trust the throwaway leaf inside one disposable Firefox profile only."""
    lines = [
        "# PSM Certificate Override Settings file",
        "# This is a generated file!  Do not edit.",
    ]
    lines.extend(
        f"{HOSTNAME}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t{certificate.sha256_fingerprint}\t"
        for port in ports
    )
    return "\n".join(lines) + "\n"


def launch_plan(
    args: argparse.Namespace, certificate: Certificate, ports: Sequence[int]
) -> LaunchPlan:
    remote = args.scenario in {"close", "resources"}
    if args.browser in CHROMIUM_BROWSERS:
        address = ipaddress.ip_address(args.listen)
        replacement = f"[{address}]" if address.version == 6 else str(address)
        extra = [
            f"--host-resolver-rules=MAP {HOSTNAME} {replacement}, EXCLUDE localhost",
            "--ignore-certificate-errors-spki-list=" + certificate.spki_sha256_base64,
            "--disable-quic",
        ]
        if remote:
            extra.append("--remote-debugging-port=0")
        if args.scenario == "resources":
            extra.append("--remote-debugging-address=127.0.0.1")
            extra[0] = (
                f"--host-resolver-rules=MAP {HOSTNAME} {replacement}, MAP * ~NOTFOUND"
            )
        return LaunchPlan(
            args.browser, args.browser_path, not args.headful, tuple(extra)
        )
    return LaunchPlan(
        "firefox",
        args.browser_path,
        not args.headful,
        ("--remote-debugging-port", "0") if remote else (),
        firefox_preferences=(
            ("network.dns.localDomains", HOSTNAME),
            ("network.dns.disableIPv6", ipaddress.ip_address(args.listen).version == 4),
            ("network.dns.preferIPv6", ipaddress.ip_address(args.listen).version == 6),
            ("network.http.http3.enable", False),
        ),
        profile_files=(
            ("cert_override.txt", firefox_cert_override(ports, certificate)),
        ),
    )


async def close_browser(browser: str, profile: Path, run: Run) -> None:
    """Close the browser as its user would, over its remote protocol."""
    if browser == "firefox":
        endpoint = await wait_for_endpoint(firefox_endpoint, profile)
    else:
        endpoint = await wait_for_endpoint(chromium_endpoint, profile)
    socket = await RemoteSocket.connect(endpoint)
    connection = None
    primary = None
    cleanup = []

    async def ignore(_: dict) -> None:
        return None

    try:
        connection = RemoteConnection(socket)
        connection.start(ignore)
        run.remote_disconnect = await request_browser_close(connection, browser)
    except BaseException as error:
        primary = error
    if connection is not None:
        try:
            await connection.close()
        except BaseException as error:
            cleanup.append(error)
    else:
        try:
            socket.close()
        except BaseException as error:
            cleanup.append(error)
        try:
            await asyncio.wait_for(socket.writer.wait_closed(), CLEANUP_SECONDS)
        except BaseException as error:
            cleanup.append(error)
    _raise_lifecycle_failures(primary, cleanup, connection or socket)


def fixture(
    args: argparse.Namespace,
    plan: LaunchPlan,
    arguments: str,
    run: Run,
    remote_close: float | None,
) -> str:
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={plan.client_name}",
        f"client_version={args.client_version}",
        f"operating_system={args.operating_system}",
        f"hostname={HOSTNAME}",
        f"launch_mode={plan.launch_mode}",
        f"launch_arguments={arguments}",
        f"capture_tool={capture_tool()}",
        f"scenario={args.scenario}",
        f"wall_clock_ms={run.now() * 1000:.0f}",
        "remote_close_ms="
        + ("none" if remote_close is None else f"{remote_close * 1000:.3f}"),
        f"page_connection={run.page_connection}",
        f"page_result={run.page_result}",
        f"connection_count={len(run.connections)}",
    ]
    for record in run.connections:
        lines.append(f"connection_{record.index}={record.line()}")
        lines.append(f"connection_{record.index}_frame_count={len(record.frames)}")
        lines.extend(
            f"connection_{record.index}_frame_{n}={line}"
            for n, line in enumerate(record.frames)
        )
    lines.append(f"request_count={len(run.requests)}")
    lines.extend(
        f"request_{n}={request.line()}" for n, request in enumerate(run.requests)
    )
    if run.resources is not None:
        lines.extend(run.resources.lines(run.page_result))
    return "\n".join(lines) + "\n"


def validate_options(args: argparse.Namespace) -> None:
    protocol = getattr(args, "resource_protocol", "h2")
    if protocol not in {"h1", "h2"}:
        raise ValueError("--resource-protocol must be h1 or h2")
    if protocol != "h2" and args.scenario != "resources":
        raise ValueError("--resource-protocol h1 requires --scenario resources")
    address = ipaddress.ip_address(args.listen)
    if not address.is_loopback:
        raise ValueError("the capture listener must be a loopback address")
    if args.browser == "firefox" and args.listen not in {"127.0.0.1", "::1"}:
        raise ValueError("Firefox local-domain captures require 127.0.0.1 or ::1")
    if (
        not math.isfinite(args.idle)
        or args.idle <= 0
        or args.idle * 1000 > MAX_TIMER_MS
    ):
        raise ValueError("--idle must be finite, positive, and fit a JavaScript timer")


async def capture(args: argparse.Namespace) -> None:
    validate_options(args)
    certificate = generate_certificate()
    main_context = server_context(certificate)
    main_context.set_alpn_protocols(
        ["http/1.1"]
        if args.scenario == "upload-h1"
        or (
            args.scenario == "resources"
            and getattr(args, "resource_protocol", "h2") == "h1"
        )
        else ["h2"]
        if args.scenario == "resources"
        else ["h2", "http/1.1"]
    )
    h1_context = server_context(certificate)
    h1_context.set_alpn_protocols(["http/1.1"])
    run = Run(args.scenario, secrets.token_hex(8), round(args.idle * 1000))
    owner = LifecycleServer(run)
    budget = {"idle-ping": args.idle + 60, "ping-unanswered": 90}.get(args.scenario, 60)
    remote_close = None
    primary = None
    try:
        port = await owner.start(args.listen, main_context, "main")
        h1_port = (
            port
            if args.scenario == "resources"
            else await owner.start(args.listen, h1_context, "h1")
        )
        run.h1_origin = f"https://{HOSTNAME}:{h1_port}"
        if args.scenario == "resources":
            run.resources = ResourceCapture(
                run.token, port, getattr(args, "resource_protocol", "h2")
            )
        plan = launch_plan(args, certificate, (port, h1_port))
        url = f"https://{HOSTNAME}:{port}/start?run={run.token}"
        async with BrowserDriver(plan, url) as driver:
            await owner.wait_done(budget)
            print(f"page finished at {run.now():.1f} s", file=sys.stderr, flush=True)
            if args.scenario in {"close", "resources"}:
                await asyncio.sleep(2)
                if driver.browser is None or driver.browser.profile is None:
                    raise RuntimeError("the browser has no remote profile")
                remote_close = run.now()
                await close_browser(args.browser, driver.browser.profile, run)
                print(
                    f"closed the browser at {run.now():.1f} s",
                    file=sys.stderr,
                    flush=True,
                )
                try:
                    await asyncio.wait_for(all_ended(run), CLOSE_GRACE)
                except asyncio.TimeoutError as error:
                    # An open connection at the end of this observation window is
                    # part of the recording, not evidence that the browser closed it.
                    run.grace_timeout = error
                    if args.scenario == "resources":
                        raise
    except BaseException as error:
        primary = error
    await owner.close(primary)
    arguments = (
        plan.recorded_arguments(url)
        .replace(certificate.spki_sha256_base64, "<certificate-spki>")
        .replace(f":{port}", ":<port>")
        .replace(run.token, "<token>")
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = args.output_dir / f"{args.scenario}.txt"
    write_text_fixture(path, fixture(args, plan, arguments, run, remote_close))
    print(f"wrote {path} in {run.now():.1f} s", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--browser", choices=(*CHROMIUM_BROWSERS, "firefox"), required=True
    )
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument(
        "--resource-protocol",
        choices=("h1", "h2"),
        default="h2",
        help="HTTPS protocol for the resources scenario (default: h2)",
    )
    parser.add_argument("--idle", type=float, default=75.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        validate_options(args)
    except ValueError as error:
        parser.error(str(error))
    for package, version in SUPPORTED.items():
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    asyncio.run(capture(args))


if __name__ == "__main__":
    main()
