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
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
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
    wait_for_endpoint,
)
from .fixture_file import write_text_fixture
from .http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    Certificate,
    generate_certificate,
    server_context,
)

FORMAT = "phantom-http-lifecycle-v1"
SUPPORTED = {"h2": "4.4.1", "hpack": "4.2.0"}
SCENARIOS = (
    "revalidate",
    "upload-h1",
    "upload-h2",
    "idle-ping",
    "ping-unanswered",
    "close",
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
            if len(self.buffer) < 9 + length:
                return
            kind, flags = self.buffer[3], self.buffer[4]
            stream = int.from_bytes(self.buffer[5:9], "big") & 0x7FFF_FFFF
            payload = bytes(self.buffer[9 : 9 + length])
            del self.buffer[: 9 + length]
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
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.record = record
        self.clock = clock
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)

    async def raw(self) -> bytes | None:
        try:
            data = await self.reader.read(READ_SIZE)
        except ConnectionError:
            self.record.reset = self.clock()
            return None
        if not data:
            self.record.eof = self.clock()
            return None
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
                return False
            await self.flush()
            data = await self.raw()
            if data is None:
                return False
            self.incoming.write(data)

    async def flush(self) -> None:
        pending = self.outgoing.read()
        if pending and not self.writer.transport.is_closing():
            self.writer.write(pending)
            with contextlib.suppress(ConnectionError):
                await self.writer.drain()

    async def read(self) -> bytes | None:
        """Decrypted bytes, or None once the client has ended the connection."""
        while True:
            try:
                data = self.tls.read(READ_SIZE)
                await self.flush()
                if data:
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
                return None
            await self.flush()
            raw = await self.raw()
            if raw is None:
                return None
            self.incoming.write(raw)

    async def after_close_notify(self) -> None:
        """Record the close_notify, then wait for the TCP end that follows."""
        self.record.close_notify = self.clock()
        await self.flush()
        while await self.raw() is not None:
            pass
        return None

    async def write(self, data: bytes) -> None:
        if data and self.record.silenced is None:
            self.tls.write(data)
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

    def now(self) -> float:
        return time.perf_counter() - self.started

    def finish(self, target: str) -> None:
        query = parse_qs(urlsplit(target).query)
        self.page_result = query.get("result", ["none"])[0]
        asyncio.get_running_loop().call_later(0.5, self.done.set)

    def silences(self, connection: int, path: str) -> bool:
        """Whether the server stops writing on `connection` at this request."""
        return (
            self.scenario == "ping-unanswered"
            and path == "/b"
            and connection == self.page_connection
        )


async def accept(
    run: Run, context: ssl.SSLContext, listener: str, reader, writer
) -> None:
    record = ConnectionRecord(len(run.connections), listener, run.now())
    run.connections.append(record)
    channel = Channel(context, reader, writer, record, run.now)
    try:
        if not await channel.handshake():
            return
        if record.alpn == "h2":
            await serve_h2(run, channel, record)
        else:
            await serve_h1(run, channel, record)
    except ValueError as error:
        record.tls_error = f"capture:{error}"
    finally:
        if not writer.transport.is_closing():
            writer.close()
        run.connection_ended.set()


async def all_ended(run: Run) -> None:
    """Return once the browser has ended every connection it opened."""
    while not all(record.ended for record in run.connections):
        run.connection_ended.clear()
        await run.connection_ended.wait()


async def serve_h2(run: Run, channel: Channel, record: ConnectionRecord) -> None:
    import h2.events
    from h2.config import H2Configuration
    from h2.connection import H2Connection

    connection = H2Connection(H2Configuration(client_side=False, header_encoding=None))
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
                fields = [
                    (n.decode("latin-1"), v.decode("latin-1")) for n, v in event.headers
                ]
                head = dict(fields)
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
                streams[event.stream_id] = request
                targets[event.stream_id] = head.get(":path", "")
                run.requests.append(request)
                if path == "/start":
                    run.page_connection = record.index
                if run.silences(record.index, path):
                    record.silenced = run.now()
            elif isinstance(event, h2.events.DataReceived):
                request = streams.get(event.stream_id)
                if request is not None:
                    request.body_bytes += len(event.data)
                    if request.body_bytes > MAX_BODY:
                        raise ValueError("request body exceeds the capture limit")
                connection.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            elif isinstance(event, h2.events.StreamEnded):
                request = streams.get(event.stream_id)
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
                    connection.send_data(
                        event.stream_id, reply.body, end_stream=not reply.stall
                    )
                if request.path == "/done":
                    run.finish(targets[event.stream_id])
        await channel.write(connection.data_to_send())


async def serve_h1(run: Run, channel: Channel, record: ConnectionRecord) -> None:
    buffer = bytearray()
    while True:
        while b"\r\n\r\n" not in buffer:
            if len(buffer) > MAX_REQUEST_HEAD:
                raise ValueError("request head exceeds the capture limit")
            data = await channel.read()
            if data is None:
                return
            buffer.extend(data)
        end = buffer.index(b"\r\n\r\n")
        lines = bytes(buffer[:end]).decode("latin-1").split("\r\n")
        del buffer[: end + 4]
        method, target, _ = lines[0].split(" ", 2)
        fields = [
            tuple(part.strip() for part in line.split(":", 1)) for line in lines[1:]
        ]
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
        run.requests.append(request)
        if path == "/start":
            run.page_connection = record.index
        if head.get("expect", "").lower() == "100-continue":
            await channel.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        if "chunked" in head.get("transfer-encoding", "").lower():
            raise ValueError("chunked request bodies are not supported")
        remaining = int(head.get("content-length", "0"))
        if remaining > MAX_BODY:
            raise ValueError("request body exceeds the capture limit")
        while remaining > 0:
            if not buffer:
                data = await channel.read()
                if data is None:
                    return
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
        if path == "/done":
            run.finish(target)


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
    remote = args.scenario == "close"
    if args.browser in CHROMIUM_BROWSERS:
        extra = [
            f"--host-resolver-rules=MAP {HOSTNAME} {args.listen}, EXCLUDE localhost",
            "--ignore-certificate-errors-spki-list=" + certificate.spki_sha256_base64,
            "--disable-quic",
        ]
        if remote:
            extra.append("--remote-debugging-port=0")
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
            ("network.dns.disableIPv6", True),
            ("network.http.http3.enable", False),
        ),
        profile_files=(
            ("cert_override.txt", firefox_cert_override(ports, certificate)),
        ),
    )


async def close_browser(browser: str, profile: Path) -> None:
    """Close the browser as its user would, over its remote protocol."""
    if browser == "firefox":
        endpoint = await wait_for_endpoint(firefox_endpoint, profile)
    else:
        endpoint = await wait_for_endpoint(chromium_endpoint, profile)
    connection = RemoteConnection(await RemoteSocket.connect(endpoint))

    async def ignore(_: dict) -> None:
        return None

    connection.start(ignore)
    try:
        if browser == "firefox":
            await connection.call("session.new", {"capabilities": {}})
            future = await connection.send("browser.close", {})
        else:
            future = await connection.send("Browser.close", {})
        with contextlib.suppress(Exception):
            await asyncio.wait_for(future, timeout=5)
    finally:
        await connection.close()


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
    return "\n".join(lines) + "\n"


async def capture(args: argparse.Namespace) -> None:
    certificate = generate_certificate()
    main_context = server_context(certificate)
    main_context.set_alpn_protocols(
        ["http/1.1"] if args.scenario == "upload-h1" else ["h2", "http/1.1"]
    )
    h1_context = server_context(certificate)
    h1_context.set_alpn_protocols(["http/1.1"])
    run = Run(args.scenario, secrets.token_hex(8), round(args.idle * 1000))
    server = await asyncio.start_server(
        lambda r, w: accept(run, main_context, "main", r, w), args.listen, 0
    )
    h1_server = await asyncio.start_server(
        lambda r, w: accept(run, h1_context, "h1", r, w), args.listen, 0
    )
    port = server.sockets[0].getsockname()[1]
    h1_port = h1_server.sockets[0].getsockname()[1]
    run.h1_origin = f"https://{HOSTNAME}:{h1_port}"
    plan = launch_plan(args, certificate, (port, h1_port))
    url = f"https://{HOSTNAME}:{port}/start?run={run.token}"
    budget = {"idle-ping": args.idle + 60, "ping-unanswered": 90}.get(args.scenario, 60)
    remote_close = None
    try:
        async with BrowserDriver(plan, url) as driver:
            await asyncio.wait_for(run.done.wait(), timeout=budget)
            print(f"page finished at {run.now():.1f} s", file=sys.stderr, flush=True)
            if args.scenario == "close":
                await asyncio.sleep(2)
                assert driver.browser is not None and driver.browser.profile is not None
                remote_close = run.now()
                await close_browser(args.browser, driver.browser.profile)
                print(
                    f"closed the browser at {run.now():.1f} s",
                    file=sys.stderr,
                    flush=True,
                )
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(all_ended(run), CLOSE_GRACE)
    finally:
        for listener in (server, h1_server):
            listener.close()
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
    parser.add_argument("--idle", type=float, default=75.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        loopback = ipaddress.ip_address(args.listen).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        parser.error("the capture listener must be a loopback address")
    if args.idle <= 0:
        parser.error("--idle must be positive")
    for package, version in SUPPORTED.items():
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    asyncio.run(capture(args))


if __name__ == "__main__":
    main()
