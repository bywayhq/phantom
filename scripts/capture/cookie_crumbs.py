"""Record how a browser sends several cookies over HTTP/1.1, HTTP/2, and HTTP/3.

One run loads `/start`, whose response sets the probe cookies, then navigates
to `/page`, which fetches `/fetch` and `/done`. Every request after `/start`
carries the probe cookies, so each run shows the cookie field (or fields) on a
navigation and on a same-origin `fetch()`, twice on one connection.

For each request the fixture keeps every field in wire order. On HTTP/2 it
keeps each HPACK representation, and on HTTP/3 each QPACK field line and the
QPACK encoder-stream instructions, so the split into one field per cookie
("crumbs") and the indexing of each crumb can be read directly. The tool
refuses to write any cookie other than its own probes, and any `authorization`
or `proxy-authorization` field.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import platform
import secrets
import sys
import time
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .browser_launch import (
    BROWSERS,
    CHROMIUM_BROWSERS,
    BrowserDriver,
    LaunchPlan,
    render_preferences,
)
from .fixture_file import write_text_fixture
from .http2_session import (
    HOSTNAME,
    Certificate,
    ConnectionRecord,
    HeaderField,
    PlainChannel,
    TlsChannel,
    analyze_http2,
    generate_certificate,
    hpack_integer,
    server_context,
)

FORMAT = "phantom-cookie-crumbs-v1"
SUPPORTED = {"h2": "4.4.1", "hpack": "4.2.0", "aioquic": "1.3.0"}
# Set in this order by `/start`. Firefox's HTTP/2 compressor sends a crumb
# shorter than 20 bytes as a never-indexed literal and indexes a longer one,
# so `pc` (19 bytes) and `pd` (20 bytes) straddle that boundary.
PROBE_COOKIES = (
    "pa=1",
    "phantom_b=12345",
    "pc=0123456789abcdef",
    "pd=0123456789abcdefg",
    "phantom_long=" + "0123456789" * 4,
)
CREDENTIAL_FIELDS = {b"authorization", b"proxy-authorization"}
MAX_REQUEST_HEAD = 64 * 1024
MAX_REQUESTS = 32
MAX_STREAM_CAPTURE = 1024 * 1024
READ_SIZE = 64 * 1024
QPACK_ENCODER_STREAM = 0x02
QPACK_STATIC_COOKIE = 5
HTTP3_HEADERS_FRAME = 0x01


@dataclass(frozen=True)
class Scenario:
    name: str
    protocol: str
    question: str


SCENARIOS = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "h1",
            "http/1.1",
            "Cookie line spelling, position, and joining over plaintext HTTP/1.1",
        ),
        Scenario(
            "h2",
            "h2",
            "cookie crumbs, their HPACK representations, and position over HTTP/2",
        ),
        Scenario(
            "h3",
            "h3",
            "cookie crumbs, their QPACK field lines and inserts, and position "
            "over HTTP/3",
        ),
    )
}


def start_page(token: str) -> bytes:
    return (
        "<!doctype html><meta charset=utf-8>"
        '<link rel=icon href="data:,">'
        f'<script>location.replace("/page?run={token}");</script>\n'
    ).encode()


def next_page(token: str) -> bytes:
    return (
        "<!doctype html><meta charset=utf-8>"
        '<link rel=icon href="data:,">'
        "<script>(async () => {"
        f'await fetch("/fetch?run={token}", {{cache: "no-store"}});'
        f'await fetch("/done?run={token}", {{cache: "no-store"}});'
        "})();</script>\n"
    ).encode()


# -- Recorded state --------------------------------------------------------


@dataclass
class RequestRecord:
    connection: int
    received: float
    kind: str
    stream_id: int | None = None
    # HTTP/1.1 only: the request line and header lines as received.
    request_line: bytes = b""
    header_lines: list[bytes] = field(default_factory=list)
    # HTTP/3 only: the fields as the server's QPACK decoder returned them.
    decoded: list[tuple[bytes, bytes]] = field(default_factory=list)


@dataclass
class QuicRecord:
    """Ordered client stream bytes of one HTTP/3 connection."""

    accepted: float
    streams: dict[int, bytearray] = field(default_factory=dict)
    received: int = 0


@dataclass
class CookieRun:
    token: str
    observation_seconds: float
    clock: Callable[[], float] = time.perf_counter
    started: float = field(init=False)
    connections: list[ConnectionRecord] = field(default_factory=list)
    quic_connections: list[QuicRecord] = field(default_factory=list)
    requests: list[RequestRecord] = field(default_factory=list)
    finished: float | None = None
    timed_out: bool = False
    done: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self) -> None:
        self.started = self.clock()

    def now(self) -> float:
        return self.clock() - self.started

    def classify(self, target: bytes) -> str:
        parts = urlsplit(target.decode("latin-1"))
        if parse_qs(parts.query).get("run", [""])[0] != self.token:
            return "other"
        return {
            "/start": "start",
            "/page": "page",
            "/fetch": "fetch",
            "/done": "done",
        }.get(parts.path, "other")

    def record(self, request: RequestRecord) -> None:
        if len(self.requests) >= MAX_REQUESTS:
            raise ValueError("run exceeds the request limit")
        self.requests.append(request)
        if request.kind == "done" and self.finished is None:
            self.finished = self.now()
            asyncio.get_running_loop().call_later(
                self.observation_seconds, self.done.set
            )

    def response(self, kind: str) -> tuple[int, bytes, list[tuple[bytes, bytes]]]:
        """Return the status, body, and extra fields for one request kind."""
        if kind == "start":
            cookies = [(b"set-cookie", f"{c}; Path=/".encode()) for c in PROBE_COOKIES]
            return 200, start_page(self.token), cookies
        if kind == "page":
            return 200, next_page(self.token), []
        if kind in {"fetch", "done"}:
            return 200, b"ok", []
        return 404, b"", []


def content_type(body: bytes) -> bytes:
    return b"text/html; charset=utf-8" if body.startswith(b"<!") else b"text/plain"


# -- HTTP/1.1 and HTTP/2 over TCP ------------------------------------------


class TcpServer:
    """A TLS listener for `HOSTNAME` (ALPN h2) and a plaintext HTTP/1.1 one."""

    def __init__(self, certificate: Certificate) -> None:
        self.context = server_context(certificate)
        self.run: CookieRun | None = None
        self.servers: list[asyncio.base_events.Server] = []
        self.writers: set[asyncio.StreamWriter] = set()
        self.tls_address: tuple[str, int] | None = None
        self.plain_address: tuple[str, int] | None = None

    async def start(self, host: str) -> None:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the capture listener must be a loopback address")
        tls = await asyncio.start_server(self.handle_tls, host, 0)
        plain = await asyncio.start_server(self.handle_plain, host, 0)
        self.servers = [tls, plain]
        self.tls_address = tls.sockets[0].getsockname()[:2]
        self.plain_address = plain.sockets[0].getsockname()[:2]

    async def close(self) -> None:
        self.drop_connections()
        for server in self.servers:
            server.close()
            await server.wait_closed()

    def drop_connections(self) -> None:
        for writer in list(self.writers):
            writer.transport.abort()
        self.writers.clear()

    def accept(
        self, listener: str, writer: asyncio.StreamWriter
    ) -> tuple[CookieRun, ConnectionRecord, int] | None:
        run = self.run
        if run is None:
            writer.transport.abort()
            return None
        self.writers.add(writer)
        record = ConnectionRecord(listener=listener, accepted=run.now())
        run.connections.append(record)
        return run, record, len(run.connections) - 1

    async def handle_tls(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        accepted = self.accept("tls", writer)
        if accepted is None:
            return
        run, record, index = accepted
        channel = TlsChannel(self.context, reader, writer, record, run.now)
        try:
            await channel.handshake()
            record.protocol = record.alpn or "http/1.1"
            if record.alpn == "h2":
                await serve_http2(channel, run, index)
            else:
                await serve_http1(channel, run, index)
        except Exception as error:  # recorded: a capture keeps partial evidence
            record.failure = record.failure or type(error).__name__
        finally:
            self.release(writer)

    async def handle_plain(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        accepted = self.accept("plain", writer)
        if accepted is None:
            return
        run, record, index = accepted
        record.protocol = "http/1.1"
        channel = PlainChannel(reader, writer, record, run.now)
        try:
            await serve_http1(channel, run, index)
        except Exception as error:  # recorded: a capture keeps partial evidence
            record.failure = record.failure or type(error).__name__
        finally:
            self.release(writer)

    def release(self, writer: asyncio.StreamWriter) -> None:
        self.writers.discard(writer)
        if not writer.transport.is_closing():
            writer.close()


async def serve_http1(channel, run: CookieRun, index: int) -> None:
    buffer = bytearray()
    while True:
        end = buffer.find(b"\r\n\r\n")
        if end < 0:
            if len(buffer) > MAX_REQUEST_HEAD:
                return
            data = await channel.read()
            if not data:
                return
            buffer.extend(data)
            continue
        head = bytes(buffer[:end])
        del buffer[: end + 4]
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ")
        target = parts[1] if len(parts) == 3 else b""
        kind = run.classify(target)
        run.record(RequestRecord(index, run.now(), kind, None, lines[0], lines[1:]))
        status, body, extra = run.response(kind)
        response = [b"HTTP/1.1 " + str(status).encode() + b" Status"]
        response.append(b"content-type: " + content_type(body))
        response.append(b"content-length: " + str(len(body)).encode())
        response.append(b"cache-control: no-store")
        response.extend(name + b": " + value for name, value in extra)
        await channel.write(b"\r\n".join(response) + b"\r\n\r\n" + body)


async def serve_http2(channel, run: CookieRun, index: int) -> None:
    import h2.events
    import h2.exceptions
    from h2.config import H2Configuration
    from h2.connection import H2Connection

    connection = H2Connection(H2Configuration(client_side=False, header_encoding=None))
    connection.initiate_connection()
    await channel.write(connection.data_to_send())
    while True:
        data = await channel.read()
        if not data:
            return
        try:
            events = connection.receive_data(data)
        except h2.exceptions.ProtocolError as error:
            channel.record.failure = f"h2:{type(error).__name__}"
            await channel.write(connection.data_to_send())
            return
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                fields = dict(event.headers)
                kind = run.classify(fields.get(b":path", b""))
                run.record(RequestRecord(index, run.now(), kind, event.stream_id))
                status, body, extra = run.response(kind)
                headers = [
                    (b":status", str(status).encode()),
                    (b"content-type", content_type(body)),
                    (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store"),
                    *extra,
                ]
                connection.send_headers(event.stream_id, headers, end_stream=not body)
                if body:
                    connection.send_data(event.stream_id, body, end_stream=True)
            elif isinstance(event, h2.events.ConnectionTerminated):
                await channel.write(connection.data_to_send())
                return
        await channel.write(connection.data_to_send())


# -- HTTP/3 ----------------------------------------------------------------


@contextlib.asynccontextmanager
async def serving_http3(
    run: CookieRun, listen_host: str, certificate: Certificate
) -> AsyncIterator[int]:
    """Serve HTTP/3 for one run on an ephemeral loopback UDP port."""
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ProtocolNegotiated, StreamDataReceived

    from .quic_resumption import load_certificate

    class CookieProtocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self.record = QuicRecord(run.now())
            self.index = len(run.quic_connections)
            run.quic_connections.append(self.record)
            self.http: H3Connection | None = None

        def quic_event_received(self, event) -> None:
            if isinstance(event, ProtocolNegotiated):
                self.http = H3Connection(self._quic)
            if isinstance(event, StreamDataReceived):
                self.record.received += len(event.data)
                if self.record.received > MAX_STREAM_CAPTURE:
                    raise ValueError("connection exceeds the capture limit")
                stream = self.record.streams.setdefault(event.stream_id, bytearray())
                stream.extend(event.data)
            if self.http is None:
                return
            for http_event in self.http.handle_event(event):
                if isinstance(http_event, HeadersReceived):
                    self.request(http_event)

        def request(self, event) -> None:
            fields = dict(event.headers)
            kind = run.classify(fields.get(b":path", b""))
            run.record(
                RequestRecord(
                    self.index,
                    run.now(),
                    kind,
                    event.stream_id,
                    decoded=[(bytes(n), bytes(v)) for n, v in event.headers],
                )
            )
            status, body, extra = run.response(kind)
            assert self.http is not None
            self.http.send_headers(
                event.stream_id,
                [
                    (b":status", str(status).encode()),
                    (b"content-type", content_type(body)),
                    (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store"),
                    *extra,
                ],
                end_stream=not body,
            )
            if body:
                self.http.send_data(event.stream_id, body, end_stream=True)
            self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    load_certificate(configuration, certificate)
    server = await serve(
        listen_host, 0, configuration=configuration, create_protocol=CookieProtocol
    )
    try:
        yield server._transport.get_extra_info("sockname")[1]
    finally:
        server.close()


# -- Offline QPACK analysis ------------------------------------------------


@dataclass(frozen=True)
class QpackString:
    huffman: bool
    raw: bytes

    def decoded(self) -> bytes:
        if not self.huffman:
            return self.raw
        from hpack.huffman_table import decode_huffman

        return decode_huffman(self.raw)


def qpack_string(data: bytes, offset: int, prefix: int) -> tuple[QpackString, int]:
    """Read a string whose H flag is the bit above a `prefix`-bit length."""
    if offset >= len(data):
        raise ValueError("truncated QPACK string")
    huffman = bool(data[offset] & (1 << prefix))
    length, offset = hpack_integer(data, offset, prefix)
    if offset + length > len(data):
        raise ValueError("truncated QPACK string")
    return QpackString(huffman, data[offset : offset + length]), offset + length


@dataclass(frozen=True)
class EncoderInstruction:
    """One QPACK encoder-stream instruction (RFC 9204 section 4.3)."""

    kind: str
    # `static`, `dynamic`, or `none`.
    table: str
    # Static index, relative dynamic index, or table capacity.
    index: int
    # Absolute index of the entry this instruction inserts, if it inserts one.
    inserted: int | None
    name: QpackString | None = None
    value: QpackString | None = None


def encoder_instructions(data: bytes) -> list[EncoderInstruction]:
    """Parse an encoder stream that starts with its stream type."""
    if not data:
        return []
    if data[0] != QPACK_ENCODER_STREAM:
        raise ValueError("not a QPACK encoder stream")
    instructions = []
    inserted = 0
    offset = 1
    while offset < len(data):
        first = data[offset]
        if first & 0x80:
            table = "static" if first & 0x40 else "dynamic"
            index, offset = hpack_integer(data, offset, 6)
            value, offset = qpack_string(data, offset, 7)
            instructions.append(
                EncoderInstruction(
                    "insert-name-ref", table, index, inserted, None, value
                )
            )
            inserted += 1
        elif first & 0x40:
            name, offset = qpack_string(data, offset, 5)
            value, offset = qpack_string(data, offset, 7)
            instructions.append(
                EncoderInstruction(
                    "insert-literal-name", "none", 0, inserted, name, value
                )
            )
            inserted += 1
        elif first & 0x20:
            capacity, offset = hpack_integer(data, offset, 5)
            instructions.append(
                EncoderInstruction("set-capacity", "none", capacity, None)
            )
        else:
            index, offset = hpack_integer(data, offset, 5)
            instructions.append(
                EncoderInstruction("duplicate", "dynamic", index, inserted)
            )
            inserted += 1
    return instructions


@dataclass(frozen=True)
class FieldLine:
    """One QPACK field line representation (RFC 9204 section 4.5)."""

    representation: str
    # `static`, `dynamic`, or `none`.
    table: str
    index: int
    # Absolute dynamic-table index referenced, if any.
    absolute: int | None
    never: bool
    name_huffman: bool | None
    value_huffman: bool | None
    name: bytes | None = None
    value: bytes | None = None


@dataclass(frozen=True)
class FieldSection:
    required_insert_count: int
    base: int
    lines: tuple[FieldLine, ...]


def field_section(block: bytes, max_table_capacity: int) -> FieldSection:
    """Classify each field line of one encoded field section."""
    encoded, offset = hpack_integer(block, 0, 8)
    max_entries = max_table_capacity // 32
    if encoded == 0:
        required = 0
    else:
        # Exact while fewer than 2 * MaxEntries entries were ever inserted,
        # which every run of this tool satisfies (RFC 9204 section 4.5.1.1).
        if max_entries == 0 or encoded > 2 * max_entries:
            raise ValueError("unsupported Required Insert Count encoding")
        required = encoded - 1
    if offset >= len(block):
        raise ValueError("truncated field section prefix")
    sign = bool(block[offset] & 0x80)
    delta, offset = hpack_integer(block, offset, 7)
    base = required - delta - 1 if sign else required + delta
    lines = []
    while offset < len(block):
        first = block[offset]
        name_huffman = None
        if first & 0x80:
            table = "static" if first & 0x40 else "dynamic"
            index, offset = hpack_integer(block, offset, 6)
            absolute = base - 1 - index if table == "dynamic" else None
            lines.append(
                FieldLine("indexed", table, index, absolute, False, None, None)
            )
            continue
        if first & 0x40:
            never = bool(first & 0x20)
            table = "static" if first & 0x10 else "dynamic"
            index, offset = hpack_integer(block, offset, 4)
            absolute = base - 1 - index if table == "dynamic" else None
            representation = "literal-name-ref"
        elif first & 0x20:
            never = bool(first & 0x10)
            table, index, absolute = "none", 0, None
            name, offset = qpack_string(block, offset, 3)
            name_huffman = name.huffman
            representation = "literal-name"
        elif first & 0x10:
            index, offset = hpack_integer(block, offset, 4)
            lines.append(
                FieldLine(
                    "indexed-post-base",
                    "dynamic",
                    index,
                    base + index,
                    False,
                    None,
                    None,
                )
            )
            continue
        else:
            never = bool(first & 0x08)
            index, offset = hpack_integer(block, offset, 3)
            table, absolute = "dynamic", base + index
            representation = "literal-post-base-name-ref"
        value, offset = qpack_string(block, offset, 7)
        lines.append(
            FieldLine(
                representation,
                table,
                index,
                absolute,
                never,
                name_huffman,
                value.huffman,
            )
        )
    return FieldSection(required, base, tuple(lines))


def http3_headers_block(stream: bytes) -> bytes:
    """Return the field section of a request stream's first HEADERS frame."""
    from .http3_wire import first_frame

    frame = first_frame(stream, has_stream_type=False)
    if frame is None or frame[0] != HTTP3_HEADERS_FRAME:
        raise ValueError("request stream has no complete first HEADERS frame")
    return frame[2]


def encoder_stream(record: QuicRecord) -> bytes:
    for stream_id, data in record.streams.items():
        if stream_id % 4 == 2 and data[:1] == bytes([QPACK_ENCODER_STREAM]):
            return bytes(data)
    return b""


# -- Retained-field checks -------------------------------------------------


def is_probe_cookie(value: bytes) -> bool:
    """Return whether a cookie field value holds only probe cookies."""
    crumbs = [crumb.strip() for crumb in value.split(b";")]
    probes = {cookie.encode() for cookie in PROBE_COOKIES}
    return all(crumb in probes for crumb in crumbs)


def check_field(name: bytes, value: bytes) -> None:
    lowered = name.lower()
    if lowered in CREDENTIAL_FIELDS:
        raise ValueError("refusing to retain a credential field")
    if lowered == b"cookie" and not is_probe_cookie(value):
        raise ValueError("refusing to retain a cookie that is not a probe")


def check_inserted_cookies(instructions: Sequence[EncoderInstruction]) -> None:
    """Refuse encoder-stream inserts of cookies that are not probes."""
    names: dict[int, bytes | None] = {}
    for item in instructions:
        if item.inserted is None:
            continue
        if item.kind == "insert-literal-name" and item.name is not None:
            name = item.name.decoded().lower()
        elif item.kind == "insert-name-ref" and item.table == "static":
            name = b"cookie" if item.index == QPACK_STATIC_COOKIE else None
        else:
            name = names.get(item.inserted - 1 - item.index)
        names[item.inserted] = name
        if name == b"cookie" and item.value is not None:
            check_field(name, item.value.decoded())


# -- Fixture ---------------------------------------------------------------


@dataclass(frozen=True)
class CaptureMetadata:
    client: str
    client_version: str
    operating_system: str
    listen_address: str
    launch_mode: str
    launch_arguments: str
    firefox_preferences: str = "none"
    profile_files: str = "none"


def milliseconds(value: float | None) -> str:
    return "none" if value is None else f"{value * 1000:.3f}"


def flag(value: bool | None) -> str:
    return "none" if value is None else str(value).lower()


def optional_hex(value: bytes | None) -> str:
    return "none" if value is None else value.hex()


def hpack_field_line(key: str, item: HeaderField) -> str:
    return (
        f"{key}=repr:{item.representation},index:{item.index},"
        f"name_huffman:{flag(item.name_huffman)},"
        f"value_huffman:{flag(item.value_huffman)},"
        f"name_hex:{optional_hex(item.name)},value_hex:{optional_hex(item.value)}"
    )


def h2_request_lines(
    key: str, run: CookieRun, request: RequestRecord, analyses: dict
) -> list[str]:
    connection = run.connections[request.connection]
    if request.connection not in analyses:
        analyses[request.connection] = analyze_http2(connection)
    blocks = [
        block
        for block in analyses[request.connection].client_headers
        if block.stream_id == request.stream_id
    ]
    if not blocks:
        raise ValueError("HTTP/2 request has no client HEADERS block")
    block = blocks[0]
    lines = [f"{key}_block_hex={block.block.hex()}"]
    names = [
        (item.name or b"").decode("latin-1")
        for item in block.fields
        if item.representation != "size-update"
    ]
    lines.append(f"{key}_field_order=" + ",".join(names))
    lines.append(f"{key}_field_count={len(block.fields)}")
    for position, item in enumerate(block.fields):
        if item.name is not None and item.value is not None:
            check_field(item.name, item.value)
        lines.append(hpack_field_line(f"{key}_field_{position}", item))
    return lines


def h3_request_lines(
    key: str,
    run: CookieRun,
    request: RequestRecord,
    decoded: Sequence[tuple[bytes, bytes]],
    max_table_capacity: int,
) -> list[str]:
    record = run.quic_connections[request.connection]
    block = http3_headers_block(bytes(record.streams.get(request.stream_id, b"")))
    section = field_section(block, max_table_capacity)
    if len(section.lines) != len(decoded):
        raise ValueError("QPACK field lines and decoded fields differ in count")
    lines = [
        f"{key}_block_hex={block.hex()}",
        f"{key}_required_insert_count={section.required_insert_count}",
        f"{key}_base={section.base}",
        f"{key}_field_order=" + ",".join(name.decode("latin-1") for name, _ in decoded),
        f"{key}_field_count={len(section.lines)}",
    ]
    for position, (line, (name, value)) in enumerate(
        zip(section.lines, decoded, strict=True)
    ):
        check_field(name, value)
        absolute = "none" if line.absolute is None else str(line.absolute)
        lines.append(
            f"{key}_field_{position}=repr:{line.representation},table:{line.table},"
            f"index:{line.index},absolute:{absolute},never:{flag(line.never)},"
            f"name_huffman:{flag(line.name_huffman)},"
            f"value_huffman:{flag(line.value_huffman)},"
            f"name_hex:{name.hex()},value_hex:{value.hex()}"
        )
    return lines


def encoder_lines(prefix: str, instructions: Sequence[EncoderInstruction]) -> list[str]:
    check_inserted_cookies(instructions)
    lines = [f"{prefix}_encoder_instruction_count={len(instructions)}"]
    for index, item in enumerate(instructions):
        inserted = "none" if item.inserted is None else str(item.inserted)
        name = None if item.name is None else item.name.decoded()
        value = None if item.value is None else item.value.decoded()
        lines.append(
            f"{prefix}_encoder_instruction_{index}=kind:{item.kind},"
            f"table:{item.table},index:{item.index},inserted:{inserted},"
            f"name_huffman:{flag(None if item.name is None else item.name.huffman)},"
            f"value_huffman:{flag(None if item.value is None else item.value.huffman)},"
            f"name_hex:{optional_hex(name)},value_hex:{optional_hex(value)}"
        )
    return lines


def run_lines(
    prefix: str,
    scenario: Scenario,
    run: CookieRun,
    max_table_capacity: int,
) -> list[str]:
    lines = [
        f"{prefix}_timed_out={flag(run.timed_out)}",
        f"{prefix}_finished_ms={milliseconds(run.finished)}",
    ]
    if scenario.protocol == "h3":
        lines.append(f"{prefix}_connection_count={len(run.quic_connections)}")
        for index, record in enumerate(run.quic_connections):
            key = f"{prefix}_connection_{index}"
            lines.append(f"{key}=accepted_ms:{milliseconds(record.accepted)}")
            stream = encoder_stream(record)
            lines.extend(encoder_lines(key, encoder_instructions(stream)))
            lines.append(f"{key}_encoder_stream_hex={stream.hex() or 'none'}")
    else:
        lines.append(f"{prefix}_connection_count={len(run.connections)}")
        for index, record in enumerate(run.connections):
            lines.append(
                f"{prefix}_connection_{index}=listener:{record.listener},"
                f"accepted_ms:{milliseconds(record.accepted)},"
                f"protocol:{record.protocol or 'none'},"
                f"failure:{record.failure or 'none'}"
            )
    lines.append(f"{prefix}_request_count={len(run.requests)}")
    analyses: dict = {}
    protocols = {index: record.protocol for index, record in enumerate(run.connections)}
    for index, request in enumerate(run.requests):
        key = f"{prefix}_request_{index}"
        if scenario.protocol == "h3":
            protocol = "h3"
        else:
            protocol = protocols.get(request.connection) or "none"
        stream = "none" if request.stream_id is None else str(request.stream_id)
        lines.append(
            f"{key}=protocol:{protocol},connection:{request.connection},"
            f"stream:{stream},kind:{request.kind},"
            f"received_ms:{milliseconds(request.received)}"
        )
        if protocol == "h3":
            lines.extend(
                h3_request_lines(key, run, request, request.decoded, max_table_capacity)
            )
        elif protocol == "h2":
            lines.extend(h2_request_lines(key, run, request, analyses))
        else:
            for line in request.header_lines:
                name, _, value = line.partition(b":")
                check_field(name.strip(), value.strip())
            lines.append(f"{key}_line_hex={request.request_line.hex()}")
            lines.append(f"{key}_header_count={len(request.header_lines)}")
            lines.extend(
                f"{key}_header_{position}={line.hex()}"
                for position, line in enumerate(request.header_lines)
            )
    return lines


def capture_tool() -> str:
    versions = " ".join(
        f"{package} {metadata.version(package)}" for package in SUPPORTED
    )
    return f"python {platform.python_version()} {versions}"


def fixture(
    scenario: Scenario,
    runs: Sequence[CookieRun],
    capture: CaptureMetadata,
    max_table_capacity: int,
) -> str:
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={capture.client}",
        f"client_version={capture.client_version}",
        f"operating_system={capture.operating_system}",
        f"hostname={HOSTNAME}",
        f"listen_address={capture.listen_address}",
        f"launch_mode={capture.launch_mode}",
        f"launch_arguments={capture.launch_arguments}",
        f"firefox_preferences={capture.firefox_preferences}",
        f"profile_files={capture.profile_files}",
        f"capture_tool={capture_tool()}",
        f"scenario={scenario.name}",
        f"scenario_question={scenario.question}",
        f"server_qpack_max_table_capacity={max_table_capacity}",
        f"probe_cookie_count={len(PROBE_COOKIES)}",
    ]
    lines.extend(
        f"probe_cookie_{index}={cookie}" for index, cookie in enumerate(PROBE_COOKIES)
    )
    lines.append(f"repeat_count={len(runs)}")
    for index, run in enumerate(runs):
        lines.extend(run_lines(f"run_{index}", scenario, run, max_table_capacity))
    return "\n".join(lines) + "\n"


# -- Browser launch --------------------------------------------------------


def firefox_cert_override(host: str, port: int, certificate: Certificate) -> str:
    """Trust the throwaway leaf inside one disposable Firefox profile only."""
    return (
        "# PSM Certificate Override Settings file\n"
        "# This is a generated file!  Do not edit.\n"
        f"{host}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t"
        f"{certificate.sha256_fingerprint}\t\n"
    )


def tcp_launch_plan(
    args: argparse.Namespace, certificate: Certificate, listen_host: str, tls_port: int
) -> LaunchPlan:
    if args.browser in CHROMIUM_BROWSERS:
        return LaunchPlan(
            browser=args.browser,
            executable=args.browser_path,
            headless=not args.headful,
            extra_arguments=(
                f"--host-resolver-rules=MAP {HOSTNAME} {listen_host}, EXCLUDE localhost",
                "--ignore-certificate-errors-spki-list="
                + certificate.spki_sha256_base64,
                "--disable-quic",
            ),
        )
    if args.browser == "firefox":
        return LaunchPlan(
            browser="firefox",
            executable=args.browser_path,
            headless=not args.headful,
            firefox_preferences=(
                ("network.dns.localDomains", HOSTNAME),
                ("network.dns.disableIPv6", True),
                ("network.http.http3.enable", False),
            ),
            profile_files=(
                (
                    "cert_override.txt",
                    firefox_cert_override(HOSTNAME, tls_port, certificate),
                ),
            ),
        )
    return LaunchPlan(browser="manual", executable=None, headless=False)


def h3_launch_plan(
    args: argparse.Namespace, certificate: Certificate, port: int
) -> LaunchPlan:
    from .quic_resumption import launch_plan

    return launch_plan(
        args.browser,
        args.browser_path,
        headless=not args.headful,
        listen_host=args.listen,
        port=port,
        certificate=certificate,
        field_trial_config=False,
    )


# -- Orchestration ---------------------------------------------------------


async def wait_for_run(run: CookieRun, plan: LaunchPlan, url: str, timeout: float):
    async with BrowserDriver(plan, url):
        try:
            await asyncio.wait_for(
                run.done.wait(), timeout=timeout + run.observation_seconds
            )
        except asyncio.TimeoutError:
            run.timed_out = True


async def capture(args: argparse.Namespace) -> None:
    certificate = generate_certificate()
    names = list(SCENARIOS) if args.scenario == ["all"] else args.scenario
    args.output_dir.mkdir(parents=True, exist_ok=True)
    server = TcpServer(certificate)
    await server.start(args.listen)
    try:
        for name in names:
            scenario = SCENARIOS[name]
            runs = []
            launch_arguments = ""
            plan = None
            listen = ""
            for _ in range(args.repeat):
                token = secrets.token_hex(8)
                run = CookieRun(token, args.observation)
                if scenario.protocol == "h3":
                    async with serving_http3(run, args.listen, certificate) as port:
                        plan = h3_launch_plan(args, certificate, port)
                        url = f"https://{HOSTNAME}:{port}/start?run={token}"
                        await wait_for_run(run, plan, url, args.run_timeout)
                        await asyncio.sleep(0.2)
                    launch_arguments = (
                        plan.recorded_arguments(url)
                        .replace(certificate.spki_sha256_base64, "<certificate-spki>")
                        .replace(f":{port}", ":<port>")
                        .replace(token, "<token>")
                    )
                    listen = f"{args.listen}:<port>"
                else:
                    tls_port = server.tls_address[1]
                    plan = tcp_launch_plan(args, certificate, args.listen, tls_port)
                    if scenario.protocol == "h2":
                        url = f"https://{HOSTNAME}:{tls_port}/start?run={token}"
                    else:
                        host, port = server.plain_address
                        url = f"http://{host}:{port}/start?run={token}"
                    server.run = run
                    try:
                        await wait_for_run(run, plan, url, args.run_timeout)
                    finally:
                        server.run = None
                        server.drop_connections()
                    launch_arguments = (
                        plan.recorded_arguments(url)
                        .replace(certificate.spki_sha256_base64, "<certificate-spki>")
                        .replace(token, "<token>")
                    )
                    listen = "tls {}:{} plain {}:{}".format(
                        *server.tls_address, *server.plain_address
                    )
                runs.append(run)
            assert plan is not None
            metadata_ = CaptureMetadata(
                client=args.client or plan.client_name,
                client_version=args.client_version,
                operating_system=args.operating_system,
                listen_address=listen,
                launch_mode=plan.launch_mode,
                launch_arguments=launch_arguments,
                firefox_preferences=render_preferences(plan.firefox_preferences)
                or "none",
                profile_files=",".join(name for name, _ in plan.profile_files)
                or "none",
            )
            write_text_fixture(
                args.output_dir / f"crumbs-{name}.txt",
                fixture(scenario, runs, metadata_, 4096),
            )
            timed_out = sum(run.timed_out for run in runs)
            print(f"captured {name} ({timed_out} timed out)", file=sys.stderr)
    finally:
        await server.close()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=(*BROWSERS, "manual"), required=True)
    parser.add_argument("--browser-path", type=Path)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--scenario", nargs="+", default=["all"])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--run-timeout", type=float, default=30.0)
    parser.add_argument("--observation", type=float, default=0.5)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.browser != "manual" and args.browser_path is None:
        parser.error("--browser-path is required unless --browser manual")
    unknown = sorted(set(args.scenario) - set(SCENARIOS) - {"all"})
    if unknown or ("all" in args.scenario and len(args.scenario) > 1):
        parser.error(f"unknown or mixed scenarios: {', '.join(unknown) or 'all'}")
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    try:
        loopback = ipaddress.ip_address(args.listen).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        parser.error("the capture listener must be a loopback address")
    for package, version in SUPPORTED.items():
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    asyncio.run(capture(args))


if __name__ == "__main__":
    main()
