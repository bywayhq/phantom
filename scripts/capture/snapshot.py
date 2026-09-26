"""Record a browser's connection fingerprint from one launch.

One run serves `server.phantom.test` on one loopback port number, over TLS/TCP
(ALPN `h2` and `http/1.1`) and over QUIC (`h3`), and serves plaintext
HTTP/1.1 on a second port. The browser opens `/`, whose response asks for
every user-agent client hint with `Accept-CH` and `Critical-CH`. The page
fetches `/fetch`; the server answers with `Alt-Svc` naming the QUIC listener,
then sends GOAWAY, so the next navigation (`/next`) needs a new connection
and can take the learned `h3` alternative. That page fetches `/fetch` again
and navigates to `/plain` on the plaintext port, whose page fetches `/done`.

Each run writes one `format=phantom-snapshot-v1` file. The lines under the
`tls.` and `quic_client_hello.` prefixes are complete `phantom-client-hello-v2`
and `phantom-quic-client-hello-v1` fixtures; `--split` writes them out.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import secrets
import socket
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .browser_launch import (
    CHROMIUM_BROWSERS,
    CLIENT_NAMES,
    DESKTOP_CHROMIUM_BROWSERS,
    BrowserDriver,
    LaunchPlan,
    render_preferences,
)
from .client_hints import (
    USER_AGENT_HINTS,
    HintRun,
    Navigation,
    derived_hints,
    is_hint,
    validate_value,
)
from .cookie_crumbs import (
    CaptureMetadata,
    RequestRecord,
    capture_tool,
    check_field,
    content_type,
    firefox_cert_override,
    h2_request_lines,
    h3_request_lines,
    milliseconds,
)
from .fixture_file import write_text_fixture
from .http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    Certificate,
    ClientHello,
    ConnectionRecord,
    HeaderBlock,
    PlainChannel,
    TlsChannel,
    analyze_http2,
    frame_details,
    generate_certificate,
    server_context,
)
from .http3_wire import capture_request_snapshot, first_frame, unidirectional_stream
from .quic_resumption import QUIC_TRANSPORT_PARAMETERS, parse_client_hello

FORMAT = "phantom-snapshot-v1"
SUPPORTED = {"h2": "4.4.1", "hpack": "4.2.0", "aioquic": "1.3.0"}
HOST = "127.0.0.1"
DESKTOP_BROWSERS = (*DESKTOP_CHROMIUM_BROWSERS, "firefox")
# QUIC rejects a certificate from an unknown root unless
# `--origin-to-force-quic-on` names its host (see alt_svc_race.py). Port 9 is
# never requested, so every QUIC connection comes from the learned Alt-Svc.
DECOY_FORCE_QUIC_PORT = 9
MAX_REQUEST_HEAD = 64 * 1024
MAX_REQUESTS = 32
MAX_STREAM_CAPTURE = 1024 * 1024
MAX_PORT_ATTEMPTS = 64
RETIRE_DRAIN_SECONDS = 1.0
PARTIAL_MARKERS = {("timed_out", "true"), ("http3", "not-used")}
# Prefixes that hold a complete fixture of an existing format, and the file
# `--split` writes each to.
DROP_IN_SECTIONS = {
    "tls": "client-hello.txt",
    "quic_client_hello": "quic-client-hello.txt",
}
# The HTTP/3 startup lines `chrome_http3.py` writes before its evidence.
H3_HEADER_KEYS = {
    "format",
    "captured_at_unix",
    "client",
    "client_version",
    "operating_system",
    "hostname",
    "listen_address",
    "launch_mode",
    "launch_arguments",
    "capture_tool",
}


def page(script: str) -> bytes:
    return (
        "<!doctype html><meta charset=utf-8>"
        '<link rel=icon href="data:,">'
        f"<script>(async () => {{{script}}})();</script>\n"
    ).encode()


def fetch_then(token: str, destination: str) -> bytes:
    return page(
        f'const r = await fetch("/fetch?run={token}", {{cache: "no-store"}});'
        f'await r.text(); location.replace("{destination}");'
    )


# -- Recorded state --------------------------------------------------------


@dataclass
class RecordedClientHello(ClientHello):
    """A ClientHello tap that also keeps the raw bytes of its records."""

    raw: bytearray = field(default_factory=bytearray)

    def feed(self, data: bytes) -> None:
        if not self.complete:
            self.raw.extend(data)
        super().feed(data)


class SnapshotTlsChannel(TlsChannel):
    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.record.client_hello = RecordedClientHello()


@dataclass
class QuicRecord:
    """Client stream bytes and startup evidence of one QUIC connection."""

    accepted: float
    streams: dict[int, bytearray] = field(default_factory=dict)
    received: int = 0
    alpn: str | None = None
    quic_version: int | None = None
    client_hello: bytes | None = None
    server_qpack_max_table_capacity: int | None = None
    server_qpack_blocked_streams: int | None = None
    # The first request's HEADERS frame and QPACK stream prefixes when it
    # was decoded, and its decoded fields.
    first_request: object | None = None
    first_headers: list[tuple[bytes, bytes]] | None = None
    failure: str | None = None


@dataclass
class Request:
    protocol: str
    record: RequestRecord


@dataclass
class SnapshotRun:
    token: str
    port: int
    plain_port: int
    observation_seconds: float
    clock: Callable[[], float] = time.perf_counter
    started: float = field(init=False)
    connections: list[ConnectionRecord] = field(default_factory=list)
    quic_connections: list[QuicRecord] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)
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
            "/": "start",
            "/fetch": "fetch",
            "/next": "next",
            "/plain": "plain",
            "/done": "done",
        }.get(parts.path, "other")

    def record(self, protocol: str, request: RequestRecord) -> None:
        if len(self.requests) >= MAX_REQUESTS:
            raise ValueError("run exceeds the request limit")
        self.requests.append(Request(protocol, request))
        if request.kind == "done" and self.finished is None:
            self.finished = self.now()
            asyncio.get_running_loop().call_later(
                self.observation_seconds, self.done.set
            )

    def response(
        self, kind: str, listener: str
    ) -> tuple[int, bytes, list[tuple[bytes, bytes]]]:
        """Return the status, body, and extra fields for one request."""
        extra = []
        # Alt-Svc is withheld from `/` so that its fetch stays on HTTP/2.
        if listener != "plain" and kind != "start":
            extra.append((b"alt-svc", f'h3=":{self.port}"; ma=86400'.encode()))
        if kind == "start":
            hints = ", ".join(USER_AGENT_HINTS).encode()
            extra.extend([(b"accept-ch", hints), (b"critical-ch", hints)])
            return 200, fetch_then(self.token, f"/next?run={self.token}"), extra
        if kind == "next":
            # Firefox can load `/next` over TCP while it validates the
            # alternative; loading it once more gives an HTTP/3 navigation.
            repeats = sum(r.record.kind == "next" for r in self.requests)
            if listener == "tls" and repeats < 2:
                destination = f"/next?run={self.token}"
            else:
                destination = f"http://{HOST}:{self.plain_port}/plain?run={self.token}"
            return 200, fetch_then(self.token, destination), extra
        if kind == "plain":
            script = f'await fetch("/done?run={self.token}", {{cache: "no-store"}});'
            return 200, page(script), extra
        if kind in {"fetch", "done"}:
            return 200, b"ok", extra
        return 404, b"", extra


def response_fields(
    status: int, body: bytes, extra: Sequence[tuple[bytes, bytes]]
) -> list[tuple[bytes, bytes]]:
    return [
        (b":status", str(status).encode()),
        (b"content-type", content_type(body)),
        (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"),
        *extra,
    ]


# -- TCP: TLS (h2, http/1.1) and plaintext HTTP/1.1 ------------------------


async def retire(channel: PlainChannel) -> None:
    """Half-close, then read until the client closes.

    Closing a Windows socket with unread input sends RST, which can discard
    the response the browser has not read yet.
    """
    if channel.writer.can_write_eof():
        channel.writer.write_eof()

    async def drain() -> None:
        while await channel.read_raw():
            pass

    with contextlib.suppress(asyncio.TimeoutError, ConnectionError):
        await asyncio.wait_for(drain(), RETIRE_DRAIN_SECONDS)


async def serve_http1(channel, run: SnapshotRun, index: int, listener: str) -> None:
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
        lines = bytes(buffer[:end]).split(b"\r\n")
        del buffer[: end + 4]
        parts = lines[0].split(b" ")
        kind = run.classify(parts[1] if len(parts) == 3 else b"")
        record = RequestRecord(index, run.now(), kind, None, lines[0], lines[1:])
        run.record("http/1.1", record)
        status, body, extra = run.response(kind, listener)
        fields = response_fields(status, body, extra)[1:]
        # A TLS HTTP/1.1 connection is retired after `/fetch`, as HTTP/2 is.
        closing = listener == "tls" and kind == "fetch"
        if closing:
            fields.append((b"connection", b"close"))
        response = [f"HTTP/1.1 {status} Status".encode()]
        response.extend(name + b": " + value for name, value in fields)
        await channel.write(b"\r\n".join(response) + b"\r\n\r\n" + body)
        if closing:
            await retire(channel)
            return


async def serve_http2(channel, run: SnapshotRun, index: int) -> None:
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
        fetched = None
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                kind = run.classify(dict(event.headers).get(b":path", b""))
                run.record("h2", RequestRecord(index, run.now(), kind, event.stream_id))
                status, body, extra = run.response(kind, "tls")
                connection.send_headers(
                    event.stream_id,
                    response_fields(status, body, extra),
                    end_stream=not body,
                )
                if body:
                    connection.send_data(event.stream_id, body, end_stream=True)
                if kind == "fetch":
                    fetched = event.stream_id
            elif isinstance(event, h2.events.ConnectionTerminated):
                await channel.write(connection.data_to_send())
                return
        if fetched is not None:
            # GOAWAY makes the next navigation open a new connection, which
            # can take the Alt-Svc alternative from the `/fetch` response.
            connection.close_connection(last_stream_id=fetched)
            await channel.write(connection.data_to_send())
            await retire(channel)
            return
        await channel.write(connection.data_to_send())


class TcpListeners:
    """The TLS listener on the shared port and a plaintext HTTP/1.1 listener."""

    def __init__(self, run: SnapshotRun, certificate: Certificate) -> None:
        self.run = run
        self.context = server_context(certificate)
        # Without tickets every connection offers a fresh ClientHello;
        # tls_resumption.py records resumption.
        self.context.num_tickets = 0
        self.servers: list[asyncio.base_events.Server] = []
        self.writers: set[asyncio.StreamWriter] = set()

    async def start(self, tls_socket: socket.socket, plain_socket: socket.socket):
        self.servers = [
            await asyncio.start_server(self.handle_tls, sock=tls_socket),
            await asyncio.start_server(self.handle_plain, sock=plain_socket),
        ]

    async def close(self) -> None:
        for writer in list(self.writers):
            writer.transport.abort()
        self.writers.clear()
        for server in self.servers:
            server.close()
            await server.wait_closed()

    async def handle(self, listener: str, reader, writer) -> None:
        self.writers.add(writer)
        record = ConnectionRecord(listener=listener, accepted=self.run.now())
        self.run.connections.append(record)
        index = len(self.run.connections) - 1
        try:
            if listener == "plain":
                record.protocol = "http/1.1"
                channel = PlainChannel(reader, writer, record, self.run.now)
                await serve_http1(channel, self.run, index, "plain")
                return
            channel = SnapshotTlsChannel(
                self.context, reader, writer, record, self.run.now
            )
            await channel.handshake()
            record.protocol = record.alpn or "http/1.1"
            if record.alpn == "h2":
                await serve_http2(channel, self.run, index)
            else:
                await serve_http1(channel, self.run, index, "tls")
        except Exception as error:  # recorded: a capture keeps partial evidence
            record.failure = record.failure or type(error).__name__
        finally:
            self.writers.discard(writer)
            if not writer.transport.is_closing():
                writer.close()

    async def handle_tls(self, reader, writer) -> None:
        await self.handle("tls", reader, writer)

    async def handle_plain(self, reader, writer) -> None:
        await self.handle("plain", reader, writer)


# -- QUIC and HTTP/3 -------------------------------------------------------


def quic_protocol(run: SnapshotRun):
    from aioquic.asyncio import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection, Setting
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.events import ProtocolNegotiated, StreamDataReceived

    class SnapshotQuicProtocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self.record = QuicRecord(run.now())
            self.index = len(run.quic_connections)
            run.quic_connections.append(self.record)
            self.http: H3Connection | None = None

        def quic_event_received(self, event) -> None:
            try:
                self.handle(event)
            except Exception as error:  # recorded: a capture keeps partial evidence
                self.record.failure = self.record.failure or type(error).__name__

        def handle(self, event) -> None:
            record = self.record
            if isinstance(event, ProtocolNegotiated):
                record.alpn = event.alpn_protocol
                record.quic_version = self._quic._version
                # Set by quic_resumption.install_hooks.
                record.client_hello = getattr(
                    self._quic.tls, "_phantom_client_hello", None
                )
                self.http = H3Connection(self._quic)
                sent = self.http.sent_settings or {}
                record.server_qpack_max_table_capacity = sent.get(
                    Setting.QPACK_MAX_TABLE_CAPACITY, 0
                )
                record.server_qpack_blocked_streams = sent.get(
                    Setting.QPACK_BLOCKED_STREAMS, 0
                )
            if isinstance(event, StreamDataReceived):
                record.received += len(event.data)
                if record.received > MAX_STREAM_CAPTURE:
                    raise ValueError("connection exceeds the capture limit")
                stream = record.streams.setdefault(event.stream_id, bytearray())
                stream.extend(event.data)
            if self.http is None:
                return
            for http_event in self.http.handle_event(event):
                if isinstance(http_event, HeadersReceived):
                    self.request(http_event)

        def request(self, event) -> None:
            headers = [(bytes(name), bytes(value)) for name, value in event.headers]
            if self.record.first_request is None:
                self.record.first_request = capture_request_snapshot(
                    self.record.streams, event.stream_id
                )
                self.record.first_headers = headers
            kind = run.classify(dict(headers).get(b":path", b""))
            run.record(
                "h3",
                RequestRecord(
                    self.index, run.now(), kind, event.stream_id, decoded=headers
                ),
            )
            status, body, extra = run.response(kind, "quic")
            assert self.http is not None
            self.http.send_headers(
                event.stream_id,
                response_fields(status, body, extra),
                end_stream=not body,
            )
            if body:
                self.http.send_data(event.stream_id, body, end_stream=True)
            self.transmit()

    return SnapshotQuicProtocol


def reserve_shared_port() -> tuple[socket.socket, socket.socket]:
    """Bind TCP and UDP on one ephemeral loopback port number.

    Windows excludes blocks of UDP ports inside its ephemeral TCP range and
    blocks of TCP ports inside its ephemeral UDP range, and hands out ports
    close to the previous one, so attempts alternate which protocol picks.
    """
    for attempt in range(MAX_PORT_ATTEMPTS):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        first, second = (tcp, udp) if attempt % 2 == 0 else (udp, tcp)
        try:
            first.bind((HOST, 0))
            second.bind((HOST, first.getsockname()[1]))
        except OSError:
            tcp.close()
            udp.close()
            continue
        tcp.listen(64)
        tcp.setblocking(False)
        udp.setblocking(False)
        return tcp, udp
    raise OSError("no loopback port is free for both TCP and UDP")


@contextlib.asynccontextmanager
async def serving(certificate: Certificate, token: str, observation: float):
    """Serve one run: TLS and QUIC on one port number, plaintext on another."""
    from aioquic.asyncio.server import QuicServer
    from aioquic.h3.connection import H3_ALPN
    from aioquic.quic.configuration import QuicConfiguration

    from .quic_resumption import install_hooks, load_certificate

    tcp, udp = reserve_shared_port()
    plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plain.bind((HOST, 0))
    plain.listen(64)
    plain.setblocking(False)
    run = SnapshotRun(token, tcp.getsockname()[1], plain.getsockname()[1], observation)
    listeners = TcpListeners(run, certificate)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    load_certificate(configuration, certificate)
    restore = install_hooks(accept_early_data=True)
    quic = None
    try:
        await listeners.start(tcp, plain)
        protocol = quic_protocol(run)
        _, quic = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: QuicServer(configuration=configuration, create_protocol=protocol),
            sock=udp,
        )
        yield run
    finally:
        if quic is not None:
            quic.close()
        else:
            udp.close()
        await listeners.close()
        restore()


# -- Rendering -------------------------------------------------------------


def client_hello_records(raw: bytes) -> list[bytes]:
    """Split the TLS records that carry the first handshake message."""
    records = []
    handshake = bytearray()
    offset = 0
    while offset + 5 <= len(raw) and raw[offset] == 22:
        end = offset + 5 + int.from_bytes(raw[offset + 3 : offset + 5], "big")
        if end > len(raw):
            break
        records.append(bytes(raw[offset:end]))
        handshake.extend(raw[offset + 5 : end])
        offset = end
        if len(handshake) >= 4 and len(handshake) >= 4 + int.from_bytes(
            handshake[1:4], "big"
        ):
            return records
    raise ValueError("the tapped bytes hold no complete ClientHello")


def hello_message(records: Sequence[bytes]) -> bytes:
    handshake = b"".join(record[5:] for record in records)
    return handshake[: 4 + int.from_bytes(handshake[1:4], "big")]


def u16_list(body: bytes) -> list[int]:
    return [int.from_bytes(body[i : i + 2], "big") for i in range(0, len(body) - 1, 2)]


def summary_lines(message: bytes) -> list[str]:
    """The summary fields in `capture_client_hello`'s order and spelling."""
    shape = parse_client_hello(message)

    def body(kind: int) -> bytes:
        return shape.extension(kind) or b""

    def u16s(values: Sequence[int]) -> str:
        return ",".join(f"0x{value:04x}" for value in values)

    alpn = body(0x0010)[2:]
    protocols = []
    while alpn:
        protocols.append(alpn[1 : 1 + alpn[0]].hex())
        alpn = alpn[1 + alpn[0] :]
    formats = body(0x000B) or bytes(1)
    name = body(0x0000)
    return [
        f"legacy_version=0x{int.from_bytes(message[4:6], 'big'):04x}",
        f"cipher_suites={u16s(shape.cipher_suites)}",
        f"extension_types={u16s(shape.extension_types)}",
        f"supported_groups={u16s(u16_list(body(0x000A)[2:]))}",
        "ec_point_formats="
        + ",".join(f"0x{value:02x}" for value in formats[1 : 1 + formats[0]]),
        f"signature_algorithms={u16s(u16_list(body(0x000D)[2:]))}",
        f"alpn_protocols_hex={','.join(protocols)}",
        f"supported_versions={u16s(u16_list(body(0x002B)[1:]))}",
        f"key_share_groups={u16s(shape.key_share_groups())}",
        f"server_name_hex={name[5:].hex() if len(name) > 5 else ''}",
    ]


def tls_lines(run: SnapshotRun, capture: CaptureMetadata) -> list[str]:
    """The first complete TCP ClientHello as a `phantom-client-hello-v2` fixture."""
    for record in run.connections:
        hello = record.client_hello
        if isinstance(hello, RecordedClientHello) and hello.complete:
            records = client_hello_records(bytes(hello.raw))
            break
    else:
        raise ValueError("no TCP connection carried a complete ClientHello")
    summary = summary_lines(hello_message(records))
    hostname = bytes.fromhex(summary[-1].split("=", 1)[1]).decode("ascii", "replace")
    lines = [
        "format=phantom-client-hello-v2",
        f"captured_at_unix={int(time.time())}",
        f"browser={capture.client}",
        f"browser_version={capture.client_version}",
        f"operating_system={capture.operating_system}",
        f"hostname={hostname}",
        f"listen_address={HOST}:{run.port}",
        f"launch_mode={capture.launch_mode}",
        f"launch_arguments={capture.launch_arguments}",
        f"record_count={len(records)}",
        *(f"record_{i}_hex={record.hex()}" for i, record in enumerate(records)),
        *summary,
    ]
    return [f"tls.{line}" for line in lines]


def http2_lines(run: SnapshotRun, analyses: dict) -> list[str]:
    """Client frames of the first HTTP/2 connection; startup ones in raw form."""
    index, record = next(
        (i, r)
        for i, r in enumerate(run.connections)
        if r.protocol == "h2" and r.client_chunks
    )
    stream = record.client_stream()
    if not stream.startswith(CONNECTION_PREFACE):
        raise ValueError("client stream does not start with the H2 preface")
    startup = []
    offset = len(CONNECTION_PREFACE)
    # The frames before the first HEADERS, as `capture_http2_tls` keeps them.
    while offset + 9 <= len(stream) and stream[offset + 3] != 0x1:
        end = offset + 9 + int.from_bytes(stream[offset : offset + 3], "big")
        startup.append(stream[offset:end])
        offset = end
    analyses.setdefault(index, analyze_http2(record))
    client = [f for f in analyses[index].frames if f.direction == "client"]
    settings = next(f for f in client if f.type_name == "SETTINGS")
    window = next(
        (f for f in client if f.type_name == "WINDOW_UPDATE" and f.stream_id == 0),
        None,
    )
    lines = [
        f"connection={index}",
        f"preface_hex={CONNECTION_PREFACE.hex()}",
        f"frame_count={len(startup)}",
        *(f"frame_{i}_hex={frame.hex()}" for i, frame in enumerate(startup)),
        "initial_settings="
        + ",".join(
            f"0x{int.from_bytes(settings.payload[i : i + 2], 'big'):04x}:"
            f"{int.from_bytes(settings.payload[i + 2 : i + 6], 'big')}"
            for i in range(0, len(settings.payload) - 5, 6)
        ),
        "connection_window_update="
        + ("none" if window is None else frame_details(window)[0].split(":")[1]),
        f"client_frame_count={len(client)}",
    ]
    for position, frame in enumerate(client):
        details = "".join(f",{item}" for item in frame_details(frame))
        lines.append(
            f"client_frame_{position}=type:{frame.type_name},"
            f"flags:0x{frame.flags:02x},stream:{frame.stream_id}{details}"
        )
    return [f"h2.{line}" for line in lines]


def h3_lines(run: SnapshotRun, capture: CaptureMetadata) -> list[str]:
    """The QUIC ClientHello fixture and the first HTTP/3 connection's startup.

    The startup lines are those of `phantom-http3-client-startup-v2` without
    its header. They are not a startup fixture: the first request is the
    script navigation to `/next`, not a first command-line navigation.
    """
    from .chrome_http3 import Capture

    record = next(r for r in run.quic_connections if r.first_request is not None)
    if record.client_hello is None:
        raise ValueError("the QUIC connection's ClientHello was not recorded")
    request = record.first_request
    state = Capture(
        complete=asyncio.Event(),
        metadata=argparse.Namespace(
            client=capture.client,
            client_version=capture.client_version,
            operating_system=capture.operating_system,
            hostname=HOSTNAME,
            listen=f"{HOST}:{run.port}",
            launch_mode=capture.launch_mode,
            launch_arguments=capture.launch_arguments,
        ),
        streams=record.streams,
        transport_parameters=parse_client_hello(record.client_hello).extension(
            QUIC_TRANSPORT_PARAMETERS
        ),
        request_stream_id=request.stream_id,
        request_headers_frame=request.headers_frame,
        request_headers_payload=request.headers_payload,
        request_qpack_encoder_stream_prefix=request.qpack_encoder_stream_prefix,
        request_qpack_decoder_stream_prefix=request.qpack_decoder_stream_prefix,
        headers=record.first_headers,
        server_qpack_max_table_capacity=record.server_qpack_max_table_capacity,
        server_qpack_blocked_streams=record.server_qpack_blocked_streams,
        alpn=record.alpn,
        quic_version=record.quic_version,
        client_hello=record.client_hello,
    )
    frame = first_frame(unidirectional_stream(record.streams, 0), has_stream_type=True)
    if frame is None or frame[0] != 0x4:
        raise ValueError("HTTP/3 control stream did not start with SETTINGS")
    state.settings_frame, state.settings_payload = frame[1], frame[2]
    lines = [
        f"quic_client_hello.{line}"
        for line in state.client_hello_fixture().split("\n")
        if line
    ]
    for line in state.fixture().splitlines():
        if line.split("=", 1)[0] not in H3_HEADER_KEYS:
            lines.append(f"h3.{line}")
    return lines


def h2_block(run: SnapshotRun, record: RequestRecord, analyses: dict) -> HeaderBlock:
    if record.connection not in analyses:
        analyses[record.connection] = analyze_http2(run.connections[record.connection])
    return next(
        block
        for block in analyses[record.connection].client_headers
        if block.stream_id == record.stream_id
    )


def request_fields(
    run: SnapshotRun, request: Request, analyses: dict
) -> list[tuple[bytes, bytes]]:
    record = request.record
    if request.protocol == "h3":
        return list(record.decoded)
    if request.protocol == "h2":
        return [
            (item.name, item.value)
            for item in h2_block(run, record, analyses).fields
            if item.name is not None and item.value is not None
        ]
    return [
        (name.strip(), value.strip())
        for name, _, value in (line.partition(b":") for line in record.header_lines)
    ]


def request_lines(key: str, run: SnapshotRun, request: Request, analyses) -> list[str]:
    record = request.record
    stream = "none" if record.stream_id is None else str(record.stream_id)
    lines = [
        f"{key}=protocol:{request.protocol},connection:{record.connection},"
        f"stream:{stream},kind:{record.kind},"
        f"received_ms:{milliseconds(record.received)}"
    ]
    if request.protocol == "h2":
        block = h2_block(run, record, analyses)
        priority = block.priority
        lines.append(
            f"{key}_headers=flags:0x{block.flags:02x},priority:"
            + (
                "none"
                if priority is None
                else f"exclusive:{str(priority.exclusive).lower()},"
                f"depends_on:{priority.depends_on},weight:{priority.weight}"
            )
        )
        lines.extend(h2_request_lines(key, run, record, analyses))
    elif request.protocol == "h3":
        quic = run.quic_connections[record.connection]
        capacity = quic.server_qpack_max_table_capacity or 0
        lines.extend(h3_request_lines(key, run, record, record.decoded, capacity))
    else:
        fields = request_fields(run, request, analyses)
        for name, value in fields:
            check_field(name, value)
        lines.append(f"{key}_line_hex={record.request_line.hex()}")
        lines.append(f"{key}_field_order=" + ",".join(n.decode() for n, _ in fields))
        lines.append(f"{key}_header_count={len(record.header_lines)}")
        lines.extend(
            f"{key}_header_{position}={line.hex()}"
            for position, line in enumerate(record.header_lines)
        )
    return lines


def hint_lines(run: SnapshotRun, analyses: dict) -> list[str]:
    """Client hints as `phantom-client-hints-v2` lines.

    The first navigation carries the default hints. The second is Chromium's
    `Critical-CH` retry of `/` when there is one, otherwise `/next`, which
    carries the hints the origin asked for with `Accept-CH`.
    """
    starts = [r for r in run.requests if r.record.kind == "start"]
    following = [r for r in run.requests if r.record.kind == "next"]
    if not starts or (len(starts) == 1 and not following):
        raise ValueError("the run has no second navigation to derive hints from")
    second, source = (
        (starts[1], "critical-ch-retry") if len(starts) > 1 else (following[0], "next")
    )

    def navigation(request: Request) -> Navigation:
        fields = request_fields(run, request, analyses)
        return Navigation(
            tuple(name for name, _ in fields),
            tuple(
                (name.lower().decode("ascii"), value)
                for name, value in fields
                if is_hint(name, USER_AGENT_HINTS)
            ),
        )

    hint_run = HintRun(
        run.token, USER_AGENT_HINTS, navigation(starts[0]), navigation(second)
    )
    hints = derived_hints([hint_run])
    return [
        f"hints_second_navigation={source}",
        f"hints_second_protocol={second.protocol}",
        f"hint_count={len(hints)}",
        *(
            f"hint_{index}={delivery}|{name}|{validate_value(value)}"
            for index, (delivery, name, value) in enumerate(hints)
        ),
    ]


def evidence(key: str, render: Callable[[], list[str]]) -> list[str]:
    """Render one part of a run; a part that does not parse is noted, not fatal.

    A timed-out run keeps whatever arrived, which can end mid-frame.
    """
    try:
        return render()
    except (ValueError, KeyError, IndexError, StopIteration, RuntimeError) as error:
        message = " ".join(str(error).split())
        return [f"{key}_error={type(error).__name__}: {message}"]


def render_snapshot(run: SnapshotRun, capture: CaptureMetadata) -> str:
    http3 = any(record.first_request for record in run.quic_connections)
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
        f"timed_out={str(run.timed_out).lower()}",
        f"finished_ms={milliseconds(run.finished)}",
        f"http3={'used' if http3 else 'not-used'}",
        f"tcp_connection_count={len(run.connections)}",
    ]
    for index, record in enumerate(run.connections):
        hello = record.client_hello
        lines.append(
            f"tcp_connection_{index}=listener:{record.listener},"
            f"accepted_ms:{milliseconds(record.accepted)},"
            f"protocol:{record.protocol or 'none'},"
            f"client_hello:{'complete' if hello and hello.complete else 'none'},"
            f"failure:{record.failure or 'none'}"
        )
    lines.append(f"quic_connection_count={len(run.quic_connections)}")
    for index, record in enumerate(run.quic_connections):
        lines.append(
            f"quic_connection_{index}=accepted_ms:{milliseconds(record.accepted)},"
            f"alpn:{record.alpn or 'none'},"
            f"client_hello:{'complete' if record.client_hello else 'none'},"
            f"failure:{record.failure or 'none'}"
        )
    analyses: dict = {}
    lines.append(f"request_count={len(run.requests)}")
    for index, request in enumerate(run.requests):
        key = f"request_{index}"
        lines.extend(
            evidence(key, lambda k=key, r=request: request_lines(k, run, r, analyses))
        )
    lines.extend(evidence("hints", lambda: hint_lines(run, analyses)))
    lines.extend(evidence("tls", lambda: tls_lines(run, capture)))
    lines.extend(evidence("h2", lambda: http2_lines(run, analyses)))
    if http3:
        lines.extend(evidence("h3", lambda: h3_lines(run, capture)))
    return "\n".join(lines) + "\n"


def problems(text: str) -> list[str]:
    """What makes a snapshot partial: a timeout, no HTTP/3, or unparsed parts."""
    found = []
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.endswith("_error") or (key, value) in PARTIAL_MARKERS:
            found.append(line)
    return found


def split_snapshot(text: str) -> dict[str, str]:
    """Return each complete fixture a snapshot embeds, keyed by file name."""
    sections: dict[str, list[str]] = {}
    for line in text.splitlines():
        prefix, dot, rest = line.partition(".")
        if dot and prefix in DROP_IN_SECTIONS:
            sections.setdefault(DROP_IN_SECTIONS[prefix], []).append(rest)
    return {name: "\n".join(lines) + "\n" for name, lines in sections.items()}


# -- Launch ----------------------------------------------------------------


def launch_plan(
    browser: str, executable: Path, headless: bool, port: int, certificate: Certificate
) -> LaunchPlan:
    if browser in CHROMIUM_BROWSERS:
        return LaunchPlan(
            browser,
            executable,
            headless,
            (
                "--enable-quic",
                f"--origin-to-force-quic-on={HOSTNAME}:{DECOY_FORCE_QUIC_PORT}",
                # Every other name fails to resolve, so background traffic
                # never leaves the machine; the listener's own address, which
                # `/plain` uses, is left alone.
                f"--host-resolver-rules=MAP {HOSTNAME} {HOST}, MAP * ~NOTFOUND, "
                f"EXCLUDE {HOST}",
                "--ignore-certificate-errors-spki-list="
                + certificate.spki_sha256_base64,
            ),
        )
    return LaunchPlan(
        "firefox",
        executable,
        headless,
        firefox_preferences=(
            ("network.dns.localDomains", HOSTNAME),
            ("network.dns.disableIPv6", True),
            ("network.http.http3.enable", True),
            # The overridden test certificate counts as a third-party root,
            # which otherwise makes Firefox close HTTP/3.
            ("network.http.http3.disable_when_third_party_roots_found", False),
        ),
        profile_files=(
            ("cert_override.txt", firefox_cert_override(HOSTNAME, port, certificate)),
        ),
    )


async def capture_run(args: argparse.Namespace, certificate: Certificate) -> str:
    token = secrets.token_hex(8)
    async with serving(certificate, token, args.observation) as run:
        plan = launch_plan(
            args.browser, args.browser_path, not args.headful, run.port, certificate
        )
        url = f"https://{HOSTNAME}:{run.port}/?run={token}"
        async with BrowserDriver(plan, url):
            try:
                await asyncio.wait_for(
                    run.done.wait(), timeout=args.run_timeout + args.observation
                )
            except asyncio.TimeoutError:
                run.timed_out = True
    capture = CaptureMetadata(
        client=CLIENT_NAMES[args.browser],
        client_version=args.client_version,
        operating_system=args.operating_system,
        listen_address=f"tls+quic {HOST}:{run.port} plain {HOST}:{run.plain_port}",
        launch_mode=plan.launch_mode,
        launch_arguments=plan.recorded_arguments(url)
        .replace(certificate.spki_sha256_base64, "<certificate-spki>")
        .replace(f":{run.port}", ":<port>")
        .replace(token, "<token>"),
        firefox_preferences=render_preferences(plan.firefox_preferences) or "none",
        profile_files=",".join(name for name, _ in plan.profile_files) or "none",
    )
    return render_snapshot(run, capture)


async def capture(args: argparse.Namespace) -> int:
    from .alt_svc_race import ignore_peer_resets

    asyncio.get_running_loop().set_exception_handler(ignore_peer_resets)
    certificate = generate_certificate()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    partial = False
    for index in range(1, args.repeat + 1):
        began = time.perf_counter()
        text = await capture_run(args, certificate)
        path = args.output_dir / f"snapshot-{index}.txt"
        write_text_fixture(path, text)
        found = problems(text)
        partial |= bool(found)
        print(
            f"run {index}: {time.perf_counter() - began:.1f} s -> {path}",
            *found,
            sep="\n  ",
            file=sys.stderr,
        )
    return 1 if partial and not args.allow_partial else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--browser", choices=DESKTOP_BROWSERS)
    parser.add_argument("--browser-path", type=Path)
    parser.add_argument("--client-version")
    parser.add_argument("--operating-system")
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--run-timeout", type=float, default=20.0)
    parser.add_argument("--observation", type=float, default=0.3)
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="exit 0 even when a run timed out, missed HTTP/3, or has *_error lines",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--split",
        type=Path,
        metavar="SNAPSHOT",
        help="write the complete fixtures a snapshot embeds into --output-dir",
    )
    args = parser.parse_args(argv)
    if args.split is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name, body in split_snapshot(args.split.read_text("utf-8")).items():
            write_text_fixture(args.output_dir / name, body)
        return 0
    for option in ("browser", "browser_path", "client_version", "operating_system"):
        if getattr(args, option) is None:
            parser.error(f"--{option.replace('_', '-')} is required")
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    for package, version in SUPPORTED.items():
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    return asyncio.run(capture(args))


if __name__ == "__main__":
    sys.exit(main())
