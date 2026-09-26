"""Record a browser's connection fingerprint from one launch.

One run serves `server.phantom.test` on one loopback port number, over TLS/TCP
(ALPN `h2` and `http/1.1`) and over QUIC (`h3`), and serves plaintext
HTTP/1.1 on a second port. The browser opens `/`. Its response asks for every
user-agent client hint with `Accept-CH` and `Critical-CH`. The page fetches
`/fetch`; the server answers with `Alt-Svc` naming the QUIC listener, then
sends GOAWAY, so the page's next navigation (`/next`) needs a new
connection and can take the learned `h3` alternative. That page fetches
`/fetch` again and navigates to `/plain` on the plaintext port, whose page
fetches `/done`.

Each run writes one `format=phantom-snapshot-v1` file. The lines under the
`tls.`, `quic_client_hello.`, and `h3_startup.` prefixes are complete
`phantom-client-hello-v2`, `phantom-quic-client-hello-v1`, and
`phantom-http3-client-startup-v2` fixtures; `--split` writes them out.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import ipaddress
import os
import platform
import plistlib
import secrets
import socket
import subprocess
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
    RequestRecord,
    check_field,
    content_type,
    firefox_cert_override,
    h2_request_lines,
    h3_request_lines,
)
from .fixture_file import write_text_fixture
from .http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    Certificate,
    ClientHello,
    ConnectionRecord,
    PlainChannel,
    TlsChannel,
    analyze_http2,
    frame_details,
    generate_certificate,
    server_context,
)
from .http3_wire import (
    RequestSnapshot,
    capture_request_snapshot,
    first_frame,
    parse_settings,
    unidirectional_stream,
)

FORMAT = "phantom-snapshot-v1"
SUPPORTED = {"aioquic": "1.3.0", "h2": "4.4.1", "hpack": "4.2.0"}
DESKTOP_BROWSERS = (*DESKTOP_CHROMIUM_BROWSERS, "firefox")
# QUIC rejects a certificate from an unknown root unless
# `--origin-to-force-quic-on` names its host (see alt_svc_race.py). Port 9 is
# never requested, so every QUIC connection comes from the learned Alt-Svc.
DECOY_FORCE_QUIC_PORT = 9
ALT_SVC_MAX_AGE = 86400
MAX_REQUEST_HEAD = 64 * 1024
MAX_REQUESTS = 32
MAX_STREAM_CAPTURE = 1024 * 1024
MAX_PORT_ATTEMPTS = 64
SERVER_QPACK_MAX_TABLE_CAPACITY = 4096
# Split prefixes and the file each becomes.
LEGACY_SECTIONS = {
    "tls": "client-hello.txt",
    "quic_client_hello": "quic-client-hello.txt",
    "h3_startup": "http3-client-startup.txt",
}
TLS_GREASE = {0x0A0A + 0x1010 * index for index in range(16)}
EXTENSION_SERVER_NAME = 0x0000
EXTENSION_SUPPORTED_GROUPS = 0x000A
EXTENSION_EC_POINT_FORMATS = 0x000B
EXTENSION_SIGNATURE_ALGORITHMS = 0x000D
EXTENSION_ALPN = 0x0010
EXTENSION_SUPPORTED_VERSIONS = 0x002B
EXTENSION_KEY_SHARE = 0x0033

WINDOWS_PATHS = {
    "chrome": (
        "{ProgramFiles}/Google/Chrome/Application/chrome.exe",
        "{ProgramFiles(x86)}/Google/Chrome/Application/chrome.exe",
        "{LOCALAPPDATA}/Google/Chrome/Application/chrome.exe",
    ),
    "edge": (
        "{ProgramFiles(x86)}/Microsoft/Edge/Application/msedge.exe",
        "{ProgramFiles}/Microsoft/Edge/Application/msedge.exe",
    ),
    "brave": (
        "{ProgramFiles}/BraveSoftware/Brave-Browser/Application/brave.exe",
        "{LOCALAPPDATA}/BraveSoftware/Brave-Browser/Application/brave.exe",
    ),
    "firefox": (
        "{ProgramFiles}/Mozilla Firefox/firefox.exe",
        "{ProgramFiles(x86)}/Mozilla Firefox/firefox.exe",
    ),
}
MACOS_PATHS = {
    "chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "edge": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "brave": "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "opera": "/Applications/Opera.app/Contents/MacOS/Opera",
    "firefox": "/Applications/Firefox.app/Contents/MacOS/firefox",
}


# -- Pages -----------------------------------------------------------------


def page(script: str) -> bytes:
    return (
        "<!doctype html><meta charset=utf-8>"
        '<link rel=icon href="data:,">'
        f"<script>(async () => {{{script}}})();</script>\n"
    ).encode()


def start_page(token: str) -> bytes:
    return page(
        f'const r = await fetch("/fetch?run={token}", {{cache: "no-store"}});'
        "await r.text();"
        f'location.replace("/next?run={token}");'
    )


def next_page(token: str, destination: str) -> bytes:
    return page(
        f'const r = await fetch("/fetch?run={token}", {{cache: "no-store"}});'
        "await r.text();"
        f'location.replace("{destination}");'
    )


def plain_page(token: str) -> bytes:
    return page(f'await fetch("/done?run={token}", {{cache: "no-store"}});')


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
    transport_parameters: bytes | None = None
    client_hello: bytes | None = None
    server_qpack_max_table_capacity: int | None = None
    server_qpack_blocked_streams: int | None = None
    # The first request: its HEADERS frame and the QPACK stream prefixes at
    # the moment it was decoded, then the decoded fields.
    first_request: RequestSnapshot | None = None
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

    def alt_svc(self) -> bytes:
        return f'h3=":{self.port}"; ma={ALT_SVC_MAX_AGE}'.encode()

    def response(
        self, kind: str, protocol: str
    ) -> tuple[int, bytes, list[tuple[bytes, bytes]]]:
        """Return the status, body, and extra fields for one request."""
        extra = []
        # Alt-Svc is withheld from `/` so that its fetch stays on HTTP/2.
        if protocol != "plain" and kind != "start":
            extra.append((b"alt-svc", self.alt_svc()))
        if kind == "start":
            hints = ", ".join(USER_AGENT_HINTS).encode()
            extra.extend([(b"accept-ch", hints), (b"critical-ch", hints)])
            return 200, start_page(self.token), extra
        if kind == "next":
            plain = f"http://127.0.0.1:{self.plain_port}/plain?run={self.token}"
            # Firefox can load `/next` over TCP while it validates the
            # alternative; loading it once more gives an HTTP/3 navigation.
            repeats = sum(r.record.kind == "next" for r in self.requests)
            again = protocol == "tls" and repeats < 2
            destination = f"/next?run={self.token}" if again else plain
            return 200, next_page(self.token, destination), extra
        if kind == "plain":
            return 200, plain_page(self.token), extra
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
        head = bytes(buffer[:end])
        del buffer[: end + 4]
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ")
        target = parts[1] if len(parts) == 3 else b""
        kind = run.classify(target)
        run.record(
            "http/1.1",
            RequestRecord(index, run.now(), kind, None, lines[0], lines[1:]),
        )
        status, body, extra = run.response(kind, listener)
        fields = response_fields(status, body, extra)[1:]
        # A TLS HTTP/1.1 connection is retired after `/fetch`, as HTTP/2 is.
        retire = listener == "tls" and kind == "fetch"
        if retire:
            fields.append((b"connection", b"close"))
        response = [f"HTTP/1.1 {status} Status".encode()]
        response.extend(name + b": " + value for name, value in fields)
        await channel.write(b"\r\n".join(response) + b"\r\n\r\n" + body)
        if retire:
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
        retire = None
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                fields = dict(event.headers)
                kind = run.classify(fields.get(b":path", b""))
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
                    retire = event.stream_id
            elif isinstance(event, h2.events.ConnectionTerminated):
                await channel.write(connection.data_to_send())
                return
        if retire is not None:
            # GOAWAY makes the next navigation open a new connection, which
            # can take the Alt-Svc alternative learned from `/`.
            connection.close_connection(last_stream_id=retire)
            await channel.write(connection.data_to_send())
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

    def accept(self, listener: str, writer) -> tuple[ConnectionRecord, int]:
        self.writers.add(writer)
        record = ConnectionRecord(listener=listener, accepted=self.run.now())
        self.run.connections.append(record)
        return record, len(self.run.connections) - 1

    async def handle_tls(self, reader, writer) -> None:
        record, index = self.accept("tls", writer)
        channel = SnapshotTlsChannel(self.context, reader, writer, record, self.run.now)
        try:
            await channel.handshake()
            record.protocol = record.alpn or "http/1.1"
            if record.alpn == "h2":
                await serve_http2(channel, self.run, index)
            else:
                await serve_http1(channel, self.run, index, "tls")
        except Exception as error:  # recorded: a capture keeps partial evidence
            record.failure = record.failure or type(error).__name__
        finally:
            self.release(writer)

    async def handle_plain(self, reader, writer) -> None:
        record, index = self.accept("plain", writer)
        record.protocol = "http/1.1"
        channel = PlainChannel(reader, writer, record, self.run.now)
        try:
            await serve_http1(channel, self.run, index, "plain")
        except Exception as error:  # recorded: a capture keeps partial evidence
            record.failure = record.failure or type(error).__name__
        finally:
            self.release(writer)

    def release(self, writer) -> None:
        self.writers.discard(writer)
        if not writer.transport.is_closing():
            writer.close()


# -- QUIC and HTTP/3 -------------------------------------------------------

_HOOKS_INSTALLED = False


def install_quic_hooks() -> None:
    """Keep each server connection's raw transport parameters and ClientHello.

    aioquic parses both and discards the bytes. The ClientHello is the first
    complete message of the Initial CRYPTO stream, before the TLS engine
    consumes it.
    """
    global _HOOKS_INSTALLED
    if _HOOKS_INSTALLED:
        return
    from aioquic import tls

    from .chrome_http3 import patch_transport_parameter_capture

    patch_transport_parameter_capture()
    original = tls.Context.handle_message

    def handle_message(self, input_data: bytes, output_buf) -> None:
        if not self._is_client and getattr(self, "_phantom_client_hello", None) is None:
            pending = bytes(self._receive_buffer) + bytes(input_data)
            if len(pending) >= 4 and pending[0] == 1:
                length = 4 + int.from_bytes(pending[1:4], "big")
                if len(pending) >= length:
                    self._phantom_client_hello = pending[:length]
        original(self, input_data, output_buf)

    tls.Context.handle_message = handle_message
    _HOOKS_INSTALLED = True


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
                record.transport_parameters = getattr(
                    self._quic, "_phantom_transport_parameters", None
                )
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
                record.streams.setdefault(event.stream_id, bytearray()).extend(
                    event.data
                )
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
            fields = dict(headers)
            kind = run.classify(fields.get(b":path", b""))
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


async def start_quic(run: SnapshotRun, certificate: Certificate, udp: socket.socket):
    from aioquic.asyncio.server import QuicServer
    from aioquic.h3.connection import H3_ALPN
    from aioquic.quic.configuration import QuicConfiguration

    from .quic_resumption import load_certificate

    install_quic_hooks()
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    load_certificate(configuration, certificate)
    protocol = quic_protocol(run)
    _, server = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: QuicServer(configuration=configuration, create_protocol=protocol),
        sock=udp,
    )
    return server


def reserve_shared_port(host: str) -> tuple[socket.socket, socket.socket]:
    """Bind TCP and UDP on one ephemeral port number.

    Windows excludes blocks of UDP ports inside its ephemeral TCP range, and
    blocks of TCP ports inside its ephemeral UDP range, and hands out
    ephemeral ports close to the previous one. Attempts therefore alternate
    which protocol picks the port, so a run of excluded ports on one side
    does not exhaust them.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for attempt in range(MAX_PORT_ATTEMPTS):
        tcp = socket.socket(family, socket.SOCK_STREAM)
        udp = socket.socket(family, socket.SOCK_DGRAM)
        first, second = (tcp, udp) if attempt % 2 == 0 else (udp, tcp)
        try:
            first.bind((host, 0))
            second.bind((host, first.getsockname()[1]))
        except OSError:
            tcp.close()
            udp.close()
            continue
        tcp.listen(64)
        tcp.setblocking(False)
        udp.setblocking(False)
        return tcp, udp
    raise OSError("no loopback port is free for both TCP and UDP")


def listening_socket(host: str) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sock.listen(64)
    sock.setblocking(False)
    return sock


@contextlib.asynccontextmanager
async def serving(host: str, certificate: Certificate, token: str, observation: float):
    """Serve one run: TLS and QUIC on one port number, plaintext on another."""
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("the capture listener must be a loopback address")
    tcp, udp = reserve_shared_port(host)
    plain = listening_socket(host)
    run = SnapshotRun(token, tcp.getsockname()[1], plain.getsockname()[1], observation)
    listeners = TcpListeners(run, certificate)
    quic = None
    try:
        await listeners.start(tcp, plain)
        quic = await start_quic(run, certificate, udp)
        yield run
    finally:
        if quic is not None:
            quic.close()
        else:
            udp.close()
        await listeners.close()


# -- TLS ClientHello -------------------------------------------------------


def client_hello_records(raw: bytes) -> list[bytes]:
    """Split the TLS records that carry the first handshake message."""
    records = []
    handshake = bytearray()
    offset = 0
    while offset + 5 <= len(raw) and raw[offset] == 22:
        length = int.from_bytes(raw[offset + 3 : offset + 5], "big")
        end = offset + 5 + length
        if end > len(raw):
            break
        records.append(bytes(raw[offset:end]))
        handshake.extend(raw[offset + 5 : end])
        offset = end
        complete = 4 + int.from_bytes(handshake[1:4], "big")
        if len(handshake) >= 4 and len(handshake) >= complete:
            return records
    raise ValueError("the tapped bytes hold no complete ClientHello")


@dataclass(frozen=True)
class HelloSummary:
    """The ClientHello fields `phantom-client-hello-v2` retains."""

    legacy_version: int
    cipher_suites: tuple[int, ...]
    extensions: tuple[tuple[int, bytes], ...]

    @classmethod
    def parse(cls, message: bytes) -> HelloSummary:
        from .quic_resumption import parse_client_hello

        shape = parse_client_hello(message)
        version = int.from_bytes(message[4:6], "big")
        return cls(version, shape.cipher_suites, shape.extensions)

    @property
    def extension_types(self) -> tuple[int, ...]:
        return tuple(kind for kind, _ in self.extensions)

    def extension(self, kind: int) -> bytes | None:
        for extension, body in self.extensions:
            if extension == kind:
                return body
        return None

    def u16_list(self, kind: int, length_width: int) -> tuple[int, ...]:
        body = self.extension(kind) or b""
        values = body[length_width:]
        return tuple(
            int.from_bytes(values[index : index + 2], "big")
            for index in range(0, len(values) - 1, 2)
        )

    @property
    def supported_groups(self) -> tuple[int, ...]:
        return self.u16_list(EXTENSION_SUPPORTED_GROUPS, 2)

    @property
    def signature_algorithms(self) -> tuple[int, ...]:
        return self.u16_list(EXTENSION_SIGNATURE_ALGORITHMS, 2)

    @property
    def supported_versions(self) -> tuple[int, ...]:
        return self.u16_list(EXTENSION_SUPPORTED_VERSIONS, 1)

    @property
    def ec_point_formats(self) -> tuple[int, ...]:
        body = self.extension(EXTENSION_EC_POINT_FORMATS) or b""
        return tuple(body[1 : 1 + body[0]]) if body else ()

    @property
    def alpn_protocols(self) -> tuple[bytes, ...]:
        body = self.extension(EXTENSION_ALPN) or b""
        protocols = []
        offset = 2
        while offset < len(body):
            size = body[offset]
            protocols.append(body[offset + 1 : offset + 1 + size])
            offset += 1 + size
        return tuple(protocols)

    @property
    def key_share_groups(self) -> tuple[int, ...]:
        body = self.extension(EXTENSION_KEY_SHARE) or b""
        groups = []
        offset = 2
        while offset + 4 <= len(body):
            groups.append(int.from_bytes(body[offset : offset + 2], "big"))
            offset += 4 + int.from_bytes(body[offset + 2 : offset + 4], "big")
        return tuple(groups)

    @property
    def server_name(self) -> bytes | None:
        body = self.extension(EXTENSION_SERVER_NAME)
        if body is None or len(body) < 5 or body[2] != 0:
            return None
        return body[5 : 5 + int.from_bytes(body[3:5], "big")]


def u16_text(values: Sequence[int]) -> str:
    return ",".join(f"0x{value:04x}" for value in values)


def summary_lines(summary: HelloSummary) -> list[str]:
    """The summary fields in `capture_client_hello`'s order and spelling."""
    return [
        f"legacy_version=0x{summary.legacy_version:04x}",
        f"cipher_suites={u16_text(summary.cipher_suites)}",
        f"extension_types={u16_text(summary.extension_types)}",
        f"supported_groups={u16_text(summary.supported_groups)}",
        "ec_point_formats="
        + ",".join(f"0x{value:02x}" for value in summary.ec_point_formats),
        f"signature_algorithms={u16_text(summary.signature_algorithms)}",
        "alpn_protocols_hex=" + ",".join(p.hex() for p in summary.alpn_protocols),
        f"supported_versions={u16_text(summary.supported_versions)}",
        f"key_share_groups={u16_text(summary.key_share_groups)}",
        f"server_name_hex={(summary.server_name or b'').hex()}",
    ]


def ja3(summary: HelloSummary) -> str:
    def join(values: Sequence[int]) -> str:
        return "-".join(str(value) for value in values if value not in TLS_GREASE)

    return ",".join(
        [
            str(summary.legacy_version),
            join(summary.cipher_suites),
            join(summary.extension_types),
            join(summary.supported_groups),
            join(summary.ec_point_formats),
        ]
    )


def ja4(summary: HelloSummary, transport: str) -> str:
    """FoxIO JA4: `t` for TLS over TCP, `q` for QUIC."""
    ciphers = [value for value in summary.cipher_suites if value not in TLS_GREASE]
    extensions = [value for value in summary.extension_types if value not in TLS_GREASE]
    versions = [v for v in summary.supported_versions if v not in TLS_GREASE]
    version = max(versions) if versions else summary.legacy_version
    version_text = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}.get(
        version, "00"
    )
    sni = "d" if EXTENSION_SERVER_NAME in extensions else "i"
    alpn = summary.alpn_protocols[0].decode("latin-1") if summary.alpn_protocols else ""
    alpn_text = alpn[0] + alpn[-1] if alpn else "00"
    head = (
        f"{transport}{version_text}{sni}{min(len(ciphers), 99):02d}"
        f"{min(len(extensions), 99):02d}{alpn_text}"
    )

    def digest(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "0" * 12

    cipher_text = ",".join(sorted(f"{value:04x}" for value in ciphers))
    extension_text = ",".join(
        sorted(
            f"{value:04x}"
            for value in extensions
            if value not in {EXTENSION_SERVER_NAME, EXTENSION_ALPN}
        )
    )
    algorithms = ",".join(
        f"{value:04x}"
        for value in summary.signature_algorithms
        if value not in TLS_GREASE
    )
    if algorithms:
        extension_text += "_" + algorithms
    return f"{head}_{digest(cipher_text)}_{digest(extension_text)}"


# -- HTTP/2 startup --------------------------------------------------------


def raw_frames(stream: bytes) -> list[bytes]:
    """Split a client HTTP/2 byte stream after its preface into wire frames."""
    if not stream.startswith(CONNECTION_PREFACE):
        raise ValueError("client stream does not start with the H2 preface")
    frames = []
    offset = len(CONNECTION_PREFACE)
    while offset + 9 <= len(stream):
        end = offset + 9 + int.from_bytes(stream[offset : offset + 3], "big")
        if end > len(stream):
            break
        frames.append(stream[offset:end])
        offset = end
    return frames


def startup_frames(frames: Sequence[bytes]) -> list[bytes]:
    """Client frames before the first HEADERS, as `capture_http2_tls` keeps."""
    startup = []
    for frame in frames:
        if frame[3] == 0x1:
            break
        startup.append(frame)
    return startup


def settings_pairs(frame: bytes) -> list[tuple[int, int]]:
    payload = frame[9:]
    return [
        (
            int.from_bytes(payload[offset : offset + 2], "big"),
            int.from_bytes(payload[offset + 2 : offset + 6], "big"),
        )
        for offset in range(0, len(payload) - 5, 6)
    ]


def akamai_http2(frames: Sequence[bytes], pseudo_order: Sequence[bytes]) -> str:
    """The Akamai HTTP/2 fingerprint: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo."""
    settings = ""
    window = "00"
    priorities = []
    for frame in frames:
        kind, stream_id = frame[3], int.from_bytes(frame[5:9], "big") & 0x7FFFFFFF
        if kind == 0x1:
            break
        if kind == 0x4 and not frame[4] & 0x1 and not settings:
            settings = ";".join(f"{i}:{v}" for i, v in settings_pairs(frame))
        elif kind == 0x8 and stream_id == 0 and window == "00":
            window = str(int.from_bytes(frame[9:13], "big") & 0x7FFFFFFF)
        elif kind == 0x2:
            raw = int.from_bytes(frame[9:13], "big")
            priorities.append(
                f"{stream_id}:{raw >> 31}:{raw & 0x7FFFFFFF}:{frame[13] + 1}"
            )
    pseudo = ",".join(name.decode("latin-1")[1:2] for name in pseudo_order)
    return f"{settings}|{window}|{','.join(priorities) or '0'}|{pseudo}"


def http2_lines(record: ConnectionRecord, index: int) -> list[str]:
    frames = raw_frames(record.client_stream())
    startup = startup_frames(frames)
    lines = [
        f"connection={index}",
        f"preface_hex={CONNECTION_PREFACE.hex()}",
        f"frame_count={len(startup)}",
    ]
    lines.extend(f"frame_{i}_hex={frame.hex()}" for i, frame in enumerate(startup))
    settings = next(
        (frame for frame in startup if frame[3] == 0x4 and not frame[4] & 0x1), None
    )
    if settings is not None:
        lines.append(
            "initial_settings="
            + ",".join(f"0x{i:04x}:{v}" for i, v in settings_pairs(settings))
        )
    window = next(
        (
            int.from_bytes(frame[9:13], "big") & 0x7FFFFFFF
            for frame in startup
            if frame[3] == 0x8 and int.from_bytes(frame[5:9], "big") == 0
        ),
        None,
    )
    lines.append(f"connection_window_update={'none' if window is None else window}")
    analysis = analyze_http2(record)
    client = [frame for frame in analysis.frames if frame.direction == "client"]
    lines.append(f"client_frame_count={len(client)}")
    for position, frame in enumerate(client):
        details = ",".join(frame_details(frame))
        lines.append(
            f"client_frame_{position}=type:{frame.type_name},"
            f"flags:0x{frame.flags:02x},stream:{frame.stream_id}"
            + (f",{details}" if details else "")
        )
    pseudo = []
    if analysis.client_headers:
        pseudo = [
            item.name
            for item in analysis.client_headers[0].fields
            if item.name is not None and item.name.startswith(b":")
        ]
    lines.append(f"akamai={akamai_http2(frames, pseudo)}")
    return lines


def http3_fingerprint(record: QuicRecord) -> str:
    """SETTINGS `id:value` in wire order, then the first request's pseudo order.

    This is the form tls.peet.ws reports for HTTP/3; GREASE settings read
    `GREASE`.
    """
    from .http3_wire import is_h3_grease

    control = unidirectional_stream(record.streams, 0)
    frame = first_frame(control, has_stream_type=True)
    settings = parse_settings(frame[2]) if frame is not None else []
    pairs = ";".join(
        "GREASE" if is_h3_grease(identifier) else f"{identifier}:{value}"
        for identifier, _, value, _ in settings
    )
    pseudo = ",".join(
        name.decode("latin-1")[1:2]
        for name, _ in record.first_headers or []
        if name.startswith(b":")
    )
    return f"{pairs}|{pseudo}"


# -- Rendering -------------------------------------------------------------


@dataclass(frozen=True)
class CaptureMetadata:
    client: str
    client_version: str
    operating_system: str
    launch_mode: str
    launch_arguments: str
    firefox_preferences: str = "none"
    profile_files: str = "none"


def milliseconds(value: float | None) -> str:
    return "none" if value is None else f"{value * 1000:.3f}"


def capture_tool() -> str:
    versions = " ".join(
        f"{package} {metadata.version(package)}" for package in SUPPORTED
    )
    return f"python {platform.python_version()} {versions}"


def first_client_hello(run: SnapshotRun) -> tuple[ConnectionRecord, list[bytes]] | None:
    """The first complete TCP ClientHello of the run."""
    for record in run.connections:
        hello = record.client_hello
        if isinstance(hello, RecordedClientHello) and hello.complete and hello.raw:
            try:
                return record, client_hello_records(bytes(hello.raw))
            except ValueError:
                continue
    return None


def tls_fixture_lines(
    records: Sequence[bytes], capture: CaptureMetadata, listen: str
) -> tuple[list[str], HelloSummary]:
    handshake = b"".join(record[5:] for record in records)
    message = handshake[: 4 + int.from_bytes(handshake[1:4], "big")]
    summary = HelloSummary.parse(message)
    hostname = (summary.server_name or b"").decode("ascii", "replace")
    lines = [
        "format=phantom-client-hello-v2",
        f"captured_at_unix={int(time.time())}",
        f"browser={capture.client}",
        f"browser_version={capture.client_version}",
        f"operating_system={capture.operating_system}",
        f"hostname={hostname}",
        f"listen_address={listen}",
        f"launch_mode={capture.launch_mode}",
        f"launch_arguments={capture.launch_arguments}",
        f"record_count={len(records)}",
    ]
    lines.extend(f"record_{i}_hex={record.hex()}" for i, record in enumerate(records))
    lines.extend(summary_lines(summary))
    return lines, summary


def h3_fixtures(
    record: QuicRecord, capture: CaptureMetadata, listen: str
) -> tuple[str, str | None]:
    """Render the legacy startup and QUIC ClientHello fixtures of one connection."""
    from .chrome_http3 import Capture

    if record.first_request is None or record.first_headers is None:
        raise ValueError("QUIC connection carried no request")
    snapshot = record.first_request
    capture_state = Capture(
        complete=asyncio.Event(),
        metadata=argparse.Namespace(
            client=capture.client,
            client_version=capture.client_version,
            operating_system=capture.operating_system,
            hostname=HOSTNAME,
            listen=listen,
            launch_mode=capture.launch_mode,
            launch_arguments=capture.launch_arguments,
        ),
        streams=record.streams,
        transport_parameters=record.transport_parameters,
        request_stream_id=snapshot.stream_id,
        request_headers_frame=snapshot.headers_frame,
        request_headers_payload=snapshot.headers_payload,
        request_qpack_encoder_stream_prefix=snapshot.qpack_encoder_stream_prefix,
        request_qpack_decoder_stream_prefix=snapshot.qpack_decoder_stream_prefix,
        headers=record.first_headers,
        server_qpack_max_table_capacity=record.server_qpack_max_table_capacity,
        server_qpack_blocked_streams=record.server_qpack_blocked_streams,
        alpn=record.alpn,
        quic_version=record.quic_version,
        client_hello=record.client_hello,
    )
    control = unidirectional_stream(record.streams, 0)
    frame = first_frame(control, has_stream_type=True)
    if frame is None or frame[0] != 4:
        raise ValueError("HTTP/3 control stream did not start with SETTINGS")
    capture_state.settings_frame, capture_state.settings_payload = frame[1], frame[2]
    hello = capture_state.client_hello_fixture() if record.client_hello else None
    return capture_state.fixture(), hello


def request_lines(key: str, run: SnapshotRun, request: Request) -> list[str]:
    record = request.record
    stream = "none" if record.stream_id is None else str(record.stream_id)
    lines = [
        f"{key}=protocol:{request.protocol},connection:{record.connection},"
        f"stream:{stream},kind:{record.kind},"
        f"received_ms:{milliseconds(record.received)}"
    ]
    if request.protocol == "h2":
        analysis = analyze_http2(run.connections[record.connection])
        block = next(
            item
            for item in analysis.client_headers
            if item.stream_id == record.stream_id
        )
        priority = block.priority
        lines.append(
            f"{key}_headers_flags=0x{block.flags:02x}"
            + (
                ""
                if priority is None
                else f",exclusive:{str(priority.exclusive).lower()},"
                f"depends_on:{priority.depends_on},weight:{priority.weight}"
            )
        )
        lines.extend(h2_request_lines(key, run, record, {}))
    elif request.protocol == "h3":
        lines.extend(
            h3_request_lines(
                key, run, record, record.decoded, SERVER_QPACK_MAX_TABLE_CAPACITY
            )
        )
    else:
        names = []
        for line in record.header_lines:
            name, _, value = line.partition(b":")
            check_field(name.strip(), value.strip())
            names.append(name.strip().decode("latin-1"))
        lines.append(f"{key}_line_hex={record.request_line.hex()}")
        lines.append(f"{key}_field_order={','.join(names)}")
        lines.append(f"{key}_header_count={len(record.header_lines)}")
        lines.extend(
            f"{key}_header_{position}={line.hex()}"
            for position, line in enumerate(record.header_lines)
        )
    return lines


def request_fields(run: SnapshotRun, request: Request) -> list[tuple[bytes, bytes]]:
    record = request.record
    if request.protocol == "h3":
        return list(record.decoded)
    if request.protocol == "h2":
        analysis = analyze_http2(run.connections[record.connection])
        block = next(
            item
            for item in analysis.client_headers
            if item.stream_id == record.stream_id
        )
        return [
            (item.name, item.value)
            for item in block.fields
            if item.name is not None and item.value is not None
        ]
    fields = []
    for line in record.header_lines:
        name, _, value = line.partition(b":")
        fields.append((name.strip(), value.strip()))
    return fields


def navigation(fields: Sequence[tuple[bytes, bytes]]) -> Navigation:
    return Navigation(
        tuple(name for name, _ in fields),
        tuple(
            (name.lower().decode("ascii"), value)
            for name, value in fields
            if is_hint(name, USER_AGENT_HINTS)
        ),
    )


def hint_lines(run: SnapshotRun) -> list[str]:
    """Client hints in `phantom-client-hints-v2` form, from this run's navigations.

    The first navigation carries the default hints. The second is Chromium's
    `Critical-CH` retry of `/` when there is one, otherwise `/next`, which
    carries the hints the origin asked for with `Accept-CH`.
    """
    starts = [request for request in run.requests if request.record.kind == "start"]
    following = [r for r in run.requests if r.record.kind == "next"]
    if not starts:
        return ["hints_second_navigation=none", "hint_count=0"]
    if len(starts) > 1:
        second, source = starts[1], "critical-ch-retry"
    elif following:
        second, source = following[0], "next"
    else:
        second, source = starts[0], "none"
    hint_run = HintRun(
        run.token,
        USER_AGENT_HINTS,
        first=navigation(request_fields(run, starts[0])),
        second=navigation(request_fields(run, second)),
    )
    lines = [
        f"hints_second_navigation={source}",
        f"hints_second_protocol={second.protocol}",
    ]
    try:
        hints = derived_hints([hint_run])
    except ValueError as error:
        # Kept as evidence: the navigations disagree in a way to investigate.
        return [*lines, f"hints_error={error}", "hint_count=0"]
    lines.append(f"hint_count={len(hints)}")
    lines.extend(
        f"hint_{index}={delivery}|{name}|{validate_value(value)}"
        for index, (delivery, name, value) in enumerate(hints)
    )
    return lines


def render_snapshot(
    run: SnapshotRun,
    capture: CaptureMetadata,
    host: str,
    run_seconds: float,
) -> str:
    listen = f"{host}:{run.port}"
    quic = [record for record in run.quic_connections if record.first_request]
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={capture.client}",
        f"client_version={capture.client_version}",
        f"operating_system={capture.operating_system}",
        f"hostname={HOSTNAME}",
        f"listen_address=tls+quic {listen} plain {host}:{run.plain_port}",
        f"launch_mode={capture.launch_mode}",
        f"launch_arguments={capture.launch_arguments}",
        f"firefox_preferences={capture.firefox_preferences}",
        f"profile_files={capture.profile_files}",
        f"capture_tool={capture_tool()}",
        f"run_seconds={run_seconds:.3f}",
        f"timed_out={str(run.timed_out).lower()}",
        f"finished_ms={milliseconds(run.finished)}",
        f"http3={'used' if quic else 'not-used'}",
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
    lines.append(f"request_count={len(run.requests)}")
    for index, request in enumerate(run.requests):
        key = f"request_{index}"
        lines.extend(
            evidence(key, lambda key=key, r=request: request_lines(key, run, r))
        )
    lines.extend(evidence("hints", lambda: hint_lines(run)))

    hello = first_client_hello(run)
    if hello is not None:
        tls_lines, summary = tls_fixture_lines(hello[1], capture, listen)
        lines.append(f"ja3={ja3(summary)}")
        lines.append(f"ja3_hash={hashlib.md5(ja3(summary).encode()).hexdigest()}")
        lines.append(f"ja4={ja4(summary, 't')}")
    if quic and quic[0].client_hello:
        lines.append(f"quic_ja4={ja4(HelloSummary.parse(quic[0].client_hello), 'q')}")
    if hello is not None:
        lines.extend(f"tls.{line}" for line in tls_lines)
    h2 = next(
        (
            (index, record)
            for index, record in enumerate(run.connections)
            if record.protocol == "h2" and record.client_chunks
        ),
        None,
    )
    if h2 is not None:
        lines.extend(evidence("h2", lambda: http2_lines(h2[1], h2[0]), "h2."))
    if quic:
        lines.extend(evidence("h3", lambda: http3_lines(quic[0], capture, listen)))
    return "\n".join(lines) + "\n"


def http3_lines(record: QuicRecord, capture: CaptureMetadata, listen: str):
    startup, quic_hello = h3_fixtures(record, capture, listen)
    lines = []
    if quic_hello is not None:
        lines.extend(f"quic_client_hello.{line}" for line in quic_hello.splitlines())
    lines.append(f"h3_fingerprint={http3_fingerprint(record)}")
    lines.extend(f"h3_startup.{line}" for line in startup.splitlines())
    return lines


def evidence(key: str, render: Callable[[], list[str]], prefix: str = "") -> list[str]:
    """Render one part of a run; a part that does not parse is noted, not fatal.

    A timed-out run keeps whatever arrived, which can end mid-frame.
    """
    try:
        return [prefix + line for line in render()]
    except (ValueError, KeyError, StopIteration, RuntimeError) as error:
        message = " ".join(str(error).split())
        return [f"{key}_error={type(error).__name__}: {message}"]


def split_snapshot(text: str) -> dict[str, str]:
    """Return each legacy fixture a snapshot embeds, keyed by file name."""
    sections: dict[str, list[str]] = {}
    for line in text.splitlines():
        prefix, dot, rest = line.partition(".")
        if dot and prefix in LEGACY_SECTIONS and "=" not in prefix:
            sections.setdefault(LEGACY_SECTIONS[prefix], []).append(rest)
    return {name: "\n".join(lines) + "\n" for name, lines in sections.items()}


# -- Browser launch --------------------------------------------------------


def launch_plan(
    browser: str,
    executable: Path,
    *,
    headless: bool,
    host: str,
    port: int,
    certificate: Certificate,
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
                # never leaves the machine or teaches QUIC state. The rules
                # would also rewrite the IP literal of `/plain`.
                f"--host-resolver-rules=MAP {HOSTNAME} {host}, MAP * ~NOTFOUND, "
                f"EXCLUDE {host}",
                "--ignore-certificate-errors-spki-list="
                + certificate.spki_sha256_base64,
            ),
        )
    if browser == "firefox":
        return LaunchPlan(
            "firefox",
            executable,
            headless,
            firefox_preferences=(
                ("network.dns.localDomains", HOSTNAME),
                ("network.dns.disableIPv6", True),
                ("network.http.http3.enable", True),
                # The overridden test certificate counts as a third-party
                # root, which otherwise makes Firefox close HTTP/3.
                ("network.http.http3.disable_when_third_party_roots_found", False),
            ),
            profile_files=(
                (
                    "cert_override.txt",
                    firefox_cert_override(HOSTNAME, port, certificate),
                ),
            ),
        )
    raise ValueError(f"unsupported browser: {browser}")


def version_key(text: str) -> tuple[int, ...]:
    return tuple(int(part) if part.isdigit() else -1 for part in text.split("."))


def default_executable(browser: str) -> Path | None:
    """The browser's usual install location on Windows or macOS."""
    if sys.platform == "darwin":
        path = Path(MACOS_PATHS[browser])
        return path if path.exists() else None
    if sys.platform != "win32":
        return None
    if browser == "opera":
        # The versioned executable, so the version under test is the one
        # that runs (the launcher beside it can start a pending update).
        root = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Opera"
        candidates = sorted(
            (path for path in root.glob("*/opera.exe")),
            key=lambda path: version_key(path.parent.name),
        )
        return candidates[-1] if candidates else None
    for template in WINDOWS_PATHS[browser]:
        try:
            path = Path(template.format_map(os.environ))
        except KeyError:
            continue
        if path.exists():
            return path
    return None


def executable_version(executable: Path) -> str | None:
    """The product version of a Windows executable or a macOS app bundle."""
    if sys.platform == "darwin":
        for parent in executable.parents:
            info = parent / "Info.plist"
            if parent.name == "Contents" and info.exists():
                with info.open("rb") as handle:
                    return plistlib.load(handle).get("CFBundleShortVersionString")
        return None
    if sys.platform == "win32":
        path = str(executable).replace("'", "''")
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-Item -LiteralPath '{path}').VersionInfo.ProductVersion",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        version = result.stdout.strip()
        return version or None
    return None


# -- Orchestration ---------------------------------------------------------


@dataclass(frozen=True)
class RunResult:
    text: str
    seconds: float
    run: SnapshotRun


async def capture_run(args: argparse.Namespace, certificate: Certificate) -> RunResult:
    token = secrets.token_hex(8)
    began = time.perf_counter()
    async with serving(args.listen, certificate, token, args.observation) as run:
        plan = launch_plan(
            args.browser,
            args.browser_path,
            headless=not args.headful,
            host=args.listen,
            port=run.port,
            certificate=certificate,
        )
        url = f"https://{HOSTNAME}:{run.port}/?run={token}"
        async with BrowserDriver(plan, url):
            try:
                await asyncio.wait_for(
                    run.done.wait(), timeout=args.run_timeout + args.observation
                )
            except asyncio.TimeoutError:
                run.timed_out = True
    seconds = time.perf_counter() - began
    capture = CaptureMetadata(
        client=args.client or CLIENT_NAMES[args.browser],
        client_version=args.client_version,
        operating_system=args.operating_system,
        launch_mode=plan.launch_mode,
        launch_arguments=plan.recorded_arguments(url)
        .replace(certificate.spki_sha256_base64, "<certificate-spki>")
        .replace(f":{run.port}", ":<port>")
        .replace(token, "<token>"),
        firefox_preferences=render_preferences(plan.firefox_preferences) or "none",
        profile_files=",".join(name for name, _ in plan.profile_files) or "none",
    )
    return RunResult(render_snapshot(run, capture, args.listen, seconds), seconds, run)


def describe(result: RunResult) -> str:
    fields = dict(
        line.split("=", 1) for line in result.text.splitlines() if "=" in line
    )
    protocols = ",".join(
        dict.fromkeys(request.protocol for request in result.run.requests)
    )
    return (
        f"{result.seconds:.1f} s; requests over {protocols or 'none'}; "
        f"ja4 {fields.get('ja4', 'none')}; quic_ja4 {fields.get('quic_ja4', 'none')}; "
        f"h2 {fields.get('h2.akamai', 'none')}; "
        f"client hints {fields.get('hint_count', '0')}"
    )


async def capture(args: argparse.Namespace) -> int:
    from .alt_svc_race import ignore_peer_resets

    asyncio.get_running_loop().set_exception_handler(ignore_peer_resets)
    certificate = generate_certificate()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    failures = 0
    for index in range(1, args.runs + 1):
        result = await capture_run(args, certificate)
        path = args.output_dir / f"snapshot-{index}.txt"
        write_text_fixture(path, result.text)
        complete = not result.run.timed_out
        failures += not complete
        status = "" if complete else " (timed out; partial evidence kept)"
        print(f"run {index}: {describe(result)}{status} -> {path}", file=sys.stderr)
    return 1 if failures else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--browser", choices=DESKTOP_BROWSERS)
    parser.add_argument("--browser-path", type=Path)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client")
    parser.add_argument("--client-version")
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--run-timeout", type=float, default=20.0)
    parser.add_argument("--observation", type=float, default=0.3)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--split",
        type=Path,
        metavar="SNAPSHOT",
        help="write the legacy fixtures a snapshot embeds into --output-dir",
    )
    args = parser.parse_args(argv)
    if args.output_dir is None:
        parser.error("--output-dir is required")
    if args.split is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        text = args.split.read_text(encoding="utf-8")
        for name, body in split_snapshot(text).items():
            write_text_fixture(args.output_dir / name, body)
            print(args.output_dir / name, file=sys.stderr)
        return 0
    if args.browser is None:
        parser.error("--browser is required")
    if args.runs < 1:
        parser.error("--runs must be positive")
    try:
        loopback = ipaddress.ip_address(args.listen).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        parser.error("the capture listener must be a loopback address")
    for package, version in SUPPORTED.items():
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    if args.browser_path is None:
        args.browser_path = default_executable(args.browser)
        if args.browser_path is None:
            parser.error(f"no {args.browser} install found; pass --browser-path")
    if args.client_version is None:
        args.client_version = executable_version(args.browser_path)
        if args.client_version is None:
            parser.error("cannot read the browser version; pass --client-version")
    return asyncio.run(capture(args))


if __name__ == "__main__":
    sys.exit(main())
