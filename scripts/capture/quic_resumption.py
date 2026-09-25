"""Capture how a browser resumes QUIC sessions and uses 0-RTT on a loopback origin.

One run serves `server.phantom.test` over HTTP/3 from aioquic and loads a page
whose script forces a sequence of new QUIC connections. The server issues one
TLS 1.3 NewSessionTicket per connection, with `max_early_data_size`
0xffffffff, and closes a connection after answering `/retire`. For every
connection the fixture keeps the raw ClientHello, the ticket it resumed, the
client packet types, the packet-number space each request stream arrived in,
each client unidirectional stream's type and the packet-number space and
time of its first byte, and each request's method, path, field names, and
body length.

The `reject` scenario resumes the PSK but ignores the client's `early_data`
offer, so every 0-RTT packet is undecryptable and the browser must resend.
No traffic secret is written anywhere; aioquic decrypts in memory.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import platform
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import aioquic
from aioquic import tls
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.buffer import Buffer, BufferReadError, encode_uint_var
from aioquic.h3.connection import (
    H3_ALPN,
    ErrorCode,
    FrameType,
    H3Connection,
    encode_frame,
)
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    ProtocolNegotiated,
    QuicEvent,
)
from aioquic.quic.packet import QuicPacketType, pull_quic_header

from .browser_launch import CHROMIUM_BROWSERS, BrowserDriver, LaunchPlan
from .fixture_file import write_text_fixture
from .http2_session import HOSTNAME, Certificate, generate_certificate
from .http3_wire import (
    INITIAL_SOURCE_CONNECTION_ID,
    SENSITIVE_REQUEST_HEADERS,
    VERSION_INFORMATION,
    is_quic_grease,
    parse_parameters,
    pull_varint,
)

SUPPORTED_AIOQUIC = "1.3.0"
FORMAT = "phantom-quic-resumption-v1"
RETIRE_DELAY_SECONDS = 0.05
RETIRE_WAIT_MILLISECONDS = 300
MAX_CONNECTIONS = 16
MAX_REQUESTS = 64
MAX_BODY = 64 * 1024
MAX_CLIENT_HELLO = 32 * 1024
PRE_SHARED_KEY = 0x0029
EARLY_DATA = 0x002A
PSK_KEY_EXCHANGE_MODES = 0x002D
KEY_SHARE = 0x0033
INITIAL_ROUND_TRIP_TIME = 0x3127
RESERVED_VERSION_SENTINEL = bytes.fromhex("0a0a0a0a")
ECH = 0xFE0D
QUIC_TRANSPORT_PARAMETERS = 0x0039

EPOCH_NAMES = {
    tls.Epoch.INITIAL: "initial",
    tls.Epoch.ZERO_RTT: "0rtt",
    tls.Epoch.HANDSHAKE: "handshake",
    tls.Epoch.ONE_RTT: "1rtt",
}
PACKET_NAMES = {
    QuicPacketType.INITIAL: "initial",
    QuicPacketType.ZERO_RTT: "0rtt",
    QuicPacketType.HANDSHAKE: "handshake",
    QuicPacketType.ONE_RTT: "1rtt",
}


@dataclass(frozen=True)
class Scenario:
    name: str
    question: str
    accept_early_data: bool
    # Holds each connection's datagrams this long before aioquic sees the
    # first one, standing in for a network round trip that loopback lacks.
    handshake_delay_ms: int = 0


SCENARIOS = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "accept",
            "Resumed ClientHello shape and which requests travel in 0-RTT",
            accept_early_data=True,
        ),
        Scenario(
            "accept-delayed",
            "Whether requests issued during a slow handshake travel in 0-RTT",
            accept_early_data=True,
            handshake_delay_ms=50,
        ),
        Scenario(
            "reject",
            "Requests after the server resumes the PSK but rejects 0-RTT",
            accept_early_data=False,
        ),
    )
}


# The page issues every request of one step at once, before its connection
# exists, so each step's requests are the first ones on a new connection.
PAGE = """<!doctype html>
<meta charset="utf-8">
<title>phantom quic resumption</title>
<link rel="icon" href="data:,">
<script>
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const plain = { cache: "no-store" };
async function retire() {
  await fetch("/retire", plain);
  await wait(RETIRE_WAIT);
}
(async () => {
  await retire();
  await Promise.all([
    fetch("/concurrent/get", plain),
    fetch("/concurrent/head", { method: "HEAD", cache: "no-store" }),
    fetch("/concurrent/options", { method: "OPTIONS", cache: "no-store" }),
    fetch("/concurrent/post", { method: "POST", body: "phantom", cache: "no-store" }),
    fetch("/concurrent/put", { method: "PUT", body: "phantom", cache: "no-store" }),
    fetch("/concurrent/delete", { method: "DELETE", cache: "no-store" }),
  ]);
  await retire();
  await fetch("/alone/post", { method: "POST", body: "phantom", cache: "no-store" });
  await retire();
  await fetch("/alone/get", plain);
  await retire();
  location.href = "/navigate";
})().catch((error) =>
  fetch("/error?" + encodeURIComponent(String(error)), plain));
</script>
""".replace("RETIRE_WAIT", str(RETIRE_WAIT_MILLISECONDS))

NAVIGATION_PAGE = """<!doctype html>
<meta charset="utf-8">
<title>phantom quic resumption navigation</title>
<link rel="icon" href="data:,">
<script>
setTimeout(() => fetch("/done", { cache: "no-store" }), RETIRE_WAIT);
</script>
""".replace("RETIRE_WAIT", str(RETIRE_WAIT_MILLISECONDS))


# -- ClientHello shape ---------------------------------------------------------


def is_tls_grease(value: int) -> bool:
    """RFC 8701 GREASE code points: 0x?A?A with equal bytes."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def tls_code(value: int) -> str:
    return "grease" if is_tls_grease(value) else f"{value:04x}"


@dataclass(frozen=True)
class ClientHelloShape:
    cipher_suites: tuple[int, ...]
    extensions: tuple[tuple[int, bytes], ...]

    @property
    def extension_types(self) -> tuple[int, ...]:
        return tuple(extension for extension, _ in self.extensions)

    def extension(self, extension_type: int) -> bytes | None:
        for extension, body in self.extensions:
            if extension == extension_type:
                return body
        return None

    def key_share_groups(self) -> tuple[int, ...]:
        body = self.extension(KEY_SHARE)
        if body is None:
            return ()
        buf = Buffer(data=body)
        length = buf.pull_uint16()
        end = buf.tell() + length
        groups = []
        while buf.tell() < end:
            groups.append(buf.pull_uint16())
            buf.pull_bytes(buf.pull_uint16())
        return tuple(groups)

    def psk_key_exchange_modes(self) -> tuple[int, ...]:
        body = self.extension(PSK_KEY_EXCHANGE_MODES)
        if body is None:
            return ()
        return tuple(body[1 : 1 + body[0]])

    def pre_shared_key(self) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
        """Identity and binder lengths of the offered PSKs."""
        body = self.extension(PRE_SHARED_KEY)
        if body is None:
            return None
        buf = Buffer(data=body)
        identities = []
        length = buf.pull_uint16()
        end = buf.tell() + length
        while buf.tell() < end:
            identities.append(len(buf.pull_bytes(buf.pull_uint16())))
            buf.pull_uint32()
        binders = []
        length = buf.pull_uint16()
        end = buf.tell() + length
        while buf.tell() < end:
            binders.append(len(buf.pull_bytes(buf.pull_uint8())))
        return tuple(identities), tuple(binders)

    def transport_parameters(self) -> dict[int, bytes]:
        """Non-GREASE parameters by id, with per-connection randomness removed.

        The initial source connection ID keeps only its length, and each
        reserved version inside `version_information` becomes 0x?a?a?a?a.
        """
        body = self.extension(QUIC_TRANSPORT_PARAMETERS)
        if body is None:
            return {}
        values = {}
        for parameter in parse_parameters(body):
            if is_quic_grease(parameter.identifier):
                continue
            value = parameter.value
            if parameter.identifier == INITIAL_SOURCE_CONNECTION_ID:
                value = len(value).to_bytes(1, "big")
            elif parameter.identifier == VERSION_INFORMATION:
                value = b"".join(
                    RESERVED_VERSION_SENTINEL
                    if is_reserved_version(value[index : index + 4])
                    else value[index : index + 4]
                    for index in range(0, len(value), 4)
                )
            values[parameter.identifier] = value
        return values

    def version_information(self) -> tuple[str, ...]:
        """Chosen version, then available versions; reserved ones as `grease`."""
        value = self.transport_parameters().get(VERSION_INFORMATION, b"")
        return tuple(
            "grease"
            if value[index : index + 4] == RESERVED_VERSION_SENTINEL
            else value[index : index + 4].hex()
            for index in range(0, len(value), 4)
        )

    def initial_rtt_us(self) -> int | None:
        """Chromium's initial_round_trip_time_us transport parameter (0x3127)."""
        value = self.transport_parameters().get(INITIAL_ROUND_TRIP_TIME)
        if value is None:
            return None
        decoded = pull_varint(value, 0)
        return None if decoded is None else decoded[0]

    def transport_parameter_ids(self) -> tuple[str, ...]:
        body = self.extension(QUIC_TRANSPORT_PARAMETERS)
        if body is None:
            return ()
        return tuple(
            "grease"
            if is_quic_grease(parameter.identifier)
            else str(parameter.identifier)
            for parameter in parse_parameters(body)
        )


def parse_client_hello(message: bytes) -> ClientHelloShape:
    """Parse a TLS 1.3 ClientHello handshake message, keeping extension order."""
    try:
        buf = Buffer(data=message)
        if buf.pull_uint8() != 1:
            raise ValueError("handshake message is not a ClientHello")
        length = int.from_bytes(buf.pull_bytes(3), "big")
        if length + 4 != len(message):
            raise ValueError("ClientHello length does not match the message")
        buf.pull_uint16()
        buf.pull_bytes(32)
        buf.pull_bytes(buf.pull_uint8())
        suites_length = buf.pull_uint16()
        suites_end = buf.tell() + suites_length
        suites = []
        while buf.tell() < suites_end:
            suites.append(buf.pull_uint16())
        buf.pull_bytes(buf.pull_uint8())
        extensions_length = buf.pull_uint16()
        extensions_end = buf.tell() + extensions_length
        if extensions_end != len(message):
            raise ValueError("ClientHello extensions do not end the message")
        extensions = []
        while buf.tell() < extensions_end:
            extension_type = buf.pull_uint16()
            extensions.append((extension_type, buf.pull_bytes(buf.pull_uint16())))
    except BufferReadError as error:
        raise ValueError("truncated ClientHello") from error
    return ClientHelloShape(tuple(suites), tuple(extensions))


def is_reserved_version(value: bytes) -> bool:
    """RFC 9000 section 15 reserved versions: 0x?a?a?a?a."""
    return len(value) == 4 and all(byte & 0x0F == 0x0A for byte in value)


def compare_shapes(fresh: ClientHelloShape, resumed: ClientHelloShape) -> list[str]:
    """Describe how a resumed ClientHello differs from a fresh one.

    Chromium permutes extension and transport-parameter order on every
    connection, so order is reported per ClientHello and compared here as a
    multiset. Key shares, ECH GREASE, and the initial source connection ID
    are random per connection, so only their groups or lengths are compared.
    """
    fresh_types = [tls_code(value) for value in fresh.extension_types]
    resumed_types = [tls_code(value) for value in resumed.extension_types]
    added = [value for value in resumed_types if value not in fresh_types]
    removed = [value for value in fresh_types if value not in resumed_types]
    random_bodies = (PRE_SHARED_KEY, EARLY_DATA, KEY_SHARE, ECH)
    changed = [
        tls_code(extension)
        for extension, body in resumed.extensions
        if extension not in random_bodies
        and extension != QUIC_TRANSPORT_PARAMETERS
        and not is_tls_grease(extension)
        and fresh.extension(extension) not in (None, body)
    ]
    fresh_parameters = fresh.transport_parameters()
    resumed_parameters = resumed.transport_parameters()
    added_parameters = sorted(set(resumed_parameters) - set(fresh_parameters))
    removed_parameters = sorted(set(fresh_parameters) - set(resumed_parameters))
    changed_parameters = sorted(
        identifier
        for identifier in set(fresh_parameters) & set(resumed_parameters)
        if fresh_parameters[identifier] != resumed_parameters[identifier]
    )
    return [
        "added_extensions=" + (",".join(added) or "none"),
        "removed_extensions=" + (",".join(removed) or "none"),
        "extension_multiset_equal_without_added="
        + flag(
            sorted(value for value in resumed_types if value not in added)
            == sorted(fresh_types)
        ),
        "cipher_suites_equal=" + flag(fresh.cipher_suites == resumed.cipher_suites),
        "key_share_groups_equal="
        + flag(fresh.key_share_groups() == resumed.key_share_groups()),
        "ech_grease_length_equal="
        + flag(len(fresh.extension(ECH) or b"") == len(resumed.extension(ECH) or b"")),
        "changed_extension_bodies=" + (",".join(changed) or "none"),
        "added_transport_parameters="
        + (",".join(str(value) for value in added_parameters) or "none"),
        "removed_transport_parameters="
        + (",".join(str(value) for value in removed_parameters) or "none"),
        "changed_transport_parameters="
        + (",".join(str(value) for value in changed_parameters) or "none"),
    ]


# -- Recording -----------------------------------------------------------------


@dataclass
class RequestRecord:
    connection: int
    stream_id: int
    method: str
    path: str
    field_names: tuple[str, ...]
    received_ms: float
    body_bytes: int = 0


@dataclass
class UnidirectionalStream:
    """The STREAM frame that carried offset 0 of a client unidirectional stream."""

    stream_type: int
    space: str
    first_frame_bytes: int
    first_ms: float


@dataclass
class ConnectionRecord:
    index: int
    first_datagram_ms: float
    packets: dict[str, int] = field(default_factory=dict)
    first_packet_version: int | None = None
    negotiated_version: int | None = None
    client_hello: bytes | None = None
    resumed: bool = False
    psk_ticket_from: int | None = None
    early_data_accepted: bool = False
    tickets_issued: int = 0
    ticket_max_early_data_size: int | None = None
    handshake_ms: float | None = None
    closed_ms: float | None = None
    closed_by: str | None = None
    stream_spaces: dict[int, list[str]] = field(default_factory=dict)
    # Client unidirectional streams in the order their first byte arrived.
    unidirectional_streams: dict[int, UnidirectionalStream] = field(
        default_factory=dict
    )


@dataclass
class RunRecord:
    started: float = field(default_factory=time.perf_counter)
    connections: list[ConnectionRecord] = field(default_factory=list)
    requests: list[RequestRecord] = field(default_factory=list)
    # Ticket bytes -> (issuing connection index, ticket).
    tickets: dict[bytes, tuple[int, tls.SessionTicket]] = field(default_factory=dict)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    error: str | None = None
    current: ConnectionRecord | None = None

    def now(self) -> float:
        return round((time.perf_counter() - self.started) * 1000, 1)

    def new_connection(self) -> ConnectionRecord:
        if len(self.connections) >= MAX_CONNECTIONS:
            raise ValueError("run exceeds the connection limit")
        record = ConnectionRecord(len(self.connections), self.now())
        self.connections.append(record)
        return record

    def store_ticket(self, ticket: tls.SessionTicket) -> None:
        if self.current is None:
            raise RuntimeError("session ticket issued outside a connection")
        self.tickets[ticket.ticket] = (self.current.index, ticket)
        self.current.tickets_issued += 1
        self.current.ticket_max_early_data_size = ticket.max_early_data_size

    def fetch_ticket(self, label: bytes) -> tls.SessionTicket | None:
        issued = self.tickets.get(label)
        if self.current is not None:
            self.current.psk_ticket_from = -1 if issued is None else issued[0]
        return None if issued is None else issued[1]


def first_long_header_version(data: bytes) -> int | None:
    if len(data) < 5 or not data[0] & 0x80:
        return None
    return int.from_bytes(data[1:5], "big")


def count_packets(data: bytes, host_cid_length: int) -> list[str]:
    """Name the packet types coalesced in one client datagram."""
    names = []
    buf = Buffer(data=data)
    while not buf.eof():
        start = buf.tell()
        try:
            header = pull_quic_header(buf, host_cid_length=host_cid_length)
        except (BufferReadError, ValueError):
            names.append("unparsed")
            break
        names.append(PACKET_NAMES.get(header.packet_type, "other"))
        buf.seek(start + header.packet_length)
    return names


def record_stream_start(
    connection: QuicConnection,
    streams: dict[int, UnidirectionalStream],
    context,
    frame_type: int,
    buf: Buffer,
) -> None:
    """Record a client unidirectional stream's type when offset 0 arrives.

    `buf` is positioned at the STREAM frame's stream ID (RFC 9000, section
    19.8): the OFF bit (0x04) adds an offset and the LEN bit (0x02) a length.
    """
    stream_id = buf.pull_uint_var()
    offset = buf.pull_uint_var() if frame_type & 0x04 else 0
    length = buf.pull_uint_var() if frame_type & 0x02 else buf.capacity - buf.tell()
    if offset != 0 or length == 0:
        return
    streams[stream_id] = UnidirectionalStream(
        stream_type=buf.pull_uint_var(),
        space=EPOCH_NAMES[context.epoch],
        first_frame_bytes=length,
        first_ms=connection._phantom_clock(),
    )


def install_hooks(accept_early_data: bool) -> Callable[[], None]:
    """Tap aioquic's server ClientHello and STREAM handling for one run."""
    original_hello = tls.Context._server_handle_hello
    original_pull = tls.pull_client_hello
    original_stream = QuicConnection._handle_stream_frame

    def server_handle_hello(self, input_buf, *args, **kwargs):
        message = input_buf.data_slice(0, input_buf.capacity)
        if len(message) > MAX_CLIENT_HELLO:
            raise ValueError("ClientHello exceeds the capture limit")
        self._phantom_client_hello = message
        return original_hello(self, input_buf, *args, **kwargs)

    def pull_client_hello(buf):
        hello = original_pull(buf)
        # Resume the PSK but never install 0-RTT keys, so early data is lost.
        hello.early_data = False
        return hello

    def handle_stream_frame(self, context, frame_type, buf):
        start = buf.tell()
        stream_id = buf.pull_uint_var()
        buf.seek(start)
        spaces = getattr(self, "_phantom_stream_spaces", None)
        if spaces is not None:
            names = spaces.setdefault(stream_id, [])
            name = EPOCH_NAMES[context.epoch]
            if name not in names:
                names.append(name)
        streams = getattr(self, "_phantom_unidirectional_streams", None)
        if streams is not None and stream_id % 4 == 2 and stream_id not in streams:
            record_stream_start(self, streams, context, frame_type, buf)
            buf.seek(start)
        return original_stream(self, context, frame_type, buf)

    tls.Context._server_handle_hello = server_handle_hello
    QuicConnection._handle_stream_frame = handle_stream_frame
    if not accept_early_data:
        tls.pull_client_hello = pull_client_hello

    def restore() -> None:
        tls.Context._server_handle_hello = original_hello
        tls.pull_client_hello = original_pull
        QuicConnection._handle_stream_frame = original_stream

    return restore


class ResumptionProtocol(QuicConnectionProtocol):
    def __init__(
        self, *args, run: RunRecord, handshake_delay_ms: int = 0, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.run = run
        self.handshake_delay_ms = handshake_delay_ms
        self.held: list[tuple[bytes, object]] | None = None
        self.record = run.new_connection()
        self._quic._phantom_stream_spaces = self.record.stream_spaces
        self._quic._phantom_unidirectional_streams = self.record.unidirectional_streams
        self._quic._phantom_clock = run.now
        self.http: H3Connection | None = None
        self.requests: dict[int, RequestRecord] = {}
        self.responded: set[int] = set()

    def datagram_received(self, data: bytes, addr) -> None:
        for name in count_packets(data, self._quic.configuration.connection_id_length):
            self.record.packets[name] = self.record.packets.get(name, 0) + 1
        if self.record.first_packet_version is None:
            self.record.first_packet_version = first_long_header_version(data)
        if self.handshake_delay_ms and self.held is None:
            self.held = [(data, addr)]
            asyncio.get_running_loop().call_later(
                self.handshake_delay_ms / 1000, self.release
            )
            self.handshake_delay_ms = 0
            return
        if self.held:
            self.held.append((data, addr))
            return
        self.deliver(data, addr)

    def release(self) -> None:
        held, self.held = self.held or [], []
        for data, addr in held:
            self.deliver(data, addr)

    def deliver(self, data: bytes, addr) -> None:
        self.run.current = self.record
        try:
            super().datagram_received(data, addr)
        finally:
            self.run.current = None

    def quic_event_received(self, event: QuicEvent) -> None:
        record = self.record
        if isinstance(event, ProtocolNegotiated):
            # Emitted while the ClientHello is handled, before any 0-RTT
            # stream data, so early requests reach an H3 layer.
            record.client_hello = getattr(self._quic.tls, "_phantom_client_hello", None)
            self.http = H3Connection(self._quic)
        if isinstance(event, HandshakeCompleted):
            record.negotiated_version = self._quic._version
            record.handshake_ms = self.run.now()
            record.resumed = event.session_resumed
            record.early_data_accepted = event.early_data_accepted
        if isinstance(event, ConnectionTerminated) and record.closed_ms is None:
            record.closed_ms = self.run.now()
            record.closed_by = record.closed_by or f"peer:0x{event.error_code:x}"
        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.headers(http_event)
            elif isinstance(http_event, DataReceived):
                request = self.requests.get(http_event.stream_id)
                if request is not None:
                    request.body_bytes += len(http_event.data)
                    if request.body_bytes > MAX_BODY:
                        raise ValueError("request body exceeds the capture limit")
                if http_event.stream_ended:
                    self.respond(http_event.stream_id)

    def headers(self, event: HeadersReceived) -> None:
        names = tuple(name.decode("latin-1") for name, _ in event.headers)
        if any(name.lower().encode() in SENSITIVE_REQUEST_HEADERS for name in names):
            raise ValueError("refusing to retain a credential-bearing request")
        fields = dict(event.headers)
        if len(self.run.requests) >= MAX_REQUESTS:
            raise ValueError("run exceeds the request limit")
        request = RequestRecord(
            connection=self.record.index,
            stream_id=event.stream_id,
            method=fields.get(b":method", b"").decode("latin-1"),
            path=fields.get(b":path", b"").decode("latin-1"),
            field_names=names,
            received_ms=self.run.now(),
        )
        self.requests[event.stream_id] = request
        self.run.requests.append(request)
        if event.stream_ended:
            self.respond(event.stream_id)

    def respond(self, stream_id: int) -> None:
        request = self.requests.get(stream_id)
        http = self.http
        if http is None or request is None or stream_id in self.responded:
            return
        self.responded.add(stream_id)
        path = request.path.split("?", 1)[0]
        if path in ("/", "/navigate"):
            body = (PAGE if path == "/" else NAVIGATION_PAGE).encode()
            content_type = b"text/html; charset=utf-8"
        else:
            body = b"ok"
            content_type = b"text/plain"
        if request.method == "HEAD":
            body = b""
        http.send_headers(
            stream_id,
            [
                (b":status", b"200"),
                (b"content-type", content_type),
                (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode()),
            ],
            end_stream=not body,
        )
        if body:
            http.send_data(stream_id, body, end_stream=True)
        self.transmit()
        if path == "/retire":
            self.goaway(stream_id + 4)
            asyncio.get_running_loop().call_later(RETIRE_DELAY_SECONDS, self.retire)
        elif path == "/error":
            self.run.error = request.path
            self.run.done.set()
        elif path == "/done":
            self.run.done.set()

    def goaway(self, next_stream_id: int) -> None:
        """Send H3 GOAWAY so no further request starts on this connection."""
        http = self.http
        if http is None or http._local_control_stream_id is None:
            return
        self._quic.send_stream_data(
            http._local_control_stream_id,
            encode_frame(FrameType.GOAWAY, encode_uint_var(next_stream_id)),
        )
        self.transmit()

    def retire(self) -> None:
        if self.record.closed_ms is None:
            self.record.closed_ms = self.run.now()
            self.record.closed_by = "server"
        # APPLICATION_CLOSE with H3_NO_ERROR: code 0 is not an H3 error code,
        # and Firefox excludes HTTP/3 for the origin after receiving it.
        self.close(error_code=ErrorCode.H3_NO_ERROR)


# -- Run orchestration ---------------------------------------------------------


def load_certificate(
    configuration: QuicConfiguration, certificate: Certificate
) -> None:
    with tempfile.TemporaryDirectory(prefix="phantom-capture-cert-") as directory:
        certificate_path = Path(directory) / "certificate.pem"
        key_path = Path(directory) / "key.pem"
        certificate_path.write_bytes(certificate.certificate_pem)
        key_path.write_bytes(certificate.private_key_pem)
        configuration.load_cert_chain(certificate_path, key_path)


def chromium_extra_arguments(
    listen_host: str,
    port: int,
    spki: str,
    *,
    field_trial_config: bool,
    netlog: Path | None = None,
) -> tuple[str, ...]:
    arguments = (
        "--enable-quic",
        f"--origin-to-force-quic-on={HOSTNAME}:{port}",
        # Every other name fails to resolve, so background traffic never
        # leaves the machine or opens another QUIC session.
        f"--host-resolver-rules=MAP {HOSTNAME} {listen_host}, MAP * ~NOTFOUND",
        f"--ignore-certificate-errors-spki-list={spki}",
    )
    if not field_trial_config:
        arguments += ("--disable-field-trial-config",)
    if netlog is not None:
        # Diagnostic only: the default capture mode omits cookies and
        # credentials, and the NetLog is never retained as a fixture.
        arguments += (f"--log-net-log={netlog}",)
    return arguments


def firefox_cert_override(host: str, port: int, certificate: Certificate) -> str:
    return (
        "# PSM Certificate Override Settings file\n"
        "# This is a generated file!  Do not edit.\n"
        f"{host}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t"
        f"{certificate.sha256_fingerprint}\t\n"
    )


def launch_plan(
    browser: str,
    executable: Path | None,
    *,
    headless: bool,
    listen_host: str,
    port: int,
    certificate: Certificate,
    field_trial_config: bool,
    netlog: Path | None = None,
) -> LaunchPlan:
    if browser in CHROMIUM_BROWSERS:
        return LaunchPlan(
            browser,
            executable,
            headless,
            chromium_extra_arguments(
                listen_host,
                port,
                certificate.spki_sha256_base64,
                field_trial_config=field_trial_config,
                netlog=netlog,
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
                # root, which otherwise makes Firefox close HTTP/3 after
                # verification succeeds.
                ("network.http.http3.disable_when_third_party_roots_found", False),
                (
                    "network.http.http3.alt-svc-mapping-for-testing",
                    f"{HOSTNAME};h3=:{port}",
                ),
            ),
            profile_files=(
                (
                    "cert_override.txt",
                    firefox_cert_override(HOSTNAME, port, certificate),
                ),
            ),
        )
    return LaunchPlan("manual", None, False)


@dataclass(frozen=True)
class RunResult:
    run: RunRecord
    port: int
    launch_arguments: str
    timed_out: bool


@contextlib.asynccontextmanager
async def serving(
    scenario: Scenario, listen_host: str, certificate: Certificate
) -> AsyncIterator[tuple[RunRecord, int]]:
    """Serve one run on an ephemeral loopback UDP port."""
    run = RunRecord()
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    load_certificate(configuration, certificate)
    restore = install_hooks(scenario.accept_early_data)
    try:
        server = await serve(
            listen_host,
            0,
            configuration=configuration,
            create_protocol=lambda *values, **kwargs: ResumptionProtocol(
                *values,
                run=run,
                handshake_delay_ms=scenario.handshake_delay_ms,
                **kwargs,
            ),
            session_ticket_fetcher=run.fetch_ticket,
            session_ticket_handler=run.store_ticket,
        )
        try:
            yield run, server._transport.get_extra_info("sockname")[1]
        finally:
            server.close()
    finally:
        restore()


async def capture_run(
    scenario: Scenario,
    *,
    browser: str,
    executable: Path | None,
    headless: bool,
    listen_host: str,
    timeout: float,
    field_trial_config: bool,
    netlog: Path | None = None,
) -> RunResult:
    certificate = generate_certificate(HOSTNAME)
    async with serving(scenario, listen_host, certificate) as (run, port):
        plan = launch_plan(
            browser,
            executable,
            headless=headless,
            listen_host=listen_host,
            port=port,
            certificate=certificate,
            field_trial_config=field_trial_config,
            netlog=netlog,
        )
        url = f"https://{HOSTNAME}:{port}/"
        recorded = (
            plan.recorded_arguments(url)
            .replace(certificate.spki_sha256_base64, "<certificate-spki>")
            .replace(f":{port}", ":<port>")
        )
        if netlog is not None:
            recorded = recorded.replace(str(netlog), "<netlog>")
        timed_out = False
        async with BrowserDriver(plan, url):
            try:
                await asyncio.wait_for(run.done.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                timed_out = True
            await asyncio.sleep(0.2)
    return RunResult(run, port, recorded, timed_out)


# -- Fixture -------------------------------------------------------------------


def flag(value: bool) -> str:
    return "true" if value else "false"


def version(value: int | None) -> str:
    return "none" if value is None else f"0x{value:08x}"


def optional(value: object) -> str:
    return "none" if value is None else str(value)


def request_space(record: ConnectionRecord, stream_id: int) -> str:
    return "+".join(record.stream_spaces.get(stream_id, [])) or "none"


def connection_lines(
    prefix: str,
    record: ConnectionRecord,
    fresh: ClientHelloShape | None,
    *,
    detail: bool,
) -> list[str]:
    if record.client_hello is None:
        return [f"{prefix}_client_hello=missing"]
    shape = parse_client_hello(record.client_hello)
    psk = shape.pre_shared_key()
    lines = [
        f"{prefix}_first_datagram_ms={record.first_datagram_ms}",
        f"{prefix}_handshake_ms={optional(record.handshake_ms)}",
        f"{prefix}_closed_ms={optional(record.closed_ms)}",
        f"{prefix}_closed_by={record.closed_by or 'open'}",
        "{}_packets={}".format(
            prefix,
            ",".join(
                f"{name}:{record.packets.get(name, 0)}"
                for name in ("initial", "0rtt", "handshake", "1rtt")
            ),
        ),
        f"{prefix}_first_packet_version={version(record.first_packet_version)}",
        f"{prefix}_negotiated_version={version(record.negotiated_version)}",
        f"{prefix}_resumed={flag(record.resumed)}",
        "{}_psk_ticket_from={}".format(
            prefix,
            "none"
            if record.psk_ticket_from is None
            else "unknown"
            if record.psk_ticket_from < 0
            else f"connection_{record.psk_ticket_from}",
        ),
        f"{prefix}_early_data_offered={flag(shape.extension(EARLY_DATA) is not None)}",
        f"{prefix}_early_data_accepted={flag(record.early_data_accepted)}",
        f"{prefix}_tickets_issued={record.tickets_issued}",
        "{}_ticket_max_early_data_size={}".format(
            prefix,
            "none"
            if record.ticket_max_early_data_size is None
            else f"0x{record.ticket_max_early_data_size:08x}",
        ),
        f"{prefix}_pre_shared_key_last={flag(shape.extension_types[-1:] == (PRE_SHARED_KEY,))}",
        "{}_extension_order={}".format(
            prefix, ",".join(tls_code(value) for value in shape.extension_types)
        ),
        "{}_key_share_groups={}".format(
            prefix, ",".join(tls_code(value) for value in shape.key_share_groups())
        ),
        "{}_psk_key_exchange_modes={}".format(
            prefix,
            ",".join(f"{value:02x}" for value in shape.psk_key_exchange_modes())
            or "none",
        ),
        "{}_pre_shared_key={}".format(
            prefix,
            "none"
            if psk is None
            else "identity_lengths:{},binder_lengths:{}".format(
                "+".join(str(value) for value in psk[0]),
                "+".join(str(value) for value in psk[1]),
            ),
        ),
        "{}_transport_parameter_ids={}".format(
            prefix, ",".join(shape.transport_parameter_ids())
        ),
        "{}_version_information={}".format(
            prefix, ",".join(shape.version_information()) or "none"
        ),
        f"{prefix}_initial_rtt_us={optional(shape.initial_rtt_us())}",
    ]
    if fresh is not None and record.index > 0:
        lines.extend(
            f"{prefix}_versus_connection_0_{line}"
            for line in compare_shapes(fresh, shape)
        )
    if detail:
        lines.append(f"{prefix}_client_hello_hex={record.client_hello.hex()}")
    stream_ids = sorted(record.stream_spaces)
    lines.append(
        "{}_stream_spaces={}".format(
            prefix,
            ",".join(
                f"{stream_id}:{request_space(record, stream_id)}"
                for stream_id in stream_ids
            )
            or "none",
        )
    )
    streams = record.unidirectional_streams
    lines.append(
        "{}_unidirectional_streams={}".format(
            prefix, ",".join(str(stream_id) for stream_id in streams) or "none"
        )
    )
    lines.extend(
        f"{prefix}_unidirectional_stream_{stream_id}="
        f"type:0x{stream.stream_type:02x},space:{stream.space},"
        f"first_frame_bytes:{stream.first_frame_bytes},first_ms:{stream.first_ms}"
        for stream_id, stream in streams.items()
    )
    return lines


def run_lines(prefix: str, result: RunResult, *, detail: bool) -> list[str]:
    """Render one run; `detail` adds raw ClientHellos and request field names."""
    run = result.run
    lines = [
        f"{prefix}_timed_out={flag(result.timed_out)}",
        f"{prefix}_page_error={run.error or 'none'}",
        f"{prefix}_listen_port={result.port}",
        f"{prefix}_connection_count={len(run.connections)}",
    ]
    fresh = None
    if run.connections and run.connections[0].client_hello is not None:
        fresh = parse_client_hello(run.connections[0].client_hello)
    for record in run.connections:
        lines.extend(
            connection_lines(
                f"{prefix}_connection_{record.index}", record, fresh, detail=detail
            )
        )
    lines.append(f"{prefix}_request_count={len(run.requests)}")
    for index, request in enumerate(run.requests):
        connection = run.connections[request.connection]
        lines.append(
            f"{prefix}_request_{index}=connection:{request.connection},"
            f"stream:{request.stream_id},method:{request.method},"
            f"path:{request.path},body_bytes:{request.body_bytes},"
            f"spaces:{request_space(connection, request.stream_id)},"
            f"received_ms:{request.received_ms}"
        )
        if detail:
            lines.append(
                f"{prefix}_request_{index}_field_names=" + ",".join(request.field_names)
            )
    return lines


def summary_lines(results: Sequence[RunResult]) -> list[str]:
    """Count, across runs, each request's packet spaces and each ClientHello shape."""
    spaces: dict[tuple[str, str], dict[str, int]] = {}
    resumed = offered = accepted = psk_last = later = 0
    added: dict[str, int] = {}
    for result in results:
        run = result.run
        fresh = None
        if run.connections and run.connections[0].client_hello is not None:
            fresh = parse_client_hello(run.connections[0].client_hello)
        for record in run.connections[1:]:
            if record.client_hello is None:
                continue
            later += 1
            shape = parse_client_hello(record.client_hello)
            resumed += record.resumed
            offered += shape.extension(EARLY_DATA) is not None
            accepted += record.early_data_accepted
            psk_last += shape.extension_types[-1:] == (PRE_SHARED_KEY,)
            if fresh is not None:
                key = compare_shapes(fresh, shape)[0].split("=", 1)[1]
                added[key] = added.get(key, 0) + 1
        for request in run.requests:
            connection = run.connections[request.connection]
            counts = spaces.setdefault((request.path, request.method), {})
            space = request_space(connection, request.stream_id)
            counts[space] = counts.get(space, 0) + 1
    lines = [
        f"summary_later_connections={later}",
        f"summary_later_connections_resumed={resumed}",
        f"summary_later_connections_offering_early_data={offered}",
        f"summary_later_connections_early_data_accepted={accepted}",
        f"summary_later_connections_pre_shared_key_last={psk_last}",
    ]
    lines.append(
        "summary_added_extensions="
        + (
            ";".join(f"{value}:{count}" for value, count in sorted(added.items()))
            or "none"
        )
    )
    lines.extend(
        f"summary_request={method} {path}:"
        + ",".join(f"{space}:{count}" for space, count in sorted(counts.items()))
        for (path, method), counts in sorted(spaces.items())
    )
    return lines


def render_fixture(
    scenario: Scenario,
    results: Sequence[RunResult],
    *,
    client: str,
    client_version: str,
    operating_system: str,
    launch_mode: str,
    listen_host: str,
) -> str:
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={client}",
        f"client_version={client_version}",
        f"operating_system={operating_system}",
        f"hostname={HOSTNAME}",
        f"listen_address={listen_host}:0",
        f"launch_mode={launch_mode}",
        f"launch_arguments={results[0].launch_arguments}",
        f"capture_tool=aioquic {aioquic.__version__}",
        f"scenario={scenario.name}",
        f"server_accepts_early_data={flag(scenario.accept_early_data)}",
        f"server_handshake_delay_ms={scenario.handshake_delay_ms}",
        f"server_retire_delay_ms={int(RETIRE_DELAY_SECONDS * 1000)}",
        f"page_retire_wait_ms={RETIRE_WAIT_MILLISECONDS}",
        f"run_count={len(results)}",
    ]
    if any(
        result.launch_arguments != results[0].launch_arguments for result in results
    ):
        raise ValueError("runs of one fixture used different launch arguments")
    lines.extend(summary_lines(results))
    for index, result in enumerate(results):
        lines.extend(run_lines(f"run_{index}", result, detail=index == 0))
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--browser",
        choices=(*CHROMIUM_BROWSERS, "firefox", "manual"),
        required=True,
    )
    parser.add_argument("--browser-path", type=Path)
    parser.add_argument("--client")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--scenario", nargs="+", default=["all"])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--keep-field-trial-config",
        action="store_true",
        help="omit --disable-field-trial-config from Chromium launches",
    )
    parser.add_argument(
        "--netlog-dir",
        type=Path,
        help="write a diagnostic Chromium NetLog per run; not a fixture input",
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--fixture-prefix",
        default="resumption",
        help="write <prefix>-<scenario>.txt instead of resumption-<scenario>.txt",
    )
    args = parser.parse_args(argv)
    if aioquic.__version__ != SUPPORTED_AIOQUIC:
        parser.error(
            f"aioquic {SUPPORTED_AIOQUIC} is required, found {aioquic.__version__}"
        )
    if args.browser != "manual" and args.browser_path is None:
        parser.error("--browser-path is required unless --browser manual")
    if not ipaddress.ip_address(args.listen).is_loopback:
        parser.error("the capture listener must be a loopback address")
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    names = list(SCENARIOS) if args.scenario == ["all"] else args.scenario
    unknown = sorted(set(names) - set(SCENARIOS))
    if unknown:
        parser.error(f"unknown scenarios: {', '.join(unknown)}")
    if args.netlog_dir is not None:
        args.netlog_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        scenario = SCENARIOS[name]
        results = []
        for index in range(args.repeat):
            result = asyncio.run(
                capture_run(
                    scenario,
                    browser=args.browser,
                    executable=args.browser_path,
                    headless=not args.headful,
                    listen_host=args.listen,
                    timeout=args.timeout,
                    field_trial_config=args.keep_field_trial_config,
                    netlog=None
                    if args.netlog_dir is None
                    else args.netlog_dir.resolve() / f"{name}-{index}.json",
                )
            )
            results.append(result)
            print(
                f"{name} run {index}: {len(result.run.connections)} connections, "
                f"{len(result.run.requests)} requests, "
                f"timed_out={flag(result.timed_out)}",
                file=sys.stderr,
                flush=True,
            )
        plan = LaunchPlan(args.browser, args.browser_path, not args.headful)
        fixture = render_fixture(
            scenario,
            results,
            client=args.client or plan.client_name,
            client_version=args.client_version,
            operating_system=args.operating_system,
            launch_mode=plan.launch_mode,
            listen_host=args.listen,
        )
        if args.output_dir is None:
            print(fixture, end="")
        else:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            write_text_fixture(
                args.output_dir / f"{args.fixture_prefix}-{name}.txt", fixture
            )


if __name__ == "__main__":
    main()
