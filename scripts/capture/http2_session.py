"""Loopback TLS and plaintext servers that tap browser WebSocket connections.

Every byte a client sends is recorded before any parser sees it: TLS
ClientHello records before the handshake and decrypted application bytes
before the HTTP/2 or HTTP/1.1 engine. Retained analysis is recomputed from
those taps, so the `h2` state machine only drives server behavior.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import ipaddress
import ssl
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import h2.events
import h2.exceptions
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.settings import SettingCodes, Settings
from hpack import Decoder

from .websocket_frames import EchoPeer

HOSTNAME = "server.phantom.test"
CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
ALPN_PROTOCOLS = ("h2", "http/1.1")
MAX_REQUEST_HEAD = 64 * 1024
MAX_CLIENT_HELLO = 64 * 1024
MAX_CONNECTION_CAPTURE = 16 * 1024 * 1024
READ_SIZE = 64 * 1024
WEBSOCKET_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
REJECT_BODY = b"phantom capture rejected this WebSocket\n"
UNOFFERED_EXTENSION = b"x-phantom-unoffered"

FRAME_TYPES = {
    0x0: "DATA",
    0x1: "HEADERS",
    0x2: "PRIORITY",
    0x3: "RST_STREAM",
    0x4: "SETTINGS",
    0x5: "PUSH_PROMISE",
    0x6: "PING",
    0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE",
    0x9: "CONTINUATION",
}
ERROR_CODES = {code.value: code.name for code in ErrorCodes}
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20


# -- Throwaway certificate -------------------------------------------------


@dataclass(frozen=True)
class Certificate:
    certificate_pem: bytes
    private_key_pem: bytes
    der: bytes

    @property
    def spki_sha256_base64(self) -> str:
        """The value Chromium's `--ignore-certificate-errors-spki-list` takes."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        spki = (
            x509.load_der_x509_certificate(self.der)
            .public_key()
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return base64.b64encode(hashlib.sha256(spki).digest()).decode()

    @property
    def sha256_fingerprint(self) -> str:
        digest = hashlib.sha256(self.der).hexdigest().upper()
        return ":".join(digest[index : index + 2] for index in range(0, 64, 2))


def generate_certificate(hostname: str = HOSTNAME) -> Certificate:
    """Create a self-signed P-256 leaf that exists only for one capture."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(key, hashes.SHA256())
    )
    return Certificate(
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
        private_key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        der=certificate.public_bytes(serialization.Encoding.DER),
    )


def server_context(certificate: Certificate) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(list(ALPN_PROTOCOLS))
    # `load_cert_chain` only reads files; they are removed immediately.
    with tempfile.TemporaryDirectory(prefix="phantom-capture-cert-") as directory:
        certificate_path = Path(directory) / "certificate.pem"
        key_path = Path(directory) / "key.pem"
        certificate_path.write_bytes(certificate.certificate_pem)
        key_path.write_bytes(certificate.private_key_pem)
        context.load_cert_chain(certificate_path, key_path)
    return context


# -- TLS ClientHello tap ---------------------------------------------------


@dataclass
class ClientHello:
    """ALPN offer and SNI parsed from the plaintext ClientHello records."""

    records: bytearray = field(default_factory=bytearray)
    handshake: bytearray = field(default_factory=bytearray)
    complete: bool = False
    alpn_offer: tuple[str, ...] | None = None
    server_name: str | None = None

    def feed(self, data: bytes) -> None:
        if self.complete:
            return
        self.records.extend(data)
        while len(self.records) >= 5:
            if self.records[0] != 22:
                self.complete = True
                return
            length = int.from_bytes(self.records[3:5], "big")
            if len(self.records) < 5 + length:
                break
            self.handshake.extend(self.records[5 : 5 + length])
            del self.records[: 5 + length]
        if len(self.handshake) >= 4:
            length = int.from_bytes(self.handshake[1:4], "big")
            if len(self.handshake) >= 4 + length:
                self.complete = True
                if self.handshake[0] == 1:
                    self._parse(bytes(self.handshake[4 : 4 + length]))
                return
        if len(self.handshake) + len(self.records) > MAX_CLIENT_HELLO:
            self.complete = True

    def _parse(self, body: bytes) -> None:
        offset = 2 + 32
        offset += 1 + body[offset]
        offset += 2 + int.from_bytes(body[offset : offset + 2], "big")
        offset += 1 + body[offset]
        end = offset + 2 + int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        while offset + 4 <= end:
            kind = int.from_bytes(body[offset : offset + 2], "big")
            length = int.from_bytes(body[offset + 2 : offset + 4], "big")
            data = body[offset + 4 : offset + 4 + length]
            offset += 4 + length
            if kind == 16:
                self.alpn_offer = tuple(length_prefixed_strings(data[2:]))
            elif kind == 0 and len(data) >= 5 and data[2] == 0:
                size = int.from_bytes(data[3:5], "big")
                self.server_name = data[5 : 5 + size].decode("ascii", "replace")


def length_prefixed_strings(data: bytes) -> list[str]:
    values = []
    offset = 0
    while offset < len(data):
        size = data[offset]
        values.append(data[offset + 1 : offset + 1 + size].decode("ascii", "replace"))
        offset += 1 + size
    return values


# -- Recorded state --------------------------------------------------------


@dataclass(frozen=True)
class ServerPolicy:
    """How the capture server answers WebSocket openings in one scenario."""

    connect_protocol: bool = True
    # accept | reject-403 | refuse-first | extension-mismatch
    response: str = "accept"
    deflate: bool = False

    def __post_init__(self) -> None:
        if self.response not in {
            "accept",
            "reject-403",
            "refuse-first",
            "extension-mismatch",
        }:
            raise ValueError(f"unsupported WebSocket response: {self.response}")


@dataclass
class ConnectionRecord:
    listener: str
    accepted: float
    client_chunks: list[tuple[float, bytes]] = field(default_factory=list)
    server_chunks: list[tuple[float, bytes]] = field(default_factory=list)
    client_hello: ClientHello | None = None
    alpn: str | None = None
    protocol: str | None = None
    client_eof: float | None = None
    failure: str | None = None
    received: int = 0

    def client_stream(self) -> bytes:
        return b"".join(chunk for _, chunk in self.client_chunks)


@dataclass
class Http1Request:
    connection: int
    received: float
    request_line: bytes
    header_lines: list[bytes]
    kind: str = "other"
    status: int | None = None

    def header(self, name: bytes) -> bytes | None:
        for line in self.header_lines:
            key, _, value = line.partition(b":")
            if key.strip().lower() == name:
                return value.strip()
        return None

    @property
    def target(self) -> bytes:
        parts = self.request_line.split(b" ")
        return parts[1] if len(parts) == 3 else b""


@dataclass
class WebSocketRecord:
    connection: int
    protocol: str
    received: float
    target: bytes
    extensions_offer: bytes | None
    outcome: str
    status: int | None
    selected_extensions: bytes | None
    stream_id: int | None = None
    request: int | None = None
    # Offset of the first WebSocket byte in the connection's client stream.
    stream_offset: int | None = None
    client_closed: bool = False

    @property
    def inflate(self) -> bool:
        return (self.selected_extensions or b"").startswith(b"permessage-deflate")


@dataclass
class CaptureRun:
    """Observations for one browser run; pages are keyed by listener."""

    token: str
    policy: ServerPolicy
    pages: dict[str, bytes]
    observation_seconds: float = 1.0
    clock: Callable[[], float] = time.perf_counter
    started: float = field(init=False)
    connections: list[ConnectionRecord] = field(default_factory=list)
    requests: list[Http1Request] = field(default_factory=list)
    websockets: list[WebSocketRecord] = field(default_factory=list)
    results: list[dict[str, str]] = field(default_factory=list)
    finished: float | None = None
    timed_out: bool = False
    done: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self) -> None:
        self.started = self.clock()

    def now(self) -> float:
        return self.clock() - self.started

    def finish(self, query: dict[str, str]) -> None:
        self.results.append(query)
        if self.finished is None:
            self.finished = self.now()
            asyncio.get_running_loop().call_later(
                self.observation_seconds, self.done.set
            )

    def owns(self, target: bytes) -> bool:
        query = parse_qs(urlsplit(target.decode("latin-1")).query)
        return query.get("run", [""])[0] == self.token

    def websocket_response(self, offer: bytes | None) -> tuple[str, int, bytes | None]:
        """Return (outcome, status, selected extensions) for the next opening."""
        attempt = len(self.websockets)
        policy = self.policy
        if policy.response == "reject-403":
            return "rejected", 403, None
        if policy.response == "refuse-first" and attempt == 0:
            return "refused", 0, None
        if policy.response == "extension-mismatch":
            return "extension-mismatch", 0, UNOFFERED_EXTENSION
        selected = None
        if policy.deflate and offer is not None:
            names = [item.split(b";")[0].strip() for item in offer.split(b",")]
            if b"permessage-deflate" in names:
                selected = b"permessage-deflate"
        return "accepted", 0, selected


def done_query(target: bytes) -> dict[str, str]:
    query = parse_qs(urlsplit(target.decode("latin-1")).query, keep_blank_values=True)
    return {key: values[0] for key, values in query.items() if key != "run"}


# -- Transport channels ----------------------------------------------------


class PlainChannel:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        record: ConnectionRecord,
        clock: Callable[[], float],
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.record = record
        self.clock = clock

    async def read_raw(self) -> bytes:
        try:
            return await self.reader.read(READ_SIZE)
        except ConnectionError:
            return b""

    async def read(self) -> bytes:
        data = await self.read_raw()
        self.tap(data)
        return data

    def tap(self, data: bytes) -> None:
        if not data:
            if self.record.client_eof is None:
                self.record.client_eof = self.clock()
            return
        self.record.received += len(data)
        if self.record.received > MAX_CONNECTION_CAPTURE:
            raise ValueError("connection exceeds the capture limit")
        self.record.client_chunks.append((self.clock(), data))

    async def write(self, data: bytes) -> None:
        if not data:
            return
        self.record.server_chunks.append((self.clock(), data))
        self.writer.write(data)
        await self.writer.drain()


class TlsChannel(PlainChannel):
    """TLS over memory BIOs, so ClientHello bytes are seen before the handshake."""

    def __init__(self, context: ssl.SSLContext, *args) -> None:
        super().__init__(*args)
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.record.client_hello = ClientHello()

    async def handshake(self) -> None:
        while True:
            try:
                self.tls.do_handshake()
                await self.flush()
                self.record.alpn = self.tls.selected_alpn_protocol()
                return
            except ssl.SSLWantReadError:
                pass
            await self.flush()
            data = await self.read_raw()
            if not data:
                raise ConnectionError("client closed during the TLS handshake")
            self.record.client_hello.feed(data)
            self.incoming.write(data)

    async def flush(self) -> None:
        pending = self.outgoing.read()
        if pending:
            self.writer.write(pending)
            await self.writer.drain()

    async def read(self) -> bytes:
        while True:
            try:
                data = self.tls.read(READ_SIZE)
            except ssl.SSLWantReadError:
                await self.flush()
                raw = await self.read_raw()
                if not raw:
                    self.tap(b"")
                    return b""
                self.incoming.write(raw)
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLError):
                data = b""
            await self.flush()
            self.tap(data)
            return data

    async def write(self, data: bytes) -> None:
        if not data:
            return
        self.record.server_chunks.append((self.clock(), data))
        self.tls.write(data)
        await self.flush()


# -- HTTP/1.1 --------------------------------------------------------------


def websocket_accept(key: bytes) -> bytes:
    return base64.b64encode(hashlib.sha1(key + WEBSOCKET_GUID).digest())


class Http1Session:
    def __init__(
        self, channel: PlainChannel, run: CaptureRun, index: int, protocol: str
    ) -> None:
        self.channel = channel
        self.run = run
        self.index = index
        self.protocol = protocol
        self.buffer = bytearray()

    async def serve(self) -> None:
        while True:
            head = await self.read_head()
            if head is None:
                return
            lines = head[:-4].split(b"\r\n")
            request = Http1Request(self.index, self.run.now(), lines[0], lines[1:])
            self.run.requests.append(request)
            if not await self.respond(request):
                return

    async def read_head(self) -> bytes | None:
        while True:
            end = self.buffer.find(b"\r\n\r\n")
            if end >= 0:
                head = bytes(self.buffer[: end + 4])
                del self.buffer[: end + 4]
                return head
            if len(self.buffer) > MAX_REQUEST_HEAD:
                return None
            data = await self.channel.read()
            if not data:
                return None
            self.buffer.extend(data)

    async def respond(self, request: Http1Request) -> bool:
        """Answer one request; return whether the connection stays usable."""
        path = urlsplit(request.target.decode("latin-1")).path
        owned = self.run.owns(request.target)
        upgrade = (request.header(b"upgrade") or b"").lower() == b"websocket"
        if owned and path == "/ws.html":
            request.kind = "page"
            page = self.run.pages[self.channel.record.listener]
            await self.simple(request, 200, b"text/html; charset=utf-8", page)
            return True
        if owned and path == "/done":
            request.kind = "done"
            self.run.finish(done_query(request.target))
            await self.simple(request, 204, None, b"")
            return True
        if owned and path == "/echo" and upgrade:
            return await self.upgrade(request)
        await self.simple(request, 404, None, b"")
        return True

    async def simple(
        self,
        request: Http1Request,
        status: int,
        content_type: bytes | None,
        body: bytes,
        extra: Sequence[bytes] = (),
    ) -> None:
        request.status = status
        lines = [b"HTTP/1.1 " + str(status).encode() + b" " + reason(status)]
        if content_type is not None:
            lines.append(b"content-type: " + content_type)
        lines.append(b"content-length: " + str(len(body)).encode())
        lines.append(b"cache-control: no-store")
        lines.extend(extra)
        await self.channel.write(b"\r\n".join(lines) + b"\r\n\r\n" + body)

    async def upgrade(self, request: Http1Request) -> bool:
        request.kind = "websocket"
        offer = request.header(b"sec-websocket-extensions")
        outcome, status, selected = self.run.websocket_response(offer)
        record = WebSocketRecord(
            connection=self.index,
            protocol=self.protocol,
            received=request.received,
            target=request.target,
            extensions_offer=offer,
            outcome=outcome,
            status=status or 101,
            selected_extensions=selected,
            request=len(self.run.requests) - 1,
        )
        self.run.websockets.append(record)
        if outcome == "rejected":
            await self.simple(
                request,
                403,
                b"text/plain",
                REJECT_BODY,
                (b"connection: close",),
            )
            return False
        if outcome == "refused":
            # Stream refusal has no HTTP/1.1 form; the fallback is accepted.
            record.outcome = "accepted"
        key = request.header(b"sec-websocket-key") or b""
        lines = [
            b"HTTP/1.1 101 Switching Protocols",
            b"upgrade: websocket",
            b"connection: Upgrade",
            b"sec-websocket-accept: " + websocket_accept(key),
        ]
        if selected is not None:
            lines.append(b"sec-websocket-extensions: " + selected)
        request.status = 101
        record.status = 101
        record.stream_offset = self.channel.record.received - len(self.buffer)
        await self.channel.write(b"\r\n".join(lines) + b"\r\n\r\n")
        peer = EchoPeer(inflate=record.inflate)
        data = bytes(self.buffer)
        self.buffer.clear()
        while True:
            if data:
                await self.channel.write(peer.feed(data))
            if peer.closed:
                # RFC 6455 section 7.1.1: the server closes TCP first.
                record.client_closed = True
                return False
            data = await self.channel.read()
            if not data:
                return False


def reason(status: int) -> bytes:
    return {
        101: b"Switching Protocols",
        200: b"OK",
        204: b"No Content",
        403: b"Forbidden",
        404: b"Not Found",
    }.get(status, b"Status")


# -- HTTP/2 ----------------------------------------------------------------


def server_settings(policy: ServerPolicy) -> Settings:
    """Build the server's SETTINGS in wire order.

    ENABLE_CONNECT_PROTOCOL is omitted, not zero, when the policy disables it.
    """
    settings = Settings(
        client=False,
        initial_values={
            SettingCodes.MAX_CONCURRENT_STREAMS: 100,
            SettingCodes.MAX_HEADER_LIST_SIZE: 65536,
            SettingCodes.ENABLE_CONNECT_PROTOCOL: 1,
        },
    )
    del settings[SettingCodes.ENABLE_PUSH]
    if not policy.connect_protocol:
        del settings[SettingCodes.ENABLE_CONNECT_PROTOCOL]
    return settings


class Http2Session:
    def __init__(self, channel: PlainChannel, run: CaptureRun, index: int) -> None:
        self.channel = channel
        self.run = run
        self.index = index
        self.connection = H2Connection(
            H2Configuration(client_side=False, header_encoding=None)
        )
        self.connection.local_settings = server_settings(run.policy)
        self.peers: dict[int, EchoPeer] = {}
        self.pending: dict[int, bytearray] = {}
        self.end_after: set[int] = set()

    async def serve(self) -> None:
        self.connection.initiate_connection()
        await self.flush()
        while True:
            data = await self.channel.read()
            if not data:
                return
            try:
                events = self.connection.receive_data(data)
                for event in events:
                    self.handle(event)
            except h2.exceptions.ProtocolError as error:
                self.channel.record.failure = f"h2:{type(error).__name__}"
                await self.flush()
                return
            await self.flush()
            if any(
                isinstance(event, h2.events.ConnectionTerminated) for event in events
            ):
                return

    async def flush(self) -> None:
        await self.channel.write(self.connection.data_to_send())

    def handle(self, event: h2.events.Event) -> None:
        if isinstance(event, h2.events.RequestReceived):
            self.request(event.stream_id, list(event.headers))
        elif isinstance(event, h2.events.DataReceived):
            if event.flow_controlled_length:
                self.connection.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            peer = self.peers.get(event.stream_id)
            if peer is not None and not peer.closed:
                self.queue(event.stream_id, peer.feed(event.data))
                if peer.closed:
                    self.websocket_for(event.stream_id).client_closed = True
                    self.end_after.add(event.stream_id)
                    self.pump(event.stream_id)
        elif isinstance(event, h2.events.WindowUpdated):
            streams = [event.stream_id] if event.stream_id else list(self.pending)
            for stream_id in streams:
                self.pump(stream_id)
        elif isinstance(event, h2.events.StreamReset):
            self.peers.pop(event.stream_id, None)
            self.pending.pop(event.stream_id, None)

    def websocket_for(self, stream_id: int) -> WebSocketRecord:
        for record in self.run.websockets:
            if record.connection == self.index and record.stream_id == stream_id:
                return record
        raise KeyError(stream_id)

    def request(self, stream_id: int, headers: list[tuple[bytes, bytes]]) -> None:
        fields = dict(headers)
        method = fields.get(b":method", b"")
        target = fields.get(b":path", b"")
        path = urlsplit(target.decode("latin-1")).path
        owned = self.run.owns(target)
        if method == b"CONNECT" and fields.get(b":protocol") == b"websocket":
            self.websocket(stream_id, target, fields, owned)
        elif owned and path == "/ws.html":
            self.respond(
                stream_id,
                200,
                b"text/html; charset=utf-8",
                self.run.pages[self.channel.record.listener],
            )
        elif owned and path == "/done":
            self.run.finish(done_query(target))
            self.respond(stream_id, 204, None, b"")
        else:
            self.respond(stream_id, 404, None, b"")

    def respond(
        self, stream_id: int, status: int, content_type: bytes | None, body: bytes
    ) -> None:
        headers = [(b":status", str(status).encode())]
        if content_type is not None:
            headers.append((b"content-type", content_type))
        headers.append((b"content-length", str(len(body)).encode()))
        headers.append((b"cache-control", b"no-store"))
        self.connection.send_headers(stream_id, headers, end_stream=not body)
        if body:
            self.queue(stream_id, body)
            self.end_after.add(stream_id)
            self.pump(stream_id)

    def websocket(
        self,
        stream_id: int,
        target: bytes,
        fields: dict[bytes, bytes],
        owned: bool,
    ) -> None:
        if not owned or urlsplit(target.decode("latin-1")).path != "/echo":
            self.respond(stream_id, 404, None, b"")
            return
        offer = fields.get(b"sec-websocket-extensions")
        outcome, status, selected = self.run.websocket_response(offer)
        record = WebSocketRecord(
            connection=self.index,
            protocol="h2",
            received=self.run.now(),
            target=target,
            extensions_offer=offer,
            outcome=outcome,
            status=status or None,
            selected_extensions=selected,
            stream_id=stream_id,
        )
        self.run.websockets.append(record)
        if outcome == "refused":
            self.connection.reset_stream(stream_id, ErrorCodes.REFUSED_STREAM)
            return
        if outcome == "rejected":
            self.respond(stream_id, 403, b"text/plain", REJECT_BODY)
            return
        headers = [(b":status", b"200")]
        if selected is not None:
            headers.append((b"sec-websocket-extensions", selected))
        record.status = 200
        self.connection.send_headers(stream_id, headers)
        self.peers[stream_id] = EchoPeer(inflate=record.inflate)

    def queue(self, stream_id: int, data: bytes) -> None:
        if data:
            self.pending.setdefault(stream_id, bytearray()).extend(data)
            self.pump(stream_id)

    def pump(self, stream_id: int) -> None:
        pending = self.pending.get(stream_id, bytearray())
        try:
            while pending:
                size = min(
                    self.connection.local_flow_control_window(stream_id),
                    self.connection.max_outbound_frame_size,
                    len(pending),
                )
                if size <= 0:
                    return
                self.connection.send_data(stream_id, bytes(pending[:size]))
                del pending[:size]
            if stream_id in self.end_after:
                self.end_after.discard(stream_id)
                self.connection.end_stream(stream_id)
        except h2.exceptions.StreamClosedError:
            self.pending.pop(stream_id, None)
            self.end_after.discard(stream_id)


# -- Listeners -------------------------------------------------------------


class CaptureServer:
    """One TLS listener for `HOSTNAME` and one plaintext listener, both loopback."""

    def __init__(self, certificate: Certificate) -> None:
        self.context = server_context(certificate)
        self.run: CaptureRun | None = None
        self.servers: list[asyncio.base_events.Server] = []
        self.writers: set[asyncio.StreamWriter] = set()
        self.tls_address: tuple[str, int] | None = None
        self.plain_address: tuple[str, int] | None = None

    async def start(self, host: str, tls_port: int = 0, plain_port: int = 0) -> None:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the capture listener must be a loopback address")
        tls = await asyncio.start_server(self.handle_tls, host, tls_port)
        plain = await asyncio.start_server(self.handle_plain, host, plain_port)
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
    ) -> tuple[CaptureRun, ConnectionRecord, int] | None:
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
                await Http2Session(channel, run, index).serve()
            else:
                await Http1Session(channel, run, index, record.protocol).serve()
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
            await Http1Session(channel, run, index, "http/1.1").serve()
        except Exception as error:  # recorded: a capture keeps partial evidence
            record.failure = record.failure or type(error).__name__
        finally:
            self.release(writer)

    def release(self, writer: asyncio.StreamWriter) -> None:
        self.writers.discard(writer)
        if not writer.transport.is_closing():
            writer.close()


# -- Offline HTTP/2 analysis ------------------------------------------------


@dataclass(frozen=True)
class Http2Frame:
    direction: str
    received: float
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes

    @property
    def type_name(self) -> str:
        return FRAME_TYPES.get(self.frame_type, f"0x{self.frame_type:02x}")


@dataclass(frozen=True)
class Priority:
    exclusive: bool
    depends_on: int
    weight: int


@dataclass(frozen=True)
class HeaderField:
    """One HPACK representation and, unless it is a size update, its field."""

    representation: str
    # Table index, literal name index (0 for a new name), or new table size.
    index: int
    name_huffman: bool | None
    value_huffman: bool | None
    name: bytes | None = None
    value: bytes | None = None


@dataclass(frozen=True)
class HeaderBlock:
    stream_id: int
    flags: int
    priority: Priority | None
    continuation_count: int
    block: bytes
    fields: tuple[HeaderField, ...]

    def field(self, name: bytes) -> bytes | None:
        for item in self.fields:
            if item.name == name:
                return item.value
        return None


@dataclass(frozen=True)
class Http2Analysis:
    frames: tuple[Http2Frame, ...]
    client_headers: tuple[HeaderBlock, ...]
    stream_data: dict[int, bytes]
    client_trailing: int


def split_frames(
    chunks: Sequence[tuple[float, bytes]], direction: str, *, preface: bool
) -> tuple[list[Http2Frame], int]:
    """Split a tapped byte stream; each frame takes its last byte's time."""
    data = bytearray()
    frames = []
    waiting_for_preface = preface
    for received, chunk in chunks:
        data.extend(chunk)
        if waiting_for_preface:
            if len(data) < len(CONNECTION_PREFACE):
                continue
            if bytes(data[: len(CONNECTION_PREFACE)]) != CONNECTION_PREFACE:
                raise ValueError("client stream does not start with the H2 preface")
            del data[: len(CONNECTION_PREFACE)]
            waiting_for_preface = False
        while len(data) >= 9:
            length = int.from_bytes(data[:3], "big")
            if len(data) < 9 + length:
                break
            frames.append(
                Http2Frame(
                    direction=direction,
                    received=received,
                    frame_type=data[3],
                    flags=data[4],
                    stream_id=int.from_bytes(data[5:9], "big") & 0x7FFFFFFF,
                    payload=bytes(data[9 : 9 + length]),
                )
            )
            del data[: 9 + length]
    return frames, len(data)


def strip_padding(frame: Http2Frame) -> tuple[int, bytes]:
    if not frame.flags & FLAG_PADDED:
        return 0, frame.payload
    pad = frame.payload[0]
    return 1, frame.payload[1 : len(frame.payload) - pad]


def headers_priority(frame: Http2Frame) -> tuple[Priority | None, bytes]:
    _, payload = strip_padding(frame)
    if not frame.flags & FLAG_PRIORITY:
        return None, payload
    return parse_priority(payload[:5]), payload[5:]


def parse_priority(payload: bytes) -> Priority:
    raw = int.from_bytes(payload[:4], "big")
    return Priority(bool(raw >> 31), raw & 0x7FFFFFFF, payload[4] + 1)


def hpack_integer(block: bytes, offset: int, prefix: int) -> tuple[int, int]:
    limit = (1 << prefix) - 1
    value = block[offset] & limit
    offset += 1
    if value < limit:
        return value, offset
    shift = 0
    while True:
        if offset >= len(block) or shift > 28:
            raise ValueError("malformed HPACK integer")
        byte = block[offset]
        offset += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, offset


def hpack_string(block: bytes, offset: int) -> tuple[bool, int]:
    if offset >= len(block):
        raise ValueError("truncated HPACK string")
    huffman = bool(block[offset] & 0x80)
    length, offset = hpack_integer(block, offset, 7)
    if offset + length > len(block):
        raise ValueError("truncated HPACK string")
    return huffman, offset + length


def hpack_representations(block: bytes) -> list[HeaderField]:
    """Classify each representation (RFC 7541 section 6) in block order."""
    representations = []
    offset = 0
    while offset < len(block):
        first = block[offset]
        if first & 0x80:
            index, offset = hpack_integer(block, offset, 7)
            representations.append(HeaderField("indexed", index, None, None))
            continue
        if first & 0x40:
            kind, prefix = "incremental", 6
        elif first & 0x20:
            size, offset = hpack_integer(block, offset, 5)
            representations.append(HeaderField("size-update", size, None, None))
            continue
        elif first & 0x10:
            kind, prefix = "never-indexed", 4
        else:
            kind, prefix = "without-indexing", 4
        index, offset = hpack_integer(block, offset, prefix)
        name_huffman = None
        if index == 0:
            name_huffman, offset = hpack_string(block, offset)
        value_huffman, offset = hpack_string(block, offset)
        representations.append(HeaderField(kind, index, name_huffman, value_huffman))
    return representations


def decode_header_block(decoder: Decoder, block: bytes) -> tuple[HeaderField, ...]:
    representations = hpack_representations(block)
    decoded = list(decoder.decode(block, raw=True))
    fields = []
    for representation in representations:
        if representation.representation == "size-update":
            fields.append(representation)
            continue
        if not decoded:
            raise ValueError("HPACK decoder returned fewer fields than the block")
        name, value = decoded.pop(0)
        fields.append(
            HeaderField(
                representation.representation,
                representation.index,
                representation.name_huffman,
                representation.value_huffman,
                bytes(name),
                bytes(value),
            )
        )
    if decoded:
        raise ValueError("HPACK decoder returned more fields than the block")
    return tuple(fields)


def analyze_http2(record: ConnectionRecord) -> Http2Analysis:
    client, trailing = split_frames(record.client_chunks, "client", preface=True)
    server, _ = split_frames(record.server_chunks, "server", preface=False)
    decoder = Decoder()
    blocks = []
    stream_data: dict[int, bytearray] = {}
    pending: tuple[Http2Frame, Priority | None, bytearray, int] | None = None
    for frame in client:
        if frame.frame_type == 0x0:
            _, payload = strip_padding(frame)
            stream_data.setdefault(frame.stream_id, bytearray()).extend(payload)
        elif frame.frame_type == 0x1:
            priority, fragment = headers_priority(frame)
            pending = (frame, priority, bytearray(fragment), 0)
        elif frame.frame_type == 0x9 and pending is not None:
            first, priority, fragment, continuations = pending
            fragment.extend(frame.payload)
            pending = (first, priority, fragment, continuations + 1)
        else:
            continue
        if pending is not None and frame.flags & FLAG_END_HEADERS:
            first, priority, fragment, continuations = pending
            block = bytes(fragment)
            blocks.append(
                HeaderBlock(
                    stream_id=first.stream_id,
                    flags=first.flags,
                    priority=priority,
                    continuation_count=continuations,
                    block=block,
                    fields=decode_header_block(decoder, block),
                )
            )
            pending = None
    frames = sorted([*client, *server], key=lambda frame: frame.received)
    return Http2Analysis(
        frames=tuple(frames),
        client_headers=tuple(blocks),
        stream_data={key: bytes(value) for key, value in stream_data.items()},
        client_trailing=trailing,
    )


def frame_details(frame: Http2Frame) -> list[str]:
    """Render the ordered, non-random fields of one frame for a fixture."""
    details = []
    kind = frame.frame_type
    if kind == 0x0:
        _, payload = strip_padding(frame)
        details.append(f"data_length:{len(payload)}")
    elif kind == 0x1:
        priority, fragment = headers_priority(frame)
        if priority is not None:
            details.append(priority_text(priority))
        details.append(f"block_length:{len(fragment)}")
    elif kind == 0x2:
        details.append(priority_text(parse_priority(frame.payload)))
    elif kind == 0x3:
        details.append(f"error:{error_name(frame.payload)}")
    elif kind == 0x4 and not frame.flags & FLAG_ACK:
        pairs = [
            f"{int.from_bytes(frame.payload[offset : offset + 2], 'big')}="
            f"{int.from_bytes(frame.payload[offset + 2 : offset + 6], 'big')}"
            for offset in range(0, len(frame.payload) - 5, 6)
        ]
        details.append("settings:" + ";".join(pairs))
    elif kind == 0x7:
        last = int.from_bytes(frame.payload[:4], "big") & 0x7FFFFFFF
        details.append(f"last_stream:{last},error:{error_name(frame.payload[4:8])}")
        details.append(f"debug_length:{max(0, len(frame.payload) - 8)}")
    elif kind == 0x8:
        increment = int.from_bytes(frame.payload[:4], "big") & 0x7FFFFFFF
        details.append(f"increment:{increment}")
    return details


def priority_text(priority: Priority) -> str:
    return (
        f"exclusive:{str(priority.exclusive).lower()},"
        f"depends_on:{priority.depends_on},weight:{priority.weight}"
    )


def error_name(payload: bytes) -> str:
    code = int.from_bytes(payload[:4], "big")
    return ERROR_CODES.get(code, f"0x{code:x}")
