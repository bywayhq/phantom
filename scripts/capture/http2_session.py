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
import errno
import hashlib
import ipaddress
import math
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

from .websocket_frames import EchoPeer

HOSTNAME = "server.phantom.test"
CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
ALPN_PROTOCOLS = ("h2", "http/1.1")
MAX_REQUEST_HEAD = 64 * 1024
MAX_CLIENT_HELLO = 64 * 1024
MAX_CONNECTION_CAPTURE = 16 * 1024 * 1024
READ_SIZE = 64 * 1024
CONNECTION_CLEANUP_SECONDS = 5.0
CONNECTION_CANCEL_SECONDS = 1.0
# Guardrails for a capture, rather than measured browser maxima.
MAX_RUNS = 32
MAX_ACTIVE_CONNECTIONS = 32
MAX_RUN_CONNECTIONS = 128
MAX_TOTAL_CONNECTIONS = MAX_RUNS * MAX_RUN_CONNECTIONS
MAX_RUN_REQUESTS = 1024
MAX_RUN_WEBSOCKETS = 256
MAX_RUN_RESULTS = 128
MAX_RUN_CAPTURE = 64 * 1024 * 1024
MAX_CAPTURE_CHUNKS = 16384
MAX_H2_FRAMES = 16384
MAX_HEADER_FIELDS = 1024
PEER_ERRNOS = frozenset((errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE))
WEBSOCKET_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
REJECT_BODY = b"phantom capture rejected this WebSocket\n"
UNOFFERED_EXTENSION = b"x-phantom-unoffered"


class CaptureLimitError(ValueError):
    """The capture cannot retain additional input without exceeding its budget."""


class MalformedCaptureError(ValueError):
    """A complete incoming record has an invalid extent or sequence."""


def peer_disconnected(error: BaseException) -> bool:
    return isinstance(error, OSError) and (
        error.errno in PEER_ERRNOS
        or getattr(error, "winerror", None) in (10053, 10054, 232)
    )


def validate_duration(value: float, name: str, *, positive: bool = False) -> None:
    if not math.isfinite(value) or value < 0 or (positive and value == 0):
        condition = "positive" if positive else "nonnegative"
        raise ValueError(f"{name} must be finite and {condition}")


def authority(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


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
        if len(self.records) + len(self.handshake) + len(data) > MAX_CLIENT_HELLO:
            raise CaptureLimitError("ClientHello exceeds the capture limit")
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
            if length + 4 > MAX_CLIENT_HELLO:
                raise CaptureLimitError("ClientHello exceeds the capture limit")
            if len(self.handshake) >= 4 + length:
                self.complete = True
                if self.handshake[0] == 1:
                    self._parse(bytes(self.handshake[4 : 4 + length]))
                return

    def _parse(self, body: bytes) -> None:
        if len(body) < 34:
            raise MalformedCaptureError("truncated ClientHello fixed fields")
        offset = 2 + 32
        session, offset = tls_vector(body, offset, 1)
        suites, offset = tls_vector(body, offset, 2)
        compression, offset = tls_vector(body, offset, 1)
        if len(session) > 32 or not suites or len(suites) % 2 or not compression:
            raise MalformedCaptureError("invalid ClientHello vectors")
        if offset == len(body):
            return
        extensions, offset = tls_vector(body, offset, 2)
        if offset != len(body):
            raise MalformedCaptureError("ClientHello extensions do not end the message")

        offset = 0
        while offset < len(extensions):
            if len(extensions) - offset < 4:
                raise MalformedCaptureError("truncated ClientHello extension")
            kind = int.from_bytes(extensions[offset : offset + 2], "big")
            data, offset = tls_vector(extensions, offset + 2, 2)
            if kind == 16:
                protocols, end = tls_vector(data, 0, 2)
                if end != len(data) or not protocols:
                    raise MalformedCaptureError("invalid ClientHello ALPN list")
                self.alpn_offer = tuple(length_prefixed_strings(protocols))
            elif kind == 0:
                names, end = tls_vector(data, 0, 2)
                if end != len(data) or not names:
                    raise MalformedCaptureError("invalid ClientHello server name list")
                position = 0
                while position < len(names):
                    name_type = names[position]
                    name, position = tls_vector(names, position + 1, 2)
                    if not name:
                        raise MalformedCaptureError("empty ClientHello server name")
                    if name_type == 0:
                        self.server_name = name.decode("ascii", "replace")


def tls_vector(data: bytes, offset: int, width: int) -> tuple[bytes, int]:
    if offset < 0 or offset + width > len(data):
        raise MalformedCaptureError("truncated ClientHello vector length")
    length = int.from_bytes(data[offset : offset + width], "big")
    start = offset + width
    end = start + length
    if end > len(data):
        raise MalformedCaptureError("truncated ClientHello vector body")
    return data[start:end], end


def length_prefixed_strings(data: bytes) -> list[str]:
    values = []
    offset = 0
    while offset < len(data):
        value, offset = tls_vector(data, offset, 1)
        if not value:
            raise MalformedCaptureError("empty ClientHello ALPN protocol")
        values.append(value.decode("ascii", "replace"))
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
    sent: int = 0

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
    retained_bytes: int = 0
    request_count: int = 0
    admitted_connections: int = 0

    def __post_init__(self) -> None:
        validate_duration(self.observation_seconds, "observation")
        self.started = self.clock()

    def now(self) -> float:
        return self.clock() - self.started

    def finish(self, query: dict[str, str]) -> None:
        if len(self.results) >= MAX_RUN_RESULTS:
            raise CaptureLimitError("run result count exceeds the capture limit")
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
        if attempt >= MAX_RUN_WEBSOCKETS:
            raise CaptureLimitError("run WebSocket count exceeds the capture limit")
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

    def retain(self, length: int) -> None:
        if self.retained_bytes + length > MAX_RUN_CAPTURE:
            raise CaptureLimitError("run bytes exceed the capture limit")
        self.retained_bytes += length

    def request(self) -> None:
        if self.request_count >= MAX_RUN_REQUESTS:
            raise CaptureLimitError("run request count exceeds the capture limit")
        self.request_count += 1


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
        run: CaptureRun | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.record = record
        self.clock = clock
        self.run = run
        self.peer_io_failure: BaseException | None = None

    async def read_raw(self) -> bytes:
        try:
            return await self.reader.read(READ_SIZE)
        except OSError as error:
            if peer_disconnected(error):
                return b""
            raise

    async def read(self) -> bytes:
        data = await self.read_raw()
        self.tap(data)
        return data

    def tap(self, data: bytes) -> None:
        if not data:
            if self.record.client_eof is None:
                self.record.client_eof = self.clock()
            return
        if self.record.received + len(data) > MAX_CONNECTION_CAPTURE:
            raise CaptureLimitError("connection exceeds the capture limit")
        if len(self.record.client_chunks) >= MAX_CAPTURE_CHUNKS:
            raise CaptureLimitError("connection chunk count exceeds the capture limit")
        if self.run is not None:
            self.run.retain(len(data))
        self.record.received += len(data)
        self.record.client_chunks.append((self.clock(), data))

    def tap_output(self, data: bytes) -> None:
        if self.record.sent + len(data) > MAX_CONNECTION_CAPTURE:
            raise CaptureLimitError("connection output exceeds the capture limit")
        if len(self.record.server_chunks) >= MAX_CAPTURE_CHUNKS:
            raise CaptureLimitError(
                "connection output chunk count exceeds the capture limit"
            )
        if self.run is not None:
            self.run.retain(len(data))
        self.record.sent += len(data)
        self.record.server_chunks.append((self.clock(), data))

    async def write(self, data: bytes) -> None:
        if not data:
            return
        self.tap_output(data)
        await self.write_raw(data)

    async def write_raw(self, data: bytes) -> None:
        try:
            self.writer.write(data)
            await self.drain()
        except OSError as error:
            if peer_disconnected(error):
                self.peer_io_failure = error
            raise

    async def drain(self) -> None:
        try:
            await self.writer.drain()
        except ConnectionResetError as error:
            # asyncio's clean connection_lost drain error has no errno.
            if (
                error.errno is None
                and self.writer.is_closing()
                and self.reader.at_eof()
                and self.reader.exception() is None
            ):
                self.peer_io_failure = error
            raise


class TlsChannel(PlainChannel):
    """TLS over memory BIOs, so ClientHello bytes are seen before the handshake."""

    def __init__(self, context: ssl.SSLContext, *args) -> None:
        super().__init__(*args)
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.record.client_hello = ClientHello()
        self.peer_handshake_failure: BaseException | None = None

    async def handshake(self) -> None:
        while True:
            try:
                self.tls.do_handshake()
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as error:
                self.peer_handshake_failure = error
                raise
            else:
                await self.flush()
                self.record.alpn = self.tls.selected_alpn_protocol()
                return

            await self.flush()
            data = await self.read_raw()
            if not data:
                error = ConnectionError("client closed during the TLS handshake")
                self.peer_handshake_failure = error
                raise error
            try:
                self.record.client_hello.feed(data)
            except MalformedCaptureError as error:
                self.peer_handshake_failure = error
                raise
            self.incoming.write(data)

    async def flush(self) -> None:
        pending = self.outgoing.read()
        if pending:
            await self.write_raw(pending)

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
            except ssl.SSLZeroReturnError:
                data = b""
            await self.flush()
            self.tap(data)
            return data

    async def write(self, data: bytes) -> None:
        if not data:
            return
        self.tap_output(data)
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
            if len(lines) - 1 > MAX_HEADER_FIELDS:
                raise CaptureLimitError(
                    "request header count exceeds the capture limit"
                )
            request = Http1Request(self.index, self.run.now(), lines[0], lines[1:])
            self.run.request()
            self.run.requests.append(request)
            if not await self.respond(request):
                return

    async def read_head(self) -> bytes | None:
        while True:
            end = self.buffer.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 > MAX_REQUEST_HEAD:
                    raise CaptureLimitError("request head exceeds the capture limit")
                head = bytes(self.buffer[: end + 4])
                del self.buffer[: end + 4]
                return head
            if len(self.buffer) > MAX_REQUEST_HEAD:
                raise CaptureLimitError("request head exceeds the capture limit")
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
        self.reset_streams: set[int] = set()
        self.frame_head = bytearray()
        self.frame_remaining = len(CONNECTION_PREFACE)
        self.frame_count = 0

    async def serve(self) -> None:
        self.connection.initiate_connection()
        await self.flush()
        while True:
            data = await self.channel.read()
            if not data:
                return
            self.count_frames(data)
            try:
                events = self.connection.receive_data(data)
            except h2.exceptions.ProtocolError as error:
                self.channel.record.failure = f"h2:{type(error).__name__}"
                await self.flush()
                return

            # receive_data applies the whole batch before local responses run.
            self.reset_streams.update(
                event.stream_id
                for event in events
                if isinstance(event, h2.events.StreamReset)
            )
            for event in events:
                self.handle(event)
            await self.flush()
            if any(
                isinstance(event, h2.events.ConnectionTerminated) for event in events
            ):
                return

    def count_frames(self, data: bytes) -> None:
        position = 0
        while position < len(data):
            if self.frame_remaining:
                size = min(self.frame_remaining, len(data) - position)
                self.frame_remaining -= size
                position += size
                continue
            size = min(9 - len(self.frame_head), len(data) - position)
            self.frame_head.extend(data[position : position + size])
            position += size
            if len(self.frame_head) == 9:
                if self.frame_count >= MAX_H2_FRAMES:
                    raise CaptureLimitError("H2 frame count exceeds the capture limit")
                self.frame_count += 1
                self.frame_remaining = int.from_bytes(self.frame_head[:3], "big")
                self.frame_head.clear()

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
            self.end_after.discard(event.stream_id)

    def websocket_for(self, stream_id: int) -> WebSocketRecord:
        for record in self.run.websockets:
            if record.connection == self.index and record.stream_id == stream_id:
                return record
        raise KeyError(stream_id)

    def request(self, stream_id: int, headers: list[tuple[bytes, bytes]]) -> None:
        if len(headers) > MAX_HEADER_FIELDS:
            raise CaptureLimitError("H2 header field count exceeds the capture limit")
        self.run.request()
        if stream_id in self.reset_streams:
            # The complete incoming batch has already closed this stream.
            return
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
            if (
                sum(map(len, self.pending.values())) + len(data)
                > MAX_CONNECTION_CAPTURE
            ):
                raise CaptureLimitError("H2 pending output exceeds the capture limit")
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
                self.peers.pop(stream_id, None)
            self.pending.pop(stream_id, None)
        except h2.exceptions.StreamClosedError as error:
            if stream_id not in self.reset_streams or error.stream_id != stream_id:
                raise
            self.pending.pop(stream_id, None)
            self.end_after.discard(stream_id)
            self.peers.pop(stream_id, None)


# -- Listeners -------------------------------------------------------------


class CaptureFailures(Exception):
    """The original capture operation and its observed cleanup failures."""

    def __init__(
        self, primary: BaseException | None, cleanup: tuple[BaseException, ...]
    ) -> None:
        self.primary = primary
        self.cleanup = cleanup
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        self.interruption_cause: BaseException | None = None
        self.interruption_context: BaseException | None = None
        super().__init__("websocket capture cleanup failed")


def raise_capture_failures(
    primary: BaseException | None, cleanup: tuple[BaseException, ...]
) -> None:
    if not cleanup:
        if primary is not None:
            raise primary
        return

    if primary is None and len(cleanup) == 1:
        raise cleanup[0]

    failure = CaptureFailures(primary, cleanup)
    interruption = next(
        (
            error
            for error in (primary, *cleanup)
            if error is not None and not isinstance(error, Exception)
        ),
        None,
    )
    if interruption is not None:
        failure.interruption_cause = interruption.__cause__
        failure.interruption_context = interruption.__context__
        raise interruption from failure

    raise failure from primary


class CaptureProtocol(asyncio.StreamReaderProtocol):
    """Retain the run before a transport queues its connection callback."""

    def __init__(
        self, owner: CaptureServer, listener: str, run: CaptureRun | None
    ) -> None:
        self.owner = owner
        self.listener = listener
        self.run = run
        self.stopping = owner.closing or run is None
        self.transport: asyncio.Transport | None = None
        self.failure: BaseException | None = None
        self.retired = asyncio.get_running_loop().create_future()
        reader = asyncio.StreamReader()
        super().__init__(reader, self.connected)

    def connection_made(self, transport: asyncio.Transport) -> None:
        self.transport = transport
        if self.failure is not None:
            # The native backend has attached this transport before this callback.
            self.owner.failed(self.failure, self.run)
        try:
            super().connection_made(transport)
        except BaseException as error:
            self.owner.failed(error, self.run)
            try:
                transport.abort()
            except BaseException as error:
                self.owner.failed(error, self.run)

    def connected(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.owner._admit(self.listener, reader, writer, self)

    def connection_lost(self, error: Exception | None) -> None:
        try:
            super().connection_lost(error)
        except BaseException as failure:
            self.owner.failed(failure, self.run)
        finally:
            if not self.retired.done():
                self.retired.set_result(None)

    async def wait_retired(self) -> None:
        # Cancelling an observer must not cancel the original closure signal.
        await asyncio.shield(self.retired)


class CaptureServer:
    """One TLS listener for `HOSTNAME` and one plaintext listener, both loopback."""

    def __init__(self, certificate: Certificate) -> None:
        self.context = server_context(certificate)
        self.run: CaptureRun | None = None
        self.servers: list[asyncio.Server] = []
        self.writers: set[asyncio.StreamWriter] = set()
        self.handlers: dict[
            asyncio.Task[None], tuple[CaptureRun, bool, BaseException | None]
        ] = {}
        self.writer_waits: dict[asyncio.Task[None], asyncio.StreamWriter] = {}
        self.listener_waits: dict[asyncio.Task[None], tuple[asyncio.Server, bool]] = {}
        self.protocol_waits: dict[asyncio.Task[None], CaptureProtocol] = {}
        self.protocols: set[CaptureProtocol] = set()
        self.accept_failures: list[BaseException] = []
        self.closing = False
        self.returned = False
        self.primary: BaseException | None = None
        self.cleanup_failures: tuple[BaseException, ...] = ()
        self.total_connections = 0
        self.run_count = 0
        self.tls_address: tuple[str, int] | None = None
        self.plain_address: tuple[str, int] | None = None

    async def start(self, host: str, tls_port: int = 0, plain_port: int = 0) -> None:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the capture listener must be a loopback address")

        try:
            for listener, port in (("tls", tls_port), ("plain", plain_port)):
                server = await asyncio.get_running_loop().create_server(
                    lambda name=listener: self.new_protocol(name),
                    host,
                    port,
                    start_serving=False,
                )
                self.servers.append(server)
                setattr(
                    self, f"{listener}_address", server.sockets[0].getsockname()[:2]
                )
                ready = asyncio.Event()
                operation = self.wait_listener(server, ready)
                try:
                    task = asyncio.create_task(operation)
                except BaseException as error:
                    failures = []
                    self.discard_operation(operation, failures, error)
                    self.accept_failures.extend(failures)
                    raise_capture_failures(error, tuple(failures[1:]))
                self.listener_waits[task] = (server, False)
                task.add_done_callback(self.wait_finished)
                await ready.wait()
                if task.done():
                    task.result()
                if self.closing:
                    raise_capture_failures(None, tuple(self.accept_failures))
                await server.start_serving()
        except BaseException as primary:
            cleanup = []
            try:
                await self.close()
            except BaseException as error:
                cleanup.append(error)
            raise_capture_failures(primary, tuple(cleanup))

    async def wait_listener(self, server: asyncio.Server, ready: asyncio.Event) -> None:
        # The ready callback runs after the original waiter has entered or failed.
        asyncio.get_running_loop().call_soon(ready.set)
        await server.wait_closed()

    def begin_run(self, run: CaptureRun) -> None:
        if self.closing or self.accept_failures:
            raise_capture_failures(
                RuntimeError("capture admission has stopped"),
                (*self.cleanup_failures, *self.accept_failures),
            )
        if self.handlers or self.writers or self.writer_waits or self.protocols:
            raise_capture_failures(
                RuntimeError("previous capture owners have not finished"),
                self.cleanup_failures,
            )
        if self.run_count >= MAX_RUNS:
            raise CaptureLimitError("run count exceeds the capture limit")
        self.run_count += 1
        self.returned = False
        self.primary = None
        self.cleanup_failures = ()
        self.run = run

    def new_protocol(self, listener: str) -> CaptureProtocol:
        run = self.run
        protocol = CaptureProtocol(self, listener, run)
        self.protocols.add(protocol)
        self.total_connections += 1
        if run is not None:
            run.admitted_connections += 1
        if (
            sum(not owner.retired.done() for owner in self.protocols)
            > MAX_ACTIVE_CONNECTIONS
            or self.total_connections > MAX_TOTAL_CONNECTIONS
            or (run is not None and run.admitted_connections > MAX_RUN_CONNECTIONS)
        ):
            protocol.stopping = True
            protocol.failure = CaptureLimitError(
                "connection count exceeds the capture limit"
            )
            self.accept_failures.append(protocol.failure)
            self.closing = True
            if run is not None:
                run.done.set()
        if self.closing:
            protocol.stopping = True
            if self.returned:
                failure = RuntimeError("connection arrived after capture shutdown")
                self.accept_failures.append(failure)
                protocol.failure = protocol.failure or failure
                # Closing here would precede the backend's transport attachment.
                self._report_failure()
        operation = protocol.wait_retired()
        try:
            task = asyncio.create_task(operation)
        except BaseException as error:
            failures = []
            self.discard_operation(operation, failures, error)
            self.accept_failures.extend(failures)
            protocol.failure = error
            protocol.stopping = True
            self.closing = True
            if run is not None:
                run.done.set()
        else:
            self.protocol_waits[task] = protocol
            task.add_done_callback(self.wait_finished)
        return protocol

    def failed(self, error: BaseException, run: CaptureRun | None) -> None:
        if not any(error is original for original in self.accept_failures):
            self.accept_failures.append(error)
        if run is not None:
            run.done.set()
        self.closing = True
        for server in self.servers:
            try:
                server.close()
            except BaseException as failure:
                if not any(failure is original for original in self.accept_failures):
                    self.accept_failures.append(failure)
        if self.returned:
            self._report_failure()

    def _report_failure(self) -> None:
        asyncio.get_running_loop().call_exception_handler(
            {
                "message": "websocket capture owner failed after cleanup returned",
                "exception": CaptureFailures(
                    self.primary, (*self.cleanup_failures, *self.accept_failures)
                ),
                "capture_owner": self,
            }
        )

    @staticmethod
    def discard_operation(
        operation, failures: list[BaseException], error: BaseException
    ) -> None:
        failures.append(error)
        try:
            operation.close()
        except BaseException as failure:
            failures.append(failure)

    def wait_finished(self, task: asyncio.Task[None]) -> None:
        if task not in {*self.writer_waits, *self.listener_waits, *self.protocol_waits}:
            return
        if not self.returned and task not in self.listener_waits:
            return
        try:
            task.result()
        except BaseException as error:
            if task in self.writer_waits and peer_disconnected(error):
                return
            if self.returned or task in self.listener_waits:
                self.failed(error, self.run)

    async def close(self) -> None:
        self.returned = False
        self.closing = True
        failures = []
        for server in list(self.servers):
            closed = False
            try:
                server.close()
            except BaseException as error:
                failures.append(error)
            else:
                closed = True

            existing = next(
                (
                    task
                    for task, (owner, _) in self.listener_waits.items()
                    if owner is server
                ),
                None,
            )
            if existing is not None:
                self.listener_waits[existing] = (
                    server,
                    closed or self.listener_waits[existing][1],
                )
                continue

            try:
                operation = server.wait_closed()
            except BaseException as error:
                failures.append(error)
                continue

            try:
                task = asyncio.create_task(operation)
            except BaseException as error:
                self.discard_operation(operation, failures, error)
            else:
                self.listener_waits[task] = (server, closed)
                task.add_done_callback(self.wait_finished)

        failures.extend(await self._stop_connections())
        self.cleanup_failures += tuple(failures)
        self.returned = True
        raise_capture_failures(None, tuple(failures))

    async def stop_connections(self) -> None:
        failures = await self._stop_connections()
        self.cleanup_failures += tuple(failures)
        self.returned = True
        raise_capture_failures(None, tuple(failures))

    async def _stop_connections(self) -> list[BaseException]:
        self.returned = False
        failures = self.accept_failures
        self.accept_failures = []
        deadline = asyncio.get_running_loop().time() + CONNECTION_CLEANUP_SECONDS
        cancelling = False
        for protocol in self.protocols:
            protocol.stopping = True
        while True:
            for writer in list(self.writers):
                if writer in self.writer_waits.values():
                    continue

                try:
                    writer.transport.abort()
                except BaseException as error:
                    failures.append(error)
                    try:
                        writer.close()
                    except BaseException as error:
                        failures.append(error)

                try:
                    operation = writer.wait_closed()
                except BaseException as error:
                    failures.append(error)
                    continue

                try:
                    task = asyncio.create_task(operation)
                except BaseException as error:
                    self.discard_operation(operation, failures, error)
                else:
                    self.writer_waits[task] = writer
                    task.add_done_callback(self.wait_finished)

            tasks = {*self.handlers, *self.writer_waits, *self.protocol_waits}
            if self.closing:
                tasks.update(self.listener_waits)
            pending = {task for task in tasks if not task.done()}
            if not pending:
                break

            interruption: BaseException | None = None
            wait_deadline = (
                deadline if cancelling else deadline - CONNECTION_CANCEL_SECONDS
            )
            if asyncio.get_running_loop().time() >= wait_deadline:
                interruption = asyncio.TimeoutError(
                    "websocket connection cleanup timed out"
                )
            else:
                try:
                    await asyncio.wait(
                        pending,
                        timeout=max(
                            0.0, wait_deadline - asyncio.get_running_loop().time()
                        ),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                except BaseException as error:
                    interruption = error

            tasks = {*self.handlers, *self.writer_waits, *self.protocol_waits}
            if self.closing:
                tasks.update(self.listener_waits)
            pending = {task for task in tasks if not task.done()}
            if interruption is not None:
                failures.append(interruption)
            elif asyncio.get_running_loop().time() < wait_deadline:
                continue
            elif not pending and all(
                writer in self.writer_waits.values() for writer in self.writers
            ):
                break
            else:
                failures.append(
                    asyncio.TimeoutError("websocket connection cleanup timed out")
                )

            for task in pending:
                # Keep uncollected owners after the finite waiting period.
                if task in self.handlers:
                    run, cancel_requested, original = self.handlers[task]
                    if not cancel_requested:
                        self.handlers[task] = (run, task.cancel(), original)
            if not cancelling and asyncio.get_running_loop().time() < deadline:
                cancelling = True
                continue
            break

        for task in list(self.handlers):
            if not task.done():
                continue

            _, _, original = self.handlers.pop(task)

            try:
                task.result()
            except asyncio.CancelledError as cancellation:
                # cancel() does not establish whether another owner cancelled first.
                error = original if original is not None else cancellation
                failures.append(error)

                # The handler retains the original cause before Task.result()
                # can reconstruct a cancellation on Python 3.10.
                seen = set()
                while id(error) not in seen:
                    seen.add(id(error))
                    if isinstance(error.__cause__, CaptureFailures):
                        failures.extend(error.__cause__.cleanup)
                        break
                    if not isinstance(error.__context__, asyncio.CancelledError):
                        break
                    error = error.__context__
            except BaseException as error:
                failures.append(original if original is not None else error)

        for task in list(self.writer_waits):
            if not task.done():
                continue

            writer = self.writer_waits.pop(task)
            closed = False

            try:
                task.result()
            except OSError as error:
                if peer_disconnected(error):
                    closed = True
                else:
                    failures.append(error)
            except asyncio.CancelledError as error:
                failures.append(error)
            except BaseException as error:
                failures.append(error)
            else:
                closed = True

            try:
                if closed and writer.is_closing():
                    self.writers.discard(writer)
            except BaseException as error:
                failures.append(error)

        for task in list(self.listener_waits):
            if not task.done():
                continue

            server, closed = self.listener_waits.pop(task)
            observed = False

            try:
                task.result()
            except asyncio.CancelledError as error:
                failures.append(error)
            except BaseException as error:
                failures.append(error)
            else:
                observed = True

            if closed and observed:
                self.servers.remove(server)

        for task, protocol in list(self.protocol_waits.items()):
            if task.done():
                try:
                    task.result()
                except BaseException as error:
                    failures.append(error)
                else:
                    self.protocols.discard(protocol)
                del self.protocol_waits[task]

        for protocol in self.protocols.difference(self.protocol_waits.values()):
            if protocol.retired.done():
                try:
                    protocol.retired.result()
                except BaseException as error:
                    failures.append(error)
                else:
                    self.protocols.discard(protocol)

        if self.protocols or self.handlers or self.writer_waits or self.writers:
            failures.append(
                RuntimeError("websocket capture cleanup retains unfinished owners")
            )

        failures.extend(self.accept_failures)
        self.accept_failures = []
        unique = []
        for error in failures:
            if not any(error is original for original in unique):
                unique.append(error)
        return unique

    def _admit(
        self,
        listener: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        protocol: CaptureProtocol,
    ) -> None:
        self.writers.add(writer)
        run = protocol.run
        if self.closing or protocol.stopping or run is None:
            try:
                writer.transport.abort()
            except BaseException as error:
                self.failed(error, run)
                try:
                    writer.close()
                except BaseException as error:
                    self.failed(error, run)
            return

        operation = self._handle(listener, reader, writer)
        try:
            task = asyncio.create_task(operation)
        except BaseException as error:
            failures = []
            self.discard_operation(operation, failures, error)
            for failure in failures:
                self.failed(failure, run)
            try:
                writer.transport.abort()
            except BaseException as error:
                self.failed(error, run)
            run.done.set()
        else:
            self.handlers[task] = (run, False, None)
            try:
                task.add_done_callback(self._handler_finished)
            except BaseException as error:
                self.failed(error, run)

    def _handler_finished(self, task: asyncio.Task[None]) -> None:
        admission = self.handlers.get(task)
        if admission is None:
            return

        run, cancel_requested, original = admission
        if not task.cancelled() and task.exception() is None:
            return

        run.done.set()
        if task.cancelled() and cancel_requested and not self.returned:
            # Let cleanup retrieve the original cancellation before this callback does.
            return

        try:
            task.result()
        except BaseException as error:
            self.failed(original if original is not None else error, run)

    def accept(
        self, listener: str, writer: asyncio.StreamWriter
    ) -> tuple[CaptureRun, ConnectionRecord, int]:
        # Admission retains this task and its run before the coroutine starts.
        run, _, _ = self.handlers[asyncio.current_task()]
        record = ConnectionRecord(listener=listener, accepted=run.now())
        run.connections.append(record)
        return run, record, len(run.connections) - 1

    async def _handle(
        self, listener: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        primary: BaseException | None = None
        peer_failure: BaseException | None = None
        channel: PlainChannel | None = None
        record: ConnectionRecord | None = None
        try:
            run, record, index = self.accept(listener, writer)
            if listener == "tls":
                channel = TlsChannel(self.context, reader, writer, record, run.now, run)
                await channel.handshake()
                record.protocol = record.alpn or "http/1.1"
            else:
                record.protocol = "http/1.1"
                channel = PlainChannel(reader, writer, record, run.now, run)

            if record.protocol == "h2":
                await Http2Session(channel, run, index).serve()
            else:
                await Http1Session(channel, run, index, record.protocol).serve()
        except BaseException as error:
            if record is not None and isinstance(error, Exception):
                record.failure = record.failure or type(error).__name__

            peer_handshake = (
                isinstance(channel, TlsChannel)
                and error is channel.peer_handshake_failure
            )
            peer_io = channel is not None and error is channel.peer_io_failure
            if peer_handshake or peer_io:
                peer_failure = error
            else:
                primary = error

        cleanup = []
        try:
            self.release(writer)
        except BaseException as error:
            cleanup.append(error)

        if cleanup and primary is None:
            primary = peer_failure

        try:
            raise_capture_failures(primary, tuple(cleanup))
        except BaseException as error:
            # Keep one authoritative failure with the handler until collection.
            # A cancelled Task may return a new exception to each observer.
            task = asyncio.current_task()
            run, cancel_requested, _ = self.handlers[task]
            self.handlers[task] = (run, cancel_requested, error)
            raise

    def release(self, writer: asyncio.StreamWriter) -> None:
        if not writer.transport.is_closing():
            writer.close()
