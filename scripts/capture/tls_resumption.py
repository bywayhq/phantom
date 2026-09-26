"""Capture how a browser resumes TLS 1.3 sessions over TCP on a loopback origin.

One run serves `server.phantom.test` over HTTPS from a TLS 1.3 server built
on aioquic's handshake state machine and a TLS record layer in this module.
The page drives a scenario's sequence of new TCP connections. The server
issues its own NewSessionTickets after each handshake, each permitting early
data (`max_early_data_size` 0xffffffff), and records which ticket every later
ClientHello presents. It closes a connection after answering `/retire`.

For every connection the fixture keeps the ClientHello shape, the tickets it
offered and resumed, whether it offered and sent early data, and which
requests arrived in early data. Traffic keys stay in memory; nothing is
written but the fixture.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import platform
import struct
import sys
import time
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import aioquic
from aioquic import tls
from aioquic.buffer import Buffer
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .browser_launch import CHROMIUM_BROWSERS, BrowserDriver, LaunchPlan
from .fixture_file import write_text_fixture
from .http2_session import HOSTNAME, Certificate, generate_certificate
from .http3_wire import SENSITIVE_REQUEST_HEADERS
from .quic_resumption import (
    EARLY_DATA,
    PRE_SHARED_KEY,
    SUPPORTED_AIOQUIC,
    ClientHelloShape,
    compare_shapes,
    flag,
    optional,
    parse_client_hello,
    tls_code,
)

FORMAT = "phantom-tls-resumption-v1"
# A second registrable domain, so a page on it is a different top-level site.
PARTITION_HOSTNAME = "top.partition.test"
RETIRE_DELAY_SECONDS = 0.05
STEP_WAIT_MILLISECONDS = 300
SLOW_RESPONSE_SECONDS = 0.5
TICKET_LIFETIME_SECONDS = 86400
MAX_EARLY_DATA_SIZE = 0xFFFFFFFF
MAX_CONNECTIONS = 48
MAX_REQUESTS = 96
MAX_BODY = 64 * 1024
MAX_HEAD = 32 * 1024
MAX_CLIENT_HELLO = 32 * 1024
MAX_RECORD = 16384 + 256
MAX_SKIPPED_EARLY_DATA = 64 * 1024

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_END_OF_EARLY_DATA = 5
SERVER_CIPHER_SUITES = [
    tls.CipherSuite.AES_128_GCM_SHA256,
    tls.CipherSuite.AES_256_GCM_SHA384,
    tls.CipherSuite.CHACHA20_POLY1305_SHA256,
]


@dataclass(frozen=True)
class Scenario:
    name: str
    question: str
    alpn: str
    tickets_per_connection: int
    # Whether every connection issues tickets, or only the run's first
    # connection to complete a handshake.
    tickets_on_first_connection_only: bool
    # Pages in order; each is (URL of the page, steps its script runs).
    # URLs use the placeholders {a}, {b}, and {p}; see `origins`.
    pages: tuple[tuple[str, tuple[object, ...]], ...]
    # Whether each ticket carries the early_data extension.
    tickets_permit_early_data: bool = True


def retire_steps(origin: str, count: int) -> tuple[object, ...]:
    return tuple(f"{origin}/retire" for _ in range(count))


METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE")
# One request of each method, issued together as the first requests on a new
# connection. A step is a URL (a GET) or a (method, URL) pair.
METHOD_STEP = tuple(
    (method, f"{{a}}/concurrent/{method.lower()}") for method in METHODS
)
METHOD_PAGES = (
    (
        "{a}/",
        (
            "{a}/retire",
            METHOD_STEP,
            "{a}/retire",
            ("POST", "{a}/retire"),
            *retire_steps("{a}", 1),
            "{a}/done",
        ),
    ),
)


SCENARIOS = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "sequential",
            "Resumed ClientHello shape, early data, and which of two tickets a new connection uses",
            alpn="h2",
            tickets_per_connection=2,
            tickets_on_first_connection_only=False,
            pages=(
                ("{a}/", retire_steps("{a}", 5)),
                ("{a}/page/1", (*retire_steps("{a}", 1), "{a}/done")),
            ),
        ),
        Scenario(
            "sequential-http1",
            "The same questions when the server selects HTTP/1.1",
            alpn="http/1.1",
            tickets_per_connection=2,
            tickets_on_first_connection_only=False,
            pages=(
                ("{a}/", retire_steps("{a}", 5)),
                ("{a}/page/1", (*retire_steps("{a}", 1), "{a}/done")),
            ),
        ),
        Scenario(
            "no-early-data",
            "Resumed ClientHello shape when the ticket does not permit early data",
            alpn="h2",
            tickets_per_connection=2,
            tickets_on_first_connection_only=False,
            pages=(("{a}/", (*retire_steps("{a}", 4), "{a}/done")),),
            tickets_permit_early_data=False,
        ),
        Scenario(
            "issue-once",
            "How many tickets one connection leaves, their order, and whether one is reused",
            alpn="h2",
            tickets_per_connection=8,
            tickets_on_first_connection_only=True,
            pages=(("{a}/", (*retire_steps("{a}", 10), "{a}/done")),),
        ),
        Scenario(
            "parallel",
            "Tickets used by six connections opened at once",
            alpn="http/1.1",
            tickets_per_connection=2,
            tickets_on_first_connection_only=False,
            pages=(
                (
                    "{a}/",
                    (
                        "{a}/retire",
                        tuple(f"{{a}}/slow/{index}" for index in range(6)),
                        *retire_steps("{a}", 2),
                        "{a}/done",
                    ),
                ),
            ),
        ),
        Scenario(
            "origins",
            "Whether a ticket from one port is offered to another port on the same host",
            alpn="h2",
            tickets_per_connection=2,
            tickets_on_first_connection_only=False,
            pages=(
                (
                    "{a}/",
                    (
                        "{a}/retire",
                        "{b}/retire",
                        "{a}/retire",
                        "{b}/retire",
                        "{a}/done",
                    ),
                ),
            ),
        ),
        Scenario(
            "methods",
            "Which request methods a resumed connection sends in early data",
            alpn="h2",
            tickets_per_connection=2,
            tickets_on_first_connection_only=False,
            pages=METHOD_PAGES,
        ),
        Scenario(
            "methods-http1",
            "The same question when the server selects HTTP/1.1",
            alpn="http/1.1",
            tickets_per_connection=2,
            tickets_on_first_connection_only=False,
            pages=METHOD_PAGES,
        ),
        Scenario(
            "partition",
            "Whether a ticket learned under one top-level site is offered under another",
            alpn="h2",
            tickets_per_connection=2,
            tickets_on_first_connection_only=False,
            pages=(
                ("{a}/", retire_steps("{a}", 2)),
                ("{p}/page/1", ("{p}/retire", *retire_steps("{a}", 2))),
                ("{a}/page/2", (*retire_steps("{a}", 1), "{a}/done")),
            ),
        ),
    )
}


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>phantom tls resumption</title>
<link rel="icon" href="data:,">
<script>
const steps = STEPS;
const next = NEXT;
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function request(step) {
  const { method, url } = typeof step === "string" ? { method: "GET", url: step } : step;
  const options = { method, cache: "no-store" };
  if (method === "POST" || method === "PUT") options.body = "phantom";
  if (new URL(url).origin !== location.origin) options.mode = "no-cors";
  return fetch(url, options);
}
(async () => {
  for (const step of steps) {
    if (Array.isArray(step)) await Promise.all(step.map(request));
    else await request(step);
    await wait(STEP_WAIT);
  }
  if (next) location.href = next;
})().catch((error) =>
  fetch("/error?" + encodeURIComponent(String(error)), { cache: "no-store" }));
</script>
"""


def render_page(scenario: Scenario, index: int, origins: dict[str, str]) -> bytes:
    def resolve(value: object) -> object:
        if isinstance(value, tuple) and value and value[0] in METHODS:
            return {"method": value[0], "url": str(value[1]).format(**origins)}
        if isinstance(value, tuple):
            return [resolve(item) for item in value]
        return str(value).format(**origins)

    steps = resolve(scenario.pages[index][1])
    next_page = (
        resolve(scenario.pages[index + 1][0])
        if index + 1 < len(scenario.pages)
        else None
    )
    return (
        PAGE.replace("STEPS", json.dumps(steps))
        .replace("NEXT", json.dumps(next_page))
        .replace("STEP_WAIT", str(STEP_WAIT_MILLISECONDS))
        .encode()
    )


def page_index(path: str) -> int | None:
    if path == "/":
        return 0
    if path.startswith("/page/") and path[6:].isdigit():
        return int(path[6:])
    return None


# -- TLS record layer ------------------------------------------------------------


@dataclass(frozen=True)
class TlsRecord:
    content_type: int
    header: bytes
    fragment: bytes


def pull_record(data: bytearray) -> TlsRecord | None:
    """Remove and return one complete TLS record from the front of `data`."""
    if len(data) < 5:
        return None
    length = int.from_bytes(data[3:5], "big")
    if length > MAX_RECORD:
        raise ValueError("TLS record exceeds the protocol limit")
    if len(data) < 5 + length:
        return None
    header = bytes(data[:5])
    fragment = bytes(data[5 : 5 + length])
    del data[: 5 + length]
    return TlsRecord(header[0], header, fragment)


def plaintext_records(content_type: int, data: bytes) -> bytes:
    out = bytearray()
    for start in range(0, len(data), 16384):
        chunk = data[start : start + 16384]
        out += struct.pack("!BHH", content_type, 0x0303, len(chunk)) + chunk
    return bytes(out)


class RecordProtection:
    """TLS 1.3 record protection for one traffic secret (RFC 8446 section 5.2)."""

    def __init__(self, cipher_suite: tls.CipherSuite, secret: bytes) -> None:
        algorithm = tls.cipher_suite_hash(cipher_suite)
        key_length = 16 if cipher_suite == tls.CipherSuite.AES_128_GCM_SHA256 else 32
        key = tls.hkdf_expand_label(algorithm, secret, b"key", b"", key_length)
        self.iv = tls.hkdf_expand_label(algorithm, secret, b"iv", b"", 12)
        self.aead = (
            ChaCha20Poly1305(key)
            if cipher_suite == tls.CipherSuite.CHACHA20_POLY1305_SHA256
            else AESGCM(key)
        )
        self.sequence = 0

    def _nonce(self) -> bytes:
        sequence = self.sequence.to_bytes(12, "big")
        self.sequence += 1
        return bytes(a ^ b for a, b in zip(self.iv, sequence, strict=True))

    def seal(self, content_type: int, data: bytes) -> bytes:
        out = bytearray()
        for start in range(0, max(len(data), 1), 16384):
            inner = data[start : start + 16384] + bytes([content_type])
            header = struct.pack(
                "!BHH", CONTENT_APPLICATION_DATA, 0x0303, len(inner) + 16
            )
            out += header + self.aead.encrypt(self._nonce(), inner, header)
        return bytes(out)

    def open(self, record: TlsRecord) -> tuple[int, bytes]:
        """Decrypt one record; raises `InvalidTag` and leaves the sequence on failure."""
        sequence = self.sequence
        try:
            inner = self.aead.decrypt(self._nonce(), record.fragment, record.header)
        except InvalidTag:
            self.sequence = sequence
            raise
        end = len(inner)
        while end and inner[end - 1] == 0:
            end -= 1
        if not end:
            raise ValueError("protected record has no content type")
        return inner[end - 1], inner[: end - 1]


class ServerContext(tls.Context):
    """aioquic's server handshake with TLS-over-TCP's EndOfEarlyData.

    QUIC has no EndOfEarlyData, so aioquic anticipates the client Finished
    over a transcript without it. When early data is accepted, the Finished
    expectation waits until `end_of_early_data` adds the message.
    """

    waiting_for_end_of_early_data = False

    def _server_expect_finished(self, onertt_buf: Buffer) -> None:
        if self.early_data_accepted and not self.waiting_for_end_of_early_data:
            self.waiting_for_end_of_early_data = True
            self._set_state(tls.State.SERVER_EXPECT_FINISHED)
            return
        super()._server_expect_finished(onertt_buf)

    def end_of_early_data(self, message: bytes) -> None:
        if not self.waiting_for_end_of_early_data:
            raise ValueError("EndOfEarlyData without accepted early data")
        self.key_schedule.update_hash(message)
        super()._server_expect_finished(Buffer(capacity=64))
        self.waiting_for_end_of_early_data = False


def issue_ticket(
    context: tls.Context, nonce: int, *, early_data: bool
) -> tuple[bytes, tls.SessionTicket]:
    """Build one NewSessionTicket message and the session it resumes."""
    message = tls.NewSessionTicket(
        ticket_lifetime=TICKET_LIFETIME_SECONDS,
        ticket_age_add=struct.unpack("!I", os.urandom(4))[0],
        ticket_nonce=bytes([nonce]),
        ticket=os.urandom(64),
        max_early_data_size=MAX_EARLY_DATA_SIZE if early_data else None,
    )
    buf = Buffer(capacity=512)
    tls.push_new_session_ticket(buf, message)
    return buf.data, context._build_session_ticket(message, [])


def psk_identities(shape: ClientHelloShape) -> tuple[bytes, ...]:
    body = shape.extension(PRE_SHARED_KEY)
    if body is None:
        return ()
    buf = Buffer(data=body)
    identities = []
    end = buf.pull_uint16() + buf.tell()
    while buf.tell() < end:
        identities.append(buf.pull_bytes(buf.pull_uint16()))
        buf.pull_uint32()
    return tuple(identities)


def server_name(shape: ClientHelloShape) -> str | None:
    body = shape.extension(0x0000)
    if body is None:
        return None
    buf = Buffer(data=body)
    buf.pull_uint16()
    if buf.pull_uint8() != 0:
        return None
    return buf.pull_bytes(buf.pull_uint16()).decode("ascii", "replace")


def offered_alpn(shape: ClientHelloShape) -> tuple[str, ...]:
    body = shape.extension(0x0010)
    if body is None:
        return ()
    buf = Buffer(data=body)
    end = buf.pull_uint16() + buf.tell()
    protocols = []
    while buf.tell() < end:
        protocols.append(buf.pull_bytes(buf.pull_uint8()).decode("ascii", "replace"))
    return tuple(protocols)


# -- Recording -------------------------------------------------------------------


@dataclass
class RequestRecord:
    connection: int
    stream_id: int
    method: str
    path: str
    host: str
    field_names: tuple[str, ...]
    received_ms: float
    early_data: bool
    body_bytes: int = 0


@dataclass
class ConnectionRecord:
    index: int
    listener: str
    accepted_ms: float
    client_hello: bytes | None = None
    resumed: bool = False
    psk_ticket_from: str | None = None
    offered_tickets: tuple[str, ...] = ()
    early_data_accepted: bool = False
    early_data_bytes: int = 0
    skipped_early_data_bytes: int = 0
    alpn: str | None = None
    tickets_issued: tuple[str, ...] = ()
    handshake_ms: float | None = None
    closed_ms: float | None = None
    closed_by: str | None = None


@dataclass
class RunRecord:
    started: float = field(default_factory=time.perf_counter)
    connections: list[ConnectionRecord] = field(default_factory=list)
    requests: list[RequestRecord] = field(default_factory=list)
    # Ticket bytes -> (label, session).
    tickets: dict[bytes, tuple[str, tls.SessionTicket]] = field(default_factory=dict)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    error: str | None = None

    def now(self) -> float:
        return round((time.perf_counter() - self.started) * 1000, 1)

    def new_connection(self, listener: str) -> ConnectionRecord:
        if len(self.connections) >= MAX_CONNECTIONS:
            raise ValueError("run exceeds the connection limit")
        record = ConnectionRecord(len(self.connections), listener, self.now())
        self.connections.append(record)
        return record

    def ticket_label(self, identity: bytes) -> str:
        issued = self.tickets.get(identity)
        return "unknown" if issued is None else issued[0]


def ticket_fetcher(
    run: RunRecord, record: ConnectionRecord
) -> Callable[[bytes], tls.SessionTicket | None]:
    def fetch(identity: bytes) -> tls.SessionTicket | None:
        issued = run.tickets.get(identity)
        record.psk_ticket_from = "unknown" if issued is None else issued[0]
        return None if issued is None else issued[1]

    return fetch


class Http1Parser:
    """Request heads and bodies from an HTTP/1.1 byte stream."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.head: tuple[bytes, list[tuple[bytes, bytes]]] | None = None
        self.body_remaining = 0

    def feed(self, data: bytes) -> list[tuple[bytes, list[tuple[bytes, bytes]], int]]:
        """Return (request line, fields, body length) for each complete request."""
        self.buffer += data
        complete = []
        while True:
            if self.head is None:
                end = self.buffer.find(b"\r\n\r\n")
                if end < 0:
                    if len(self.buffer) > MAX_HEAD:
                        raise ValueError("request head exceeds the capture limit")
                    return complete
                lines = bytes(self.buffer[:end]).split(b"\r\n")
                del self.buffer[: end + 4]
                fields = []
                for line in lines[1:]:
                    name, _, value = line.partition(b":")
                    fields.append((name, value.strip()))
                length = next(
                    (
                        int(value)
                        for name, value in fields
                        if name.lower() == b"content-length"
                    ),
                    0,
                )
                if length > MAX_BODY:
                    raise ValueError("request body exceeds the capture limit")
                self.head = (lines[0], fields)
                self.body_remaining = length
            if len(self.buffer) < self.body_remaining:
                return complete
            del self.buffer[: self.body_remaining]
            line, fields = self.head
            complete.append((line, fields, self.body_remaining))
            self.head = None


class Connection:
    """One accepted TCP connection: TLS 1.3 handshake, then HTTP."""

    def __init__(
        self,
        server: CaptureServer,
        listener: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.server = server
        self.run = server.run
        self.scenario = server.scenario
        self.reader = reader
        self.writer = writer
        self.record = self.run.new_connection(listener)
        self.incoming = bytearray()
        self.context: ServerContext | None = None
        self.decrypt: RecordProtection | None = None
        self.encrypt: RecordProtection | None = None
        self.keys: dict[tuple[tls.Direction, tls.Epoch], RecordProtection] = {}
        self.handshake_bytes = bytearray()
        self.in_early_data = False
        self.early_data_offered = False
        self.closing = False
        self.http1 = Http1Parser()
        self.h2 = None
        self.goaway_sent = False
        self.h2_requests: dict[int, RequestRecord] = {}
        self.responded: set[int] = set()
        self.tasks: set[asyncio.Task] = set()

    # Handshake ---------------------------------------------------------------

    def update_key(
        self,
        direction: tls.Direction,
        epoch: tls.Epoch,
        cipher_suite: tls.CipherSuite,
        secret: bytes,
    ) -> None:
        self.keys[(direction, epoch)] = RecordProtection(cipher_suite, secret)

    def start_handshake(self, message: bytes) -> None:
        if len(message) > MAX_CLIENT_HELLO:
            raise ValueError("ClientHello exceeds the capture limit")
        self.record.client_hello = message
        shape = parse_client_hello(message)
        self.record.offered_tickets = tuple(
            self.run.ticket_label(identity) for identity in psk_identities(shape)
        )
        self.early_data_offered = shape.extension(EARLY_DATA) is not None
        name = server_name(shape) or HOSTNAME
        certificate = self.server.certificates.get(name)
        if certificate is None:
            raise ValueError(f"no certificate for server name {name}")
        context = ServerContext(
            is_client=False,
            alpn_protocols=[self.scenario.alpn],
            cipher_suites=list(SERVER_CIPHER_SUITES),
            max_early_data=MAX_EARLY_DATA_SIZE,
        )
        context.certificate = certificate[0]
        context.certificate_private_key = certificate[1]
        context.get_session_ticket_cb = ticket_fetcher(self.run, self.record)
        context.update_traffic_key_cb = self.update_key
        self.context = context
        output = self.handle_handshake(message)
        self.record.resumed = context.session_resumed
        self.record.early_data_accepted = context.early_data_accepted
        self.record.alpn = context.alpn_negotiated
        out = plaintext_records(CONTENT_HANDSHAKE, output[tls.Epoch.INITIAL].data)
        # Middlebox compatibility mode (RFC 8446 appendix D.4).
        if context.legacy_session_id:
            out += plaintext_records(CONTENT_CHANGE_CIPHER_SPEC, b"\x01")
        self.encrypt = self.keys[(tls.Direction.ENCRYPT, tls.Epoch.HANDSHAKE)]
        out += self.encrypt.seal(CONTENT_HANDSHAKE, output[tls.Epoch.HANDSHAKE].data)
        self.encrypt = self.keys[(tls.Direction.ENCRYPT, tls.Epoch.ONE_RTT)]
        if context.early_data_accepted:
            self.decrypt = self.keys[(tls.Direction.DECRYPT, tls.Epoch.ZERO_RTT)]
            self.in_early_data = True
        else:
            self.decrypt = self.keys[(tls.Direction.DECRYPT, tls.Epoch.HANDSHAKE)]
        self.writer.write(out)

    def handle_handshake(self, data: bytes) -> dict[tls.Epoch, Buffer]:
        assert self.context is not None
        output = {epoch: Buffer(capacity=65536) for epoch in tls.Epoch}
        try:
            self.context.handle_message(data, output)
        except tls.Alert as error:
            raise ValueError(f"TLS handshake failed: {error!r}") from error
        return output

    def finish_handshake(self) -> None:
        assert self.context is not None
        self.record.handshake_ms = self.run.now()
        self.decrypt = self.keys[(tls.Direction.DECRYPT, tls.Epoch.ONE_RTT)]
        # A browser may abandon its first connection before the handshake
        # completes, so "first" means the first completed handshake.
        issues = not self.scenario.tickets_on_first_connection_only or not any(
            record.tickets_issued for record in self.run.connections
        )
        if issues and self.context._psk_key_exchange_mode is not None:
            messages = b""
            labels = []
            for nonce in range(self.scenario.tickets_per_connection):
                message, ticket = issue_ticket(
                    self.context,
                    nonce,
                    early_data=self.scenario.tickets_permit_early_data,
                )
                label = f"connection_{self.record.index}.ticket_{nonce}"
                self.run.tickets[ticket.ticket] = (label, ticket)
                labels.append(label)
                messages += message
            self.record.tickets_issued = tuple(labels)
            self.writer.write(self.seal(CONTENT_HANDSHAKE, messages))
        if self.scenario.alpn == "h2" and self.h2 is None:
            self.start_http2()

    def seal(self, content_type: int, data: bytes) -> bytes:
        assert self.encrypt is not None
        return self.encrypt.seal(content_type, data)

    # Records -----------------------------------------------------------------

    def handle_record(self, record: TlsRecord) -> None:
        if record.content_type == CONTENT_CHANGE_CIPHER_SPEC:
            return
        if self.context is None:
            if record.content_type != CONTENT_HANDSHAKE:
                raise ValueError("first record is not a handshake record")
            self.handshake_bytes += record.fragment
            if len(self.handshake_bytes) >= 4:
                length = 4 + int.from_bytes(self.handshake_bytes[1:4], "big")
                if self.handshake_bytes[0] != HANDSHAKE_CLIENT_HELLO:
                    raise ValueError("first handshake message is not a ClientHello")
                if len(self.handshake_bytes) >= length:
                    message = bytes(self.handshake_bytes[:length])
                    del self.handshake_bytes[:length]
                    self.start_handshake(message)
            return
        if record.content_type == CONTENT_ALERT:
            self.close_by("client:alert")
            return
        if record.content_type != CONTENT_APPLICATION_DATA:
            raise ValueError("unexpected plaintext record after the ClientHello")
        assert self.decrypt is not None
        try:
            content_type, content = self.decrypt.open(record)
        except InvalidTag:
            # RFC 8446 section 4.2.10: skip early data the server cannot read.
            if self.early_data_offered and not self.record.early_data_accepted:
                self.record.skipped_early_data_bytes += len(record.fragment)
                if self.record.skipped_early_data_bytes > MAX_SKIPPED_EARLY_DATA:
                    raise ValueError(
                        "skipped early data exceeds the capture limit"
                    ) from None
                return
            raise
        if content_type == CONTENT_ALERT:
            self.close_by("client:alert")
        elif content_type == CONTENT_HANDSHAKE:
            self.handle_handshake_content(content)
        elif content_type == CONTENT_APPLICATION_DATA:
            if self.in_early_data:
                self.record.early_data_bytes += len(content)
            self.handle_application_data(content)
        else:
            raise ValueError(f"unexpected inner content type {content_type}")

    def handle_handshake_content(self, content: bytes) -> None:
        assert self.context is not None
        if self.in_early_data:
            if content != bytes([HANDSHAKE_END_OF_EARLY_DATA, 0, 0, 0]):
                raise ValueError("early data ended without EndOfEarlyData")
            self.context.end_of_early_data(content)
            self.in_early_data = False
            self.decrypt = self.keys[(tls.Direction.DECRYPT, tls.Epoch.HANDSHAKE)]
            return
        if self.context.state == tls.State.SERVER_POST_HANDSHAKE:
            raise ValueError("post-handshake message from the client")
        self.handle_handshake(content)
        if self.context.state == tls.State.SERVER_POST_HANDSHAKE:
            self.finish_handshake()

    # HTTP --------------------------------------------------------------------

    def handle_application_data(self, data: bytes) -> None:
        if self.scenario.alpn == "h2":
            self.handle_http2(data)
            return
        for line, fields, body_length in self.http1.feed(data):
            method, _, rest = line.decode("latin-1").partition(" ")
            path = rest.rpartition(" ")[0]
            host = next(
                (
                    value.decode("latin-1")
                    for name, value in fields
                    if name.lower() == b"host"
                ),
                "",
            )
            request = self.add_request(
                0,
                method,
                path,
                host,
                tuple(name.decode("latin-1") for name, _ in fields),
            )
            request.body_bytes = body_length
            self.schedule_response(request)

    def add_request(
        self,
        stream_id: int,
        method: str,
        path: str,
        host: str,
        names: tuple[str, ...],
    ) -> RequestRecord:
        if any(name.lower().encode() in SENSITIVE_REQUEST_HEADERS for name in names):
            raise ValueError("refusing to retain a credential-bearing request")
        if len(self.run.requests) >= MAX_REQUESTS:
            raise ValueError("run exceeds the request limit")
        request = RequestRecord(
            connection=self.record.index,
            stream_id=stream_id,
            method=method,
            path=path,
            host=host,
            field_names=names,
            received_ms=self.run.now(),
            early_data=self.in_early_data,
        )
        self.run.requests.append(request)
        return request

    def start_http2(self) -> None:
        import h2.config
        import h2.connection

        self.h2 = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=False, header_encoding=None)
        )
        self.h2.initiate_connection()
        self.flush_http2()

    def handle_http2(self, data: bytes) -> None:
        import h2.events
        import h2.exceptions

        if self.h2 is None:
            # Early data arrives before the handshake finishes.
            self.start_http2()
        assert self.h2 is not None
        try:
            events = self.h2.receive_data(data)
        except h2.exceptions.ProtocolError:
            # After the server's GOAWAY the client may still send frames,
            # such as a SETTINGS acknowledgement; h2 rejects them.
            if self.goaway_sent:
                return
            raise
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                fields = dict(event.headers)
                request = self.add_request(
                    event.stream_id,
                    fields.get(b":method", b"").decode("latin-1"),
                    fields.get(b":path", b"").decode("latin-1"),
                    fields.get(b":authority", b"").decode("latin-1"),
                    tuple(name.decode("latin-1") for name, _ in event.headers),
                )
                self.h2_requests[event.stream_id] = request
                if event.stream_ended is not None:
                    self.schedule_response(request)
            elif isinstance(event, h2.events.DataReceived):
                request = self.h2_requests.get(event.stream_id)
                if request is not None:
                    request.body_bytes += len(event.data)
                    if request.body_bytes > MAX_BODY:
                        raise ValueError("request body exceeds the capture limit")
                self.h2.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                if event.stream_ended is not None and request is not None:
                    self.schedule_response(request)
            elif isinstance(event, h2.events.StreamEnded):
                request = self.h2_requests.get(event.stream_id)
                if request is not None:
                    self.schedule_response(request)
            elif isinstance(event, h2.events.ConnectionTerminated):
                self.close_by("client:goaway")
        self.flush_http2()

    def flush_http2(self) -> None:
        if self.h2 is None or self.encrypt is None:
            return
        data = self.h2.data_to_send()
        if data:
            self.writer.write(self.seal(CONTENT_APPLICATION_DATA, data))

    def schedule_response(self, request: RequestRecord) -> None:
        key = request.stream_id if self.scenario.alpn == "h2" else id(request)
        if key in self.responded:
            return
        self.responded.add(key)
        path = request.path.split("?", 1)[0]
        delay = SLOW_RESPONSE_SECONDS if path.startswith("/slow/") else 0.0
        task = asyncio.get_running_loop().create_task(self.respond(request, delay))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def respond(self, request: RequestRecord, delay: float) -> None:
        if delay:
            await asyncio.sleep(delay)
        path = request.path.split("?", 1)[0]
        index = page_index(path)
        if index is not None and index < len(self.scenario.pages):
            body = render_page(self.scenario, index, self.server.origins)
            content_type = b"text/html; charset=utf-8"
        else:
            body = b"ok"
            content_type = b"text/plain"
        retire = path in ("/retire", "/done") or path.startswith("/slow/")
        if request.method == "HEAD":
            body = b""
        fields = [
            (b"content-type", content_type),
            (b"cache-control", b"no-store"),
            (b"content-length", str(len(body)).encode()),
        ]
        if self.closing:
            return
        if self.scenario.alpn == "h2":
            assert self.h2 is not None
            self.h2.send_headers(
                request.stream_id, [(b":status", b"200"), *fields], end_stream=not body
            )
            if body:
                self.h2.send_data(request.stream_id, body, end_stream=True)
            if retire:
                self.h2.close_connection(last_stream_id=request.stream_id)
                self.goaway_sent = True
            self.flush_http2()
        else:
            head = b"HTTP/1.1 200 OK\r\n" + b"".join(
                name + b": " + value + b"\r\n" for name, value in fields
            )
            if retire:
                head += b"connection: close\r\n"
            self.writer.write(
                self.seal(CONTENT_APPLICATION_DATA, head + b"\r\n" + body)
            )
        if path == "/error":
            self.run.error = request.path
            self.run.done.set()
        elif path == "/done":
            self.run.done.set()
        if retire:
            await asyncio.sleep(RETIRE_DELAY_SECONDS)
            self.close_by("server")

    def close_by(self, who: str) -> None:
        if self.record.closed_ms is None:
            self.record.closed_ms = self.run.now()
            self.record.closed_by = who
        if self.closing:
            return
        self.closing = True
        if who == "server" and self.encrypt is not None:
            # close_notify
            self.writer.write(self.seal(CONTENT_ALERT, b"\x01\x00"))
        self.writer.close()

    async def serve(self) -> None:
        try:
            while not self.closing:
                data = await self.reader.read(65536)
                if not data:
                    self.close_by("client")
                    break
                self.incoming += data
                while not self.closing:
                    record = pull_record(self.incoming)
                    if record is None:
                        break
                    self.handle_record(record)
                await self.writer.drain()
        except (ConnectionError, OSError):
            self.close_by("client:reset")
        except Exception as error:
            # Any other failure ends this connection and is recorded in the
            # fixture as the run's page error.
            reason = str(error) or type(error).__name__
            self.close_by(f"server:error:{reason}")
            if self.run.error is None:
                self.run.error = f"connection_{self.record.index}:{reason}"
        finally:
            for task in list(self.tasks):
                task.cancel()
            if not self.closing:
                self.close_by("server")


class CaptureServer:
    def __init__(
        self,
        scenario: Scenario,
        certificates: dict[str, tuple[object, object]],
    ) -> None:
        self.scenario = scenario
        self.run = RunRecord()
        self.certificates = certificates
        self.origins: dict[str, str] = {}
        self.connections: list[Connection] = []

    def handler(self, listener: str):
        async def handle(reader, writer) -> None:
            connection = Connection(self, listener, reader, writer)
            self.connections.append(connection)
            await connection.serve()

        return handle


def load_certificate(certificate: Certificate) -> tuple[object, object]:
    return (
        tls.load_pem_x509_certificates(certificate.certificate_pem)[0],
        tls.load_pem_private_key(certificate.private_key_pem),
    )


@contextlib.asynccontextmanager
async def serving(
    scenario: Scenario,
    listen_host: str,
    certificates: dict[str, Certificate],
) -> AsyncIterator[CaptureServer]:
    """Serve one run on ephemeral loopback ports: listener `a`, then `b`."""
    server = CaptureServer(
        scenario,
        {name: load_certificate(value) for name, value in certificates.items()},
    )
    listeners = []
    try:
        for name in ("a", "b"):
            listener = await asyncio.start_server(server.handler(name), listen_host, 0)
            listeners.append(listener)
        port_a = listeners[0].sockets[0].getsockname()[1]
        port_b = listeners[1].sockets[0].getsockname()[1]
        server.origins = {
            "a": f"https://{HOSTNAME}:{port_a}",
            "b": f"https://{HOSTNAME}:{port_b}",
            "p": f"https://{PARTITION_HOSTNAME}:{port_a}",
        }
        yield server
    finally:
        for listener in listeners:
            listener.close()
        for connection in server.connections:
            if not connection.closing:
                connection.close_by("server:end")


# -- Browser launch ----------------------------------------------------------------


def chromium_extra_arguments(
    listen_host: str, spki: Sequence[str], *, netlog: Path | None = None
) -> tuple[str, ...]:
    arguments = (
        # Every other name fails to resolve, so background traffic never
        # leaves the machine.
        f"--host-resolver-rules=MAP {HOSTNAME} {listen_host}, "
        f"MAP {PARTITION_HOSTNAME} {listen_host}, MAP * ~NOTFOUND",
        f"--ignore-certificate-errors-spki-list={','.join(spki)}",
        "--disable-quic",
        "--disable-field-trial-config",
    )
    if netlog is not None:
        # Diagnostic only; never retained as a fixture.
        arguments += (f"--log-net-log={netlog}",)
    return arguments


def firefox_cert_override(
    ports: Sequence[int], certificates: dict[str, Certificate]
) -> str:
    lines = [
        "# PSM Certificate Override Settings file",
        "# This is a generated file!  Do not edit.",
    ]
    for name, certificate in certificates.items():
        for port in ports:
            lines.append(
                f"{name}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t"
                f"{certificate.sha256_fingerprint}\t"
            )
    return "\n".join(lines) + "\n"


def launch_plan(
    browser: str,
    executable: Path | None,
    *,
    headless: bool,
    listen_host: str,
    ports: Sequence[int],
    certificates: dict[str, Certificate],
    netlog: Path | None = None,
) -> LaunchPlan:
    if browser in CHROMIUM_BROWSERS:
        return LaunchPlan(
            browser,
            executable,
            headless,
            chromium_extra_arguments(
                listen_host,
                [value.spki_sha256_base64 for value in certificates.values()],
                netlog=netlog,
            ),
        )
    if browser == "firefox":
        return LaunchPlan(
            "firefox",
            executable,
            headless,
            firefox_preferences=(
                ("network.dns.localDomains", f"{HOSTNAME},{PARTITION_HOSTNAME}"),
                ("network.dns.disableIPv6", True),
                ("network.http.http3.enable", False),
            ),
            profile_files=(
                ("cert_override.txt", firefox_cert_override(ports, certificates)),
            ),
        )
    return LaunchPlan("manual", None, False)


@dataclass(frozen=True)
class RunResult:
    run: RunRecord
    ports: tuple[int, int]
    launch_arguments: str
    timed_out: bool


async def capture_run(
    scenario: Scenario,
    *,
    browser: str,
    executable: Path | None,
    headless: bool,
    listen_host: str,
    timeout: float,
    netlog: Path | None = None,
) -> RunResult:
    certificates = {
        HOSTNAME: generate_certificate(HOSTNAME),
        PARTITION_HOSTNAME: generate_certificate(PARTITION_HOSTNAME),
    }
    async with serving(scenario, listen_host, certificates) as server:
        ports = tuple(
            int(server.origins[name].rsplit(":", 1)[1]) for name in ("a", "b")
        )
        plan = launch_plan(
            browser,
            executable,
            headless=headless,
            listen_host=listen_host,
            ports=ports,
            certificates=certificates,
            netlog=netlog,
        )
        url = server.origins["a"] + "/"
        recorded = plan.recorded_arguments(url)
        for index, certificate in enumerate(certificates.values()):
            recorded = recorded.replace(
                certificate.spki_sha256_base64, f"<certificate-spki-{index}>"
            )
        recorded = recorded.replace(f":{ports[0]}", ":<port>")
        if netlog is not None:
            recorded = recorded.replace(str(netlog), "<netlog>")
        timed_out = False
        async with BrowserDriver(plan, url):
            try:
                await asyncio.wait_for(server.run.done.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                timed_out = True
            await asyncio.sleep(0.3)
    return RunResult(server.run, ports, recorded, timed_out)


# -- Fixture -----------------------------------------------------------------------


def connection_lines(
    prefix: str,
    record: ConnectionRecord,
    fresh: ClientHelloShape | None,
    *,
    detail: bool,
) -> list[str]:
    lines = [
        f"{prefix}_listener={record.listener}",
        f"{prefix}_accepted_ms={record.accepted_ms}",
        f"{prefix}_handshake_ms={optional(record.handshake_ms)}",
        f"{prefix}_closed_ms={optional(record.closed_ms)}",
        f"{prefix}_closed_by={record.closed_by or 'open'}",
    ]
    if record.client_hello is None:
        return [*lines, f"{prefix}_client_hello=missing"]
    shape = parse_client_hello(record.client_hello)
    psk = shape.pre_shared_key()
    lines += [
        f"{prefix}_server_name={server_name(shape) or 'none'}",
        f"{prefix}_alpn_offered={','.join(offered_alpn(shape)) or 'none'}",
        f"{prefix}_alpn_selected={record.alpn or 'none'}",
        f"{prefix}_resumed={flag(record.resumed)}",
        f"{prefix}_offered_tickets={','.join(record.offered_tickets) or 'none'}",
        f"{prefix}_psk_ticket_from={record.psk_ticket_from or 'none'}",
        f"{prefix}_early_data_offered={flag(shape.extension(EARLY_DATA) is not None)}",
        f"{prefix}_early_data_accepted={flag(record.early_data_accepted)}",
        f"{prefix}_early_data_bytes={record.early_data_bytes}",
        f"{prefix}_skipped_early_data_bytes={record.skipped_early_data_bytes}",
        f"{prefix}_tickets_issued={','.join(record.tickets_issued) or 'none'}",
        f"{prefix}_pre_shared_key_last="
        + flag(shape.extension_types[-1:] == (PRE_SHARED_KEY,)),
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
        f"{prefix}_session_ticket_extension_length={optional(len_or_none(shape.extension(0x0023)))}",
    ]
    if fresh is not None and record.index > 0:
        lines.extend(
            f"{prefix}_versus_connection_0_{line}"
            for line in compare_shapes(fresh, shape)
            if "transport_parameters" not in line
        )
    if detail:
        lines.append(f"{prefix}_client_hello_hex={record.client_hello.hex()}")
    return lines


def len_or_none(value: bytes | None) -> int | None:
    return None if value is None else len(value)


def fresh_shape(run: RunRecord) -> ClientHelloShape | None:
    for record in run.connections:
        if record.client_hello is not None:
            return parse_client_hello(record.client_hello)
    return None


def run_lines(prefix: str, result: RunResult, *, detail: bool) -> list[str]:
    """Render one run; `detail` adds raw ClientHellos and request field names."""
    run = result.run
    lines = [
        f"{prefix}_timed_out={flag(result.timed_out)}",
        f"{prefix}_page_error={run.error or 'none'}",
        f"{prefix}_listen_ports=a:{result.ports[0]},b:{result.ports[1]}",
        f"{prefix}_connection_count={len(run.connections)}",
    ]
    fresh = fresh_shape(run)
    for record in run.connections:
        lines.extend(
            connection_lines(
                f"{prefix}_connection_{record.index}", record, fresh, detail=detail
            )
        )
    lines.append(f"{prefix}_request_count={len(run.requests)}")
    for index, request in enumerate(run.requests):
        lines.append(
            f"{prefix}_request_{index}=connection:{request.connection},"
            f"stream:{request.stream_id},method:{request.method},"
            f"host:{request.host},path:{request.path},"
            f"body_bytes:{request.body_bytes},"
            f"early_data:{flag(request.early_data)},"
            f"received_ms:{request.received_ms}"
        )
        if detail:
            lines.append(
                f"{prefix}_request_{index}_field_names=" + ",".join(request.field_names)
            )
    return lines


def summary_lines(results: Sequence[RunResult]) -> list[str]:
    """Count ClientHello shapes and ticket use across runs."""
    hellos = resumed = offered = accepted = psk_last = early_requests = 0
    offered_psk = reused = unknown = 0
    added: dict[str, int] = {}
    for result in results:
        run = result.run
        fresh = fresh_shape(run)
        seen: set[str] = set()
        for record in run.connections:
            if record.client_hello is None:
                continue
            hellos += 1
            shape = parse_client_hello(record.client_hello)
            resumed += record.resumed
            offered += shape.extension(EARLY_DATA) is not None
            accepted += record.early_data_accepted
            if record.offered_tickets:
                offered_psk += 1
                psk_last += shape.extension_types[-1:] == (PRE_SHARED_KEY,)
                for label in record.offered_tickets:
                    unknown += label == "unknown"
                    reused += label in seen
                    seen.add(label)
            if fresh is not None and record.index > 0:
                key = compare_shapes(fresh, shape)[0].split("=", 1)[1]
                added[key] = added.get(key, 0) + 1
        early_requests += sum(request.early_data for request in run.requests)
    return [
        f"summary_client_hellos={hellos}",
        f"summary_client_hellos_offering_psk={offered_psk}",
        f"summary_client_hellos_resumed={resumed}",
        f"summary_client_hellos_offering_early_data={offered}",
        f"summary_client_hellos_early_data_accepted={accepted}",
        f"summary_psk_offers_with_pre_shared_key_last={psk_last}",
        f"summary_ticket_offers_reusing_an_offered_ticket={reused}",
        f"summary_ticket_offers_unknown={unknown}",
        f"summary_requests_in_early_data={early_requests}",
        "summary_added_extensions_versus_first="
        + (
            ";".join(f"{value}:{count}" for value, count in sorted(added.items()))
            or "none"
        ),
    ]


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
    if any(
        result.launch_arguments != results[0].launch_arguments for result in results
    ):
        raise ValueError("runs of one fixture used different launch arguments")
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={client}",
        f"client_version={client_version}",
        f"operating_system={operating_system}",
        f"hostname={HOSTNAME}",
        f"partition_hostname={PARTITION_HOSTNAME}",
        f"listen_address={listen_host}:0",
        f"launch_mode={launch_mode}",
        f"launch_arguments={results[0].launch_arguments}",
        f"capture_tool=aioquic {aioquic.__version__} TLS 1.3 over TCP",
        f"scenario={scenario.name}",
        f"server_alpn={scenario.alpn}",
        f"server_tickets_per_connection={scenario.tickets_per_connection}",
        "server_tickets_on="
        + (
            "first_completed_handshake"
            if scenario.tickets_on_first_connection_only
            else "every_connection"
        ),
        "server_ticket_max_early_data_size="
        + (
            f"0x{MAX_EARLY_DATA_SIZE:08x}"
            if scenario.tickets_permit_early_data
            else "none"
        ),
        "server_accepts_early_data=true",
        f"server_retire_delay_ms={int(RETIRE_DELAY_SECONDS * 1000)}",
        f"page_step_wait_ms={STEP_WAIT_MILLISECONDS}",
        f"run_count={len(results)}",
    ]
    lines.extend(summary_lines(results))
    for index, result in enumerate(results):
        lines.extend(run_lines(f"run_{index}", result, detail=index == 0))
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--browser", choices=(*CHROMIUM_BROWSERS, "firefox", "manual"), required=True
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
        "--netlog-dir",
        type=Path,
        help="write a diagnostic Chromium NetLog per run; not a fixture input",
    )
    parser.add_argument("--output-dir", type=Path)
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
                    netlog=None
                    if args.netlog_dir is None
                    else args.netlog_dir.resolve() / f"{name}-{index}.json",
                )
            )
            results.append(result)
            print(
                f"{name} run {index}: {len(result.run.connections)} connections, "
                f"{len(result.run.requests)} requests, "
                f"timed_out={flag(result.timed_out)}, "
                f"error={result.run.error or 'none'}",
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
            write_text_fixture(args.output_dir / f"resumption-{name}.txt", fixture)


if __name__ == "__main__":
    main()
