"""Capture Chromium Alt-Svc racing decisions against loopback H2 and H3 origins.

One run serves `HOSTNAME` over TLS/TCP (ALPN `h2`) and QUIC/UDP on the same
port number, loads a scripted page in a fresh browser profile with a Chrome
NetLog, and records server-side connection and request times. The page learns
`Alt-Svc: h3=":<port>"` from `/learn` and then issues scripted requests; the
server can retire every connection so the next request needs a new one.

The QUIC listener's behavior is the scenario's variable: it serves H3, drops
every datagram, presents a certificate the browser does not accept, or offers
no common ALPN. Retained fixtures hold only derived times and decisions;
NetLogs stay wherever `--netlog-dir` points.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import platform
import random
import socket
import ssl
import statistics
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import h2.events
import h2.exceptions
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
)
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes

from .browser_launch import BrowserDriver, LaunchPlan
from .chrome_netlog import NetLog, RaceObservation, broken_until_seconds, observe_races
from .fixture_file import write_text_fixture
from .http2_session import Certificate, generate_certificate, server_context

FORMAT = "phantom-alt-svc-race-v1"
HOSTNAME = "server.phantom.test"
WRONG_HOSTNAME = "wrong.phantom.test"
UNSUPPORTED_ALPN = "phantom-unsupported"
DECOY_FORCE_QUIC_PORT = 9
ALT_SVC_MAX_AGE = 86400
READ_SIZE = 64 * 1024
MAX_PORT_ATTEMPTS = 64
RACE_WINDOW_MS = 1000
EXIT_WAIT_SECONDS = 60.0
CANDIDATE_PORTS = (20000, 40000)
QUIC_MODES = ("serve", "blackhole", "bad-certificate", "bad-alpn")
# A 1x1 transparent GIF: `/hold` keeps the page's load event pending.
HOLD_BODY = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000"
    "010001000002024401003b"
)


@dataclass(frozen=True)
class Scenario:
    name: str
    question: str
    quic: str
    # Page steps in order: `learn`, `learn-retire`, `retire`, `fetch:<name>`,
    # or `wait:<milliseconds>`.
    steps: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.quic not in QUIC_MODES:
            raise ValueError(f"unsupported QUIC mode: {self.quic}")
        for step in self.steps:
            kind, _, argument = step.partition(":")
            if kind in {"learn", "learn-retire", "retire"} and not argument:
                continue
            if kind == "fetch" and argument.isalnum():
                continue
            if kind == "wait" and argument.isdigit():
                continue
            raise ValueError(f"unsupported page step: {step}")

    @property
    def page_milliseconds(self) -> int:
        return sum(
            int(step.partition(":")[2]) for step in self.steps if step[:5] == "wait:"
        )


SCENARIOS = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "race-after-learning",
            "First new connection after learning h3 on a fresh profile",
            "serve",
            ("learn-retire", "wait:300", "fetch:r1", "wait:500", "fetch:r2"),
        ),
        Scenario(
            "race-after-quic-worked",
            "New connection after QUIC already worked and its sessions closed",
            "serve",
            (
                "learn-retire",
                "wait:300",
                "fetch:r1",
                "wait:500",
                "retire",
                "wait:500",
                "fetch:r2",
            ),
        ),
        Scenario(
            "udp-blackhole",
            "When TCP starts and whether a blackholed alternative is marked broken",
            "blackhole",
            (
                "learn-retire",
                "wait:300",
                "fetch:r1",
                "wait:15000",
                "retire",
                "wait:300",
                "fetch:r2",
            ),
        ),
        Scenario(
            "quic-bad-certificate",
            "Whether a QUIC certificate failure marks the alternative broken",
            "bad-certificate",
            (
                "learn-retire",
                "wait:300",
                "fetch:r1",
                "wait:2000",
                "retire",
                "wait:300",
                "fetch:r2",
            ),
        ),
        Scenario(
            "quic-bad-alpn",
            "Whether a QUIC ALPN failure marks the alternative broken",
            "bad-alpn",
            (
                "learn-retire",
                "wait:300",
                "fetch:r1",
                "wait:2000",
                "retire",
                "wait:300",
                "fetch:r2",
            ),
        ),
        Scenario(
            "broken-backoff",
            "Brokenness lifetime, expiry, and the lifetime after a second failure",
            "blackhole",
            (
                "learn-retire",
                "wait:300",
                "fetch:r1",
                # r2 runs about 290 s after the first mark and r3 about 305 s
                # after it; the blackholed QUIC job fails after 4 s.
                "wait:293700",
                "retire",
                "wait:300",
                "fetch:r2",
                "wait:15000",
                "retire",
                "wait:300",
                "fetch:r3",
                "wait:6000",
            ),
        ),
        Scenario(
            "existing-h2-session",
            "Same-page requests while an H2 session exists when h3 is learned",
            "serve",
            ("learn", "wait:300", "fetch:r1", "wait:500", "fetch:r2", "fetch:r3"),
        ),
    )
}


def render_page(scenario: Scenario) -> bytes:
    """Return the scripted page; results report to `/done` as JSON."""
    steps = json.dumps(list(scenario.steps))
    script = (
        "const steps = " + steps + ";\n"
        "const results = [];\n"
        "(async () => {\n"
        "  for (const step of steps) {\n"
        "    const [kind, argument] = step.split(':');\n"
        "    if (kind === 'wait') {\n"
        "      await new Promise((resolve) => setTimeout(resolve, Number(argument)));\n"
        "      continue;\n"
        "    }\n"
        "    const path = kind === 'fetch' ? '/r/' + argument : '/' + kind;\n"
        "    const url = new URL(path, location.href).href;\n"
        "    const started = performance.now();\n"
        "    let status = 0;\n"
        "    try {\n"
        "      const response = await fetch(url, {cache: 'no-store'});\n"
        "      status = response.status;\n"
        "      await response.text();\n"
        "    } catch (error) {\n"
        "      status = -1;\n"
        "    }\n"
        "    const entries = performance.getEntriesByName(url);\n"
        "    const entry = entries[entries.length - 1];\n"
        "    results.push({step, status,\n"
        "      protocol: entry ? entry.nextHopProtocol : '',\n"
        "      elapsed_ms: Math.round(performance.now() - started)});\n"
        "  }\n"
        "  await fetch('/done?results=' + encodeURIComponent(JSON.stringify(results)),\n"
        "    {cache: 'no-store'});\n"
        "})();\n"
    )
    return (
        "<!doctype html><meta charset=utf-8><title>alt-svc race</title>"
        '<img src="/hold" alt="">'
        f"<script>{script}</script>"
    ).encode()


# -- Server-side records ----------------------------------------------------


@dataclass
class RequestRecord:
    received_ms: float
    transport: str
    connection: int
    path: str


@dataclass
class TcpRecord:
    index: int
    accepted_ms: float
    tls_ms: float | None = None
    alpn: str | None = None
    requests: int = 0
    retired_ms: float | None = None
    closed_ms: float | None = None
    failure: str | None = None


@dataclass
class UdpPeerRecord:
    index: int
    first_datagram_ms: float
    datagrams: int = 0
    handshake_ms: float | None = None
    requests: int = 0
    closed_ms: float | None = None
    close_reason: str | None = None


@dataclass
class RunRecord:
    """Everything one browser run did, in milliseconds since the run began."""

    started_wall: float
    started_counter: float
    tcp: list[TcpRecord] = field(default_factory=list)
    udp: dict[tuple[str, int], UdpPeerRecord] = field(default_factory=dict)
    requests: list[RequestRecord] = field(default_factory=list)
    page_results: list[dict[str, object]] | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)

    def now(self) -> float:
        return round((time.perf_counter() - self.started_counter) * 1000, 3)

    def wall_ms(self, relative_ms: float) -> float:
        return self.started_wall * 1000 + relative_ms

    def udp_peer(self, address: tuple[str, int]) -> UdpPeerRecord:
        peer = self.udp.get(address)
        if peer is None:
            peer = UdpPeerRecord(index=len(self.udp), first_datagram_ms=self.now())
            self.udp[address] = peer
        return peer


def new_run() -> RunRecord:
    return RunRecord(started_wall=time.time(), started_counter=time.perf_counter())


# -- Shared request routing ---------------------------------------------------


@dataclass(frozen=True)
class Response:
    status: int
    content_type: bytes | None = None
    body: bytes = b""
    alt_svc: bool = False


class Origin:
    """Routes requests for one scenario and owns connection retirement."""

    def __init__(self, scenario: Scenario, port: int) -> None:
        self.scenario = scenario
        self.port = port
        self.page = render_page(scenario)
        self.run: RunRecord | None = None
        self.retirers: list[Callable[[], None]] = []
        self.holds: list[Callable[[Response], None]] = []

    @property
    def alt_svc_value(self) -> bytes:
        return f'h3=":{self.port}"; ma={ALT_SVC_MAX_AGE}'.encode()

    def begin(self, run: RunRecord) -> None:
        self.run = run
        self.retirers.clear()
        self.holds.clear()

    def request(
        self,
        transport: str,
        connection: int,
        target: str,
        respond: Callable[[Response], None],
        retire_own: Callable[[], None],
    ) -> None:
        run = self.run
        if run is None:
            respond(Response(503))
            return
        parts = urlsplit(target)
        run.requests.append(RequestRecord(run.now(), transport, connection, parts.path))
        if parts.path == "/start":
            respond(Response(200, b"text/html; charset=utf-8", self.page))
        elif parts.path == "/hold":
            if run.done.is_set():
                respond(hold_response())
            else:
                self.holds.append(respond)
        elif parts.path in {"/learn", "/learn-retire"}:
            respond(Response(200, b"text/plain", b"learn", alt_svc=True))
            if parts.path == "/learn-retire":
                retire_own()
        elif parts.path == "/retire":
            respond(Response(200, b"text/plain", b"retire", alt_svc=True))
            for retire in list(self.retirers):
                retire()
        elif parts.path.startswith("/r/"):
            respond(Response(200, b"text/plain", b"ok", alt_svc=True))
        elif parts.path == "/done":
            results = parse_qs(parts.query).get("results", ["[]"])[0]
            run.page_results = json.loads(results)
            respond(Response(204))
            run.done.set()
            for hold in self.holds:
                hold(hold_response())
            self.holds.clear()
        else:
            respond(Response(404))

    def response_headers(self, response: Response) -> list[tuple[bytes, bytes]]:
        headers = [(b":status", str(response.status).encode())]
        if response.content_type is not None:
            headers.append((b"content-type", response.content_type))
        headers.append((b"content-length", str(len(response.body)).encode()))
        headers.append((b"cache-control", b"no-store"))
        if response.alt_svc:
            headers.append((b"alt-svc", self.alt_svc_value))
        return headers


def hold_response() -> Response:
    return Response(200, b"image/gif", HOLD_BODY)


# -- TLS/TCP origin -----------------------------------------------------------


class TlsStream:
    """Server-side TLS over memory BIOs on an accepted TCP stream."""

    def __init__(
        self,
        context: ssl.SSLContext,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)

    async def handshake(self) -> str | None:
        while True:
            try:
                self.tls.do_handshake()
                self.flush()
                return self.tls.selected_alpn_protocol()
            except ssl.SSLWantReadError:
                pass
            self.flush()
            data = await self.read_raw()
            if not data:
                raise ConnectionError("client closed during the TLS handshake")
            self.incoming.write(data)

    async def read_raw(self) -> bytes:
        try:
            return await self.reader.read(READ_SIZE)
        except ConnectionError:
            return b""

    async def read(self) -> bytes:
        while True:
            try:
                data = self.tls.read(READ_SIZE)
            except ssl.SSLWantReadError:
                self.flush()
                raw = await self.read_raw()
                if not raw:
                    return b""
                self.incoming.write(raw)
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLError):
                data = b""
            self.flush()
            return data

    def write(self, data: bytes) -> None:
        if data:
            self.tls.write(data)
            self.flush()

    def flush(self) -> None:
        pending = self.outgoing.read()
        if pending and not self.writer.transport.is_closing():
            self.writer.write(pending)


class Http2Origin:
    """TLS listener that serves `Origin` over H2 and records each connection."""

    def __init__(self, origin: Origin, certificate: Certificate) -> None:
        self.origin = origin
        self.context = server_context(certificate)
        self.server: asyncio.base_events.Server | None = None
        self.writers: set[asyncio.StreamWriter] = set()

    async def start(self, sock: socket.socket) -> None:
        self.server = await asyncio.start_server(self.handle, sock=sock)

    async def close(self) -> None:
        for writer in list(self.writers):
            writer.transport.abort()
        self.writers.clear()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        run = self.origin.run
        if run is None:
            writer.transport.abort()
            return
        self.writers.add(writer)
        record = TcpRecord(index=len(run.tcp), accepted_ms=run.now())
        run.tcp.append(record)
        stream = TlsStream(self.context, reader, writer)
        try:
            record.alpn = await stream.handshake()
            record.tls_ms = run.now()
            if record.alpn != "h2":
                record.failure = f"alpn:{record.alpn}"
                return
            await self.serve_h2(stream, record, run)
        except Exception as error:  # recorded: a capture keeps partial evidence
            record.failure = record.failure or type(error).__name__
        finally:
            if record.closed_ms is None:
                record.closed_ms = run.now()
            self.writers.discard(writer)
            if not writer.transport.is_closing():
                writer.close()

    async def serve_h2(
        self, stream: TlsStream, record: TcpRecord, run: RunRecord
    ) -> None:
        connection = H2Connection(
            H2Configuration(client_side=False, header_encoding=None)
        )
        connection.initiate_connection()
        stream.write(connection.data_to_send())
        highest_stream = 0

        def retire() -> None:
            if record.retired_ms is None and record.closed_ms is None:
                record.retired_ms = run.now()
                stream.write(connection.data_to_send())
                # Written beside the h2 state machine, which would otherwise
                # refuse to answer the streams GOAWAY leaves open.
                stream.write(goaway_frame(highest_stream))

        self.origin.retirers.append(retire)
        try:
            while True:
                data = await stream.read()
                if not data:
                    return
                try:
                    events = connection.receive_data(data)
                except h2.exceptions.ProtocolError as error:
                    record.failure = f"h2:{type(error).__name__}"
                    return
                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        highest_stream = max(highest_stream, event.stream_id)
                        record.requests += 1
                        self.request(connection, stream, record, event, retire)
                    elif isinstance(event, h2.events.DataReceived):
                        connection.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                stream.write(connection.data_to_send())
                if any(isinstance(e, h2.events.ConnectionTerminated) for e in events):
                    return
        finally:
            if retire in self.origin.retirers:
                self.origin.retirers.remove(retire)

    def request(
        self,
        connection: H2Connection,
        stream: TlsStream,
        record: TcpRecord,
        event: h2.events.RequestReceived,
        retire: Callable[[], None],
    ) -> None:
        fields = dict(event.headers or [])
        target = fields.get(b":path", b"/").decode("latin-1")
        stream_id = event.stream_id

        def respond(response: Response) -> None:
            try:
                connection.send_headers(
                    stream_id,
                    self.origin.response_headers(response),
                    end_stream=not response.body,
                )
                if response.body:
                    connection.send_data(stream_id, response.body, end_stream=True)
            except h2.exceptions.H2Error:
                return
            stream.write(connection.data_to_send())

        self.origin.request("h2", record.index, target, respond, retire)


def goaway_frame(last_stream_id: int) -> bytes:
    """Return GOAWAY(NO_ERROR) naming `last_stream_id` (RFC 9113 section 6.8)."""
    payload = (last_stream_id & 0x7FFFFFFF).to_bytes(4, "big") + (
        ErrorCodes.NO_ERROR
    ).to_bytes(4, "big")
    return len(payload).to_bytes(3, "big") + bytes([0x7, 0]) + bytes(4) + payload


# -- QUIC/UDP alternative -----------------------------------------------------


class Http3Protocol(QuicConnectionProtocol):
    """One aioquic connection that serves `Origin` over H3."""

    def __init__(self, *args, origin: Origin, peers: UdpRecorder, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.origin = origin
        self.peers = peers
        self.http: H3Connection | None = None
        self.peer: UdpPeerRecord | None = None

    def quic_event_received(self, event: QuicEvent) -> None:
        run = self.origin.run
        if run is None:
            return
        if self.peer is None:
            self.peer = self.peers.peer_for(self._quic)
        if isinstance(event, HandshakeCompleted):
            if self.peer is not None:
                self.peer.handshake_ms = run.now()
            self.http = H3Connection(self._quic)
            self.origin.retirers.append(self.retire)
        if isinstance(event, ConnectionTerminated):
            if self.peer is not None and self.peer.closed_ms is None:
                self.peer.closed_ms = run.now()
                self.peer.close_reason = f"0x{event.error_code:x}"
            if self.retire in self.origin.retirers:
                self.origin.retirers.remove(self.retire)
        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.request(http_event)

    def request(self, event: HeadersReceived) -> None:
        fields = dict(event.headers)
        target = fields.get(b":path", b"/").decode("latin-1")
        stream_id = event.stream_id
        http = self.http
        if http is None:
            return
        if self.peer is not None:
            self.peer.requests += 1

        def respond(response: Response) -> None:
            http.send_headers(
                stream_id,
                self.origin.response_headers(response),
                end_stream=not response.body,
            )
            if response.body:
                http.send_data(stream_id, response.body, end_stream=True)
            self.transmit()

        index = self.peer.index if self.peer is not None else -1
        self.origin.request("h3", index, target, respond, self.retire)

    def retire(self) -> None:
        # The retiring response is flushed before CONNECTION_CLOSE(NO_ERROR).
        asyncio.get_running_loop().call_later(0.05, self.close)


class UdpRecorder:
    """Records the first arrival and count of datagrams per client address."""

    def __init__(self, origin: Origin) -> None:
        self.origin = origin
        self.addresses: dict[bytes, tuple[str, int]] = {}

    def datagram(self, address: tuple[str, int]) -> None:
        run = self.origin.run
        if run is not None:
            run.udp_peer(address[:2]).datagrams += 1

    def peer_for(self, quic) -> UdpPeerRecord | None:
        run = self.origin.run
        address = getattr(quic, "_network_paths", None)
        if run is None or not address:
            return None
        return run.udp.get(tuple(address[0].addr[:2]))


class BlackholeProtocol(asyncio.DatagramProtocol):
    def __init__(self, recorder: UdpRecorder) -> None:
        self.recorder = recorder

    def datagram_received(self, data: bytes, addr) -> None:
        self.recorder.datagram(addr)


def quic_configuration(mode: str, certificate: Certificate) -> QuicConfiguration:
    alpn = [UNSUPPORTED_ALPN] if mode == "bad-alpn" else H3_ALPN
    configuration = QuicConfiguration(is_client=False, alpn_protocols=alpn)
    chosen = (
        generate_certificate(WRONG_HOSTNAME)
        if mode == "bad-certificate"
        else certificate
    )
    load_certificate(configuration, chosen)
    return configuration


def load_certificate(
    configuration: QuicConfiguration, certificate: Certificate
) -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="phantom-capture-cert-") as directory:
        certificate_path = Path(directory) / "certificate.pem"
        key_path = Path(directory) / "key.pem"
        certificate_path.write_bytes(certificate.certificate_pem)
        key_path.write_bytes(certificate.private_key_pem)
        configuration.load_cert_chain(certificate_path, key_path)


class UdpAlternative:
    def __init__(self, origin: Origin, certificate: Certificate, mode: str) -> None:
        self.origin = origin
        self.certificate = certificate
        self.mode = mode
        self.recorder = UdpRecorder(origin)
        self.transport: asyncio.DatagramTransport | None = None
        self.server = None

    async def start(self, sock: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        if self.mode == "blackhole":
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: BlackholeProtocol(self.recorder), sock=sock
            )
            return
        host, port = sock.getsockname()[:2]
        # aioquic binds its own socket; release the reservation immediately
        # before it rebinds the same loopback port.
        sock.close()
        recorder = self.recorder
        origin = self.origin
        self.server = await serve(
            host,
            port,
            configuration=quic_configuration(self.mode, self.certificate),
            create_protocol=lambda *values, **kwargs: Http3Protocol(
                *values, origin=origin, peers=recorder, **kwargs
            ),
        )
        received = self.server.datagram_received

        def tap(data: bytes, addr) -> None:
            recorder.datagram(addr)
            received(data, addr)

        self.server.datagram_received = tap

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
        if self.server is not None:
            self.server.close()


def reserve_ports(
    host: str, candidates: Sequence[int] | None = None
) -> tuple[socket.socket, socket.socket]:
    """Bind UDP first, then TCP on the same port number.

    Windows reserves UDP and TCP port ranges independently, and an ephemeral
    UDP choice often collides with a TCP exclusion, so candidates come from a
    fixed range outside the dynamic ports.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    ports = (
        candidates
        if candidates is not None
        else random.sample(range(*CANDIDATE_PORTS), MAX_PORT_ATTEMPTS)
    )
    for port in ports:
        udp = socket.socket(family, socket.SOCK_DGRAM)
        tcp = socket.socket(family, socket.SOCK_STREAM)
        try:
            udp.bind((host, port))
            tcp.bind((host, port))
        except OSError:
            udp.close()
            tcp.close()
            continue
        tcp.listen(64)
        tcp.setblocking(False)
        udp.setblocking(False)
        return udp, tcp
    raise OSError("no loopback port is free for both UDP and TCP")


# -- Run orchestration ----------------------------------------------------------


def chromium_extra_arguments(
    listen_host: str, spki: str, netlog: Path | str
) -> tuple[str, ...]:
    return (
        "--enable-quic",
        # Every other name fails to resolve, so browser background traffic
        # never leaves the machine and never teaches QUIC state.
        f"--host-resolver-rules=MAP {HOSTNAME} {listen_host}, MAP * ~NOTFOUND",
        f"--ignore-certificate-errors-spki-list={spki}",
        # QUIC rejects certificates from unknown roots unless the host is
        # named here (proof_verifier_chromium.cc). The decoy port is never
        # requested, so the capture's own origin is not forced onto QUIC.
        f"--origin-to-force-quic-on={HOSTNAME}:{DECOY_FORCE_QUIC_PORT}",
        f"--log-net-log={netlog}",
        "--net-log-capture-mode=Everything",
        "--dump-dom",
    )


@dataclass(frozen=True)
class RunResult:
    run: RunRecord
    port: int
    netlog: Path
    launch_arguments: str
    exited_gracefully: bool


async def capture_run(
    scenario: Scenario,
    *,
    listen_host: str,
    browser: str,
    executable: Path | None,
    headless: bool,
    netlog: Path,
    timeout: float,
) -> RunResult:
    asyncio.get_running_loop().set_exception_handler(ignore_peer_resets)
    certificate = generate_certificate(HOSTNAME)
    udp_socket, tcp_socket = reserve_ports(listen_host)
    port = tcp_socket.getsockname()[1]
    origin = Origin(scenario, port)
    tcp = Http2Origin(origin, certificate)
    udp = UdpAlternative(origin, certificate, scenario.quic)
    run = new_run()
    origin.begin(run)
    await udp.start(udp_socket)
    await tcp.start(tcp_socket)
    url = f"https://{HOSTNAME}:{port}/start"
    extra = chromium_extra_arguments(
        listen_host, certificate.spki_sha256_base64, netlog
    )
    plan = LaunchPlan(browser, executable, headless, extra)
    recorded = plan.recorded_arguments(url).replace(
        certificate.spki_sha256_base64, "<certificate-spki>"
    )
    recorded = recorded.replace(str(netlog), "<netlog>")
    exited = False
    try:
        async with BrowserDriver(plan, url) as driver:
            await asyncio.wait_for(run.done.wait(), timeout=timeout)
            process = driver.browser.process if driver.browser else None
            if process is not None:
                # `--dump-dom` exits after the load event; a graceful exit
                # writes the NetLog's closing polled data.
                exited = await wait_for_exit(process, EXIT_WAIT_SECONDS)
            await asyncio.sleep(0.5)
    finally:
        udp.close()
        await tcp.close()
    return RunResult(run, port, netlog, recorded, exited)


def ignore_peer_resets(loop: asyncio.AbstractEventLoop, context: dict) -> None:
    """Drop Windows proactor noise from browser sockets closed during shutdown."""
    if isinstance(
        context.get("exception"), (ConnectionResetError, ConnectionAbortedError)
    ):
        return
    loop.default_exception_handler(context)


async def wait_for_exit(process, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return True
        await asyncio.sleep(0.1)
    return False


# -- Derived observations ---------------------------------------------------------


@dataclass(frozen=True)
class RunSummary:
    """Per-run decisions derived from server records and the NetLog."""

    run: int
    page: tuple[tuple[str, int, str], ...]
    requests: tuple[tuple[str, str], ...]
    tcp_connections: int
    idle_tcp_connections: int
    udp_peers: int
    server_first_tcp_minus_first_udp_ms: float | None
    races: tuple[RaceObservation, ...]
    netlog_complete: bool
    broken_lifetimes_s: tuple[int, ...]


def summarize_run(index: int, result: RunResult, netlog: NetLog) -> RunSummary:
    run = result.run
    page = tuple(
        (
            str(entry.get("step")),
            int(entry.get("status", 0)),
            str(entry.get("protocol")),
        )
        for entry in run.page_results or ()
    )
    learned = next(
        (
            request.received_ms
            for request in run.requests
            if request.path in {"/learn", "/learn-retire"}
        ),
        None,
    )
    first_udp = min((peer.first_datagram_ms for peer in run.udp.values()), default=None)
    gap = None
    if learned is not None and first_udp is not None and first_udp > learned:
        # Only a TCP connection opened by the same race counts; a main job
        # that reused an idle preconnected socket opens none.
        first_tcp = min(
            (
                tcp.accepted_ms
                for tcp in run.tcp
                if first_udp <= tcp.accepted_ms <= first_udp + RACE_WINDOW_MS
            ),
            default=None,
        )
        if first_tcp is not None:
            gap = round(first_tcp - first_udp, 3)
    requests = tuple(
        (request.path, request.transport)
        for request in run.requests
        if request.path.startswith("/r/")
    )
    # Controllers before learning and the browser's own favicon fetch carry no
    # racing decision; the scripted requests after learning do.
    races = tuple(
        race
        for race in observe_races(netlog, HOSTNAME, result.port)
        if race.alt_svc_broken is not None and race.path != "/favicon.ico"
    )
    marks = [
        race.end_ms
        for race in races
        if race.end_ms is not None and "failed" in race.alternative_outcome
    ]
    lifetimes = tuple(broken_until_seconds(netlog, marks[-1])) if marks else ()
    return RunSummary(
        run=index,
        page=page,
        requests=requests,
        tcp_connections=len(run.tcp),
        idle_tcp_connections=sum(1 for tcp in run.tcp if tcp.requests == 0),
        udp_peers=len(run.udp),
        server_first_tcp_minus_first_udp_ms=gap,
        races=races,
        netlog_complete=netlog.complete,
        broken_lifetimes_s=lifetimes,
    )


def spread(values: Sequence[float]) -> str:
    if not values:
        return "none"
    ordered = sorted(values)
    return (
        f"min:{ordered[0]:g},median:{statistics.median(ordered):g},"
        f"max:{ordered[-1]:g},values:{'/'.join(f'{value:g}' for value in ordered)}"
    )


def render_fixture(
    scenario: Scenario,
    summaries: Sequence[RunSummary],
    *,
    client: str,
    client_version: str,
    operating_system: str,
    launch_mode: str,
    launch_arguments: str,
    listen_host: str,
) -> str:
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={client}",
        f"client_version={client_version}",
        f"operating_system={operating_system}",
        f"hostname={HOSTNAME}",
        f"listen_address={listen_host}",
        f"launch_mode={launch_mode}",
        f"launch_arguments={launch_arguments}",
        f"scenario={scenario.name}",
        f"quic_listener={scenario.quic}",
        f"page_steps={','.join(scenario.steps)}",
        f'alt_svc=h3=":<port>"; ma={ALT_SVC_MAX_AGE}',
        f"runs={len(summaries)}",
    ]
    for summary in summaries:
        prefix = f"run_{summary.run}"
        lines.append(
            f"{prefix}_page="
            + ";".join(
                f"{step}>{status}>{protocol}" for step, status, protocol in summary.page
            )
        )
        lines.append(
            f"{prefix}_server_requests="
            + ";".join(f"{path}>{transport}" for path, transport in summary.requests)
        )
        lines.append(
            f"{prefix}_connections=tcp:{summary.tcp_connections},"
            f"idle_tcp:{summary.idle_tcp_connections},udp_peers:{summary.udp_peers}"
        )
        lines.append(f"{prefix}_netlog_complete={str(summary.netlog_complete).lower()}")
        if summary.server_first_tcp_minus_first_udp_ms is not None:
            lines.append(
                f"{prefix}_server_first_tcp_minus_first_udp_ms="
                f"{summary.server_first_tcp_minus_first_udp_ms:g}"
            )
        for number, race in enumerate(summary.races):
            lines.append(f"{prefix}_controller_{number}={race.render()}")
        lines.append(
            f"{prefix}_broken_lifetime_s="
            + ("/".join(str(value) for value in summary.broken_lifetimes_s) or "none")
        )
    lines.extend(aggregate_lines(summaries))
    return "\n".join(lines) + "\n"


def race_label(path: str) -> str:
    return path.rsplit("/", 1)[-1] or "root"


def aggregate_lines(summaries: Sequence[RunSummary]) -> list[str]:
    """Summarize, per request path, each controller that raced a new QUIC session."""
    by_path: dict[str, list[RaceObservation]] = {}
    for summary in summaries:
        for race in summary.races:
            if race.quic_first_packet_ms is not None:
                by_path.setdefault(race_label(race.path), []).append(race)
    lines = []
    for label, races in by_path.items():
        prefix = f"aggregate_race_{label}"
        lines.append(f"{prefix}_controllers={len(races)}")
        for name, values in (
            (
                "main_job_wait_ms",
                [r.main_job_wait_ms for r in races if r.main_job_wait_ms is not None],
            ),
            (
                "main_resumed_ms",
                [r.main_resumed_ms for r in races if r.main_resumed_ms is not None],
            ),
            (
                "tcp_minus_quic_first_packet_ms",
                [
                    r.tcp_minus_quic_start_ms
                    for r in races
                    if r.tcp_minus_quic_start_ms is not None
                ],
            ),
        ):
            lines.append(f"{prefix}_{name}={spread(values)}")
        for name in ("bound_job", "main_outcome", "alternative_outcome"):
            counts: dict[str, int] = {}
            for race in races:
                value = getattr(race, name)
                counts[value] = counts.get(value, 0) + 1
            lines.append(
                f"{prefix}_{name}="
                + ",".join(f"{key}:{count}" for key, count in sorted(counts.items()))
            )
    gaps = [
        summary.server_first_tcp_minus_first_udp_ms
        for summary in summaries
        if summary.server_first_tcp_minus_first_udp_ms is not None
    ]
    lines.append(f"aggregate_server_first_tcp_minus_first_udp_ms={spread(gaps)}")
    lifetimes = [value for summary in summaries for value in summary.broken_lifetimes_s]
    lines.append(f"aggregate_broken_lifetime_s={spread(lifetimes)}")
    return lines


# -- Command line ------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("chrome", "edge"), default="chrome")
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--scenario", nargs="+", default=["all"])
    parser.add_argument("--repeat", type=int, default=10)
    parser.add_argument("--netlog-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    if not ipaddress.ip_address(args.listen).is_loopback:
        parser.error("the capture listener must be a loopback address")
    names = list(SCENARIOS) if args.scenario == ["all"] else args.scenario
    for name in names:
        if name not in SCENARIOS:
            parser.error(f"unknown scenario: {name}")
    args.netlog_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        scenario = SCENARIOS[name]
        summaries = []
        arguments = ""
        for index in range(args.repeat):
            netlog_path = args.netlog_dir / f"{name}-{index}.json"
            result = asyncio.run(
                capture_run(
                    scenario,
                    listen_host=args.listen,
                    browser=args.browser,
                    executable=args.browser_path,
                    headless=not args.headful,
                    netlog=netlog_path,
                    timeout=args.timeout + scenario.page_milliseconds / 1000,
                )
            )
            arguments = result.launch_arguments
            netlog = NetLog.load(netlog_path)
            summary = summarize_run(index, result, netlog)
            summaries.append(summary)
            print(
                f"{name} run {index}: "
                + "; ".join(race.render() for race in summary.races),
                flush=True,
            )
        fixture = render_fixture(
            scenario,
            summaries,
            client="Google Chrome" if args.browser == "chrome" else "Microsoft Edge",
            client_version=args.client_version,
            operating_system=args.operating_system,
            launch_mode="headful" if args.headful else "headless",
            launch_arguments=arguments,
            listen_host=args.listen,
        )
        if args.output_dir is None:
            print(fixture, end="")
        else:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            write_text_fixture(args.output_dir / f"{name}.txt", fixture)


if __name__ == "__main__":
    main()
