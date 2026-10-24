"""Record HTTP/2 client frames across requests separated by idle periods.

The browser opens `/start` over TLS (ALPN `h2`) on a loopback listener. The
page fetches `/a`, waits `--idle` seconds, fetches `/b`, waits `--short`
seconds, fetches `/c`, waits `--idle` seconds again, and sends a `POST /p`
with a 100-byte body before `/done`. A Chromium browser sends a preface PING
after a request frame on a connection that has read nothing for 10 seconds,
so the default waits straddle that threshold.

The fixture keeps each connection's client frames after the connection
preface: time, type, flags, stream, length, the request path of a HEADERS
frame, and the payload of a PING. No other frame payload is written.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import math
import platform
import secrets
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from importlib import metadata
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .browser_failures import CleanupFailures
from .browser_launch import CHROMIUM_BROWSERS, BrowserDriver, LaunchPlan
from .fixture_file import write_text_fixture
from .http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    READ_SIZE,
    ConnectionRecord,
    TlsChannel,
    generate_certificate,
    server_context,
)

FORMAT = "phantom-http2-preface-ping-v2"
SUPPORTED = {"h2": "4.4.1", "hpack": "4.2.0"}
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
POST_BODY_BYTES = 100
MAX_FRAMES = 200
# The server leaves its inbound HTTP/2 MAX_FRAME_SIZE at the 16 KiB default.
MAX_FRAME_BYTES = 16 * 1024
MAX_CONNECTIONS = 32
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
CLEANUP_SECONDS = 5.0
MAX_TIMER_MILLISECONDS = 2**31 - 1
PEER_DISCONNECT = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)
REQUEST_SEQUENCE = (
    ("/start", b"GET"),
    ("/a", b"GET"),
    ("/b", b"GET"),
    ("/c", b"GET"),
    ("/p", b"POST"),
    ("/done", b"GET"),
)


def page(token: str, idle: float, short: float) -> bytes:
    idle_ms = round(idle * 1000)
    short_ms = round(short * 1000)
    return (
        "<!doctype html><meta charset=utf-8>"
        '<link rel=icon href="data:,">'
        "<script>const wait = ms => new Promise(done => setTimeout(done, ms));"
        "const get = path => fetch(path, {cache: 'no-store'});"
        "(async () => {"
        f"await get('/a?run={token}');"
        f"await wait({idle_ms});"
        f"await get('/b?run={token}');"
        f"await wait({short_ms});"
        f"await get('/c?run={token}');"
        f"await wait({idle_ms});"
        f"await fetch('/p?run={token}', {{method: 'POST', cache: 'no-store', "
        f"body: 'x'.repeat({POST_BODY_BYTES})}});"
        f"await get('/done?run={token}');"
        "})();</script>\n"
    ).encode()


@dataclass
class Frame:
    milliseconds: float
    kind: int
    flags: int
    stream: int
    length: int
    path: str | None = None
    ping: bytes | None = None

    def line(self) -> str:
        items = [
            f"ms:{self.milliseconds:.3f}",
            f"type:{FRAME_TYPES.get(self.kind, f'0x{self.kind:02x}')}",
            f"flags:0x{self.flags:02x}",
            f"stream:{self.stream}",
            f"length:{self.length}",
        ]
        if self.path is not None:
            items.append(f"path:{self.path}")
        if self.ping is not None:
            items.append(f"payload:{self.ping.hex()}")
        return ",".join(items)


class FrameLog:
    """Splits the client's decrypted bytes into frames as they arrive."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.preface_seen = False
        self.frames: list[Frame] = []

    def feed(self, data: bytes, milliseconds: float) -> None:
        if (
            len(self.buffer) + len(data)
            > MAX_FRAME_BYTES + READ_SIZE + len(CONNECTION_PREFACE) + 9
        ):
            raise ValueError("connection exceeds the frame buffer limit")
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
            if length > MAX_FRAME_BYTES:
                raise ValueError("frame exceeds the capture byte limit")
            if len(self.buffer) < 9 + length:
                return
            kind, flags = self.buffer[3], self.buffer[4]
            stream = int.from_bytes(self.buffer[5:9], "big") & 0x7FFF_FFFF
            payload = bytes(self.buffer[9 : 9 + length])
            del self.buffer[: 9 + length]
            if len(self.frames) >= MAX_FRAMES:
                raise ValueError("connection exceeds the frame limit")
            ping = payload if kind == 0x6 else None
            self.frames.append(
                Frame(milliseconds, kind, flags, stream, length, None, ping)
            )

    def name_request(self, stream: int, path: str) -> None:
        """Attach `path` to the first HEADERS frame on `stream`."""
        for frame in self.frames:
            if frame.kind == 0x1 and frame.stream == stream and frame.path is None:
                frame.path = path
                return


def request_path(target: bytes) -> str:
    """Return the path of `target` without its query, which holds the token."""
    return target.split(b"?", 1)[0].decode("ascii", "replace")


@dataclass
class Run:
    token: str
    idle: float
    short: float
    started: float = field(default_factory=time.perf_counter)
    connections: list[FrameLog] = field(default_factory=list)
    page_connection: FrameLog | None = None
    completion_connection: FrameLog | None = None
    request_index: int = 0
    done: asyncio.Event = field(default_factory=asyncio.Event)
    failure: BaseException | None = field(default=None, repr=False)
    retained: int = 0
    stopping: bool = False
    completion: asyncio.TimerHandle | None = field(default=None, repr=False)

    def now(self) -> float:
        return time.perf_counter() - self.started

    def retain(self, size: int) -> None:
        if self.retained + size > MAX_CAPTURE_BYTES:
            raise ValueError("run exceeds the capture byte limit")
        self.retained += size

    def complete(self) -> None:
        if not self.stopping:
            self.done.set()


async def serve(run: Run, context, reader, writer) -> None:
    import h2.events
    from h2.config import H2Configuration
    from h2.connection import H2Connection

    record = ConnectionRecord(listener="tls", accepted=run.now())
    channel = TlsChannel(context, reader, writer, record, run.now, run)
    log = FrameLog()
    try:
        await channel.handshake()
    except ConnectionError as error:
        # A clean handshake EOF can come from an unused speculative connection.
        if (
            type(error) is ConnectionError
            and channel.peer_handshake_failure is error
            and reader.at_eof()
            and reader.exception() is None
        ):
            return
        raise
    if record.alpn != "h2":
        return
    run.connections.append(log)
    connection = H2Connection(H2Configuration(client_side=False, header_encoding=None))
    connection.initiate_connection()
    await channel.write(connection.data_to_send())
    while not run.stopping:
        data = await channel.read()
        if not data:
            return
        log.feed(data, run.now() * 1000)
        for event in connection.receive_data(data):
            if not isinstance(event, h2.events.RequestReceived):
                continue
            headers = dict(event.headers)
            target = headers.get(b":path", b"")
            path = request_path(target)
            parts = urlsplit(target.decode("ascii"))
            query = parse_qs(parts.query, keep_blank_values=True, max_num_fields=16)
            belongs = (
                not parts.scheme
                and not parts.netloc
                and b"#" not in target
                and query.get("run") == [run.token]
            )
            log.name_request(event.stream_id, path)
            if path == "/start" and belongs and run.page_connection in (None, log):
                run.page_connection = log
                body = page(run.token, run.idle, run.short)
                content_type = b"text/html; charset=utf-8"
            else:
                body = b"ok"
                content_type = b"text/plain"
            if (
                belongs
                and run.page_connection is not None
                and run.request_index < len(REQUEST_SEQUENCE)
                and (path, headers.get(b":method"))
                == REQUEST_SEQUENCE[run.request_index]
            ):
                run.request_index += 1
            connection.send_headers(
                event.stream_id,
                [
                    (b":status", b"200"),
                    (b"content-type", content_type),
                    (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store"),
                ],
            )
            connection.send_data(event.stream_id, body, end_stream=True)
            if run.request_index == len(REQUEST_SEQUENCE) and run.completion is None:
                run.completion_connection = log
                run.completion = asyncio.get_running_loop().call_later(
                    0.5, run.complete
                )
        await channel.write(connection.data_to_send())


class PrefaceFailures(CleanupFailures):
    """Retain original failures and unfinished capture owners for retry."""

    def __init__(
        self,
        primary: BaseException | None,
        cleanup: tuple[BaseException, ...],
        owner: PrefaceServer,
    ) -> None:
        self.owner = owner
        super().__init__(primary, cleanup, "preface capture cleanup failed")


def _raise_preface_failures(
    primary: BaseException | None,
    cleanup: Sequence[BaseException],
    owner: PrefaceServer,
) -> None:
    cleanup = tuple(error for error in cleanup if error is not primary)
    if cleanup:
        failure = PrefaceFailures(primary, cleanup, owner)
        failure.raise_interruption()
        if primary is not None:
            raise primary from failure
        raise failure from cleanup[0]
    if primary is not None:
        raise primary


class PrefaceProtocol(asyncio.StreamReaderProtocol):
    """Own accepted callbacks before connection_made is queued."""

    def __init__(self, owner: PrefaceServer) -> None:
        self.owner = owner
        self.transport: asyncio.Transport | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.handler: asyncio.Task[None] | None = None
        self.waiter: asyncio.Task[None] | None = None
        self.observed: set[asyncio.Task] = set()
        self.closed = asyncio.get_running_loop().create_future()
        self.retired = False
        super().__init__(asyncio.StreamReader(limit=READ_SIZE), self.connected)

    def connection_made(self, transport) -> None:
        self.transport = transport
        if self.owner.run.stopping:
            self.owner.stop_listener()
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
        if error is not None and not isinstance(error, PEER_DISCONNECT):
            self.owner.failed(error)
        try:
            super().connection_lost(error)
        except BaseException as cleanup:
            self.owner.failed(cleanup)
        finally:
            self.retired = True
            if not self.closed.done():
                self.closed.set_result(None)


class RetiringPrefaceProtocol(asyncio.Protocol):
    """Adopt a socket whose ordinary protocol could not be constructed."""

    def __init__(self, owner: PrefaceServer) -> None:
        self.owner = owner
        self.transport: asyncio.Transport | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.handler: asyncio.Task[None] | None = None
        self.waiter: asyncio.Task[None] | None = None
        self.closed = asyncio.get_running_loop().create_future()
        self.retired = False

    def connection_made(self, transport: asyncio.Transport) -> None:
        self.transport = transport
        # The backend has attached this transport before listener closure.
        self.owner.stop_listener()
        try:
            transport.abort()
        except BaseException as error:
            self.owner.failed(error)
            try:
                transport.close()
            except BaseException as cleanup:
                self.owner.failed(cleanup)

    def connection_lost(self, error: Exception | None) -> None:
        if error is not None and not isinstance(error, PEER_DISCONNECT):
            self.owner.failed(error)
        self.retired = True
        if not self.closed.done():
            self.closed.set_result(None)


class PrefaceServer:
    """One listener, its accepted streams, and their original outcomes."""

    def __init__(self, run: Run, context) -> None:
        self.run = run
        self.context = context
        self.listener: asyncio.Server | None = None
        self.listener_wait: asyncio.Task[None] | None = None
        self.listener_observed = False
        self.protocols: set[PrefaceProtocol | RetiringPrefaceProtocol] = set()
        self.failures: list[BaseException] = []
        self.port: int | None = None

    async def start(self, host: str) -> None:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the capture listener must be a loopback address")
        self.listener = await asyncio.get_running_loop().create_server(
            self.new_protocol,
            host,
            0,
            start_serving=False,
        )
        self.port = self.listener.sockets[0].getsockname()[1]
        ready = asyncio.Event()
        self.listener_wait = self.submit(self.wait_listener(ready))
        self.listener_wait.add_done_callback(lambda _task: ready.set())
        await asyncio.wait_for(ready.wait(), CLEANUP_SECONDS)
        if self.listener_wait.done():
            self.listener_observed = True
            self.listener_wait.result()
        await self.listener.start_serving()

    async def wait_listener(self, ready) -> None:
        # Register the original attached-transport waiter before accepting peers.
        asyncio.get_running_loop().call_soon(ready.set)
        await self.listener.wait_closed()

    def new_protocol(self) -> PrefaceProtocol | RetiringPrefaceProtocol:
        try:
            protocol = PrefaceProtocol(self)
        except BaseException as error:
            # A raised factory error leaves the backend's accepted socket
            # outside our owner. Adopt it before stopping the listener.
            self.remember(error)
            protocol = RetiringPrefaceProtocol(self)
        self.protocols.add(protocol)
        if len(self.protocols) > MAX_CONNECTIONS:
            # Closing here would precede the backend's transport attachment.
            self.remember(ValueError("run exceeds the connection limit"))
        return protocol

    def remember(self, error: BaseException) -> None:
        if not any(previous is error for previous in self.failures):
            self.failures.append(error)
        if self.run.failure is None:
            self.run.failure = error
        self.run.done.set()
        self.run.stopping = True

    def stop_listener(self) -> None:
        if self.listener is not None:
            try:
                self.listener.close()
            except BaseException as error:
                self.remember(error)

    def failed(self, error: BaseException) -> None:
        self.remember(error)
        self.stop_listener()

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

    def observed(self, protocol: PrefaceProtocol, task: asyncio.Task) -> None:
        if task in protocol.observed:
            return
        protocol.observed.add(task)
        try:
            task.result()
        except BaseException as error:
            self.failed(error)

    def accept(self, reader, protocol: PrefaceProtocol) -> None:
        try:
            if self.run.stopping:
                protocol.transport.abort()
            else:
                protocol.handler = self.submit(self.handle(reader, protocol.writer))
                protocol.handler.add_done_callback(
                    lambda task: self.observed(protocol, task)
                )
            protocol.waiter = self.submit(self.wait_writer(protocol.writer))
            protocol.waiter.add_done_callback(
                lambda task: self.observed(protocol, task)
            )
        except BaseException as error:
            self.failed(error)
            try:
                protocol.transport.abort()
            except BaseException as cleanup:
                self.failed(cleanup)

    async def handle(self, reader, writer) -> None:
        try:
            await serve(self.run, self.context, reader, writer)
        except PEER_DISCONNECT:
            pass
        except BaseException as error:
            self.failed(error)
        finally:
            try:
                writer.close()
            except PEER_DISCONNECT:
                pass
            except BaseException as error:
                self.failed(error)

    async def wait_writer(self, writer) -> None:
        try:
            await writer.wait_closed()
        except PEER_DISCONNECT:
            pass
        except BaseException as error:
            self.failed(error)

    async def close(self, primary: BaseException | None = None) -> None:
        self.run.stopping = True
        if self.run.completion is not None:
            self.run.completion.cancel()
        self.stop_listener()
        deadline = asyncio.get_running_loop().time() + CLEANUP_SECONDS
        while True:
            for protocol in tuple(self.protocols):
                if protocol.transport is not None:
                    try:
                        protocol.transport.abort()
                    except BaseException as error:
                        self.failed(error)
                if protocol.writer is not None and protocol.waiter is None:
                    try:
                        protocol.waiter = self.submit(self.wait_writer(protocol.writer))
                    except BaseException as error:
                        self.failed(error)
                for task in (protocol.handler, protocol.waiter):
                    if task is not None and task.done():
                        self.observed(protocol, task)
                if (
                    protocol.retired
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
                for task in (protocol.handler, protocol.waiter, protocol.closed)
                if task is not None and not task.done()
            }
            if self.listener_wait is not None:
                if self.listener_wait.done() and not self.listener_observed:
                    self.listener_observed = True
                    try:
                        self.listener_wait.result()
                    except BaseException as error:
                        self.failed(error)
                elif not self.listener_wait.done():
                    tasks.add(self.listener_wait)
            if not tasks:
                if self.protocols:
                    self.failed(RuntimeError("connection retirement is unobserved"))
                break
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                self.failed(TimeoutError("preface capture peers did not stop"))
                break
            try:
                await asyncio.wait(
                    tasks, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                )
            except BaseException as error:
                self.failed(error)
        failures, self.failures = self.failures, []
        _raise_preface_failures(primary, failures, self)


def capture_tool() -> str:
    versions = " ".join(
        f"{package} {metadata.version(package)}" for package in SUPPORTED
    )
    return f"python {platform.python_version()} {versions}"


def fixture(
    args: argparse.Namespace, plan: LaunchPlan, arguments: str, run: Run, wall: float
) -> str:
    log = run.page_connection
    if log is None:
        raise ValueError("no HTTP/2 connection carried the page")
    if run.completion_connection is None:
        raise ValueError("no HTTP/2 connection completed the request sequence")
    client = args.client or plan.client_name
    for name, value in (
        ("client", client),
        ("client_version", args.client_version),
        ("operating_system", args.operating_system),
        ("launch_mode", plan.launch_mode),
        ("launch_arguments", arguments),
    ):
        validate_metadata(name, value)

    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={client}",
        f"client_version={args.client_version}",
        f"operating_system={args.operating_system}",
        f"hostname={HOSTNAME}",
        f"launch_mode={plan.launch_mode}",
        f"launch_arguments={arguments}",
        f"capture_tool={capture_tool()}",
        f"idle_ms={round(run.idle * 1000)}",
        f"short_wait_ms={round(run.short * 1000)}",
        f"post_body_bytes={POST_BODY_BYTES}",
        f"h2_connection_count={len(run.connections)}",
        f"wall_clock_ms={wall * 1000:.0f}",
        f"page_connection={run.connections.index(log)}",
        f"completion_connection={run.connections.index(run.completion_connection)}",
    ]
    for index, connection in enumerate(run.connections):
        prefix = f"connection_{index}"
        lines.append(f"{prefix}_frame_count={len(connection.frames)}")
        lines.extend(
            f"{prefix}_frame_{number}={frame.line()}"
            for number, frame in enumerate(connection.frames)
        )
    return "\n".join(lines) + "\n"


def report_partial(run: Run) -> None:
    print(f"partial_h2_connections={len(run.connections)}", file=sys.stderr)
    for index, log in enumerate(run.connections):
        prefix = f"connection_{index}"
        selected = str(log is run.page_connection).lower()
        print(f"{prefix}_selected_page={selected}", file=sys.stderr)
        print(f"{prefix}_preface_seen={str(log.preface_seen).lower()}", file=sys.stderr)
        print(f"{prefix}_buffer_bytes={len(log.buffer)}", file=sys.stderr)
        print(f"{prefix}_frame_count={len(log.frames)}", file=sys.stderr)
        for number, frame in enumerate(log.frames):
            # Failed input may not have passed HTTP/2 validation yet.
            safe = replace(
                frame,
                path=frame.path
                if frame.path in ("/start", "/a", "/b", "/c", "/p", "/done")
                else None,
                ping=frame.ping
                if frame.kind == 0x6 and frame.ping is not None and len(frame.ping) == 8
                else None,
            )
            print(f"{prefix}_frame_{number}={safe.line()}", file=sys.stderr)


async def capture(args: argparse.Namespace) -> None:
    timeout = validate_options(args)
    certificate = generate_certificate()
    context = server_context(certificate)
    token = secrets.token_hex(8)
    run = Run(token, args.idle, args.short)
    server = PrefaceServer(run, context)
    primary = None
    try:
        await server.start(args.listen)
        port = server.port
        plan = LaunchPlan(
            browser=args.browser,
            executable=args.browser_path,
            headless=not args.headful,
            extra_arguments=(
                f"--host-resolver-rules=MAP {HOSTNAME} {resolver_address(args.listen)}, EXCLUDE localhost",
                "--ignore-certificate-errors-spki-list="
                + certificate.spki_sha256_base64,
                "--disable-quic",
            ),
        )
        url = f"https://{HOSTNAME}:{port}/start?run={token}"
        async with BrowserDriver(plan, url):
            await asyncio.wait_for(run.done.wait(), timeout=timeout)
            if run.failure is not None:
                raise run.failure
    except BaseException as error:
        primary = error
    if primary is not None:
        try:
            report_partial(run)
        except BaseException as error:
            server.remember(error)
    await server.close(primary)
    arguments = (
        plan.recorded_arguments(url)
        .replace(certificate.spki_sha256_base64, "<certificate-spki>")
        .replace(f":{port}", ":<port>")
        .replace(token, "<token>")
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = args.output_dir / "preface-ping.txt"
    write_text_fixture(path, fixture(args, plan, arguments, run, run.now()))
    print(f"wrote {path} in {run.now():.1f} s", file=sys.stderr)


def validate_options(args: argparse.Namespace) -> float:
    if not ipaddress.ip_address(args.listen).is_loopback:
        raise ValueError("the capture listener must be a loopback address")
    for name in ("idle", "short"):
        value = getattr(args, name)
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"--{name} must be finite and positive")
        if value > MAX_TIMER_MILLISECONDS / 1000:
            raise ValueError(f"--{name} exceeds the page timer limit")
    timeout = 2 * args.idle + args.short + 30
    if not math.isfinite(timeout):
        raise ValueError("combined capture timeout must be finite")
    for name in ("client", "client_version", "operating_system"):
        value = getattr(args, name)
        if value is not None:
            validate_metadata(name, value)
    return timeout


def validate_metadata(name: str, value: str) -> None:
    if any(not 0x20 <= ord(character) <= 0x7E for character in value):
        raise ValueError(f"{name} must contain only printable ASCII characters")


def resolver_address(host: str) -> str:
    address = str(ipaddress.ip_address(host))
    return f"[{address}]" if ":" in address else address


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=CHROMIUM_BROWSERS, required=True)
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--idle", type=float, default=11.5)
    parser.add_argument("--short", type=float, default=9.0)
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
