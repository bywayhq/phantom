"""Record browser EventSource reconnect behavior against a loopback server."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import math
import platform
import secrets
import socket
import statistics
import struct
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .browser_launch import BROWSERS, BrowserDriver, LaunchPlan
from .fixture_file import write_text_fixture

FORMAT = "phantom-sse-reconnect-v1"
MAX_REQUEST_HEAD = 64 * 1024
SENSITIVE_HEADERS = {b"authorization", b"proxy-authorization"}
PROBE_COOKIE = b"phantom_probe=1"
CONNECTION_CLEANUP_SECONDS = 5.0


@dataclass(frozen=True)
class ListenAddress:
    host: str
    port: int

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.host)
        if not address.is_loopback:
            raise ValueError("the capture listener must be a loopback address")
        if not isinstance(self.port, int) or not 0 <= self.port <= 65535:
            raise ValueError("the capture listener port must be between 0 and 65535")

    @classmethod
    def parse(cls, value: str) -> ListenAddress:
        host, separator, port = value.rpartition(":")
        if not separator or not port.isascii() or not port.isdecimal():
            raise ValueError("the capture listener must include an IP address and port")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return cls(host, int(port))

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


class CaptureCleanupFailure(RuntimeError):
    """Retain the server and original errors when connection cleanup fails."""

    def __init__(self, owner, primary, failures) -> None:
        self.owner = owner
        self.primary = primary
        self.failures = tuple(failures)
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        super().__init__("SSE capture connection cleanup failed")


def raise_capture_failures(owner, primary, failures) -> None:
    if primary is None and failures:
        primary, *failures = failures
    if primary is not None:
        if failures:
            raise primary from CaptureCleanupFailure(owner, primary, failures)
        raise primary


def validate_capture_limits(repeat: int, run_timeout: float) -> None:
    if not isinstance(repeat, int) or isinstance(repeat, bool) or repeat < 1:
        raise ValueError("repeat must be a positive integer")
    if not math.isfinite(run_timeout) or run_timeout <= 0:
        raise ValueError("run timeout must be finite and positive")


def validate_metadata(name: str, value: str) -> None:
    if not value or any(not 32 <= ord(character) <= 126 for character in value):
        raise ValueError(f"{name} must be nonempty, single-line printable ASCII")


@dataclass(frozen=True)
class Stimulus:
    """The server's complete behavior for one EventSource request."""

    status: int = 200
    content_type: bytes | None = b"text/event-stream"
    headers: tuple[tuple[bytes, bytes], ...] = ()
    body: bytes = b""
    ending: str = "close"
    hold_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.ending not in {"close", "reset", "hold-close", "response"}:
            raise ValueError(f"unsupported stimulus ending: {self.ending}")

    @property
    def terminal(self) -> bool:
        """Whether a conforming EventSource must stop after this response."""
        return (
            self.status == 204
            or self.status not in {200, 301, 302, 303, 307, 308}
            or (self.status == 200 and self.content_type != b"text/event-stream")
        )


@dataclass(frozen=True)
class Scenario:
    name: str
    purpose: str
    attempts: tuple[Stimulus, ...]
    observation_seconds: float = 3.0

    def __post_init__(self) -> None:
        if not self.attempts or not self.attempts[-1].terminal:
            raise ValueError(f"scenario {self.name} must end with a terminal response")
        if any(attempt.terminal for attempt in self.attempts[:-1]):
            raise ValueError(f"scenario {self.name} has an early terminal response")


def event_stream(*records: bytes) -> bytes:
    return b"".join(record + b"\n\n" for record in records)


def stream(body: bytes, ending: str = "close", **options) -> Stimulus:
    return Stimulus(body=body, ending=ending, **options)


NO_CONTENT = Stimulus(status=204, content_type=None, ending="response")
FAST_RETRY = b"retry: 200"
CATALOG = (
    Scenario(
        "id-then-close",
        "Last-Event-ID value, name spelling, and header position",
        (
            stream(event_stream(FAST_RETRY + b"\nid: phantom-1\ndata: a")),
            NO_CONTENT,
        ),
    ),
    *(
        Scenario(
            f"retry-{value}",
            f"server retry field of {value} ms and any browser clamp",
            (
                stream(event_stream(b"retry: " + str(value).encode() + b"\ndata: a")),
                stream(event_stream(b"data: b")),
                stream(event_stream(b"data: c")),
                NO_CONTENT,
            ),
        )
        for value in (750, 100, 0)
    ),
    Scenario(
        "default-delay",
        "browser reconnect delay without a retry field",
        (
            stream(event_stream(b"data: a")),
            stream(event_stream(b"data: b")),
            NO_CONTENT,
        ),
        observation_seconds=12.0,
    ),
    Scenario(
        "retry-persists-across-reconnect",
        "retry value retained by later connections that omit it",
        (
            stream(event_stream(b"retry: 600\ndata: a")),
            stream(event_stream(b"data: b")),
            stream(event_stream(b"data: c")),
            NO_CONTENT,
        ),
    ),
    Scenario(
        "invalid-retry-ignored",
        "non-digit retry value leaves the previous delay unchanged",
        (
            stream(event_stream(b"retry: 600\ndata: a")),
            stream(event_stream(b"retry: 12x\ndata: b")),
            stream(event_stream(b"data: c")),
            NO_CONTENT,
        ),
    ),
    Scenario(
        "empty-id-resets",
        "empty id field clears Last-Event-ID for the next request",
        (
            stream(event_stream(FAST_RETRY + b"\nid: phantom-1\ndata: a")),
            stream(event_stream(b"id\ndata: b")),
            NO_CONTENT,
        ),
    ),
    Scenario(
        "non-ascii-id",
        "Last-Event-ID byte encoding for a non-ASCII id",
        (
            stream(event_stream(FAST_RETRY + "\nid: é-☃\ndata: a".encode())),
            NO_CONTENT,
        ),
    ),
    Scenario(
        "reconnect-204",
        "204 on reconnect ends the EventSource",
        (stream(event_stream(FAST_RETRY + b"\ndata: a")), NO_CONTENT),
    ),
    *(
        Scenario(
            f"reconnect-{name}",
            f"{name} on reconnect fails the EventSource permanently",
            (stream(event_stream(FAST_RETRY + b"\ndata: a")), terminal),
        )
        for name, terminal in (
            ("404", Stimulus(status=404, content_type=None, ending="response")),
            ("500", Stimulus(status=500, content_type=None, ending="response")),
            (
                "wrong-content-type",
                Stimulus(content_type=b"text/plain", ending="response"),
            ),
        )
    ),
    Scenario(
        "reset-before-head",
        "reconnect interval after connection resets before any response",
        (
            Stimulus(ending="reset"),
            Stimulus(ending="reset"),
            Stimulus(ending="reset"),
            NO_CONTENT,
        ),
        observation_seconds=12.0,
    ),
    Scenario(
        "idle-headers-only-90s",
        "whether the browser closes an idle stream on its own",
        (
            Stimulus(ending="hold-close", hold_seconds=90.0),
            NO_CONTENT,
        ),
    ),
    Scenario(
        "redirect-307-then-close",
        "reconnect target after a followed 307 redirect",
        (
            Stimulus(
                status=307,
                content_type=None,
                headers=((b"location", b"{target}"),),
                ending="response",
            ),
            stream(event_stream(FAST_RETRY + b"\nid: phantom-1\ndata: a")),
            NO_CONTENT,
        ),
    ),
    Scenario(
        "set-cookie-then-close",
        "cookie set by the stream response on the reconnect request",
        (
            stream(
                event_stream(FAST_RETRY + b"\ndata: a"),
                headers=((b"set-cookie", PROBE_COOKIE + b"; Path=/"),),
            ),
            NO_CONTENT,
        ),
    ),
)
SCENARIOS = {scenario.name: scenario for scenario in CATALOG}


@dataclass
class RecordedRequest:
    connection: int
    connection_request: int
    received: float
    request_line: bytes
    header_lines: list[bytes]
    kind: str
    attempt: int | None = None
    after_stimulus: float | None = None
    stimulus: str | None = None
    extra: bool = False
    stream_id: int | None = None
    decoded_headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    client_reset: float | None = None
    client_reset_code: int | None = None

    def header(self, name: bytes) -> bytes | None:
        for key, value in self.decoded_headers:
            if key == name:
                return value
        for line in self.header_lines:
            key, _, value = line.partition(b":")
            if key.strip().lower() == name:
                return value.strip()
        return None

    @property
    def target(self) -> bytes:
        if self.decoded_headers:
            return self.header(b":path") or b""
        parts = self.request_line.split(b" ")
        return parts[1] if len(parts) == 3 else b""


@dataclass
class RecordedConnection:
    accepted: float
    request_count: int = 0
    client_eof: float | None = None
    protocol: str | None = None
    closed: float | None = None
    close_code: int | None = None
    peer_reset: float | None = None
    peer_reset_winerror: int | None = None
    h2_startup: bytes = b""


@dataclass
class ScenarioRun:
    """Server state and observations for one browser run of one scenario."""

    scenario: Scenario
    token: str
    clock: Callable[[], float] = time.perf_counter
    started: float = field(init=False)
    connections: list[RecordedConnection] = field(default_factory=list)
    requests: list[RecordedRequest] = field(default_factory=list)
    next_attempt: int = 0
    last_stimulus: float | None = None
    terminated: float | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    observation: asyncio.TimerHandle | None = None
    udp_cleanup_disconnects: list[tuple[float, int]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.started = self.clock()

    def now(self) -> float:
        return self.clock() - self.started

    def page_path(self) -> str:
        return f"/run/{self.token}"

    def stream_path(self) -> str:
        return f"/sse/{self.scenario.name}?run={self.token}"

    def target_path(self) -> str:
        return f"/sse/{self.scenario.name}/target?run={self.token}"

    def page(self) -> bytes:
        return (
            "<!doctype html><meta charset=utf-8>"
            '<link rel=icon href="data:,">'
            f"<script>new EventSource({self.stream_path()!r})</script>\n"
        ).encode()

    def claim_attempt(self, request: RecordedRequest) -> Stimulus:
        request.kind = "sse"
        if self.last_stimulus is not None:
            request.after_stimulus = request.received - self.last_stimulus
        if self.next_attempt >= len(self.scenario.attempts):
            request.extra = True
            return NO_CONTENT
        request.attempt = self.next_attempt
        self.next_attempt += 1
        return self.scenario.attempts[request.attempt]

    def stimulus_finished(self, request: RecordedRequest, stimulus: Stimulus) -> None:
        self.last_stimulus = self.now()
        request.stimulus = stimulus.ending
        if (
            stimulus.terminal
            and not request.extra
            and self.terminated is None
            and request.attempt == len(self.scenario.attempts) - 1
        ):
            self.terminated = self.last_stimulus
            self.observation = asyncio.get_running_loop().call_later(
                self.scenario.observation_seconds, self.done.set
            )


class ReconnectServer:
    """Loopback HTTP/1.1 server that drives one scenario run at a time."""

    def __init__(self) -> None:
        self.run: ScenarioRun | None = None
        self.server: asyncio.Server | None = None
        self.writers: set[asyncio.StreamWriter] = set()
        self.tasks: set[asyncio.Task] = set()
        self.cancelled: set[asyncio.Task] = set()
        self.writer_tasks: dict[asyncio.StreamWriter, asyncio.Task] = {}
        self.failures: list[BaseException] = []
        self.cleanup: asyncio.Task | None = None
        self.address: tuple[str, int] | None = None

    async def start(self, host: str, port: int) -> None:
        ListenAddress(host, port)
        self.server = await asyncio.start_server(
            self.accept, host, port, limit=MAX_REQUEST_HEAD
        )
        self.address = self.server.sockets[0].getsockname()[:2]

    def url(self, run: ScenarioRun) -> str:
        if self.address is None:
            raise RuntimeError("server has not started")
        host, port = self.address
        return f"http://{ListenAddress(host, port).authority}{run.page_path()}"

    async def close(self) -> None:
        primary = None
        if self.server is not None:
            try:
                self.server.close()
                await asyncio.wait_for(
                    self.server.wait_closed(), timeout=CONNECTION_CLEANUP_SECONDS
                )
            except BaseException as error:
                primary = error

        failures = []
        try:
            await self.finish_run()
        except BaseException as error:
            failures.append(error)
        if primary is not None:
            raise primary from CaptureCleanupFailure(self, primary, failures)
        raise_capture_failures(self, primary, failures)

    async def finish_run(self) -> None:
        """Stop and collect accepted workers; interrupted cleanup can be retried."""
        run, self.run = self.run, None
        if run is not None and run.observation is not None:
            run.observation.cancel()

        if self.cleanup is None:
            self.cleanup = asyncio.create_task(self.collect_connections())
        try:
            await asyncio.shield(self.cleanup)
        except BaseException as primary:
            raise primary from CaptureCleanupFailure(
                self, primary, [*self.failures, *self.outcomes()]
            )

        self.cleanup = None
        failures = self.failures.copy()
        if self.tasks or self.writers:
            primary, *secondary = failures
            raise primary from CaptureCleanupFailure(self, primary, secondary)
        self.failures.clear()
        raise_capture_failures(self, None, failures)

    async def wait_writer_closed(self, writer: asyncio.StreamWriter) -> None:
        await writer.wait_closed()

    async def collect_connections(self) -> None:
        deadline = asyncio.get_running_loop().time() + CONNECTION_CLEANUP_SECONDS
        while self.tasks or self.writers:
            if asyncio.get_running_loop().time() >= deadline:
                self.failures.append(TimeoutError("SSE connection cleanup timed out"))
                return

            for task in self.tasks:
                if not task.done() and task not in self.cancelled:
                    self.cancelled.add(task)
                    task.cancel()

            failed_closures = False
            for writer in self.writers:
                if writer not in self.writer_tasks:
                    try:
                        writer.close()
                    except BaseException as error:
                        self.failures.append(error)
                        failed_closures = True
                    else:
                        self.writer_tasks[writer] = asyncio.create_task(
                            self.wait_writer_closed(writer)
                        )

            pending_workers = set()
            if self.tasks:
                done, pending = await asyncio.wait(
                    self.tasks,
                    timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
                )
                for task in done:
                    if task.cancelled():
                        if task not in self.cancelled:
                            try:
                                task.result()
                            except asyncio.CancelledError as error:
                                self.failures.append(error)
                    elif task.result() is not None:
                        self.failures.append(task.result())
                    self.tasks.remove(task)
                    self.cancelled.discard(task)
                pending_workers = pending

            pending_writers = set()
            if self.writer_tasks:
                done, pending = await asyncio.wait(
                    self.writer_tasks.values(),
                    timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
                )
                for writer, task in list(self.writer_tasks.items()):
                    if task not in done:
                        continue
                    del self.writer_tasks[writer]
                    try:
                        task.result()
                    except BaseException as error:
                        self.failures.append(error)
                        failed_closures = True
                    else:
                        self.writers.discard(writer)
                pending_writers = pending

            if pending_workers:
                self.failures.append(TimeoutError("accepted SSE workers did not stop"))
            if pending_writers:
                self.failures.append(TimeoutError("accepted SSE writers did not close"))
            if pending_workers or pending_writers:
                return

            if failed_closures:
                return

    def outcomes(self) -> list[BaseException]:
        failures = []
        for task in self.tasks:
            if task.cancelled():
                if task not in self.cancelled:
                    try:
                        task.result()
                    except asyncio.CancelledError as error:
                        failures.append(error)
            elif task.done() and task.result() is not None:
                failures.append(task.result())
        return failures

    def accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        run = self.run
        self.writers.add(writer)
        task = asyncio.create_task(self.handle(reader, writer, run))
        self.tasks.add(task)

        def completed(task: asyncio.Task) -> None:
            if not task.cancelled() and task.result() is not None and run is not None:
                run.done.set()

        task.add_done_callback(completed)

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        run: ScenarioRun | None,
    ) -> BaseException | None:
        """Keep failures as outcomes, including close errors after owned cancellation."""
        primary = None
        try:
            if run is None:
                return
            connection = RecordedConnection(accepted=run.now())
            run.connections.append(connection)
            index = len(run.connections) - 1
            while True:
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                except asyncio.IncompleteReadError:
                    connection.client_eof = run.now()
                    return
                except (asyncio.LimitOverrunError, ConnectionError):
                    return
                request = parse_request(head, index, connection, run.now())
                run.requests.append(request)
                if not await self.respond(run, request, reader, writer):
                    return
        except BaseException as error:
            if not (
                isinstance(error, asyncio.CancelledError)
                and asyncio.current_task() in self.cancelled
            ):
                primary = error
        finally:
            failures = []
            try:
                writer.close()
            except BaseException as error:
                failures.append(error)
            try:
                raise_capture_failures(self, primary, failures)
            except BaseException as error:
                return error

    async def respond(
        self,
        run: ScenarioRun,
        request: RecordedRequest,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """Answer one request; return whether the connection stays usable."""
        path = urlsplit(request.target.decode("latin-1")).path
        query = parse_qs(urlsplit(request.target.decode("latin-1")).query)
        if path == run.page_path():
            request.kind = "page"
            await write_response(writer, 200, b"text/html; charset=utf-8", run.page())
            return True
        token = query.get("run", [""])[0]
        if (
            path
            not in {f"/sse/{run.scenario.name}", f"/sse/{run.scenario.name}/target"}
            or token != run.token
        ):
            request.kind = "other"
            await write_response(writer, 404, None, b"")
            return True
        stimulus = run.claim_attempt(request)
        headers = tuple(
            (name, value.replace(b"{target}", run.target_path().encode()))
            for name, value in stimulus.headers
        )
        if stimulus.ending == "reset":
            run.stimulus_finished(request, stimulus)
            reset(writer)
            return False
        if stimulus.ending == "response":
            await write_response(
                writer, stimulus.status, stimulus.content_type, stimulus.body, headers
            )
            run.stimulus_finished(request, stimulus)
            return True
        await write_stream_head(writer, stimulus, headers)
        if stimulus.ending == "hold-close":
            await hold(reader, stimulus.hold_seconds, run, request)
        run.stimulus_finished(request, stimulus)
        writer.close()
        return False


def parse_request(
    head: bytes, connection_index: int, connection: RecordedConnection, received: float
) -> RecordedRequest:
    lines = head[:-4].split(b"\r\n")
    request = RecordedRequest(
        connection=connection_index,
        connection_request=connection.request_count,
        received=received,
        request_line=lines[0],
        header_lines=lines[1:],
        kind="other",
    )
    connection.request_count += 1
    return request


async def write_response(
    writer: asyncio.StreamWriter,
    status: int,
    content_type: bytes | None,
    body: bytes,
    headers: Sequence[tuple[bytes, bytes]] = (),
) -> None:
    lines = [b"HTTP/1.1 " + str(status).encode() + b" " + reason(status)]
    if content_type is not None:
        lines.append(b"content-type: " + content_type)
    lines.extend(name + b": " + value for name, value in headers)
    lines.append(b"content-length: " + str(len(body)).encode())
    lines.append(b"cache-control: no-store")
    writer.write(b"\r\n".join(lines) + b"\r\n\r\n" + body)
    await writer.drain()


async def write_stream_head(
    writer: asyncio.StreamWriter,
    stimulus: Stimulus,
    headers: Sequence[tuple[bytes, bytes]],
) -> None:
    # A close-delimited body keeps each stimulus independent of chunked framing.
    lines = [b"HTTP/1.1 200 OK"]
    if stimulus.content_type is not None:
        lines.append(b"content-type: " + stimulus.content_type)
    lines.extend(name + b": " + value for name, value in headers)
    lines.extend([b"cache-control: no-store", b"connection: close"])
    writer.write(b"\r\n".join(lines) + b"\r\n\r\n" + stimulus.body)
    await writer.drain()


async def hold(
    reader: asyncio.StreamReader,
    seconds: float,
    run: ScenarioRun,
    request: RecordedRequest,
) -> None:
    connection = run.connections[request.connection]
    try:
        data = await asyncio.wait_for(reader.read(1), timeout=seconds)
    except asyncio.TimeoutError:
        return
    except ConnectionError:
        data = b""
    if not data:
        connection.client_eof = run.now()


def reset(writer: asyncio.StreamWriter) -> None:
    """Abort with SO_LINGER zero so the peer observes a TCP reset."""
    sock = writer.get_extra_info("socket")
    if sock is not None:
        linger = (
            struct.pack("HH", 1, 0)
            if sys.platform == "win32"
            else struct.pack("ii", 1, 0)
        )
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
    writer.transport.abort()


def reason(status: int) -> bytes:
    return {
        200: b"OK",
        204: b"No Content",
        307: b"Temporary Redirect",
        404: b"Not Found",
        500: b"Internal Server Error",
    }.get(status, b"Status")


@dataclass(frozen=True)
class CaptureMetadata:
    client: str
    client_version: str
    operating_system: str
    listen_address: str
    launch_mode: str
    launch_arguments: str
    protocol: str = "h1"
    firefox_preferences: str = "none"
    profile_files: str = "none"

    def __post_init__(self) -> None:
        for name in (
            "client",
            "client_version",
            "operating_system",
            "listen_address",
            "launch_mode",
            "launch_arguments",
            "protocol",
            "firefox_preferences",
            "profile_files",
        ):
            validate_metadata(name, getattr(self, name))


def validate_retained_headers(run: ScenarioRun) -> None:
    for request in run.requests:
        fields = [line.partition(b":")[::2] for line in request.header_lines]
        fields.extend(request.decoded_headers)
        for name, value in fields:
            name = name.strip().lower()
            if name in SENSITIVE_HEADERS:
                raise ValueError(
                    "refusing to retain a fixture with credential-bearing headers"
                )
            if name == b"cookie" and any(
                pair.strip() != PROBE_COOKIE for pair in value.split(b";")
            ):
                raise ValueError("refusing to retain a cookie the scenario did not set")


def milliseconds(value: float | None) -> str:
    return "none" if value is None else f"{value * 1000:.3f}"


def fixture(
    scenario: Scenario, runs: Sequence[ScenarioRun], metadata: CaptureMetadata
) -> str:
    for run in runs:
        validate_retained_headers(run)
    secure = any(
        connection.protocol is not None
        for run in runs
        for connection in run.connections
    )
    lines = [
        f"format={'phantom-sse-reconnect-v2' if secure else FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={metadata.client}",
        f"client_version={metadata.client_version}",
        f"operating_system={metadata.operating_system}",
        f"listen_address={metadata.listen_address}",
        f"launch_mode={metadata.launch_mode}",
        f"launch_arguments={metadata.launch_arguments}",
        f"capture_tool=python {platform.python_version()}",
        f"scenario={scenario.name}",
        f"scenario_purpose={scenario.purpose}",
        f"observation_ms={milliseconds(scenario.observation_seconds)}",
        f"repeat_count={len(runs)}",
    ]
    for run_index, run in enumerate(runs):
        prefix = f"run_{run_index}"
        lines.append(f"{prefix}_terminated_ms={milliseconds(run.terminated)}")
        lines.append(f"{prefix}_connection_count={len(run.connections)}")
        lines.extend(
            f"{prefix}_connection_{index}=accepted_ms:{milliseconds(connection.accepted)},"
            f"request_count:{connection.request_count},"
            f"client_eof_ms:{milliseconds(connection.client_eof)}"
            for index, connection in enumerate(run.connections)
        )
        lines.append(f"{prefix}_request_count={len(run.requests)}")
        for index, request in enumerate(run.requests):
            key = f"{prefix}_request_{index}"
            attempt = "none" if request.attempt is None else str(request.attempt)
            lines.append(
                f"{key}=kind:{request.kind},attempt:{attempt},"
                f"extra:{str(request.extra).lower()},"
                f"connection:{request.connection},"
                f"reused:{str(request.connection_request > 0).lower()},"
                f"received_ms:{milliseconds(request.received)},"
                f"after_stimulus_ms:{milliseconds(request.after_stimulus)},"
                f"stimulus:{request.stimulus or 'none'}"
            )
            lines.append(f"{key}_line_hex={request.request_line.hex()}")
            lines.append(f"{key}_header_count={len(request.header_lines)}")
            lines.extend(
                f"{key}_header_{header_index}={line.hex()}"
                for header_index, line in enumerate(request.header_lines)
            )
    if secure:
        from .sse_multiplexed import decode_h2_startup, library_versions

        lines.extend(
            [
                f"requested_protocol={metadata.protocol}",
                f"firefox_preferences={metadata.firefox_preferences}",
                f"profile_files={metadata.profile_files}",
                f"transport_libraries={library_versions(metadata.protocol)}",
                "header_encoding=ordered-decoded-name-value-bytes",
                "close_stimulus=end-stream",
                "reset_stimulus=stream-reset",
            ]
        )
        for run_index, run in enumerate(runs):
            lines.append(
                f"run_{run_index}_udp_cleanup_disconnect_count={len(run.udp_cleanup_disconnects)}"
            )
            lines.extend(
                f"run_{run_index}_udp_cleanup_disconnect_{index}=received_ms:{milliseconds(received)},winerror:{code}"
                for index, (received, code) in enumerate(run.udp_cleanup_disconnects)
            )
            for index, connection in enumerate(run.connections):
                if (
                    connection.protocol not in {"h2", "h3"}
                    or connection.protocol != metadata.protocol
                ):
                    raise ValueError("secure SSE connection has no verified protocol")
                lines.append(
                    f"run_{run_index}_connection_{index}_alpn={connection.protocol}"
                )
                if connection.protocol == "h2" and connection.h2_startup:
                    startup = decode_h2_startup(connection.h2_startup)
                    if startup is None or startup.wire != connection.h2_startup:
                        raise ValueError("SSE H2 retained startup is incomplete")
                    key = f"run_{run_index}_connection_{index}_h2_startup"
                    lines.extend(
                        [
                            f"{key}_hex={startup.wire.hex()}",
                            f"{key}_settings="
                            + ";".join(
                                f"{name}:{value}" for name, value in startup.settings
                            ),
                            f"{key}_connection_window_updates="
                            + ";".join(map(str, startup.connection_window_updates)),
                            f"{key}_connection_credit={65535 + sum(startup.connection_window_updates)}",
                            f"{key}_first_stream_id={startup.first_stream_id}",
                        ]
                    )
                lines.append(
                    f"run_{run_index}_connection_{index}_closed_ms={milliseconds(connection.closed)}"
                )
                lines.append(
                    f"run_{run_index}_connection_{index}_close_code={connection.close_code if connection.close_code is not None else 'none'}"
                )
                if connection.peer_reset is not None:
                    lines.append(
                        f"run_{run_index}_connection_{index}_peer_reset=received_ms:{milliseconds(connection.peer_reset)},winerror:{connection.peer_reset_winerror}"
                    )
            for index, request in enumerate(run.requests):
                key = f"run_{run_index}_request_{index}"
                lines.append(f"{key}_stream_id={request.stream_id}")
                lines.append(
                    f"{key}_client_reset_ms={milliseconds(request.client_reset)}"
                )
                lines.append(
                    f"{key}_client_reset_code={request.client_reset_code if request.client_reset_code is not None else 'none'}"
                )
                lines.append(f"{key}_field_count={len(request.decoded_headers)}")
                lines.extend(
                    f"{key}_field_{i}={name.hex()}:{value.hex()}"
                    for i, (name, value) in enumerate(request.decoded_headers)
                )
    lines.extend(delay_lines(scenario, runs))
    return "\n".join(lines) + "\n"


def delay_lines(scenario: Scenario, runs: Sequence[ScenarioRun]) -> list[str]:
    lines = []
    for attempt in range(1, len(scenario.attempts)):
        values = [
            request.after_stimulus
            for run in runs
            for request in run.requests
            if request.attempt == attempt and request.after_stimulus is not None
        ]
        if not values:
            lines.append(f"attempt_{attempt}_after_stimulus_ms=none")
            continue
        lines.append(
            f"attempt_{attempt}_after_stimulus_ms="
            f"min:{milliseconds(min(values))},"
            f"median:{milliseconds(statistics.median(values))},"
            f"max:{milliseconds(max(values))},"
            f"spread:{milliseconds(max(values) - min(values))},"
            "values:" + ";".join(milliseconds(value) for value in values)
        )
    return lines


async def capture_scenario(
    server: ReconnectServer,
    scenario: Scenario,
    *,
    repeat: int,
    run_timeout: float,
    drive: Callable[[str], object],
) -> list[ScenarioRun]:
    """Run `scenario` `repeat` times; `drive(url)` starts one client per run.

    `drive` returns an async context manager that owns the client for the run.
    """
    validate_capture_limits(repeat, run_timeout)
    if (
        server.run is not None
        or server.cleanup is not None
        or server.tasks
        or server.writers
    ):
        raise RuntimeError("the previous SSE run must finish before another starts")
    runs = []
    for _ in range(repeat):
        run = ScenarioRun(scenario, secrets.token_hex(8))
        server.run = run
        primary = None
        try:
            async with drive(server.url(run)):
                await asyncio.wait_for(
                    run.done.wait(),
                    timeout=run_timeout + scenario.observation_seconds,
                )
        except BaseException as error:
            primary = error

        failures = []
        try:
            await server.finish_run()
        except BaseException as error:
            failures.append(error)
        raise_capture_failures(server, primary, failures)
        runs.append(run)
    return runs


async def run(args: argparse.Namespace) -> None:
    validate_capture_limits(args.repeat, args.run_timeout)
    address = ListenAddress.parse(args.listen)
    for name, value in (
        ("client", args.client if args.client is not None else args.browser),
        ("client_version", args.client_version),
        ("operating_system", args.operating_system),
    ):
        validate_metadata(name, value)

    plan = LaunchPlan(
        browser=args.browser,
        executable=args.browser_path,
        headless=not args.headful,
    )
    protocol = getattr(args, "protocol", "h1")
    if protocol != "h1" and args.browser.endswith("-android"):
        raise ValueError("secure SSE modes require a desktop browser")
    if protocol == "h1":
        server = ReconnectServer()
    else:
        from .sse_multiplexed import secure_server

        server = secure_server(protocol)
    await server.start(address.host, address.port)
    primary = None
    try:
        listen = ListenAddress(*server.address).authority
        if protocol != "h1":
            plan = server.launch_plan(args)
        names = list(SCENARIOS) if args.scenario == ["all"] else args.scenario
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name in names:
            scenario = SCENARIOS[name]
            runs = await capture_scenario(
                server,
                scenario,
                repeat=args.repeat,
                run_timeout=args.run_timeout,
                drive=lambda url: BrowserDriver(plan, url),
            )
            from .browser_launch import render_preferences

            metadata = CaptureMetadata(
                client=args.client or plan.client_name,
                client_version=args.client_version,
                operating_system=args.operating_system,
                listen_address=listen,
                protocol=protocol,
                firefox_preferences=render_preferences(plan.firefox_preferences)
                if plan.firefox_preferences
                else "none",
                profile_files=",".join(name for name, _ in plan.profile_files)
                or "none",
                launch_mode=plan.launch_mode,
                launch_arguments=plan.recorded_arguments(
                    server.url(ScenarioRun(SCENARIOS[names[0]], "<token>"))
                ),
            )
            write_text_fixture(
                args.output_dir / f"{name}.txt", fixture(scenario, runs, metadata)
            )
            print(f"captured {name}", file=sys.stderr, flush=True)
    except BaseException as error:
        primary = error

    failures = []
    try:
        await server.close()
    except BaseException as error:
        failures.append(error)
    raise_capture_failures(server, primary, failures)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=(*BROWSERS, "manual"), required=True)
    parser.add_argument("--browser-path", type=Path)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1:0")
    parser.add_argument("--protocol", choices=("h1", "h2", "h3"), default="h1")
    parser.add_argument("--scenario", nargs="+", default=["all"])
    parser.add_argument("--repeat", type=int, default=10)
    parser.add_argument("--run-timeout", type=float, default=120.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.browser != "manual" and args.browser_path is None:
        parser.error("--browser-path is required unless --browser manual")
    unknown = sorted(set(args.scenario) - set(SCENARIOS) - {"all"})
    if unknown or ("all" in args.scenario and len(args.scenario) > 1):
        parser.error(f"unknown or mixed scenarios: {', '.join(unknown) or 'all'}")
    try:
        validate_capture_limits(args.repeat, args.run_timeout)
        ListenAddress.parse(args.listen)
        for name, value in (
            ("client", args.client if args.client is not None else args.browser),
            ("client_version", args.client_version),
            ("operating_system", args.operating_system),
        ):
            validate_metadata(name, value)
    except ValueError as error:
        parser.error(str(error))
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
