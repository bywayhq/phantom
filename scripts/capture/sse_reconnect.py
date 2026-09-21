"""Record browser EventSource reconnect behavior against a loopback server."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
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
class RecordedConnection:
    accepted: float
    request_count: int = 0
    client_eof: float | None = None


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
            asyncio.get_running_loop().call_later(
                self.scenario.observation_seconds, self.done.set
            )


class ReconnectServer:
    """Loopback HTTP/1.1 server that drives one scenario run at a time."""

    def __init__(self) -> None:
        self.run: ScenarioRun | None = None
        self.server: asyncio.Server | None = None
        self.writers: set[asyncio.StreamWriter] = set()
        self.address: tuple[str, int] | None = None

    async def start(self, host: str, port: int) -> None:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the capture listener must be a loopback address")
        self.server = await asyncio.start_server(
            self.handle, host, port, limit=MAX_REQUEST_HEAD
        )
        self.address = self.server.sockets[0].getsockname()[:2]

    def url(self, run: ScenarioRun) -> str:
        if self.address is None:
            raise RuntimeError("server has not started")
        host, port = self.address
        return f"http://{host}:{port}{run.page_path()}"

    async def close(self) -> None:
        self.drop_connections()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    def drop_connections(self) -> None:
        for writer in list(self.writers):
            writer.transport.abort()
        self.writers.clear()

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        run = self.run
        if run is None:
            writer.transport.abort()
            return
        self.writers.add(writer)
        connection = RecordedConnection(accepted=run.now())
        run.connections.append(connection)
        index = len(run.connections) - 1
        try:
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
        finally:
            self.writers.discard(writer)
            if not writer.transport.is_closing():
                writer.close()

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


def validate_retained_headers(run: ScenarioRun) -> None:
    for request in run.requests:
        for line in request.header_lines:
            name, _, value = line.partition(b":")
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
    lines = [
        f"format={FORMAT}",
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
    runs = []
    for _ in range(repeat):
        run = ScenarioRun(scenario, secrets.token_hex(8))
        server.run = run
        try:
            async with drive(server.url(run)):
                await asyncio.wait_for(
                    run.done.wait(),
                    timeout=run_timeout + scenario.observation_seconds,
                )
        finally:
            server.run = None
            server.drop_connections()
        runs.append(run)
    return runs


async def run(args: argparse.Namespace) -> None:
    plan = LaunchPlan(
        browser=args.browser,
        executable=args.browser_path,
        headless=not args.headful,
    )
    host, port = args.listen.rsplit(":", 1)
    server = ReconnectServer()
    await server.start(host, int(port))
    try:
        listen = "{}:{}".format(*server.address)
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
            metadata = CaptureMetadata(
                client=args.client or plan.client_name,
                client_version=args.client_version,
                operating_system=args.operating_system,
                listen_address=listen,
                launch_mode=plan.launch_mode,
                launch_arguments=plan.recorded_arguments(
                    f"http://{listen}/run/<token>"
                ),
            )
            write_text_fixture(
                args.output_dir / f"{name}.txt", fixture(scenario, runs, metadata)
            )
            print(f"captured {name}", file=sys.stderr, flush=True)
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
    parser.add_argument("--listen", default="127.0.0.1:0")
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
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    if not ipaddress.ip_address(args.listen.rsplit(":", 1)[0]).is_loopback:
        parser.error("the capture listener must be a loopback address")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
