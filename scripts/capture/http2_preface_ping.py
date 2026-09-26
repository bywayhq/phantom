"""Record the client frames of one HTTP/2 connection reused after idle periods.

The browser opens `/start` over TLS (ALPN `h2`) on a loopback listener. The
page fetches `/a`, waits `--idle` seconds, fetches `/b`, waits `--short`
seconds, fetches `/c`, waits `--idle` seconds again, and sends a `POST /p`
with a 100-byte body before `/done`. A Chromium browser sends a preface PING
after a request frame on a connection that has read nothing for 10 seconds,
so the default waits straddle that threshold.

The fixture keeps, for the connection that carried `/start`, every client
frame after the connection preface: its time, type, flags, stream, length,
the request path of a HEADERS frame, and the payload of a PING. No frame
payload other than a PING's is written.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import platform
import secrets
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

from .browser_launch import CHROMIUM_BROWSERS, BrowserDriver, LaunchPlan
from .fixture_file import write_text_fixture
from .http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    ConnectionRecord,
    TlsChannel,
    generate_certificate,
    server_context,
)

FORMAT = "phantom-http2-preface-ping-v1"
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
    done: asyncio.Event = field(default_factory=asyncio.Event)

    def now(self) -> float:
        return time.perf_counter() - self.started


async def serve(run: Run, context, reader, writer) -> None:
    import h2.events
    from h2.config import H2Configuration
    from h2.connection import H2Connection

    record = ConnectionRecord(listener="tls", accepted=run.now())
    channel = TlsChannel(context, reader, writer, record, run.now)
    log = FrameLog()
    try:
        await channel.handshake()
        if record.alpn != "h2":
            return
        run.connections.append(log)
        connection = H2Connection(
            H2Configuration(client_side=False, header_encoding=None)
        )
        connection.initiate_connection()
        await channel.write(connection.data_to_send())
        while True:
            data = await channel.read()
            if not data:
                return
            log.feed(data, run.now() * 1000)
            for event in connection.receive_data(data):
                if not isinstance(event, h2.events.RequestReceived):
                    continue
                target = dict(event.headers).get(b":path", b"")
                path = request_path(target)
                log.name_request(event.stream_id, path)
                if path == "/start":
                    run.page_connection = log
                    body = page(run.token, run.idle, run.short)
                    content_type = b"text/html; charset=utf-8"
                else:
                    body = b"ok"
                    content_type = b"text/plain"
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
                if path == "/done":
                    asyncio.get_running_loop().call_later(0.5, run.done.set)
            await channel.write(connection.data_to_send())
    except (ConnectionError, ValueError) as error:
        record.failure = type(error).__name__
    finally:
        if not writer.transport.is_closing():
            writer.close()


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
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={args.client or plan.client_name}",
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
        f"frame_count={len(log.frames)}",
    ]
    lines.extend(
        f"frame_{index}={frame.line()}" for index, frame in enumerate(log.frames)
    )
    return "\n".join(lines) + "\n"


async def capture(args: argparse.Namespace) -> None:
    certificate = generate_certificate()
    context = server_context(certificate)
    token = secrets.token_hex(8)
    run = Run(token, args.idle, args.short)
    server = await asyncio.start_server(
        lambda reader, writer: serve(run, context, reader, writer), args.listen, 0
    )
    port = server.sockets[0].getsockname()[1]
    plan = LaunchPlan(
        browser=args.browser,
        executable=args.browser_path,
        headless=not args.headful,
        extra_arguments=(
            f"--host-resolver-rules=MAP {HOSTNAME} {args.listen}, EXCLUDE localhost",
            "--ignore-certificate-errors-spki-list=" + certificate.spki_sha256_base64,
            "--disable-quic",
        ),
    )
    url = f"https://{HOSTNAME}:{port}/start?run={token}"
    timeout = 2 * args.idle + args.short + 30
    try:
        async with BrowserDriver(plan, url):
            await asyncio.wait_for(run.done.wait(), timeout=timeout)
    finally:
        server.close()
        await server.wait_closed()
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
        loopback = ipaddress.ip_address(args.listen).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        parser.error("the capture listener must be a loopback address")
    if args.idle <= 0 or args.short <= 0:
        parser.error("--idle and --short must be positive")
    for package, version in SUPPORTED.items():
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    asyncio.run(capture(args))


if __name__ == "__main__":
    main()
