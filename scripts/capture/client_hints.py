"""Record browser user-agent client hints across an `Accept-CH` navigation."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import math
import platform
import re
import secrets
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .browser_launch import (
    BROWSERS,
    BrowserDriver,
    LaunchPlan,
    add_browser_switch_option,
    check_browser_switches,
)
from .fixture_file import write_text_fixture

FORMAT = "phantom-client-hints-v2"
MAX_REQUEST_HEAD = 64 * 1024
SENSITIVE_HEADERS = {b"authorization", b"proxy-authorization", b"cookie"}
# Every user-agent client hint Chromium defines. The server requests all of
# them so the second navigation shows each hint the browser will send.
USER_AGENT_HINTS = (
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-model",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-wow64",
    "sec-ch-ua-form-factors",
)


@dataclass(frozen=True)
class Navigation:
    """One recorded navigation request: raw field names and client hints."""

    field_names: tuple[bytes, ...]
    hints: tuple[tuple[str, bytes], ...]


@dataclass
class HintRun:
    """Server state and observations for one fresh-profile browser run."""

    token: str
    accept_ch: tuple[str, ...]
    first: Navigation | None = None
    second: Navigation | None = None
    other_requests: int = 0
    done: asyncio.Event = field(default_factory=asyncio.Event)

    def first_path(self) -> str:
        return f"/run/{self.token}/first"

    def second_path(self) -> str:
        return f"/run/{self.token}/second"

    def first_page(self) -> bytes:
        return (
            "<!doctype html><meta charset=utf-8>"
            '<link rel=icon href="data:,">'
            f"<script>location.replace({self.second_path()!r})</script>\n"
        ).encode()


def is_hint(name: bytes, requested: Sequence[str]) -> bool:
    lowered = name.lower().decode("latin-1")
    return lowered in requested or lowered.startswith("sec-ch-")


def parse_navigation(head: bytes, requested: Sequence[str]) -> Navigation:
    lines = head[:-4].split(b"\r\n")[1:]
    names = []
    hints = []
    for line in lines:
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError("request header line has no colon")
        name = name.strip()
        if name.lower() in SENSITIVE_HEADERS:
            raise ValueError("refusing to retain a credential-bearing request field")
        names.append(name)
        if is_hint(name, requested):
            hint_name = name.lower().decode("ascii")
            validate_hint_name(hint_name)
            hints.append((hint_name, value.strip()))
    return Navigation(tuple(names), tuple(hints))


class HintServer:
    """Loopback HTTP/1.1 server driving one two-navigation run at a time."""

    def __init__(self) -> None:
        self.run: HintRun | None = None
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

    def url(self, run: HintRun) -> str:
        if self.address is None:
            raise RuntimeError("server has not started")
        host, port = self.address
        host = f"[{host}]" if ":" in host else host
        return f"http://{host}:{port}{run.first_path()}"

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
        try:
            while True:
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                except (
                    asyncio.IncompleteReadError,
                    asyncio.LimitOverrunError,
                    ConnectionError,
                ):
                    return
                await self.respond(run, head, writer)
        finally:
            self.writers.discard(writer)
            if not writer.transport.is_closing():
                writer.close()

    async def respond(
        self, run: HintRun, head: bytes, writer: asyncio.StreamWriter
    ) -> None:
        request_line = head.split(b"\r\n", 1)[0].split(b" ")
        target = request_line[1].decode("latin-1") if len(request_line) == 3 else ""
        path = urlsplit(target).path
        if path == run.first_path() and run.first is None:
            run.first = parse_navigation(head, run.accept_ch)
            accept_ch = ", ".join(run.accept_ch).encode()
            await write_response(
                writer, 200, run.first_page(), ((b"accept-ch", accept_ch),)
            )
            return
        if path == run.second_path() and run.first is not None and run.second is None:
            run.second = parse_navigation(head, run.accept_ch)
            await write_response(writer, 200, b"<!doctype html>done\n")
            run.done.set()
            return
        run.other_requests += 1
        await write_response(writer, 404, b"")


async def write_response(
    writer: asyncio.StreamWriter,
    status: int,
    body: bytes,
    headers: Sequence[tuple[bytes, bytes]] = (),
) -> None:
    reason = b"OK" if status == 200 else b"Not Found"
    lines = [b"HTTP/1.1 " + str(status).encode() + b" " + reason]
    lines.append(b"content-type: text/html; charset=utf-8")
    lines.extend(name + b": " + value for name, value in headers)
    lines.append(b"content-length: " + str(len(body)).encode())
    lines.append(b"cache-control: no-store")
    writer.write(b"\r\n".join(lines) + b"\r\n\r\n" + body)
    await writer.drain()


@dataclass(frozen=True)
class CaptureMetadata:
    client: str
    client_version: str
    operating_system: str
    listen_address: str
    launch_mode: str
    launch_arguments: str


def derived_hints(runs: Sequence[HintRun]) -> list[tuple[str, str, bytes]]:
    """Return `(delivery, name, value)` in second-navigation order.

    A hint is `default` when the first navigation already carried it and
    `accept-ch` when it appeared only after the server requested it. Every run
    must agree exactly; a disagreement is evidence to investigate, not average.
    """
    if not runs:
        raise ValueError("at least one run is required")
    for run in runs:
        if run.first is None or run.second is None:
            raise ValueError("a run did not complete both navigations")
        for navigation in (run.first, run.second):
            for name, _value in navigation.hints:
                validate_hint_name(name)
    reference = runs[0]
    for run in runs[1:]:
        if run.first.hints != reference.first.hints:
            raise ValueError("runs disagree on first-navigation hints")
        if run.second.hints != reference.second.hints:
            raise ValueError("runs disagree on second-navigation hints")
    second = reference.second.hints
    names = [name for name, _ in second]
    if len(set(names)) != len(names):
        raise ValueError("second navigation repeated a hint field")
    first = dict(reference.first.hints)
    if len(first) != len(reference.first.hints):
        raise ValueError("first navigation repeated a hint field")
    second_values = dict(second)
    for name, value in first.items():
        if second_values.get(name) != value:
            raise ValueError(f"default hint {name} changed after Accept-CH")
    order = [name for name in names if name in first]
    if order != [name for name, _ in reference.first.hints]:
        raise ValueError("default hints changed relative order after Accept-CH")
    return [
        ("default" if name in first else "accept-ch", name, value)
        for name, value in second
    ]


def validate_value(value: bytes) -> str:
    text = value.decode("ascii")
    if any(not (" " <= character <= "~" or character == "\t") for character in text):
        raise ValueError("hint value is not visible ASCII")
    return text


def fixture(
    runs: Sequence[HintRun], metadata: CaptureMetadata, accept_ch: Sequence[str]
) -> str:
    hints = derived_hints(runs)
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
        "transport=HTTP/1.1",
        f"accept_ch={','.join(accept_ch)}",
        f"repeat_count={len(runs)}",
    ]
    for run_index, run in enumerate(runs):
        for label, navigation in (("first", run.first), ("second", run.second)):
            key = f"run_{run_index}_{label}"
            names = b",".join(navigation.field_names).decode("ascii")
            lines.append(f"{key}_field_order={names}")
            lines.append(f"{key}_hint_count={len(navigation.hints)}")
            lines.extend(
                f"{key}_hint_{index}={name}|{validate_value(value)}"
                for index, (name, value) in enumerate(navigation.hints)
            )
        lines.append(f"run_{run_index}_other_requests={run.other_requests}")
    lines.append(f"hint_count={len(hints)}")
    lines.extend(
        f"hint_{index}={delivery}|{name}|{validate_value(value)}"
        for index, (delivery, name, value) in enumerate(hints)
    )
    return "\n".join(lines) + "\n"


async def capture_runs(
    server: HintServer,
    *,
    repeat: int,
    accept_ch: Sequence[str],
    run_timeout: float,
    drive: Callable[[str], object],
) -> list[HintRun]:
    """Run `repeat` fresh clients; `drive(url)` returns an async context."""
    validate_options(repeat, accept_ch, run_timeout)
    runs = []
    for _ in range(repeat):
        run = HintRun(secrets.token_hex(8), tuple(accept_ch))
        server.run = run
        try:
            async with drive(server.url(run)):
                await asyncio.wait_for(run.done.wait(), timeout=run_timeout)
        finally:
            server.run = None
            server.drop_connections()
        runs.append(run)
    return runs


async def run(args: argparse.Namespace) -> None:
    validate_options(args.repeat, args.accept_ch, args.run_timeout)
    host, port = parse_listen(args.listen)
    plan = LaunchPlan(
        browser=args.browser,
        executable=args.browser_path,
        headless=not args.headful,
        extra_arguments=tuple(args.browser_switch),
    )
    server = HintServer()
    await server.start(host, port)
    try:
        host, port = server.address
        host = f"[{host}]" if ":" in host else host
        listen = f"{host}:{port}"
        runs = await capture_runs(
            server,
            repeat=args.repeat,
            accept_ch=args.accept_ch,
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
                f"http://{listen}/run/<token>/first"
            ),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_text_fixture(args.output, fixture(runs, metadata, args.accept_ch))
        print(f"captured {args.output}", file=sys.stderr, flush=True)
    finally:
        await server.close()


def validate_options(repeat: int, accept_ch: Sequence[str], run_timeout: float) -> None:
    if repeat < 1:
        raise ValueError("--repeat must be positive")
    if not math.isfinite(run_timeout) or run_timeout <= 0:
        raise ValueError("--run-timeout must be finite and positive")
    for name in accept_ch:
        validate_hint_name(name)


def validate_hint_name(name: str) -> None:
    if re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9a-z]+", name) is None:
        raise ValueError("client-hint names must be lowercase HTTP field names")
    if "|" in name:
        raise ValueError("client-hint names cannot contain the fixture separator '|'")


def parse_listen(value: str) -> tuple[str, int]:
    host, port_text = value.rsplit(":", 1)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    address = ipaddress.ip_address(host)
    if not address.is_loopback:
        raise ValueError("the capture listener must be a loopback address")
    port = int(port_text)
    if not 0 <= port <= 65535:
        raise ValueError("the capture listener port must be between 0 and 65535")
    return str(address), port


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=(*BROWSERS, "manual"), required=True)
    parser.add_argument("--browser-path", type=Path)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1:0")
    parser.add_argument("--accept-ch", nargs="+", default=list(USER_AGENT_HINTS))
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--run-timeout", type=float, default=30.0)
    parser.add_argument("--output", type=Path, required=True)
    add_browser_switch_option(parser)
    args = parser.parse_args(argv)
    check_browser_switches(parser, args)
    if args.browser != "manual" and args.browser_path is None:
        parser.error("--browser-path is required unless --browser manual")
    try:
        validate_options(args.repeat, args.accept_ch, args.run_timeout)
        parse_listen(args.listen)
    except ValueError as error:
        parser.error(str(error))
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
