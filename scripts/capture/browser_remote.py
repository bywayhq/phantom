"""Answer proxy credential challenges in a launched browser over its remote protocol.

Chromium is driven over the Chrome DevTools Protocol (CDP) and Firefox over
WebDriver BiDi. Both run on a loopback WebSocket that the browser opens when it
is launched with a remote debugging port. The client here speaks only the
subset of RFC 6455 those endpoints need, so the capture environment needs no
extra package.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

WEBSOCKET_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_MESSAGE = 16 * 1024 * 1024
OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA
# Chromium writes this file into --user-data-dir: port, then browser path.
CHROMIUM_PORT_FILE = "DevToolsActivePort"
# Firefox writes this file into its profile when the BiDi server listens.
FIREFOX_PORT_FILE = "WebDriverBiDiServer.json"


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str


# -- WebSocket client -------------------------------------------------------


def encode_frame(opcode: int, payload: bytes, mask: bytes) -> bytes:
    """One final client frame; RFC 6455 section 5.3 requires the mask."""
    if len(mask) != 4:
        raise ValueError("a client frame mask is four bytes")
    head = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        head.append(0x80 | length)
    elif length < 1 << 16:
        head.append(0x80 | 126)
        head.extend(length.to_bytes(2, "big"))
    else:
        head.append(0x80 | 127)
        head.extend(length.to_bytes(8, "big"))
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return bytes(head) + mask + masked


async def read_frame(reader: asyncio.StreamReader) -> tuple[bool, int, bytes]:
    """Read one server frame as (final, opcode, payload)."""
    first, second = await reader.readexactly(2)
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(await reader.readexactly(2), "big")
    elif length == 127:
        length = int.from_bytes(await reader.readexactly(8), "big")
    if length > MAX_MESSAGE:
        raise ValueError("remote protocol frame exceeds the capture limit")
    mask = await reader.readexactly(4) if second & 0x80 else b""
    payload = await reader.readexactly(length)
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return bool(first & 0x80), first & 0x0F, payload


class RemoteSocket:
    """A text-message WebSocket client for a loopback remote protocol endpoint."""

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.reader = reader
        self.writer = writer

    @classmethod
    async def connect(cls, url: str) -> RemoteSocket:
        parts = urlsplit(url)
        if parts.scheme != "ws" or parts.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("the remote protocol endpoint must be loopback ws://")
        reader, writer = await asyncio.open_connection(parts.hostname, parts.port)
        key = base64.b64encode(os.urandom(16))
        path = parts.path or "/"
        writer.write(
            f"GET {path} HTTP/1.1\r\nHost: {parts.netloc}\r\n".encode()
            + b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            + b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "
            + key
            + b"\r\n\r\n"
        )
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if not lines[0].startswith(b"HTTP/1.1 101"):
            writer.close()
            raise ConnectionError(f"remote protocol upgrade refused: {lines[0]!r}")
        expected = base64.b64encode(hashlib.sha1(key + WEBSOCKET_GUID).digest())
        accept = next(
            (
                line.partition(b":")[2].strip()
                for line in lines[1:]
                if line.partition(b":")[0].strip().lower() == b"sec-websocket-accept"
            ),
            None,
        )
        if accept != expected:
            writer.close()
            raise ConnectionError("remote protocol upgrade has a wrong accept key")
        return cls(reader, writer)

    async def send(self, text: str) -> None:
        self.writer.write(encode_frame(OPCODE_TEXT, text.encode(), os.urandom(4)))
        await self.writer.drain()

    async def receive(self) -> str:
        """Return the next text message; answer pings; raise on close."""
        message = bytearray()
        while True:
            final, opcode, payload = await read_frame(self.reader)
            if opcode == OPCODE_PING:
                self.writer.write(encode_frame(OPCODE_PONG, payload, os.urandom(4)))
                await self.writer.drain()
                continue
            if opcode == OPCODE_PONG:
                continue
            if opcode == OPCODE_CLOSE:
                raise ConnectionError("remote protocol endpoint closed")
            if opcode not in {OPCODE_TEXT, OPCODE_BINARY, OPCODE_CONTINUATION}:
                raise ValueError(f"unexpected WebSocket opcode {opcode}")
            message.extend(payload)
            if len(message) > MAX_MESSAGE:
                raise ValueError("remote protocol message exceeds the capture limit")
            if final:
                return message.decode()

    def close(self) -> None:
        self.writer.transport.abort()


# -- Message dispatch --------------------------------------------------------


EventHandler = Callable[[dict], Awaitable[None]]
Note = Callable[[str], None]


class RemoteConnection:
    """JSON commands with ids, responses by id, and events to one handler.

    CDP and WebDriver BiDi share this shape: a command is
    `{"id", "method", "params"}`, a response echoes the id with `result` or
    `error`, and an event carries `method` without an id.
    """

    def __init__(self, socket: RemoteSocket) -> None:
        self.socket = socket
        self.next_id = 1
        self.pending: dict[int, asyncio.Future[dict]] = {}
        self.handler: EventHandler | None = None
        self.reader: asyncio.Task[None] | None = None
        self.failure: BaseException | None = None

    def start(self, handler: EventHandler) -> None:
        self.handler = handler
        self.reader = asyncio.create_task(self.read_loop())

    async def read_loop(self) -> None:
        try:
            while True:
                message = json.loads(await self.socket.receive())
                await self.dispatch(message)
        except (ConnectionError, asyncio.IncompleteReadError, ValueError) as error:
            self.failure = error
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError(str(error)))

    async def dispatch(self, message: dict) -> None:
        identifier = message.get("id")
        if identifier is not None and message.get("type") != "event":
            future = self.pending.pop(identifier, None)
            if future is not None and not future.done():
                if "error" in message:
                    future.set_exception(RemoteError(message))
                else:
                    future.set_result(message.get("result", {}))
            return
        if "method" in message and self.handler is not None:
            await self.handler(message)

    async def send(
        self, method: str, params: dict, session_id: str | None = None
    ) -> asyncio.Future[dict]:
        identifier = self.next_id
        self.next_id += 1
        command: dict = {"id": identifier, "method": method, "params": params}
        if session_id is not None:
            command["sessionId"] = session_id
        future = asyncio.get_running_loop().create_future()
        self.pending[identifier] = future
        await self.socket.send(json.dumps(command))
        return future

    async def call(
        self, method: str, params: dict, session_id: str | None = None
    ) -> dict:
        return await asyncio.wait_for(
            await self.send(method, params, session_id), timeout=15
        )

    async def reply(self, command: tuple[str, dict], event: dict, note: Note) -> None:
        """Send an answer to `event` without waiting; note a refused answer."""
        method, params = command
        future = await self.send(method, params, event.get("sessionId"))

        def settled(done: asyncio.Future[dict]) -> None:
            if not done.cancelled() and done.exception() is not None:
                note(f"event:reply-error,method:{method}")

        future.add_done_callback(settled)

    async def close(self) -> None:
        if self.reader is not None:
            self.reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.reader
        self.socket.close()


class RemoteError(Exception):
    def __init__(self, message: dict) -> None:
        super().__init__(
            json.dumps(message.get("error")) + " " + message.get("message", "")
        )


# -- Chrome DevTools Protocol -----------------------------------------------


def cdp_reply(event: dict, credentials: Credentials) -> tuple[str, dict] | None:
    """The command answering one Fetch event, or None for other events."""
    method = event.get("method")
    params = event.get("params", {})
    if method == "Fetch.requestPaused":
        return "Fetch.continueRequest", {"requestId": params["requestId"]}
    if method == "Fetch.authRequired":
        if params.get("authChallenge", {}).get("source") == "Proxy":
            response = {
                "response": "ProvideCredentials",
                "username": credentials.username,
                "password": credentials.password,
            }
        else:
            response = {"response": "CancelAuth"}
        return "Fetch.continueWithAuth", {
            "requestId": params["requestId"],
            "authChallengeResponse": response,
        }
    return None


def cdp_note(event: dict) -> str | None:
    """A fixture note for a credential challenge; no URL query or credential."""
    if event.get("method") != "Fetch.authRequired":
        return None
    params = event.get("params", {})
    challenge = params.get("authChallenge", {})
    source = challenge.get("source", "none")
    path = urlsplit(params.get("request", {}).get("url", "")).path or "none"
    answer = "ProvideCredentials" if source == "Proxy" else "CancelAuth"
    return (
        f"event:Fetch.authRequired,source:{source},"
        f"scheme:{challenge.get('scheme', 'none')},"
        f"realm:{challenge.get('realm', 'none')},path:{path},answer:{answer}"
    )


def chromium_endpoint(profile: Path) -> str | None:
    try:
        text = (profile / CHROMIUM_PORT_FILE).read_text(encoding="utf-8")
    except OSError:
        return None
    lines = text.splitlines()
    if len(lines) < 2 or not lines[0].strip().isdigit():
        return None
    return f"ws://127.0.0.1:{lines[0].strip()}{lines[1].strip()}"


# -- WebDriver BiDi ----------------------------------------------------------


def bidi_reply(event: dict, credentials: Credentials) -> tuple[str, dict] | None:
    """The command answering one blocked `network.authRequired` event."""
    if event.get("method") != "network.authRequired":
        return None
    params = event.get("params", {})
    if not params.get("isBlocked", False):
        return None
    request = params.get("request", {}).get("request")
    # BiDi has no challenge source; a proxy challenge is a 407 response.
    if params.get("response", {}).get("status") == 407:
        return "network.continueWithAuth", {
            "request": request,
            "action": "provideCredentials",
            "credentials": {
                "type": "password",
                "username": credentials.username,
                "password": credentials.password,
            },
        }
    return "network.continueWithAuth", {"request": request, "action": "cancel"}


def bidi_note(event: dict) -> str | None:
    if event.get("method") != "network.authRequired":
        return None
    params = event.get("params", {})
    response = params.get("response", {})
    challenges = response.get("authChallenges") or [{}]
    status = response.get("status", "none")
    path = urlsplit(params.get("request", {}).get("url", "")).path or "none"
    answer = "provideCredentials" if status == 407 else "cancel"
    if not params.get("isBlocked", False):
        answer = "none"
    return (
        f"event:network.authRequired,status:{status},"
        f"scheme:{challenges[0].get('scheme', 'none')},"
        f"realm:{challenges[0].get('realm', 'none')},path:{path},answer:{answer}"
    )


def firefox_endpoint(profile: Path) -> str | None:
    try:
        data = json.loads((profile / FIREFOX_PORT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    host, port = data.get("ws_host"), data.get("ws_port")
    if host not in {"127.0.0.1", "localhost"} or not isinstance(port, int):
        return None
    return f"ws://127.0.0.1:{port}/session"


# -- Drivers -----------------------------------------------------------------


async def wait_for_endpoint(
    find: Callable[[Path], str | None], profile: Path, timeout: float = 30.0
) -> str:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        endpoint = find(profile)
        if endpoint is not None:
            return endpoint
        await asyncio.sleep(0.1)
    raise TimeoutError("the browser did not publish a remote protocol endpoint")


async def first_page_target(connection: RemoteConnection) -> str:
    """Return the id of the browser's first page target, polling until it opens."""
    for _ in range(100):
        result = await connection.call("Target.getTargets", {})
        pages = [
            item["targetId"]
            for item in result.get("targetInfos", [])
            if item.get("type") == "page"
        ]
        if pages:
            return pages[0]
        await asyncio.sleep(0.1)
    raise TimeoutError("the browser opened no page target")


async def navigate_page(profile: Path, url: str, settle: float) -> None:
    """Navigate a Chromium browser's first page to `url` over DevTools.

    The browser must have been started with `--remote-debugging-port=0` and
    `--user-data-dir=<profile>`. The call waits `settle` seconds after the
    endpoint appears, so connections the browser opens and abandons at
    startup are over before the navigation starts.
    """
    endpoint = await wait_for_endpoint(chromium_endpoint, profile)
    await asyncio.sleep(settle)
    connection = RemoteConnection(await RemoteSocket.connect(endpoint))

    async def ignore(_: dict) -> None:
        return None

    connection.start(ignore)
    try:
        target = await first_page_target(connection)
        attached = await connection.call(
            "Target.attachToTarget", {"targetId": target, "flatten": True}
        )
        await connection.call("Page.navigate", {"url": url}, attached["sessionId"])
    finally:
        await connection.close()


class ChromiumAuthDriver:
    """Attach to the first page, answer proxy challenges, then navigate."""

    def __init__(self, credentials: Credentials, note: Note) -> None:
        self.credentials = credentials
        self.note = note
        self.connection: RemoteConnection | None = None
        self.session: str | None = None

    async def start(self, profile: Path, url: str) -> None:
        endpoint = await wait_for_endpoint(chromium_endpoint, profile)
        self.connection = RemoteConnection(await RemoteSocket.connect(endpoint))
        self.connection.start(self.handle)
        target = await self.page_target()
        attached = await self.connection.call(
            "Target.attachToTarget", {"targetId": target, "flatten": True}
        )
        session = attached["sessionId"]
        self.session = session
        await self.connection.call(
            "Fetch.enable",
            {"handleAuthRequests": True, "patterns": [{"urlPattern": "*"}]},
            session,
        )
        await self.connection.call("Page.navigate", {"url": url}, session)

    async def navigate(self, url: str) -> None:
        """Navigate the attached page again, as the address bar does."""
        assert self.connection is not None and self.session is not None
        await self.connection.call("Page.navigate", {"url": url}, self.session)

    async def page_target(self) -> str:
        assert self.connection is not None
        return await first_page_target(self.connection)

    async def handle(self, event: dict) -> None:
        note = cdp_note(event)
        if note is not None:
            self.note(note)
        reply = cdp_reply(event, self.credentials)
        if reply is not None and self.connection is not None:
            # Replies are not awaited: the reader must keep dispatching.
            await self.connection.reply(reply, event, self.note)

    async def close(self) -> None:
        if self.connection is not None:
            await self.connection.close()


class FirefoxAuthDriver:
    """Open a BiDi session, intercept auth challenges, then navigate."""

    def __init__(self, credentials: Credentials, note: Note) -> None:
        self.credentials = credentials
        self.note = note
        self.connection: RemoteConnection | None = None
        self.context: str | None = None

    async def start(self, profile: Path, url: str) -> None:
        endpoint = await wait_for_endpoint(firefox_endpoint, profile)
        self.connection = RemoteConnection(await RemoteSocket.connect(endpoint))
        self.connection.start(self.handle)
        await self.connection.call("session.new", {"capabilities": {}})
        await self.connection.call(
            "session.subscribe", {"events": ["network.authRequired"]}
        )
        await self.connection.call("network.addIntercept", {"phases": ["authRequired"]})
        tree = await self.connection.call("browsingContext.getTree", {})
        context = tree["contexts"][0]["context"]
        self.context = context
        await self.connection.call(
            "browsingContext.navigate", {"context": context, "url": url, "wait": "none"}
        )

    async def navigate(self, url: str) -> None:
        """Navigate the top-level context again, as the address bar does."""
        assert self.connection is not None and self.context is not None
        await self.connection.call(
            "browsingContext.navigate",
            {"context": self.context, "url": url, "wait": "none"},
        )

    async def handle(self, event: dict) -> None:
        note = bidi_note(event)
        if note is not None:
            self.note(note)
        reply = bidi_reply(event, self.credentials)
        if reply is not None and self.connection is not None:
            await self.connection.reply(reply, event, self.note)

    async def close(self) -> None:
        if self.connection is not None:
            await self.connection.close()
