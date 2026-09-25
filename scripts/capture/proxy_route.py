"""Record what a browser sends to an HTTP proxy for plaintext and TLS origins."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import platform
import secrets
import shlex
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from .browser_launch import (
    BROWSERS,
    CHROMIUM_BROWSERS,
    LaunchedBrowser,
    LaunchPlan,
    browser_arguments,
    render_preferences,
)
from .browser_remote import ChromiumAuthDriver, Credentials, FirefoxAuthDriver
from .fixture_file import write_text_fixture
from .http2_session import (
    Certificate,
    ConnectionRecord,
    HeaderField,
    PlainChannel,
    TlsChannel,
    analyze_http2,
    frame_details,
    generate_certificate,
    server_context,
)

FORMAT = "phantom-proxy-route-v1"
ORIGIN_HOST = "origin.phantom.test"
PROXY_HOST = "proxy.phantom.test"
SUPPORTED_H2 = "4.4.1"
SUPPORTED_HPACK = "4.2.0"
MAX_REQUEST_HEAD = 64 * 1024
# Fields the tool refuses to retain at all.
SENSITIVE_HEADERS = {b"authorization", b"cookie"}
# Retained with its name and position; the value becomes a marker.
PROXY_AUTHORIZATION = b"proxy-authorization"
# Throwaway credentials for the auth scenarios' loopback proxy only.
PROXY_USERNAME = "phantom-user"
PROXY_PASSWORD = "phantom-pass"
PROXY_REALM = b"phantom-capture"
PROXY_CREDENTIAL = b"Basic " + base64.b64encode(
    f"{PROXY_USERNAME}:{PROXY_PASSWORD}".encode()
)
REDACTED_CAPTURE = "redacted:capture-credential"
REDACTED_OTHER = "redacted:other"
WEBSOCKET_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# One unmasked server text frame; the page ends the run when it arrives.
WEBSOCKET_MESSAGE = b"\x81\x07phantom"
# ws:// openings an auth scenario page makes one after another.
AUTH_WEBSOCKETS = 2
DIRECT_FLAG = "--no-proxy-server"
# CONNECT ports of the `secure` page: an https:// fetch and a wss:// opening.
# The proxy answers 200 and closes, so no origin TLS completes; the ports
# only tell the two tunnels apart.
SECURE_CONNECT_KINDS = {b"443": "https-connect", b"8443": "wss-connect"}
# Chromium field trials can change network behavior between otherwise equal
# launches; the proxy captures pin the built-in defaults.
CHROMIUM_EXTRA_FLAGS = ("--disable-field-trial-config",)
# Auth scenarios start on about:blank and navigate over the remote protocol
# once the credential handler is installed.
REMOTE_START_URL = "about:blank"
CHROMIUM_REMOTE_FLAG = "--remote-debugging-port=0"
FIREFOX_REMOTE_ARGUMENTS = ("--remote-debugging-port", "0")
CREDENTIAL_SUPPLY = {
    "chrome": "cdp:Target.attachToTarget(flatten);"
    "Fetch.enable(handleAuthRequests=true,urlPattern=*);"
    "Fetch.continueRequest;"
    "Fetch.continueWithAuth(ProvideCredentials if source=Proxy);"
    "Page.navigate",
    "firefox": "webdriver-bidi:session.new;"
    "session.subscribe(network.authRequired);"
    "network.addIntercept(phases=authRequired);"
    "network.continueWithAuth(provideCredentials if status=407);"
    "browsingContext.navigate",
    "manual": "manual",
}
CREDENTIAL_SUPPLY["edge"] = CREDENTIAL_SUPPLY["chrome"]


@dataclass(frozen=True)
class Scenario:
    purpose: str
    # none | http | https
    proxy: str
    # loopback pages use 127.0.0.1; hostname pages use ORIGIN_HOST.
    origin: str
    # Both proxy listeners answer capture requests without the expected
    # Proxy-Authorization with 407, and the page opens two ws:// in turn.
    auth: bool = False
    # websocket: ws:// on the page's origin (two in turn with auth).
    # secure: an https:// fetch, then a wss:// opening, each through CONNECT.
    # remembered: a fetch to /probe, then a second navigation over the
    # remote protocol.
    page: str = "websocket"
    # Which capture requests an auth scenario challenges: all, connect
    # (CONNECT only), or probe (the /probe fetch only).
    challenge: str = "all"


SCENARIOS = {
    "direct-loopback": Scenario(
        "direct plaintext request and ws:// opening to a loopback origin",
        "none",
        "loopback",
    ),
    "direct-hostname": Scenario(
        "direct plaintext request and ws:// opening to a named origin",
        "none",
        "hostname",
    ),
    "http-proxy-loopback": Scenario(
        "loopback http:// and ws:// through a plaintext HTTP proxy",
        "http",
        "loopback",
    ),
    "http-proxy-hostname": Scenario(
        "named http:// and ws:// through a plaintext HTTP proxy",
        "http",
        "hostname",
    ),
    "https-proxy-loopback": Scenario(
        "loopback http:// and ws:// through a TLS proxy offering h2",
        "https",
        "loopback",
    ),
    "https-proxy-hostname": Scenario(
        "named http:// and ws:// through a TLS proxy offering h2",
        "https",
        "hostname",
    ),
    "http-proxy-auth-loopback": Scenario(
        "loopback http:// and two ws:// through a plaintext HTTP proxy "
        "requiring Basic auth",
        "http",
        "loopback",
        auth=True,
    ),
    "http-proxy-auth-hostname": Scenario(
        "named http:// and two ws:// through a plaintext HTTP proxy "
        "requiring Basic auth",
        "http",
        "hostname",
        auth=True,
    ),
    "https-proxy-auth-loopback": Scenario(
        "loopback http:// and two ws:// through a TLS proxy offering h2 "
        "requiring Basic auth",
        "https",
        "loopback",
        auth=True,
    ),
    "https-proxy-auth-hostname": Scenario(
        "named http:// and two ws:// through a TLS proxy offering h2 "
        "requiring Basic auth",
        "https",
        "hostname",
        auth=True,
    ),
    "http-proxy-secure-hostname": Scenario(
        "CONNECT for an https:// fetch and a wss:// opening through a "
        "plaintext HTTP proxy",
        "http",
        "hostname",
        page="secure",
    ),
    "https-proxy-secure-hostname": Scenario(
        "CONNECT for an https:// fetch and a wss:// opening through a TLS "
        "proxy offering h2",
        "https",
        "hostname",
        page="secure",
    ),
    "http-proxy-auth-secure-hostname": Scenario(
        "CONNECT for an https:// fetch and a wss:// opening through a "
        "plaintext HTTP proxy that challenges CONNECT with Basic auth",
        "http",
        "hostname",
        auth=True,
        page="secure",
        challenge="connect",
    ),
    "https-proxy-auth-secure-hostname": Scenario(
        "CONNECT for an https:// fetch and a wss:// opening through a TLS "
        "proxy offering h2 that challenges CONNECT with Basic auth",
        "https",
        "hostname",
        auth=True,
        page="secure",
        challenge="connect",
    ),
    "http-proxy-auth-remembered-hostname": Scenario(
        "a fetch challenged by a plaintext HTTP proxy, then a navigation "
        "with the remembered credentials",
        "http",
        "hostname",
        auth=True,
        page="remembered",
        challenge="probe",
    ),
    "https-proxy-auth-remembered-hostname": Scenario(
        "a fetch challenged by a TLS proxy offering h2, then a navigation "
        "with the remembered credentials",
        "https",
        "hostname",
        auth=True,
        page="remembered",
        challenge="probe",
    ),
}


# -- Recorded state --------------------------------------------------------


@dataclass
class RequestRecord:
    connection: int
    received: float
    # h1 | h2
    protocol: str
    # none | h1-connect | h2-connect
    tunnel: str
    stream_id: int | None
    request_line: bytes
    header_lines: list[bytes]
    kind: str = "other"
    status: int | None = None
    method: bytes = b""
    authority: bytes = b""
    # none | capture-credential | other
    proxy_authorization: str = "none"

    @property
    def form(self) -> str:
        if self.protocol == "h2":
            return "h2"
        target = self.request_line.split(b" ")
        target = target[1] if len(target) == 3 else b""
        if target.startswith(b"/"):
            return "origin"
        if b"://" in target:
            return "absolute"
        return "authority"


@dataclass
class CaptureRun:
    token: str
    scenario: str
    observation_seconds: float = 1.0
    clock: Callable[[], float] = time.perf_counter
    # The exact Proxy-Authorization value the proxies require, or None.
    proxy_credential: bytes | None = None
    started: float = field(init=False)
    connections: list[ConnectionRecord] = field(default_factory=list)
    requests: list[RequestRecord] = field(default_factory=list)
    results: list[dict[str, str]] = field(default_factory=list)
    # Remote-protocol credential events, as (received, note).
    remote_events: list[tuple[float, str]] = field(default_factory=list)
    finished: float | None = None
    timed_out: bool = False
    done: asyncio.Event = field(default_factory=asyncio.Event)
    # Set when a `remembered` page is ready for its second navigation.
    ready: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self) -> None:
        self.started = self.clock()

    @property
    def scenario_spec(self) -> Scenario:
        return SCENARIOS[self.scenario]

    def now(self) -> float:
        return self.clock() - self.started

    def finish(self, query: dict[str, str]) -> None:
        self.results.append(query)
        if self.finished is None:
            self.finished = self.now()
            asyncio.get_running_loop().call_later(
                self.observation_seconds, self.done.set
            )

    def note(self, text: str) -> None:
        self.remote_events.append((self.now(), text))

    def page(self, step: str = "") -> bytes:
        token = self.token
        kind = self.scenario_spec.page
        if kind == "secure":
            return self.secure_page()
        if kind == "remembered":
            return self.remembered_page(step)
        if self.proxy_credential is not None:
            return self.sequential_page()
        return (
            "<!doctype html><meta charset=utf-8>"
            '<link rel=icon href="data:,"><script>\n'
            "let sent = false;\n"
            "function done(outcome) {\n"
            "  if (sent) return;\n"
            "  sent = true;\n"
            f"  fetch('/done?run={token}&websocket=' + outcome);\n"
            "}\n"
            f"const socket = new WebSocket('ws://' + location.host + '/echo?run={token}');\n"
            "socket.onmessage = () => { socket.close(1000); done('message'); };\n"
            "socket.onerror = () => done('error');\n"
            "socket.onclose = (event) => done('close-' + event.code);\n"
            "setTimeout(() => done('timeout'), 10000);\n"
            "</script>\n"
        ).encode()

    def secure_page(self) -> bytes:
        """Open an https:// fetch, then a wss:// opening, then report."""
        token = self.token
        return (
            "<!doctype html><meta charset=utf-8>"
            '<link rel=icon href="data:,"><script>\n'
            "async function run() {\n"
            "  const outcomes = [];\n"
            "  try {\n"
            f"    await fetch('https://{ORIGIN_HOST}:443/tls?run={token}',"
            " {mode: 'no-cors'});\n"
            "    outcomes.push('fetch-ok');\n"
            "  } catch (error) { outcomes.push('fetch-error'); }\n"
            "  outcomes.push(await new Promise((resolve) => {\n"
            f"    const socket = new WebSocket('wss://{ORIGIN_HOST}:8443/tls?run={token}');\n"
            "    socket.onerror = () => resolve('websocket-error');\n"
            "    socket.onclose = () => resolve('websocket-close');\n"
            "    setTimeout(() => resolve('websocket-timeout'), 5000);\n"
            "  }));\n"
            f"  fetch('/done?run={token}&secure=' + outcomes.join('.'));\n"
            "}\n"
            "run();\n"
            "</script>\n"
        ).encode()

    def remembered_page(self, step: str) -> bytes:
        """Step 1 fetches /probe, then /ready; step 2 reports to /done."""
        token = self.token
        if step == "2":
            script = f"fetch('/done?run={token}&step=2');\n"
        else:
            script = (
                f"fetch('/probe?run={token}')"
                f".then(() => fetch('/ready?run={token}'));\n"
            )
        return (
            "<!doctype html><meta charset=utf-8>"
            '<link rel=icon href="data:,"><script>\n' + script + "</script>\n"
        ).encode()

    def sequential_page(self) -> bytes:
        """Open ws:// openings one after another, then report every outcome."""
        token = self.token
        return (
            "<!doctype html><meta charset=utf-8>"
            '<link rel=icon href="data:,"><script>\n'
            "const outcomes = [];\n"
            "let sent = false;\n"
            "function done() {\n"
            "  if (sent) return;\n"
            "  sent = true;\n"
            f"  fetch('/done?run={token}&websocket=' + outcomes.join('.'));\n"
            "}\n"
            "function open(index) {\n"
            "  let settled = false;\n"
            "  const url = 'ws://' + location.host + "
            f"'/echo?run={token}&socket=' + index;\n"
            "  const socket = new WebSocket(url);\n"
            "  const settle = (outcome) => {\n"
            "    if (settled) return;\n"
            "    settled = true;\n"
            "    outcomes.push(outcome);\n"
            f"    if (index + 1 < {AUTH_WEBSOCKETS}) open(index + 1); else done();\n"
            "  };\n"
            "  socket.onmessage = () => { socket.close(1000); settle('message'); };\n"
            "  socket.onerror = () => settle('error');\n"
            "  socket.onclose = (event) => settle('close-' + event.code);\n"
            "}\n"
            "open(0);\n"
            "setTimeout(() => { outcomes.push('timeout'); done(); }, 10000);\n"
            "</script>\n"
        ).encode()


def connect_kind(authority: bytes) -> str:
    """The kind of a capture CONNECT: a secure page's tunnel or ws://."""
    return SECURE_CONNECT_KINDS.get(authority.rsplit(b":", 1)[-1], "connect")


def is_capture_authority(authority: bytes) -> bool:
    """Whether a request names the capture origin rather than browser traffic."""
    host = authority.rsplit(b":", 1)[0]
    return host in {ORIGIN_HOST.encode(), b"127.0.0.1"}


def websocket_accept(key: bytes) -> bytes:
    return base64.b64encode(hashlib.sha1(key + WEBSOCKET_GUID).digest())


def header_value(lines: Sequence[bytes], name: bytes) -> bytes | None:
    for line in lines:
        key, _, value = line.partition(b":")
        if key.strip().lower() == name:
            return value.strip()
    return None


def response_head(status: int, fields: Sequence[tuple[bytes, bytes]]) -> bytes:
    reasons = {
        101: b"Switching Protocols",
        200: b"OK",
        204: b"No Content",
        404: b"Not Found",
        407: b"Proxy Authentication Required",
    }
    lines = [b"HTTP/1.1 " + str(status).encode() + b" " + reasons[status]]
    lines.extend(name + b": " + value for name, value in fields)
    return b"\r\n".join(lines) + b"\r\n\r\n"


def route(
    run: CaptureRun, method: bytes, target: bytes
) -> tuple[str, int, list[tuple[bytes, bytes]], bytes]:
    """Return (kind, status, fields, body) for an ordinary request."""
    parts = urlsplit(target.decode("latin-1"))
    query = parse_qs(parts.query, keep_blank_values=True)
    owned = query.get("run", [""])[0] == run.token
    if method == b"GET" and owned and parts.path == "/page":
        body = run.page(query.get("step", [""])[0])
        fields = [(b"content-type", b"text/html; charset=utf-8")]
    elif method == b"GET" and owned and parts.path == "/done":
        run.finish({key: values[0] for key, values in query.items() if key != "run"})
        return "done", 204, [(b"cache-control", b"no-store")], b""
    elif method == b"GET" and owned and parts.path in ("/probe", "/ready"):
        if parts.path == "/ready":
            run.ready.set()
        return parts.path[1:], 204, [(b"cache-control", b"no-store")], b""
    else:
        return "other", 404, [(b"content-length", b"0")], b""
    fields.append((b"content-length", str(len(body)).encode()))
    fields.append((b"cache-control", b"no-store"))
    return "page", 200, fields, body


def proxy_authorization(value: bytes | None, expected: bytes | None) -> str:
    """Classify a Proxy-Authorization value without keeping it."""
    if value is None:
        return "none"
    return "capture-credential" if value == expected else "other"


def challenge_fields() -> list[tuple[bytes, bytes]]:
    return [
        (b"Proxy-Authenticate", b'Basic realm="' + PROXY_REALM + b'"'),
        (b"Content-Length", b"0"),
    ]


def challenged_kind(run: CaptureRun, method: bytes, target: bytes) -> str:
    """The kind a request would have had, without routing it."""
    if method == b"CONNECT":
        return connect_kind(target)
    parts = urlsplit(target.decode("latin-1"))
    query = parse_qs(parts.query, keep_blank_values=True)
    if query.get("run", [""])[0] != run.token:
        return "other"
    return {
        "/page": "page",
        "/done": "done",
        "/echo": "websocket",
        "/probe": "probe",
        "/ready": "ready",
    }.get(parts.path, "other")


def challenges(run: CaptureRun, method: bytes, target: bytes) -> bool:
    """Whether the scenario's challenge policy covers this capture request."""
    policy = run.scenario_spec.challenge
    if policy == "connect":
        return method == b"CONNECT"
    if policy == "probe":
        return challenged_kind(run, method, target) == "probe"
    return True


class Http1Exchange:
    """Sans-I/O HTTP/1.1 server for one byte stream: a connection or tunnel."""

    def __init__(
        self,
        run: CaptureRun,
        connection: int,
        *,
        tunnel: str = "none",
        stream_id: int | None = None,
        proxy: bool = False,
    ) -> None:
        self.run = run
        self.connection = connection
        self.tunnel = tunnel
        self.stream_id = stream_id
        # A proxy listener's own requests are challenged; tunnelled ones not.
        self.proxy = proxy
        self.buffer = bytearray()
        # Set after a WebSocket upgrade or a background tunnel; later bytes
        # are not HTTP and are discarded.
        self.detached = False
        # Set after a secure page's CONNECT: the connection closes once the
        # 200 is written, before any origin TLS.
        self.closing = False

    def feed(self, data: bytes) -> bytes:
        """Consume client bytes; return the bytes to send back."""
        if self.detached:
            return b""
        self.buffer.extend(data)
        output = bytearray()
        while not self.detached:
            end = self.buffer.find(b"\r\n\r\n")
            if end < 0:
                if len(self.buffer) > MAX_REQUEST_HEAD:
                    raise ValueError("request head exceeds the capture limit")
                break
            head = bytes(self.buffer[:end])
            del self.buffer[: end + 4]
            output.extend(self.handle(head))
        return bytes(output)

    def handle(self, head: bytes) -> bytes:
        lines = head.split(b"\r\n")
        request = RequestRecord(
            connection=self.connection,
            received=self.run.now(),
            protocol="h1",
            tunnel=self.tunnel,
            stream_id=self.stream_id,
            request_line=lines[0],
            header_lines=lines[1:],
        )
        self.run.requests.append(request)
        parts = lines[0].split(b" ")
        method, target = (parts[0], parts[1]) if len(parts) == 3 else (b"", b"")
        request.method = method
        if method == b"CONNECT":
            request.authority = target
        else:
            request.authority = header_value(request.header_lines, b"host") or b""
        background = not is_capture_authority(request.authority)
        expected = self.run.proxy_credential
        request.proxy_authorization = proxy_authorization(
            header_value(request.header_lines, PROXY_AUTHORIZATION), expected
        )
        if (
            self.proxy
            and self.tunnel == "none"
            and expected is not None
            and not background
            and request.proxy_authorization != "capture-credential"
            and challenges(self.run, method, target)
        ):
            # The connection stays open so a retry can reuse it.
            request.kind = challenged_kind(self.run, method, target)
            request.status = 407
            return response_head(407, challenge_fields())
        if method == b"CONNECT":
            request.kind = "background" if background else connect_kind(target)
            request.status = 200
            self.tunnel = "h1-connect"
            self.detached = background or request.kind != "connect"
            self.closing = request.kind != "connect" and not background
            return b"HTTP/1.1 200 Connection established\r\n\r\n"
        if background:
            request.kind, request.status = "background", 404
            return response_head(404, [(b"content-length", b"0")])
        upgrade = header_value(request.header_lines, b"upgrade")
        key = header_value(request.header_lines, b"sec-websocket-key")
        if upgrade is not None and upgrade.lower() == b"websocket" and key:
            request.kind, request.status = "websocket", 101
            self.detached = True
            fields = [
                (b"Upgrade", b"websocket"),
                (b"Connection", b"Upgrade"),
                (b"Sec-WebSocket-Accept", websocket_accept(key)),
            ]
            return response_head(101, fields) + WEBSOCKET_MESSAGE
        kind, status, fields, body = route(self.run, method, target)
        request.kind, request.status = kind, status
        return response_head(status, fields) + body


class Http2Proxy:
    """HTTP/2 proxy session: forwards plain requests and CONNECT tunnels."""

    def __init__(self, run: CaptureRun, connection: int, channel: PlainChannel) -> None:
        from h2.config import H2Configuration
        from h2.connection import H2Connection

        self.run = run
        self.connection = connection
        self.channel = channel
        self.h2 = H2Connection(H2Configuration(client_side=False, header_encoding=None))
        # None marks a background tunnel whose bytes are discarded.
        self.tunnels: dict[int, Http1Exchange | None] = {}

    async def serve(self) -> None:
        import h2.events

        self.h2.initiate_connection()
        await self.flush()
        while True:
            data = await self.channel.read()
            if not data:
                return
            for event in self.h2.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    self.request(event.stream_id, event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    self.h2.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    tunnel = self.tunnels.get(event.stream_id)
                    if tunnel is not None:
                        output = tunnel.feed(event.data)
                        if output:
                            self.h2.send_data(event.stream_id, output)
                elif isinstance(event, h2.events.StreamEnded):
                    if event.stream_id in self.tunnels:
                        self.h2.end_stream(event.stream_id)
                elif isinstance(event, h2.events.ConnectionTerminated):
                    await self.flush()
                    return
            await self.flush()

    def request(self, stream_id: int, headers: Sequence[tuple[bytes, bytes]]) -> None:
        pseudo = {name: value for name, value in headers if name.startswith(b":")}
        method = pseudo.get(b":method", b"")
        record = RequestRecord(
            connection=self.connection,
            received=self.run.now(),
            protocol="h2",
            tunnel="none",
            stream_id=stream_id,
            request_line=b"",
            header_lines=[],
            method=method,
            authority=pseudo.get(b":authority", b""),
        )
        self.run.requests.append(record)
        background = not is_capture_authority(record.authority)
        expected = self.run.proxy_credential
        credential = next(
            (value for name, value in headers if name == PROXY_AUTHORIZATION), None
        )
        record.proxy_authorization = proxy_authorization(credential, expected)
        if (
            expected is not None
            and not background
            and record.proxy_authorization != "capture-credential"
            and challenges(
                self.run,
                method,
                record.authority if method == b"CONNECT" else pseudo.get(b":path", b""),
            )
        ):
            record.kind = challenged_kind(
                self.run,
                method,
                record.authority if method == b"CONNECT" else pseudo.get(b":path", b""),
            )
            record.status = 407
            response = [(b":status", b"407")]
            response.extend((name.lower(), value) for name, value in challenge_fields())
            self.h2.send_headers(stream_id, response, end_stream=True)
            return
        if method == b"CONNECT" and b":protocol" not in pseudo:
            record.kind = "background" if background else connect_kind(record.authority)
            record.status = 200
            if record.kind not in ("background", "connect"):
                # A secure page's tunnel ends at once, before any origin TLS.
                self.h2.send_headers(stream_id, [(b":status", b"200")], end_stream=True)
                return
            self.h2.send_headers(stream_id, [(b":status", b"200")])
            self.tunnels[stream_id] = None
            if not background:
                self.tunnels[stream_id] = Http1Exchange(
                    self.run, self.connection, tunnel="h2-connect", stream_id=stream_id
                )
            return
        if background:
            record.kind, record.status = "background", 404
            self.h2.send_headers(stream_id, [(b":status", b"404")], end_stream=True)
            return
        target = pseudo.get(b":path", b"")
        kind, status, fields, body = route(self.run, method, target)
        record.kind, record.status = kind, status
        response = [(b":status", str(status).encode())]
        response.extend((name.lower(), value) for name, value in fields)
        self.h2.send_headers(stream_id, response, end_stream=not body)
        if body:
            self.h2.send_data(stream_id, body, end_stream=True)

    async def flush(self) -> None:
        await self.channel.write(self.h2.data_to_send())


# -- Listeners -------------------------------------------------------------


class CaptureServer:
    """A plaintext origin, a plaintext proxy, and a TLS proxy on loopback."""

    def __init__(self, certificate: Certificate) -> None:
        self.context = server_context(certificate)
        self.run: CaptureRun | None = None
        self.servers: list[asyncio.Server] = []
        self.addresses: dict[str, tuple[str, int]] = {}
        self.writers: set[asyncio.StreamWriter] = set()

    async def start(self, host: str) -> None:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the capture listener must be a loopback address")
        for listener in ("origin", "http-proxy", "https-proxy"):
            server = await asyncio.start_server(
                lambda reader, writer, name=listener: self.handle(name, reader, writer),
                host,
                0,
            )
            self.servers.append(server)
            self.addresses[listener] = server.sockets[0].getsockname()[:2]

    def note(self, text: str) -> None:
        if self.run is not None:
            self.run.note(text)

    def address(self, listener: str) -> str:
        return "{}:{}".format(*self.addresses[listener])

    async def close(self) -> None:
        self.drop_connections()
        for server in self.servers:
            server.close()
            await server.wait_closed()

    def drop_connections(self) -> None:
        for writer in list(self.writers):
            writer.transport.abort()
        self.writers.clear()

    async def handle(
        self,
        listener: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        run = self.run
        if run is None:
            writer.transport.abort()
            return
        self.writers.add(writer)
        record = ConnectionRecord(listener=listener, accepted=run.now())
        run.connections.append(record)
        index = len(run.connections) - 1
        try:
            if listener == "https-proxy":
                channel: PlainChannel = TlsChannel(
                    self.context, reader, writer, record, run.now
                )
                await channel.handshake()
            else:
                channel = PlainChannel(reader, writer, record, run.now)
            if record.alpn == "h2":
                record.protocol = "h2"
                await Http2Proxy(run, index, channel).serve()
            else:
                record.protocol = "http/1.1"
                exchange = Http1Exchange(run, index, proxy=listener != "origin")
                await serve_http1(exchange, channel)
        except Exception as error:  # noqa: BLE001 - recorded as evidence
            record.failure = type(error).__name__
        finally:
            self.writers.discard(writer)
            if not writer.transport.is_closing():
                writer.close()


async def serve_http1(exchange: Http1Exchange, channel: PlainChannel) -> None:
    while True:
        data = await channel.read()
        if not data:
            return
        await channel.write(exchange.feed(data))
        if exchange.closing:
            return


# -- Fixture ---------------------------------------------------------------


@dataclass(frozen=True)
class CaptureMetadata:
    client: str
    client_version: str
    operating_system: str
    listen_addresses: str
    launch_mode: str
    launch_arguments: str
    firefox_preferences: str
    profile_files: str
    # How an auth scenario's browser received the proxy credential.
    credential_supply: str = "none"


def milliseconds(value: float | None) -> str:
    return "none" if value is None else f"{value * 1000:.3f}"


def optional(value: object) -> str:
    return "none" if value is None else str(value)


def check_retainable(request: RequestRecord) -> None:
    for line in request.header_lines:
        if line.partition(b":")[0].strip().lower() in SENSITIVE_HEADERS:
            raise ValueError("refusing to retain a credential-bearing request field")


def redaction(value: bytes, expected: bytes | None) -> str:
    if expected is not None and value == expected:
        return REDACTED_CAPTURE
    return REDACTED_OTHER


def retained_line(line: bytes, expected: bytes | None) -> bytes:
    """An H1 field line with a Proxy-Authorization value replaced by a marker."""
    name, _, value = line.partition(b":")
    if name.strip().lower() != PROXY_AUTHORIZATION:
        return line
    return name + b": " + redaction(value.strip(), expected).encode()


def connection_lines(
    prefix: str,
    record: ConnectionRecord,
    background_streams: set[int],
    expected: bytes | None = None,
) -> list[str]:
    hello = record.client_hello
    offer = "none"
    server_name = "none"
    if hello is not None:
        offer = ";".join(hello.alpn_offer) if hello.alpn_offer else "none"
        server_name = hello.server_name or "none"
    lines = [
        f"{prefix}=listener:{record.listener},"
        f"accepted_ms:{milliseconds(record.accepted)},"
        f"alpn_offer:{offer},sni:{server_name},alpn:{optional(record.alpn)},"
        f"protocol:{optional(record.protocol)},client_bytes:{record.received},"
        f"client_eof_ms:{milliseconds(record.client_eof)},"
        f"failure:{optional(record.failure)}"
    ]
    if record.protocol != "h2":
        return lines
    analysis = analyze_http2(record)
    lines.append(f"{prefix}_frame_count={len(analysis.frames)}")
    for index, frame in enumerate(analysis.frames):
        details = ",".join(frame_details(frame))
        lines.append(
            f"{prefix}_frame_{index}={frame.direction}:{frame.type_name},"
            f"stream:{frame.stream_id},flags:0x{frame.flags:02x}"
            + (f",{details}" if details else "")
        )
    lines.append(f"{prefix}_headers_count={len(analysis.client_headers)}")
    for index, block in enumerate(analysis.client_headers):
        key = f"{prefix}_headers_{index}"
        lines.append(f"{key}_stream={block.stream_id}")
        if block.stream_id in background_streams:
            # Browser background traffic: only its existence is retained.
            lines.append(f"{key}_background=true")
            continue
        for item in block.fields:
            if (item.name or b"").lower() in SENSITIVE_HEADERS:
                raise ValueError("refusing to retain a credential-bearing field")
        lines.append(
            f"{key}_field_order="
            + ",".join(
                (item.name or b"").decode("latin-1")
                for item in block.fields
                if item.representation != "size-update"
            )
        )
        lines.append(f"{key}_field_count={len(block.fields)}")
        lines.extend(
            field_line(f"{key}_field_{position}", item, expected)
            for position, item in enumerate(block.fields)
        )
    return lines


def field_line(key: str, item: HeaderField, expected: bytes | None) -> str:
    value = item.value or b""
    redacted = (item.name or b"").lower() == PROXY_AUTHORIZATION
    if redacted:
        # Representation and index stay; the value is a marker, never hex.
        value = redaction(value, expected).encode()
    return (
        f"{key}=repr:{item.representation},"
        f"index:{item.index},"
        f"name_hex:{(item.name or b'').hex() or 'none'},"
        f"value_hex:{value.hex() or 'none'}" + (",redacted:true" if redacted else "")
    )


def run_lines(prefix: str, run: CaptureRun) -> list[str]:
    lines = [
        f"{prefix}_timed_out={str(run.timed_out).lower()}",
        f"{prefix}_finished_ms={milliseconds(run.finished)}",
        f"{prefix}_result_count={len(run.results)}",
    ]
    lines.extend(
        f"{prefix}_result_{index}={urlencode(result)}"
        for index, result in enumerate(run.results)
    )
    lines.append(f"{prefix}_connection_count={len(run.connections)}")
    for index, connection in enumerate(run.connections):
        background = {
            request.stream_id
            for request in run.requests
            if request.connection == index
            and request.protocol == "h2"
            and request.kind == "background"
            and request.stream_id is not None
        }
        lines.extend(
            connection_lines(
                f"{prefix}_connection_{index}",
                connection,
                background,
                run.proxy_credential,
            )
        )
    lines.append(f"{prefix}_request_count={len(run.requests)}")
    for index, request in enumerate(run.requests):
        check_retainable(request)
        key = f"{prefix}_request_{index}"
        lines.append(
            f"{key}=connection:{request.connection},protocol:{request.protocol},"
            f"form:{request.form},tunnel:{request.tunnel},"
            f"stream:{optional(request.stream_id)},kind:{request.kind},"
            f"status:{optional(request.status)},"
            f"received_ms:{milliseconds(request.received)}"
            + (
                f",proxy_authorization:{request.proxy_authorization}"
                if run.proxy_credential is not None
                else ""
            )
        )
        if request.kind == "background":
            # The target of browser background traffic can carry per-install
            # tokens, so only the method and authority are kept.
            lines.append(f"{key}_method={request.method.decode('latin-1')}")
            lines.append(f"{key}_authority={request.authority.decode('latin-1')}")
            continue
        if request.protocol == "h2":
            continue
        lines.append(f"{key}_line_hex={request.request_line.hex()}")
        lines.append(f"{key}_header_count={len(request.header_lines)}")
        lines.extend(
            f"{key}_header_{position}={retained_line(line, run.proxy_credential).hex()}"
            for position, line in enumerate(request.header_lines)
        )
    if run.proxy_credential is not None:
        lines.append(f"{prefix}_remote_event_count={len(run.remote_events)}")
        lines.extend(
            f"{prefix}_remote_event_{index}=received_ms:{milliseconds(received)},{note}"
            for index, (received, note) in enumerate(run.remote_events)
        )
    return lines


def fixture(
    name: str, page_url: str, runs: Sequence[CaptureRun], capture: CaptureMetadata
) -> str:
    scenario = SCENARIOS[name]
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={capture.client}",
        f"client_version={capture.client_version}",
        f"operating_system={capture.operating_system}",
        f"origin_hostname={ORIGIN_HOST}",
        f"proxy_hostname={PROXY_HOST}",
        f"listen_addresses={capture.listen_addresses}",
        f"launch_mode={capture.launch_mode}",
        f"launch_arguments={capture.launch_arguments}",
        f"firefox_preferences={capture.firefox_preferences}",
        f"profile_files={capture.profile_files}",
        f"capture_tool=python {platform.python_version()} "
        f"h2 {SUPPORTED_H2} hpack {SUPPORTED_HPACK}",
        f"scenario={name}",
        f"scenario_purpose={scenario.purpose}",
        f"proxy={scenario.proxy}",
    ]
    if scenario.auth:
        lines.extend(
            [
                "proxy_auth=scheme:basic,realm:"
                + PROXY_REALM.decode()
                + ",credential:throwaway,value:not-retained",
                f"credential_supply={capture.credential_supply}",
            ]
        )
    lines += [
        f"page_url={page_url}",
        f"repeat_count={len(runs)}",
    ]
    for index, run in enumerate(runs):
        lines.extend(run_lines(f"run_{index}", run))
    return "\n".join(lines) + "\n"


# -- Browser launch --------------------------------------------------------


def page_url(server: CaptureServer, scenario: Scenario, token: str) -> str:
    port = server.addresses["origin"][1]
    host = ORIGIN_HOST if scenario.origin == "hostname" else "127.0.0.1"
    return f"http://{host}:{port}/page?run={token}"


def firefox_cert_override(host: str, port: int, certificate: Certificate) -> str:
    """Trust the throwaway proxy leaf inside one disposable profile only."""
    return (
        "# PSM Certificate Override Settings file\n"
        "# This is a generated file!  Do not edit.\n"
        f"{host}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t"
        f"{certificate.sha256_fingerprint}\t\n"
    )


def launch_plan(
    browser: str,
    executable: Path | None,
    headless: bool,
    scenario: Scenario,
    server: CaptureServer,
    certificate: Certificate,
) -> LaunchPlan:
    listen = server.addresses["origin"][0]
    http_proxy = server.addresses["http-proxy"]
    https_port = server.addresses["https-proxy"][1]
    if browser in CHROMIUM_BROWSERS:
        extra = [
            *CHROMIUM_EXTRA_FLAGS,
            f"--host-resolver-rules=MAP {ORIGIN_HOST} {listen}, "
            f"MAP {PROXY_HOST} {listen}, EXCLUDE localhost",
        ]
        if scenario.proxy == "http":
            extra.append("--proxy-server=http://{}:{}".format(*http_proxy))
        elif scenario.proxy == "https":
            extra.append(f"--proxy-server=https://{PROXY_HOST}:{https_port}")
            extra.append(
                "--ignore-certificate-errors-spki-list="
                + certificate.spki_sha256_base64
            )
        if scenario.proxy != "none":
            # Without this rule Chromium sends loopback origins directly.
            extra.append("--proxy-bypass-list=<-loopback>")
        if scenario.auth:
            extra.append(CHROMIUM_REMOTE_FLAG)
        return LaunchPlan(
            browser=browser,
            executable=executable,
            headless=headless,
            extra_arguments=tuple(extra),
        )
    if browser == "firefox":
        preferences: list[tuple[str, bool | int | str]] = [
            ("network.dns.localDomains", f"{ORIGIN_HOST},{PROXY_HOST}"),
            ("network.dns.disableIPv6", True),
            ("network.http.http3.enable", False),
        ]
        files: tuple[tuple[str, str], ...] = ()
        if scenario.proxy == "http":
            preferences.extend(
                [
                    ("network.proxy.type", 1),
                    ("network.proxy.http", http_proxy[0]),
                    ("network.proxy.http_port", http_proxy[1]),
                ]
            )
            if scenario.page == "secure":
                # Manual `http` settings cover http:// and ws:// only; an
                # https:// fetch needs the `ssl` proxy, as a user who picks
                # "Also use this proxy for HTTPS" sets it.
                preferences.extend(
                    [
                        ("network.proxy.ssl", http_proxy[0]),
                        ("network.proxy.ssl_port", http_proxy[1]),
                    ]
                )
        elif scenario.proxy == "https":
            # Manual proxy settings cannot name a TLS proxy; a PAC result can.
            pac = (
                "data:text/plain,function FindProxyForURL(url, host) "
                f"{{ return 'HTTPS {PROXY_HOST}:{https_port}'; }}"
            )
            preferences.extend(
                [("network.proxy.type", 2), ("network.proxy.autoconfig_url", pac)]
            )
            files = (
                (
                    "cert_override.txt",
                    firefox_cert_override(PROXY_HOST, https_port, certificate),
                ),
            )
        if scenario.proxy != "none":
            preferences.extend(
                [
                    ("network.proxy.allow_hijacking_localhost", True),
                    ("network.proxy.no_proxies_on", ""),
                ]
            )
        extra_arguments: tuple[str, ...] = ()
        if scenario.auth:
            extra_arguments = FIREFOX_REMOTE_ARGUMENTS
            # The remote agent otherwise applies its automation preferences,
            # which change connection behavior against the other captures.
            preferences.append(("remote.prefs.recommended", False))
        return LaunchPlan(
            browser="firefox",
            executable=executable,
            headless=headless,
            extra_arguments=extra_arguments,
            firefox_preferences=tuple(preferences),
            profile_files=files,
        )
    return LaunchPlan(browser="manual", executable=None, headless=False)


def launch_arguments(plan: LaunchPlan, profile: Path, url: str) -> list[str]:
    """Browser arguments; a Chromium proxy launch drops the direct-route flag."""
    arguments = browser_arguments(
        plan.browser, profile, url, headless=plan.headless, extra=plan.extra_arguments
    )
    proxied = any(item.startswith("--proxy-server=") for item in arguments)
    if plan.browser in CHROMIUM_BROWSERS and proxied:
        # `--no-proxy-server` takes precedence over `--proxy-server`.
        arguments.remove(DIRECT_FLAG)
    return arguments


def recorded_arguments(plan: LaunchPlan, url: str) -> str:
    if plan.browser == "manual":
        return "manual"
    return shlex.join(launch_arguments(plan, Path("<temporary-profile>"), url))


class ProxyLaunchedBrowser(LaunchedBrowser):
    def _start(self, profile: Path) -> subprocess.Popen[bytes]:
        if self.plan.browser not in CHROMIUM_BROWSERS:
            return super()._start(profile)
        return subprocess.Popen(
            [
                str(self.plan.executable),
                *launch_arguments(self.plan, profile, self.url),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **({} if sys.platform == "win32" else {"start_new_session": True}),
        )


class ProxyBrowserDriver:
    """One browser run; an auth run answers proxy challenges remotely."""

    def __init__(
        self,
        plan: LaunchPlan,
        url: str,
        *,
        auth: bool = False,
        note: Callable[[str], None] | None = None,
    ) -> None:
        self.plan = plan
        self.url = url
        self.auth = auth
        self.note = note or (lambda _: None)
        self.browser: ProxyLaunchedBrowser | None = None
        self.remote: ChromiumAuthDriver | FirefoxAuthDriver | None = None

    async def __aenter__(self) -> ProxyBrowserDriver:
        if self.plan.browser == "manual":
            print(f"open {self.url}", file=sys.stderr, flush=True)
            return self
        if not self.auth:
            self.browser = ProxyLaunchedBrowser(self.plan, self.url).__enter__()
            return self
        self.browser = ProxyLaunchedBrowser(self.plan, REMOTE_START_URL).__enter__()
        credentials = Credentials(PROXY_USERNAME, PROXY_PASSWORD)
        if self.plan.browser in CHROMIUM_BROWSERS:
            self.remote = ChromiumAuthDriver(credentials, self.note)
        else:
            self.remote = FirefoxAuthDriver(credentials, self.note)
        assert self.browser.profile is not None
        try:
            await self.remote.start(self.browser.profile, self.url)
        except Exception as error:  # noqa: BLE001 - recorded as evidence
            self.note(f"event:driver-failure,error:{type(error).__name__}")
            print(f"remote driver failed: {error!r}", file=sys.stderr, flush=True)
        return self

    async def navigate(self, url: str) -> None:
        """Navigate the page again over the remote protocol."""
        if self.remote is None:
            print(f"open {url}", file=sys.stderr, flush=True)
            return
        try:
            await self.remote.navigate(url)
        except Exception as error:  # noqa: BLE001 - recorded as evidence
            self.note(f"event:driver-failure,error:{type(error).__name__}")

    async def __aexit__(self, *details: object) -> None:
        if self.remote is not None:
            await self.remote.close()
        if self.browser is not None:
            self.browser.__exit__(*details)


async def capture_scenario(
    server: CaptureServer,
    name: str,
    *,
    repeat: int,
    run_timeout: float,
    observation_seconds: float,
    drive: Callable[[str], object],
) -> list[CaptureRun]:
    """Run `repeat` fresh clients; `drive(url)` returns an async context."""
    runs = []
    auth = SCENARIOS[name].auth
    for _ in range(repeat):
        run = CaptureRun(
            secrets.token_hex(8),
            name,
            observation_seconds=observation_seconds,
            proxy_credential=PROXY_CREDENTIAL if auth else None,
        )
        server.run = run
        try:
            url = page_url(server, SCENARIOS[name], run.token)
            async with drive(url) as driver:
                try:
                    if SCENARIOS[name].page == "remembered":
                        await asyncio.wait_for(run.ready.wait(), timeout=run_timeout)
                        await driver.navigate(url + "&step=2")
                    await asyncio.wait_for(run.done.wait(), timeout=run_timeout)
                except asyncio.TimeoutError:
                    run.timed_out = True
        finally:
            server.run = None
            server.drop_connections()
        runs.append(run)
    return runs


async def run(args: argparse.Namespace) -> None:
    certificate = generate_certificate(PROXY_HOST)
    server = CaptureServer(certificate)
    await server.start(args.listen)
    try:
        listen = ",".join(f"{name}={server.address(name)}" for name in server.addresses)
        names = list(SCENARIOS) if args.scenario == ["all"] else args.scenario
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name in names:
            scenario = SCENARIOS[name]
            plan = launch_plan(
                args.browser,
                args.browser_path,
                not args.headful,
                scenario,
                server,
                certificate,
            )
            runs = await capture_scenario(
                server,
                name,
                repeat=args.repeat,
                run_timeout=args.run_timeout,
                observation_seconds=args.observation,
                drive=lambda url, plan=plan, auth=scenario.auth: ProxyBrowserDriver(
                    plan, url, auth=auth, note=server.note
                ),
            )
            url = page_url(server, scenario, "<token>")
            start = REMOTE_START_URL if scenario.auth else url
            capture = CaptureMetadata(
                client=args.client or plan.client_name,
                client_version=args.client_version,
                operating_system=args.operating_system,
                listen_addresses=listen,
                launch_mode=plan.launch_mode,
                launch_arguments=recorded_arguments(plan, start),
                firefox_preferences=render_preferences(plan.firefox_preferences)
                or "none",
                profile_files=",".join(item for item, _ in plan.profile_files)
                or "none",
                credential_supply=CREDENTIAL_SUPPLY[plan.browser]
                if scenario.auth
                else "none",
            )
            write_text_fixture(
                args.output_dir / f"{name}.txt", fixture(name, url, runs, capture)
            )
            timed_out = sum(item.timed_out for item in runs)
            print(f"captured {name} ({timed_out} timed out)", file=sys.stderr)
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
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--scenario", nargs="+", default=["all"])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--run-timeout", type=float, default=20.0)
    parser.add_argument("--observation", type=float, default=1.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.browser != "manual" and args.browser_path is None:
        parser.error("--browser-path is required unless --browser manual")
    unknown = sorted(set(args.scenario) - set(SCENARIOS) - {"all"})
    if unknown or ("all" in args.scenario and len(args.scenario) > 1):
        parser.error(f"unknown or mixed scenarios: {', '.join(unknown) or 'all'}")
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    try:
        loopback = ipaddress.ip_address(args.listen).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        parser.error("the capture listener must be a loopback address")
    for package, version in (("h2", SUPPORTED_H2), ("hpack", SUPPORTED_HPACK)):
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
