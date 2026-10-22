"""Serve local assets and record lifecycle resource requests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote

from h2.events import PriorityUpdated

from .http2_analysis import Priority, analyze_http2, split_frames
from .http2_session import HOSTNAME, ConnectionRecord

FONT = Path(__file__).resolve().parents[2] / "fixtures/resources/assets/ahem/Ahem.ttf"
FONT_SHA256 = "b719ecb31c5b21fc573c03f6421c74ac63c271a5a3ff841e34f9705fb94b8448"
MAX_PEER_BYTES = 512 * 1024
ASSETS = {
    "/resource.js": "script",
    "/resource.css": "stylesheet",
    "/resource.gif": "image",
    "/resource.ttf": "font",
}
SAFE_FIELDS = frozenset(
    (
        ":method",
        ":scheme",
        ":authority",
        ":path",
        "accept",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "pragma",
        "priority",
        "referer",
        "origin",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "user-agent",
        "upgrade-insecure-requests",
        "te",
        "dnt",
        "sec-gpc",
    )
)


@dataclass(frozen=True)
class ResourceRequest:
    connection: int
    stream: int
    path: str
    fields: tuple[tuple[bytes, bytes], ...]
    priority: Priority | None
    raw_head: bytes | None = None


def resource_page(token: str) -> bytes:
    paths = {kind: f"{path}?run={token}" for path, kind in ASSETS.items()}
    return (
        '<!doctype html><meta charset=utf-8><link rel=icon href="data:,">'
        "<body><span id=resource-font>A</span><script>(async () => {"
        "let result = 'resources:error'; try {"
        "const load = (element, name, url) => new Promise((resolve, reject) => {"
        "element.onload = resolve; element.onerror = () => reject(Error('asset'));"
        "element[name] = url; document.body.append(element); });"
        "const script = document.createElement('script');"
        "const style = document.createElement('link'); style.rel = 'stylesheet';"
        "const image = new Image();"
        "await Promise.all(["
        f"load(script, 'src', {json.dumps(paths['script'])}),"
        f"load(style, 'href', {json.dumps(paths['stylesheet'])}),"
        f"load(image, 'src', {json.dumps(paths['image'])})]);"
        "if (!window.phantomResourceLoaded || image.naturalWidth !== 1) "
        "throw Error('asset');"
        "const faces = await document.fonts.load('20px PhantomCapture', 'A');"
        "if (faces.length !== 1 || faces[0].status !== 'loaded') throw Error('font');"
        "result = 'resources:ok'; } catch (_) {}"
        f"await fetch({json.dumps('/done?run=' + token + '&result=')} + "
        "encodeURIComponent(result), {cache:'no-store'});})();</script>"
    ).encode("ascii")


class ResourceCapture:
    """Keep only a fresh local page's requests; unexpected input prevents output."""

    def __init__(self, token: str, port: int, protocol: str = "h2") -> None:
        if not token or len(token) > 64 or not token.isascii() or not token.isalnum():
            raise ValueError("resource token must be bounded ASCII letters and digits")
        if not 1 <= port <= 65535:
            raise ValueError("resource origin must have a valid listener port")
        if protocol not in {"h1", "h2", "h3"}:
            raise ValueError("resource protocol must be h1, h2 or h3")
        self.protocol = protocol
        self.token = token
        self.authority = f"{HOSTNAME}:{port}".encode("ascii")
        self.origin = b"https://" + self.authority
        self.requests: list[ResourceRequest] = []
        self.taps: dict[int, ConnectionRecord] = {}
        self.responded: set[str] = set()
        self.retained = 0
        self.font = FONT.read_bytes()
        if hashlib.sha256(self.font).hexdigest() != FONT_SHA256:
            raise ValueError("resource font does not match its retained source")

    def target(self, path: str) -> str:
        return f"{path}?run={self.token}"

    def done_target(self, result: str) -> str:
        return self.target("/done") + "&result=" + quote(result, safe="")

    def asset(self, path: str) -> tuple[str, bytes]:
        if path == "/resource.js":
            return "text/javascript", b"window.phantomResourceLoaded = true;"
        if path == "/resource.css":
            body = (
                "@font-face {font-family:PhantomCapture;src:url("
                + json.dumps(self.target("/resource.ttf"))
                + ") format('truetype')}"
                "#resource-font {font-family:PhantomCapture;font-size:20px}"
            )
            return "text/css", body.encode("ascii")
        if path == "/resource.gif":
            return "image/gif", bytes.fromhex(
                "47494638396101000100800000000000ffffff21f9040100000000"
                "2c00000000010001000002024401003b"
            )
        if path == "/resource.ttf":
            return "font/ttf", self.font
        raise ValueError("unknown local resource path")

    def tap(self, index: int, listener: str, accepted: float) -> ConnectionRecord:
        tap = ConnectionRecord(listener, accepted)
        self.taps[index] = tap
        return tap

    def retain(
        self, tap: ConnectionRecord | None, direction: str, when: float, data: bytes
    ) -> None:
        if tap is None:
            raise ValueError("resource bytes arrived without an owned connection")
        if self.retained + len(data) > MAX_PEER_BYTES:
            raise ValueError("resource peer bytes exceed the capture limit")
        self.retained += len(data)
        chunks = tap.client_chunks if direction == "client" else tap.server_chunks
        chunks.append((when, data))

    def observe(
        self,
        connection: int,
        stream: int,
        fields: Sequence[tuple[bytes, bytes]],
        priority: PriorityUpdated | None,
    ) -> None:
        fields = tuple(fields)
        if any(name.decode("ascii") not in SAFE_FIELDS for name, _ in fields):
            raise ValueError("resource request contains an unapproved header name")
        head = dict(fields)
        if (
            head.get(b":method") != b"GET"
            or head.get(b":scheme") != b"https"
            or head.get(b":authority") != self.authority
        ):
            raise ValueError("resource request does not name the owned HTTPS origin")
        target = head.get(b":path", b"").decode("ascii")
        targets = {self.target(path): path for path in ("/start", *ASSETS)}
        targets.update(
            {
                self.done_target(value): "/done"
                for value in ("resources:ok", "resources:error")
            }
        )
        path = targets.get(target)
        if path is None:
            raise ValueError("resource request does not name an owned path and token")
        if any(request.path == path for request in self.requests):
            raise ValueError("resource request repeats an owned path")
        referrers = {self.origin + self.target("/start").encode()}
        if path == "/resource.ttf":
            referrers.add(self.origin + self.target("/resource.css").encode())
        for name, value in fields:
            if name == b"referer" and value not in referrers:
                raise ValueError("resource referrer does not name the owned page")
            if name == b"origin" and value != self.origin:
                raise ValueError(
                    "resource origin header does not name the owned origin"
                )
        initial = (
            None
            if priority is None
            else Priority(priority.exclusive, priority.depends_on, priority.weight)
        )
        self.requests.append(ResourceRequest(connection, stream, path, fields, initial))

    def observe_h1(self, connection: int, raw_head: bytes) -> None:
        """Admit a bodyless owned request without rewriting its wire spelling."""
        if self.protocol != "h1" or not raw_head.endswith(b"\r\n\r\n"):
            raise ValueError("resource HTTP/1 request head is incomplete")
        lines = raw_head[:-4].split(b"\r\n")
        parts = lines[0].split(b" ")
        if len(parts) != 3 or parts[0] != b"GET" or parts[2] != b"HTTP/1.1":
            raise ValueError("resource HTTP/1 request requires GET and HTTP/1.1")
        if not parts[1] or any(not 0x21 <= byte <= 0x7E for byte in parts[1]):
            raise ValueError("resource HTTP/1 target must contain visible ASCII only")
        fields = []
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if not separator:
                raise ValueError("resource HTTP/1 header field is malformed")
            if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
                raise ValueError("resource HTTP/1 header value contains a control byte")
            fields.append((name, value.strip(b" \t")))
        allowed = SAFE_FIELDS - {":method", ":scheme", ":authority", ":path"}
        lengths = []
        hosts = []
        for name, value in fields:
            lower = name.lower()
            if lower == b"host":
                hosts.append(value)
            elif lower == b"content-length":
                if value != b"0" or lengths:
                    raise ValueError("resource HTTP/1 request bodies are unsupported")
                lengths.append(value)
            elif lower == b"connection":
                if value.lower() not in {b"keep-alive", b"close"}:
                    raise ValueError(
                        "resource HTTP/1 connection options are unsupported"
                    )
            elif lower.decode("ascii", errors="replace") not in allowed:
                raise ValueError("resource request contains an unapproved header name")
        if hosts != [self.authority]:
            raise ValueError("resource request does not name one owned HTTPS origin")
        normalized = [
            (b":method", parts[0]),
            (b":scheme", b"https"),
            (b":authority", hosts[0]),
            (b":path", parts[1]),
            *(
                (name.lower(), value)
                for name, value in fields
                if name.lower() not in {b"host", b"connection", b"content-length"}
            ),
        ]
        ordinal = sum(r.connection == connection for r in self.requests)
        self.observe(connection, ordinal, normalized, None)
        self.requests[-1] = replace(
            self.requests[-1], fields=tuple(fields), raw_head=raw_head
        )

    def check_complete(self, page_result: str | None) -> None:
        expected = {"/start", "/done", *ASSETS}
        if (
            page_result != "resources:ok"
            or {r.path for r in self.requests} != expected
            or self.responded != expected
        ):
            raise ValueError(
                "resource page did not complete every owned asset successfully"
            )

    def lines(self, page_result: str | None) -> list[str]:
        self.check_complete(page_result)
        if self.protocol == "h1":
            return self._h1_lines()
        if self.protocol == "h3":
            raise ValueError("resource HTTP/3 evidence requires its stream owner")
        actual = {(r.connection, r.stream): r for r in self.requests}
        observed = set()
        lines = []
        for index, tap in self.taps.items():
            analysis = analyze_http2(tap)
            _, server_trailing = split_frames(
                tap.server_chunks, "server", preface=False
            )
            client_frames = [
                frame for frame in analysis.frames if frame.direction == "client"
            ]
            if (
                analysis.client_trailing
                or server_trailing
                or sum(f.frame_type == 1 for f in client_frames)
                != len(analysis.client_headers)
            ):
                raise ValueError(
                    "resource HTTP/2 capture has incomplete frames or headers"
                )
            for frame in client_frames:
                if (
                    frame.frame_type not in {0, 1, 2, 3, 4, 6, 7, 8, 9}
                    or (frame.frame_type == 0 and frame.payload)
                    or (frame.frame_type == 7 and len(frame.payload) != 8)
                ):
                    raise ValueError(
                        "resource HTTP/2 capture contains unapproved peer data"
                    )
            for block in analysis.client_headers:
                key = (index, block.stream_id)
                request = actual.get(key)
                decoded = tuple(
                    (field.name, field.value)
                    for field in block.fields
                    if field.name is not None
                )
                if (
                    request is None
                    or key in observed
                    or decoded != request.fields
                    or block.priority != request.priority
                ):
                    raise ValueError(
                        "resource HTTP/2 bytes disagree with the owned request"
                    )
                observed.add(key)
            for direction, chunks in (
                ("client", tap.client_chunks),
                ("server", tap.server_chunks),
            ):
                prefix = f"resource_connection_{index}_{direction}"
                lines.append(f"{prefix}_chunk_count={len(chunks)}")
                lines.extend(
                    f"{prefix}_chunk_{i}=ms:{when * 1000:.3f},data_hex:{data.hex()}"
                    for i, (when, data) in enumerate(chunks)
                )
        if observed != set(actual):
            raise ValueError("resource HTTP/2 bytes omit an owned request")
        lines.extend(self.field_lines())
        return lines

    def field_lines(self) -> list[str]:
        lines = []
        for request in self.requests:
            if request.path not in ASSETS:
                continue
            prefix = "resource_" + ASSETS[request.path]
            lines.extend(
                (
                    f"{prefix}_connection={request.connection}",
                    f"{prefix}_stream={request.stream}",
                    f"{prefix}_field_count={len(request.fields)}",
                )
            )
            for i, (name, value) in enumerate(request.fields):
                if name == b":authority":
                    value = f"{HOSTNAME}:<port>".encode()
                elif name == b":path":
                    value = (request.path + "?run=<token>").encode()
                elif name == b"referer":
                    referrer_path = value[len(self.origin) :].split(b"?", 1)[0]
                    value = (
                        b"https://"
                        + HOSTNAME.encode()
                        + b":<port>"
                        + referrer_path
                        + b"?run=<token>"
                    )
                elif name == b"origin":
                    value = f"https://{HOSTNAME}:<port>".encode()
                lines.append(
                    f"{prefix}_field_{i}=name_hex:{name.hex()},value_hex:{value.hex()}"
                )
            p = request.priority
            priority = (
                "none"
                if p is None
                else f"exclusive:{str(p.exclusive).lower()},depends_on:{p.depends_on},weight:{p.weight}"
            )
            lines.append(f"{prefix}_initial_priority={priority}")
        return lines

    def _h1_lines(self) -> list[str]:
        lines = ["resource_protocol=http/1.1"]
        for index, tap in self.taps.items():
            requests = [r for r in self.requests if r.connection == index]
            client = b"".join(data for _, data in tap.client_chunks)
            if client != b"".join(r.raw_head or b"" for r in requests):
                raise ValueError(
                    "resource HTTP/1 bytes disagree with owned request heads"
                )
            server = b"".join(data for _, data in tap.server_chunks)
            for request in requests:
                head, separator, tail = server.partition(b"\r\n\r\n")
                if not separator or not head.startswith(b"HTTP/1.1 200 OK\r\n"):
                    raise ValueError(
                        "resource HTTP/1 response head is incomplete or failed"
                    )
                lengths = [
                    line.partition(b":")[2].strip()
                    for line in head.split(b"\r\n")[1:]
                    if line.partition(b":")[0].lower() == b"content-length"
                ]
                body = (
                    resource_page(self.token)
                    if request.path == "/start"
                    else b"ok"
                    if request.path == "/done"
                    else self.asset(request.path)[1]
                )
                if lengths != [str(len(body)).encode()] or not tail.startswith(body):
                    raise ValueError(
                        "resource HTTP/1 response body is incomplete or changed"
                    )
                server = tail[len(body) :]
            if server:
                raise ValueError("resource HTTP/1 response bytes are unowned")
            for direction, chunks in (
                ("client", tap.client_chunks),
                ("server", tap.server_chunks),
            ):
                prefix = f"resource_connection_{index}_{direction}"
                lines.append(f"{prefix}_chunk_count={len(chunks)}")
                lines.extend(
                    f"{prefix}_chunk_{i}=ms:{when * 1000:.3f},data_hex:{data.hex()}"
                    for i, (when, data) in enumerate(chunks)
                )
        if any(r.connection not in self.taps for r in self.requests):
            raise ValueError("resource HTTP/1 bytes omit an owned request")
        for request in self.requests:
            if request.path not in ASSETS:
                continue
            prefix = "resource_" + ASSETS[request.path]
            lines.extend(
                (
                    f"{prefix}_connection={request.connection}",
                    f"{prefix}_request={request.stream}",
                    f"{prefix}_head_hex={request.raw_head.hex()}",
                    f"{prefix}_field_count={len(request.fields)}",
                )
            )
            lines.extend(
                f"{prefix}_field_{i}=name_hex:{name.hex()},value_hex:{value.hex()}"
                for i, (name, value) in enumerate(request.fields)
            )
        return lines
