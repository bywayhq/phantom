import asyncio
import contextlib
import io
import ssl
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived

from scripts.capture.proxy_route import (
    CHROMIUM_REMOTE_FLAG,
    DIRECT_FLAG,
    FIREFOX_REMOTE_ARGUMENTS,
    FORMAT,
    PROXY_CREDENTIAL,
    PROXY_HOST,
    REMOTE_START_URL,
    SCENARIOS,
    WEBSOCKET_MESSAGE,
    CaptureMetadata,
    CaptureRun,
    CaptureServer,
    Http1Exchange,
    capture_scenario,
    fixture,
    generate_certificate,
    launch_arguments,
    launch_plan,
    main,
    recorded_arguments,
)

METADATA = CaptureMetadata(
    client="scripted proxy client",
    client_version="0",
    operating_system="test",
    listen_addresses="none",
    launch_mode="scripted",
    launch_arguments="none",
    firefox_preferences="none",
    profile_files="none",
)
CERTIFICATE = generate_certificate(PROXY_HOST)
TIMEOUT = 20.0
KEY = b"dGhlIHNhbXBsZSBub25jZQ=="
BACKGROUND_TARGET = b"http://background.example/time?secret=per-install-token"
WRONG_CREDENTIAL = b"Basic d3Jvbmc6d3Jvbmc="
CHALLENGE = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Basic realm="phantom-capture"\r\n'
    b"Content-Length: 0\r\n\r\n"
)


def auth_run() -> CaptureRun:
    return CaptureRun(
        "0123456789abcdef",
        "http-proxy-auth-hostname",
        proxy_credential=PROXY_CREDENTIAL,
    )


def proxy_field(credential: bytes | None) -> bytes:
    if credential is None:
        return b""
    return b"Proxy-Authorization: " + credential + b"\r\n"


def leaks(text: str) -> bool:
    """Whether fixture text holds the credential in any retained encoding."""
    secrets = [PROXY_CREDENTIAL, PROXY_CREDENTIAL.split(b" ")[1], b"phantom-pass"]
    secrets.append(WRONG_CREDENTIAL.split(b" ")[1])
    return any(item.decode() in text or item.hex() in text for item in secrets)


def upgrade_request(authority: bytes, token: str) -> bytes:
    return (
        b"GET /echo?run=" + token.encode() + b" HTTP/1.1\r\n"
        b"Host: " + authority + b"\r\n"
        b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
        b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + KEY + b"\r\n\r\n"
    )


async def read_response(reader: asyncio.StreamReader) -> tuple[bytes, bytes]:
    head = await reader.readuntil(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    return head, await reader.readexactly(length)


class ScriptedHttpProxyClient:
    """Behaves like a browser pointed at the plaintext HTTP proxy listener."""

    def __init__(self, server: CaptureServer, url: str) -> None:
        self.server = server
        self.url = url
        self.task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> "ScriptedHttpProxyClient":
        self.task = asyncio.create_task(self.run())
        return self

    async def __aexit__(self, *_: object) -> None:
        if self.task is not None:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionError):
                await self.task

    async def run(self) -> None:
        parts = urlsplit(self.url)
        authority = parts.netloc.encode()
        token = parse_qs(parts.query)["run"][0]
        port = self.server.addresses["http-proxy"][1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            b"GET " + BACKGROUND_TARGET + b" HTTP/1.1\r\n"
            b"Host: background.example\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        await read_response(reader)
        writer.write(
            b"GET " + self.url.encode() + b" HTTP/1.1\r\n"
            b"Host: " + authority + b"\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        await read_response(reader)
        tunnel_reader, tunnel_writer = await asyncio.open_connection("127.0.0.1", port)
        tunnel_writer.write(
            b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n"
        )
        await tunnel_reader.readuntil(b"\r\n\r\n")
        tunnel_writer.write(upgrade_request(authority, token))
        await tunnel_reader.readuntil(b"\r\n\r\n")
        await tunnel_reader.readexactly(len(WEBSOCKET_MESSAGE))
        done = f"http://{parts.netloc}/done?run={token}&websocket=message"
        writer.write(
            b"GET " + done.encode() + b" HTTP/1.1\r\n"
            b"Host: " + authority + b"\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        await read_response(reader)
        await asyncio.Event().wait()


async def capture_http_proxy(name: str) -> tuple[CaptureServer, list[CaptureRun]]:
    server = CaptureServer(CERTIFICATE)
    await server.start("127.0.0.1")
    try:
        runs = await capture_scenario(
            server,
            name,
            repeat=1,
            run_timeout=TIMEOUT,
            observation_seconds=0.05,
            drive=lambda url: ScriptedHttpProxyClient(server, url),
        )
    finally:
        await server.close()
    return server, runs


async def h2_auth_run() -> tuple[CaptureRun, dict[int, bytes], dict[int, dict]]:
    """Drive the TLS proxy over h2 with missing, wrong, and right credentials."""
    server = CaptureServer(CERTIFICATE)
    await server.start("127.0.0.1")
    run = CaptureRun(
        "feedfacefeedface",
        "https-proxy-auth-hostname",
        0.05,
        proxy_credential=PROXY_CREDENTIAL,
    )
    server.run = run
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    authority = b"origin.phantom.test:9"
    page = [
        (b":method", b"GET"),
        (b":authority", authority),
        (b":scheme", b"http"),
        (b":path", b"/page?run=" + run.token.encode()),
    ]
    connect = [(b":method", b"CONNECT"), (b":authority", authority)]
    right = [(b"proxy-authorization", PROXY_CREDENTIAL)]
    wrong = [(b"proxy-authorization", WRONG_CREDENTIAL)]
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            server.addresses["https-proxy"][1],
            ssl=context,
            server_hostname=PROXY_HOST,
        )
        h2 = H2Connection(H2Configuration(client_side=True, header_encoding=None))
        h2.initiate_connection()
        h2.send_headers(1, page, end_stream=True)
        h2.send_headers(3, page + wrong, end_stream=True)
        h2.send_headers(5, page + right, end_stream=True)
        h2.send_headers(7, connect)
        h2.send_headers(9, connect + right)
        h2.send_data(9, upgrade_request(authority, run.token))
        h2.send_headers(
            11, [(b":method", b"CONNECT"), (b":authority", b"background.example:443")]
        )
        writer.write(h2.data_to_send())
        statuses: dict[int, bytes] = {}
        responses: dict[int, dict] = {}
        tunnel = b""
        while not (len(statuses) == 6 and len(tunnel) >= len(WEBSOCKET_MESSAGE)):
            data = await asyncio.wait_for(reader.read(65536), TIMEOUT)
            if not data:
                break
            for event in h2.receive_data(data):
                if isinstance(event, ResponseReceived):
                    responses[event.stream_id] = dict(event.headers)
                    statuses[event.stream_id] = dict(event.headers)[b":status"]
                elif isinstance(event, DataReceived):
                    h2.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    if event.stream_id == 9:
                        tunnel += event.data
            writer.write(h2.data_to_send())
        writer.close()
        assert tunnel.endswith(WEBSOCKET_MESSAGE), tunnel
    finally:
        server.run = None
        await server.close()
    return run, statuses, responses


async def h2_proxy_run() -> CaptureRun:
    """Drive the TLS proxy listener with an HTTP/2 client over ALPN h2."""
    server = CaptureServer(CERTIFICATE)
    await server.start("127.0.0.1")
    run = CaptureRun("feedfacefeedface", "https-proxy-hostname", 0.05)
    server.run = run
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    authority = b"origin.phantom.test:9"
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            server.addresses["https-proxy"][1],
            ssl=context,
            server_hostname=PROXY_HOST,
        )
        h2 = H2Connection(H2Configuration(client_side=True, header_encoding=None))
        h2.initiate_connection()
        h2.send_headers(
            1,
            [
                (b":method", b"GET"),
                (b":authority", authority),
                (b":scheme", b"http"),
                (b":path", b"/page?run=" + run.token.encode()),
                (b"accept-encoding", b"gzip, deflate"),
            ],
            end_stream=True,
        )
        h2.send_headers(3, [(b":method", b"CONNECT"), (b":authority", authority)])
        h2.send_data(3, upgrade_request(authority, run.token))
        h2.send_headers(
            5, [(b":method", b"CONNECT"), (b":authority", b"background.example:443")]
        )
        h2.send_data(5, b"\x16\x03\x01 not HTTP\r\n\r\n")
        h2.send_headers(
            7,
            [
                (b":method", b"GET"),
                (b":authority", authority),
                (b":scheme", b"http"),
                (b":path", b"/done?run=" + run.token.encode() + b"&websocket=message"),
            ],
            end_stream=True,
        )
        writer.write(h2.data_to_send())
        statuses: dict[int, bytes] = {}
        tunnel = b""
        while not (len(statuses) == 4 and len(tunnel) >= len(WEBSOCKET_MESSAGE)):
            data = await asyncio.wait_for(reader.read(65536), TIMEOUT)
            if not data:
                break
            for event in h2.receive_data(data):
                if isinstance(event, ResponseReceived):
                    statuses[event.stream_id] = dict(event.headers)[b":status"]
                elif isinstance(event, DataReceived):
                    h2.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    if event.stream_id == 3:
                        tunnel += event.data
            writer.write(h2.data_to_send())
        await asyncio.wait_for(run.done.wait(), TIMEOUT)
        writer.close()
        assert statuses == {1: b"200", 3: b"200", 5: b"200", 7: b"204"}, statuses
        assert tunnel.startswith(b"HTTP/1.1 101 ") and tunnel.endswith(
            WEBSOCKET_MESSAGE
        )
    finally:
        server.run = None
        await server.close()
    return run


class Http1ExchangeTests(unittest.TestCase):
    def test_connect_then_upgrade_is_recorded_inside_the_tunnel(self) -> None:
        async def exercise() -> tuple[CaptureRun, bytes, bytes]:
            run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
            exchange = Http1Exchange(run, 0)
            established = exchange.feed(
                b"CONNECT origin.phantom.test:80 HTTP/1.1\r\n"
                b"Host: origin.phantom.test:80\r\n\r\n"
            )
            upgraded = exchange.feed(
                upgrade_request(b"origin.phantom.test:80", run.token)
            )
            return run, established, upgraded

        run, established, upgraded = asyncio.run(exercise())
        self.assertEqual(established, b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.assertTrue(upgraded.startswith(b"HTTP/1.1 101 Switching Protocols"))
        self.assertTrue(upgraded.endswith(WEBSOCKET_MESSAGE))
        self.assertIn(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", upgraded)
        kinds = [(r.kind, r.form, r.tunnel) for r in run.requests]
        self.assertEqual(
            kinds,
            [
                ("connect", "authority", "none"),
                ("websocket", "origin", "h1-connect"),
            ],
        )

    def test_background_tunnel_bytes_are_discarded(self) -> None:
        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        exchange = Http1Exchange(run, 0)
        exchange.feed(b"CONNECT www.example.com:443 HTTP/1.1\r\n\r\n")
        self.assertEqual(exchange.feed(b"GET / HTTP/1.1\r\n\r\n"), b"")
        self.assertEqual([r.kind for r in run.requests], ["background"])

    def test_absolute_form_request_is_split_across_reads(self) -> None:
        run = CaptureRun("0123456789abcdef", "http-proxy-loopback")
        exchange = Http1Exchange(run, 0)
        request = (
            b"GET http://127.0.0.1:9/page?run=0123456789abcdef HTTP/1.1\r\n"
            b"Host: 127.0.0.1:9\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        self.assertEqual(exchange.feed(request[:20]), b"")
        response = exchange.feed(request[20:])
        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK"))
        self.assertEqual(run.requests[0].form, "absolute")
        self.assertEqual(run.requests[0].kind, "page")


class ProxyRouteCaptureTests(unittest.TestCase):
    def test_http_proxy_fixture_keeps_lines_and_redacts_background(self) -> None:
        _, runs = asyncio.run(capture_http_proxy("http-proxy-hostname"))
        run = runs[0]
        self.assertFalse(run.timed_out)
        self.assertEqual(run.results, [{"websocket": "message"}])
        self.assertEqual(
            [(r.kind, r.form, r.tunnel) for r in run.requests],
            [
                ("background", "absolute", "none"),
                ("page", "absolute", "none"),
                ("connect", "authority", "none"),
                ("websocket", "origin", "h1-connect"),
                ("done", "absolute", "none"),
            ],
        )
        text = fixture("http-proxy-hostname", "page", runs, METADATA)
        self.assertTrue(text.startswith(f"format={FORMAT}\n"))
        self.assertIn("run_0_request_0_authority=background.example\n", text)
        self.assertNotIn(b"per-install-token".hex(), text)
        self.assertNotIn("per-install-token", text)
        self.assertIn(
            "run_0_request_1_header_1=" + b"Proxy-Connection: keep-alive".hex(), text
        )

    def test_http2_proxy_records_forwarded_and_tunneled_requests(self) -> None:
        run = asyncio.run(h2_proxy_run())
        self.assertEqual(
            [(r.kind, r.protocol, r.tunnel, r.stream_id) for r in run.requests],
            [
                ("page", "h2", "none", 1),
                ("connect", "h2", "none", 3),
                ("websocket", "h1", "h2-connect", 3),
                ("background", "h2", "none", 5),
                ("done", "h2", "none", 7),
            ],
        )
        text = fixture("https-proxy-hostname", "page", [run], METADATA)
        self.assertIn("run_0_connection_0=listener:https-proxy,", text)
        self.assertIn("alpn_offer:h2;http/1.1,sni:proxy.phantom.test,alpn:h2", text)
        self.assertIn(
            "run_0_connection_0_headers_0_field_order="
            ":method,:authority,:scheme,:path,accept-encoding\n",
            text,
        )
        self.assertIn(
            "run_0_connection_0_headers_1_field_order=:method,:authority\n", text
        )
        self.assertIn("run_0_connection_0_headers_2_background=true\n", text)
        self.assertNotIn(b"background.example".hex(), text)

    def test_fixture_refuses_credential_bearing_fields(self) -> None:
        for field in (b"Authorization: Basic eDp5", b"Cookie: session=1"):
            run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
            exchange = Http1Exchange(run, 0)
            exchange.feed(
                b"GET http://origin.phantom.test:9/x HTTP/1.1\r\n"
                b"Host: origin.phantom.test:9\r\n" + field + b"\r\n\r\n"
            )
            with self.assertRaises(ValueError):
                fixture("http-proxy-hostname", "page", [run], METADATA)

    def test_listener_rejects_non_loopback_address(self) -> None:
        with self.assertRaises(ValueError):
            asyncio.run(CaptureServer(CERTIFICATE).start("0.0.0.0"))


class ProxyAuthTests(unittest.TestCase):
    def feed(self, exchange: Http1Exchange, head: bytes) -> bytes:
        async def exercise() -> bytes:
            return exchange.feed(head)

        return asyncio.run(exercise())

    def test_http1_connect_is_challenged_until_the_credential_matches(self) -> None:
        run = auth_run()
        exchange = Http1Exchange(run, 0, proxy=True)
        request = (
            b"CONNECT origin.phantom.test:9 HTTP/1.1\r\nHost: origin.phantom.test:9\r\n"
        )
        for credential in (None, WRONG_CREDENTIAL):
            response = self.feed(exchange, request + proxy_field(credential) + b"\r\n")
            self.assertEqual(response, CHALLENGE)
            self.assertEqual(exchange.tunnel, "none")
        response = self.feed(
            exchange, request + proxy_field(PROXY_CREDENTIAL) + b"\r\n"
        )
        self.assertEqual(response, b"HTTP/1.1 200 Connection established\r\n\r\n")
        upgraded = self.feed(
            exchange, upgrade_request(b"origin.phantom.test:9", run.token)
        )
        self.assertTrue(upgraded.startswith(b"HTTP/1.1 101 "))
        self.assertEqual(
            [(r.kind, r.status, r.proxy_authorization, r.tunnel) for r in run.requests],
            [
                ("connect", 407, "none", "none"),
                ("connect", 407, "other", "none"),
                ("connect", 200, "capture-credential", "none"),
                ("websocket", 101, "none", "h1-connect"),
            ],
        )

    def test_http1_forwarded_request_is_challenged_until_the_credential_matches(
        self,
    ) -> None:
        run = auth_run()
        exchange = Http1Exchange(run, 0, proxy=True)
        request = (
            b"GET http://origin.phantom.test:9/page?run=" + run.token.encode() + b" "
            b"HTTP/1.1\r\nHost: origin.phantom.test:9\r\n"
        )
        self.assertEqual(self.feed(exchange, request + b"\r\n"), CHALLENGE)
        self.assertEqual(
            self.feed(exchange, request + proxy_field(WRONG_CREDENTIAL) + b"\r\n"),
            CHALLENGE,
        )
        response = self.feed(
            exchange, request + proxy_field(PROXY_CREDENTIAL) + b"\r\n"
        )
        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK"))
        self.assertEqual(
            [(r.kind, r.status, r.proxy_authorization) for r in run.requests],
            [
                ("page", 407, "none"),
                ("page", 407, "other"),
                ("page", 200, "capture-credential"),
            ],
        )

    def test_origin_listener_and_background_traffic_are_not_challenged(self) -> None:
        run = auth_run()
        origin = Http1Exchange(run, 0)
        page = (
            b"GET /page?run=" + run.token.encode() + b" HTTP/1.1\r\n"
            b"Host: origin.phantom.test:9\r\n\r\n"
        )
        self.assertTrue(self.feed(origin, page).startswith(b"HTTP/1.1 200 OK"))
        proxy = Http1Exchange(run, 1, proxy=True)
        response = self.feed(proxy, b"CONNECT www.example.com:443 HTTP/1.1\r\n\r\n")
        self.assertEqual(response, b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.assertEqual([r.kind for r in run.requests], ["page", "background"])

    def test_scenario_without_auth_is_never_challenged(self) -> None:
        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        exchange = Http1Exchange(run, 0, proxy=True)
        response = self.feed(
            exchange, b"CONNECT origin.phantom.test:9 HTTP/1.1\r\n\r\n"
        )
        self.assertEqual(response, b"HTTP/1.1 200 Connection established\r\n\r\n")

    def test_http1_fixture_keeps_the_field_position_but_not_the_value(self) -> None:
        run = auth_run()
        exchange = Http1Exchange(run, 0, proxy=True)
        request = (
            b"CONNECT origin.phantom.test:9 HTTP/1.1\r\nHost: origin.phantom.test:9\r\n"
        )
        self.feed(exchange, request + proxy_field(WRONG_CREDENTIAL) + b"\r\n")
        self.feed(
            exchange,
            request + proxy_field(PROXY_CREDENTIAL) + b"User-Agent: test\r\n\r\n",
        )
        run.note("event:Fetch.authRequired,source:Proxy")
        text = fixture("http-proxy-auth-hostname", "page", [run], METADATA)
        self.assertFalse(leaks(text))
        self.assertIn(",status:407,", text)
        self.assertIn(",proxy_authorization:other\n", text)
        self.assertIn(",proxy_authorization:capture-credential\n", text)
        self.assertIn(
            "run_0_request_0_header_1="
            + b"Proxy-Authorization: redacted:other".hex()
            + "\n",
            text,
        )
        self.assertIn(
            "run_0_request_1_header_1="
            + b"Proxy-Authorization: redacted:capture-credential".hex()
            + "\n",
            text,
        )
        self.assertIn("run_0_request_1_header_2=" + b"User-Agent: test".hex(), text)
        self.assertIn("proxy_auth=scheme:basic,realm:phantom-capture,", text)
        self.assertIn("run_0_remote_event_count=1\n", text)
        self.assertIn(",event:Fetch.authRequired,source:Proxy\n", text)

    def test_http2_forwarded_and_connect_streams_are_challenged(self) -> None:
        run, statuses, responses = asyncio.run(h2_auth_run())
        self.assertEqual(
            statuses,
            {1: b"407", 3: b"407", 5: b"200", 7: b"407", 9: b"200", 11: b"200"},
        )
        self.assertEqual(
            responses[1][b"proxy-authenticate"], b'Basic realm="phantom-capture"'
        )
        self.assertEqual(responses[7][b"content-length"], b"0")
        self.assertEqual(
            [(r.kind, r.status, r.proxy_authorization) for r in run.requests],
            [
                ("page", 407, "none"),
                ("page", 407, "other"),
                ("page", 200, "capture-credential"),
                ("connect", 407, "none"),
                ("connect", 200, "capture-credential"),
                ("websocket", 101, "none"),
                ("background", 200, "none"),
            ],
        )
        text = fixture("https-proxy-auth-hostname", "page", [run], METADATA)
        self.assertFalse(leaks(text))
        self.assertIn(
            "run_0_connection_0_headers_2_field_order="
            ":method,:authority,:scheme,:path,proxy-authorization\n",
            text,
        )
        self.assertIn(
            # h2 sends proxy-authorization never-indexed on the static name.
            "run_0_connection_0_headers_1_field_4=repr:never-indexed,index:49,"
            f"name_hex:{b'proxy-authorization'.hex()},"
            f"value_hex:{b'redacted:other'.hex()},redacted:true\n",
            text,
        )
        self.assertIn(
            f"value_hex:{b'redacted:capture-credential'.hex()},redacted:true\n", text
        )

    def test_connect_policy_challenges_only_connect(self) -> None:
        run = CaptureRun(
            "0123456789abcdef",
            "http-proxy-auth-secure-hostname",
            proxy_credential=PROXY_CREDENTIAL,
        )
        exchange = Http1Exchange(run, 0, proxy=True)
        page = (
            b"GET http://origin.phantom.test:9/page?run=" + run.token.encode() + b" "
            b"HTTP/1.1\r\nHost: origin.phantom.test:9\r\n\r\n"
        )
        self.assertTrue(self.feed(exchange, page).startswith(b"HTTP/1.1 200 OK"))
        connect = b"CONNECT origin.phantom.test:443 HTTP/1.1\r\n"
        self.assertEqual(self.feed(exchange, connect + b"\r\n"), CHALLENGE)
        self.assertFalse(exchange.closing)
        response = self.feed(
            exchange, connect + proxy_field(PROXY_CREDENTIAL) + b"\r\n"
        )
        self.assertEqual(response, b"HTTP/1.1 200 Connection established\r\n\r\n")
        # The secure page's tunnel ends before any origin TLS.
        self.assertTrue(exchange.closing)
        self.assertEqual(self.feed(exchange, b"\x16\x03\x01"), b"")
        self.assertEqual(
            [(r.kind, r.status, r.proxy_authorization) for r in run.requests],
            [
                ("page", 200, "none"),
                ("https-connect", 407, "none"),
                ("https-connect", 200, "capture-credential"),
            ],
        )
        wss = Http1Exchange(run, 1, proxy=True)
        self.feed(
            wss,
            b"CONNECT origin.phantom.test:8443 HTTP/1.1\r\n"
            + proxy_field(PROXY_CREDENTIAL)
            + b"\r\n",
        )
        self.assertEqual(run.requests[-1].kind, "wss-connect")

    def test_probe_policy_challenges_only_the_probe_and_signals_ready(self) -> None:
        run = CaptureRun(
            "0123456789abcdef",
            "http-proxy-auth-remembered-hostname",
            proxy_credential=PROXY_CREDENTIAL,
        )
        exchange = Http1Exchange(run, 0, proxy=True)

        def request(path: bytes, credential: bytes | None = None) -> bytes:
            return self.feed(
                exchange,
                b"GET http://origin.phantom.test:9"
                + path
                + b"run="
                + run.token.encode()
                + b" HTTP/1.1\r\nHost: origin.phantom.test:9\r\n"
                + proxy_field(credential)
                + b"\r\n",
            )

        first = request(b"/page?")
        self.assertIn(b"fetch('/probe?run=", first)
        self.assertEqual(request(b"/probe?"), CHALLENGE)
        self.assertTrue(
            request(b"/probe?", PROXY_CREDENTIAL).startswith(b"HTTP/1.1 204 ")
        )
        self.assertFalse(run.ready.is_set())
        request(b"/ready?", PROXY_CREDENTIAL)
        self.assertTrue(run.ready.is_set())
        second = request(b"/page?step=2&", PROXY_CREDENTIAL)
        self.assertIn(b"fetch('/done?run=", second)
        self.assertEqual(
            [(r.kind, r.status, r.proxy_authorization) for r in run.requests],
            [
                ("page", 200, "none"),
                ("probe", 407, "none"),
                ("probe", 204, "capture-credential"),
                ("ready", 204, "capture-credential"),
                ("page", 200, "capture-credential"),
            ],
        )

    def test_secure_page_opens_an_https_fetch_then_a_wss_socket(self) -> None:
        page = (
            CaptureRun("0123456789abcdef", "https-proxy-secure-hostname")
            .page()
            .decode()
        )
        self.assertIn("fetch('https://origin.phantom.test:443/tls?run=", page)
        self.assertIn("new WebSocket('wss://origin.phantom.test:8443/tls?run=", page)
        self.assertLess(page.index("https://"), page.index("wss://"))

    def test_nostore_page_fetches_the_probe_then_done_without_cache(self) -> None:
        page = (
            CaptureRun("0123456789abcdef", "http-proxy-auth-nostore-hostname")
            .page()
            .decode()
        )
        self.assertIn("fetch('/probe?run=0123456789abcdef', {cache: 'no-store'})", page)
        self.assertIn("{cache: 'no-store'}));", page)
        self.assertEqual(
            SCENARIOS["http-proxy-auth-nostore-hostname"].challenge, "probe"
        )

    def test_auth_page_opens_two_websockets_in_turn(self) -> None:
        page = auth_run().page().decode()
        self.assertIn("open(0);", page)
        self.assertIn("if (index + 1 < 2) open(index + 1); else done();", page)
        plain = CaptureRun("0123456789abcdef", "http-proxy-hostname").page().decode()
        self.assertNotIn("open(", plain)


class LaunchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = CaptureServer(CERTIFICATE)
        self.server.addresses = {
            "origin": ("127.0.0.1", 1001),
            "http-proxy": ("127.0.0.1", 1002),
            "https-proxy": ("127.0.0.1", 1003),
        }

    def chromium(self, scenario: str) -> list[str]:
        plan = launch_plan(
            "chrome",
            Path("chrome.exe"),
            True,
            SCENARIOS[scenario],
            self.server,
            CERTIFICATE,
        )
        return launch_arguments(plan, Path("<temporary-profile>"), "http://x/")

    def test_chromium_proxy_launch_drops_the_direct_flag(self) -> None:
        direct = self.chromium("direct-loopback")
        self.assertIn(DIRECT_FLAG, direct)
        self.assertFalse(any(a.startswith("--proxy-server=") for a in direct))
        http = self.chromium("http-proxy-loopback")
        self.assertNotIn(DIRECT_FLAG, http)
        self.assertIn("--proxy-server=http://127.0.0.1:1002", http)
        self.assertIn("--proxy-bypass-list=<-loopback>", http)
        self.assertIn("--disable-field-trial-config", http)
        https = self.chromium("https-proxy-hostname")
        self.assertIn(f"--proxy-server=https://{PROXY_HOST}:1003", https)
        self.assertIn(
            "--ignore-certificate-errors-spki-list=" + CERTIFICATE.spki_sha256_base64,
            https,
        )

    def test_android_browser_without_switches_runs_only_the_direct_loopback_page(
        self,
    ) -> None:
        plan = launch_plan(
            "opera-android",
            Path("adb"),
            False,
            SCENARIOS["direct-loopback"],
            self.server,
            CERTIFICATE,
        )

        self.assertEqual(plan.browser, "opera-android")
        self.assertEqual(plan.extra_arguments, ())
        for name in ("direct-hostname", "http-proxy-loopback"):
            with self.assertRaises(ValueError):
                launch_plan(
                    "opera-android",
                    Path("adb"),
                    False,
                    SCENARIOS[name],
                    self.server,
                    CERTIFICATE,
                )

    def test_android_browsers_refuse_proxy_authentication_scenarios(self) -> None:
        for browser in ("chrome-android", "opera-android"):
            with self.subTest(browser=browser), self.assertRaises(ValueError):
                launch_plan(
                    browser,
                    Path("adb"),
                    False,
                    SCENARIOS["http-proxy-auth-loopback"],
                    self.server,
                    CERTIFICATE,
                )

    def test_firefox_tls_proxy_uses_pac_and_a_profile_override(self) -> None:
        plan = launch_plan(
            "firefox",
            Path("firefox.exe"),
            True,
            SCENARIOS["https-proxy-hostname"],
            self.server,
            CERTIFICATE,
        )
        preferences = dict(plan.firefox_preferences)
        self.assertEqual(preferences["network.proxy.type"], 2)
        self.assertIn(
            f"HTTPS {PROXY_HOST}:1003", preferences["network.proxy.autoconfig_url"]
        )
        self.assertIs(preferences["network.proxy.allow_hijacking_localhost"], True)
        [(name, text)] = plan.profile_files
        self.assertEqual(name, "cert_override.txt")
        self.assertIn(f"{PROXY_HOST}:1003:", text)
        self.assertIn(CERTIFICATE.sha256_fingerprint, text)

    def test_auth_launches_open_a_remote_port_on_a_blank_page(self) -> None:
        chrome = launch_plan(
            "chrome",
            Path("chrome.exe"),
            True,
            SCENARIOS["https-proxy-auth-hostname"],
            self.server,
            CERTIFICATE,
        )
        arguments = launch_arguments(
            chrome, Path("<temporary-profile>"), REMOTE_START_URL
        )
        self.assertIn(CHROMIUM_REMOTE_FLAG, arguments)
        self.assertEqual(arguments[-1], "about:blank")
        self.assertNotIn(DIRECT_FLAG, arguments)
        self.assertTrue(
            recorded_arguments(chrome, REMOTE_START_URL).endswith(
                "--remote-debugging-port=0 about:blank"
            )
        )
        firefox = launch_plan(
            "firefox",
            Path("firefox.exe"),
            True,
            SCENARIOS["http-proxy-auth-loopback"],
            self.server,
            CERTIFICATE,
        )
        self.assertEqual(firefox.extra_arguments, FIREFOX_REMOTE_ARGUMENTS)
        self.assertIs(
            dict(firefox.firefox_preferences)["remote.prefs.recommended"], False
        )
        plain = self.chromium("https-proxy-hostname")
        self.assertNotIn(CHROMIUM_REMOTE_FLAG, plain)

    def test_firefox_http_proxy_uses_manual_settings(self) -> None:
        plan = launch_plan(
            "firefox",
            Path("firefox.exe"),
            True,
            SCENARIOS["http-proxy-loopback"],
            self.server,
            CERTIFICATE,
        )
        preferences = dict(plan.firefox_preferences)
        self.assertEqual(preferences["network.proxy.type"], 1)
        self.assertEqual(preferences["network.proxy.http"], "127.0.0.1")
        self.assertEqual(preferences["network.proxy.http_port"], 1002)
        self.assertEqual(plan.profile_files, ())

    def test_firefox_secure_page_also_sets_the_ssl_proxy(self) -> None:
        def preferences(scenario: str) -> dict[str, object]:
            plan = launch_plan(
                "firefox",
                Path("firefox.exe"),
                True,
                SCENARIOS[scenario],
                self.server,
                CERTIFICATE,
            )
            return dict(plan.firefox_preferences)

        secure = preferences("http-proxy-auth-secure-hostname")
        self.assertEqual(secure["network.proxy.ssl"], "127.0.0.1")
        self.assertEqual(secure["network.proxy.ssl_port"], 1002)
        self.assertNotIn("network.proxy.ssl", preferences("http-proxy-hostname"))

    def test_cli_rejects_non_loopback_listener(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            main(
                [
                    "--browser",
                    "manual",
                    "--client-version",
                    "0",
                    "--listen",
                    "192.0.2.1",
                    "--output-dir",
                    "unused",
                ]
            )


if __name__ == "__main__":
    unittest.main()
