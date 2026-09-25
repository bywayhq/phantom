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
    DIRECT_FLAG,
    FORMAT,
    PROXY_HOST,
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
        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        exchange = Http1Exchange(run, 0)
        exchange.feed(
            b"GET http://origin.phantom.test:9/x HTTP/1.1\r\n"
            b"Host: origin.phantom.test:9\r\nProxy-Authorization: Basic eDp5\r\n\r\n"
        )
        with self.assertRaises(ValueError):
            fixture("http-proxy-hostname", "page", [run], METADATA)

    def test_listener_rejects_non_loopback_address(self) -> None:
        with self.assertRaises(ValueError):
            asyncio.run(CaptureServer(CERTIFICATE).start("0.0.0.0"))


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
