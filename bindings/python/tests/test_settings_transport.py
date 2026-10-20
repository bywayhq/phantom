"""Settings exercised through public clients and independent loopback peers."""

import asyncio
import contextlib
import http.server
import socket
import ssl
import sys
import threading
import traceback
import unittest
from pathlib import Path

from phantom_http import (
    AsyncClient,
    Client,
    Error,
    Header,
    Proxy,
    TimeoutError,
    TimeoutOverrides,
    Timeouts,
    Trust,
)

PROFILE = "chrome/154.0.8037.97/windows-11-26200/r1"
FIXTURES = Path(__file__).with_name("fixtures")
ROOT = (FIXTURES / "certificate.der").read_bytes()


class SettingsPeer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *, tls=False, basic_auth=False):
        super().__init__(("127.0.0.1", 0), SettingsHandler)
        self.requests = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.disconnected = threading.Event()
        self.basic_auth = basic_auth
        self.errors = []
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(FIXTURES / "certificate.pem", FIXTURES / "key.pem")
            self.socket = context.wrap_socket(self.socket, server_side=True)
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.server_port}"

    def handle_error(self, *_):
        error = sys.exc_info()[1]
        if isinstance(
            error, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)
        ):
            self.disconnected.set()
            return
        self.errors.append(traceback.format_exc())


class SettingsHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests.append(
            (
                self.path,
                self.client_address,
                list(self.headers.raw_items()),
                getattr(self.connection, "session_reused", None),
            )
        )
        try:
            if (
                self.server.basic_auth
                and self.headers.get("Proxy-Authorization") != "Basic dXNlcjpwYXNz"
            ):
                self.send_response(407)
                self.send_header("Proxy-Authenticate", 'Basic realm="loopback"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/head":
                self.server.entered.set()
                if not self.server.release.wait(5):
                    raise AssertionError("response-head test was not released")
            body = b"ab" if self.path == "/live" else b"hello"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[:1] if self.path in ("/live", "/idle") else body)
            self.wfile.flush()
            if self.path == "/live":
                self.server.entered.set()
                if not self.server.release.wait(5):
                    raise AssertionError("live response was not released")
                self.wfile.write(body[1:])
                self.wfile.flush()
            elif self.path == "/idle":
                self.server.entered.set()
                self.connection.settimeout(5)
                if self.connection.recv(1):
                    raise AssertionError("unexpected bytes after stalled response")
                self.server.disconnected.set()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.server.disconnected.set()


@contextlib.contextmanager
def peer(**options):
    server = SettingsPeer(**options)
    worker = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    worker.start()
    try:
        yield server
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()
        worker.join(5)
        if worker.is_alive():
            raise AssertionError("settings peer did not stop")
        if server.errors:
            raise AssertionError(server.errors)


class PeerFailureTests(unittest.TestCase):
    def test_expected_disconnects_outside_the_handler_are_retained_as_disconnects(self):
        for kind in (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            with self.subTest(kind=kind.__name__):
                server = SettingsPeer()
                try:
                    try:
                        raise kind("peer disconnected")
                    except kind:
                        server.handle_error()
                    self.assertTrue(server.disconnected.is_set())
                    self.assertEqual(server.errors, [])
                finally:
                    server.server_close()

    def test_unexpected_handler_errors_retain_their_traceback(self):
        server = SettingsPeer()
        try:
            try:
                raise RuntimeError("unexpected test failure")
            except RuntimeError:
                server.handle_error()
            self.assertFalse(server.disconnected.is_set())
            self.assertEqual(len(server.errors), 1)
            self.assertIn("Traceback (most recent call last)", server.errors[0])
            self.assertIn("RuntimeError: unexpected test failure", server.errors[0])
        finally:
            server.server_close()


class ClientSettingsTests(unittest.TestCase):
    def test_base_url_ordered_headers_and_idle_pool_controls(self):
        with (
            peer() as server,
            Client(
                profile=PROFILE, protocol="h1", base_url=server.url + "/api/"
            ) as client,
        ):
            for path in ("child?x=1", "/root"):
                with client.request(
                    "GET",
                    path,
                    headers=[
                        ("X-Duplicate", "one"),
                        Header("X-Secret", b"private", True),
                        ("X-Duplicate", b"two"),
                    ],
                ) as response:
                    self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(
                [row[0] for row in server.requests], ["/api/child?x=1", "/root"]
            )
            self.assertEqual(server.requests[0][1], server.requests[1][1])
            self.assertEqual(
                [
                    (name.lower(), value)
                    for name, value in server.requests[0][2]
                    if name.lower().startswith("x-")
                ],
                [
                    ("x-duplicate", "one"),
                    ("x-secret", "private"),
                    ("x-duplicate", "two"),
                ],
            )
            client.close_idle_connections()
            with client.request("GET", "next") as response:
                self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertNotEqual(server.requests[1][1], server.requests[2][1])
            client.clear_dns_cache()
            client.clear_client_hints()
            client.clear_alt_svc()
            client.clear_alt_svc_racing_history()
            self.assertEqual(client.clear_session_tickets(), 0)

    def test_origin_roots_verify_and_tickets_survive_refresh_until_cleared(self):
        with peer(tls=True) as server:
            with Client(profile=PROFILE, protocol="h1", timeout_ms=2000) as client:
                with self.assertRaises(Error) as failure:
                    client.request("GET", server.url)
                self.assertEqual(failure.exception.kind, "tls")
            with Client(
                profile=PROFILE,
                protocol="h1",
                trust=Trust(roots=(ROOT,)),
                timeout_ms=2000,
            ) as client:
                for index in range(3):
                    with client.request("GET", server.url) as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    if index == 0:
                        client.refresh_connections()
                    elif index == 1:
                        self.assertGreater(client.clear_session_tickets(), 0)
                        client.refresh_connections()
                self.assertEqual(
                    [row[3] for row in server.requests], [False, True, False]
                )
                self.assertEqual(len({row[1] for row in server.requests}), 3)
        with self.assertRaises(Error) as failure:
            Client(profile=PROFILE, protocol="h1", trust=Trust(roots=(b"not DER",)))
        self.assertEqual(failure.exception.kind, "invalid_client_configuration")

    def test_https_proxy_roots_and_basic_auth_are_separate_from_origin_roots(self):
        with peer(tls=True, basic_auth=True) as server:
            proxy = Proxy(server.url, "user", "pass")
            for trust in (Trust(), Trust(roots=(ROOT,))):
                with (
                    Client(
                        profile=PROFILE,
                        protocol="h1",
                        proxy=proxy,
                        trust=trust,
                        timeout_ms=2000,
                    ) as client,
                    self.assertRaises(Error),
                ):
                    client.request("GET", "http://origin.invalid/path")
            with (
                Client(
                    profile=PROFILE,
                    protocol="h1",
                    proxy=proxy,
                    trust=Trust(proxy_roots=(ROOT,)),
                    timeout_ms=2000,
                ) as client,
                client.request("GET", "http://origin.invalid/path") as response,
            ):
                self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(
                [row[0] for row in server.requests],
                [
                    "http://origin.invalid/path",
                    "http://origin.invalid/path",
                ],
            )
            self.assertIsNone(dict(server.requests[0][2]).get("Proxy-Authorization"))
            self.assertEqual(
                dict(server.requests[1][2])["Proxy-Authorization"], "Basic dXNlcjpwYXNz"
            )
            self.assertEqual(server.requests[0][1], server.requests[1][1])

    def test_explicit_socks5_credentials_and_remote_destination(self):
        for password, success in (("pass", True), ("wrong", False)):
            with (
                self.subTest(success=success),
                SocksPeer() as server,
                Client(
                    profile=PROFILE,
                    protocol="h1",
                    timeout_ms=2000,
                    proxy=Proxy(server.url, "user", password),
                ) as client,
            ):
                if success:
                    with client.request(
                        "GET", "http://origin.invalid/path"
                    ) as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                else:
                    with self.assertRaises(Error) as failure:
                        client.request("GET", "http://origin.invalid/path")
                    self.assertEqual(failure.exception.kind, "proxy")
                    self.assertNotIn(password, str(failure.exception))
            self.assertEqual(server.credentials, (b"user", password.encode()))
            self.assertEqual(
                server.destination, (b"origin.invalid", 80) if success else None
            )

    def test_invalid_base_url_and_proxy_credentials_are_rejected(self):
        for options in (
            {"base_url": "relative/path"},
            {"proxy": "http://user:secret@127.0.0.1:1"},
            {"proxy": Proxy("socks4://127.0.0.1:1", "user", "secret")},
            {"proxy": Proxy("socks5h://127.0.0.1:1", "user", "")},
        ):
            with (
                self.subTest(options=tuple(options)),
                self.assertRaises(Error) as failure,
            ):
                Client(profile=PROFILE, protocol="h1", **options)
            self.assertNotIn("secret", str(failure.exception))


class SocksPeer:
    """One authenticated SOCKS5 exchange followed by an HTTP response."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(5)
        self.url = f"socks5h://127.0.0.1:{self.listener.getsockname()[1]}"
        self.credentials = None
        self.destination = None
        self.error = None
        self.worker = threading.Thread(target=self.run, daemon=True)

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, *_):
        self.worker.join(5)
        self.listener.close()
        if self.worker.is_alive():
            raise AssertionError("SOCKS5 peer did not stop")
        if self.error is not None:
            raise self.error

    def run(self):
        try:
            connection, _ = self.listener.accept()
            with connection:
                connection.settimeout(5)
                with connection.makefile("rb") as reader:

                    def exact(count):
                        value = reader.read(count)
                        if len(value) != count:
                            raise AssertionError("incomplete SOCKS5 exchange")
                        return value

                    version, count = exact(2)
                    if version != 5 or 2 not in exact(count):
                        raise AssertionError("username/password method was not offered")
                    connection.sendall(b"\x05\x02")
                    version, size = exact(2)
                    if version != 1:
                        raise AssertionError("unexpected authentication version")
                    username = exact(size)
                    password = exact(exact(1)[0])
                    self.credentials = username, password
                    accepted = self.credentials == (b"user", b"pass")
                    connection.sendall(b"\x01\x00" if accepted else b"\x01\x01")
                    if not accepted:
                        return
                    if exact(4) != b"\x05\x01\x00\x03":
                        raise AssertionError("expected remote hostname CONNECT")
                    hostname = exact(exact(1)[0])
                    self.destination = hostname, int.from_bytes(exact(2), "big")
                    connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                    size = 0
                    while line := reader.readline(8193):
                        size += len(line)
                        if size > 32768:
                            raise AssertionError("unbounded HTTP header block")
                        if line == b"\r\n":
                            break
                    else:
                        raise AssertionError("incomplete HTTP header block")
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                    )
        except Exception as error:
            self.error = error


class AsyncSettingsTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_inherits_disables_and_overrides_phase_timeouts(self):
        with peer() as server:
            async with AsyncClient(
                profile=PROFILE, protocol="h1", timeouts=Timeouts(response_head=0.05)
            ) as client:
                with self.assertRaises(TimeoutError) as failure:
                    await client.request("GET", server.url + "/head")
                self.assertEqual(failure.exception.timeout_phase, "response_head")
                self.assertTrue(server.entered.is_set())
                server.release.set()
                server.entered.clear()
                # The next held response uses a fresh peer so its gate cannot inherit release.
        with peer() as server:
            async with AsyncClient(
                profile=PROFILE, protocol="h1", timeouts=Timeouts(response_head=0.05)
            ) as client:
                pending = asyncio.create_task(
                    client.request(
                        "GET",
                        server.url + "/head",
                        timeouts=TimeoutOverrides(response_head=None),
                    )
                )
                try:
                    self.assertTrue(await asyncio.to_thread(server.entered.wait, 2))
                    done, _ = await asyncio.wait({pending}, timeout=0.15)
                    self.assertFalse(done)
                    server.release.set()
                    response = await asyncio.wait_for(pending, 2)
                    self.assertEqual(await response.read(max_bytes=5), b"hello")
                finally:
                    server.release.set()
                    if not pending.done():
                        pending.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await pending
                with self.assertRaises(TimeoutError) as failure:
                    await client.request(
                        "GET", server.url, timeouts=TimeoutOverrides(total=0)
                    )
                self.assertEqual(failure.exception.timeout_phase, "total")

    async def test_read_idle_timeout_and_refresh_preserve_unrelated_live_body(self):
        with peer() as server:
            async with AsyncClient(
                profile=PROFILE, protocol="h1", timeouts=Timeouts(read_idle=0.1)
            ) as client:
                response = await client.request("GET", server.url + "/idle")
                self.assertEqual(await response.read_chunk(1), b"h")
                with self.assertRaises(TimeoutError) as failure:
                    await response.read(max_bytes=10)
                self.assertEqual(failure.exception.timeout_phase, "read_idle")
                self.assertTrue(await asyncio.to_thread(server.disconnected.wait, 2))
        with peer() as server:
            async with AsyncClient(
                profile=PROFILE, protocol="h1", timeout_ms=2000
            ) as client:
                response = await client.request("GET", server.url + "/live")
                self.assertEqual(await response.read_chunk(1), b"a")
                await client.refresh_connections()
                healthy = await client.request("GET", server.url + "/healthy")
                self.assertEqual(await healthy.read(max_bytes=5), b"hello")
                self.assertNotEqual(server.requests[0][1], server.requests[1][1])
                server.release.set()
                self.assertEqual(await response.read(max_bytes=1), b"b")
