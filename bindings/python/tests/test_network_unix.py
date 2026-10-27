"""Fixed native Unix sockets preserve HTTP identity and stream ownership."""

import asyncio
import contextlib
import os
import socket
import socketserver
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from phantom_http import (
    AsyncClient,
    Client,
    Error,
    HostOverride,
    NetworkOptions,
    SessionSnapshotError,
    TimeoutOverrides,
    Trust,
    _native,
)
from test_http2 import H2Peer
from test_settings_transport import (
    FIXTURES,
    PROFILE,
    ROOT,
    SettingsHandler,
    SettingsPeer,
    peer,
)


class UnixPeer(SettingsPeer):
    """Reuse the owned HTTP handler lifecycle over an actual Unix listener."""

    address_family = getattr(socket, "AF_UNIX", socket.AF_INET)
    server_bind = socketserver.TCPServer.server_bind

    def __init__(self, path, *, tls=False):
        self.requests = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.disconnected = threading.Event()
        self.basic_auth = False
        self.errors = []
        self.request_workers = []
        self.client_certificates = []
        self.accepted = 0
        self.server_names = []
        socketserver.TCPServer.__init__(self, str(path), SettingsHandler)
        self.url = "http://unresolved.invalid:4321"
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(FIXTURES / "certificate.pem", FIXTURES / "key.pem")
            context.set_alpn_protocols(["http/1.1"])
            context.set_servername_callback(
                lambda _socket, name, _context: self.server_names.append(name)
            )
            self.socket = context.wrap_socket(self.socket, server_side=True)
            self.url = "https://localhost"

    def get_request(self):
        stream, _ = super().get_request()
        self.accepted += 1
        return stream, self.accepted


@contextlib.contextmanager
def unix_peer(path, **options):
    server = UnixPeer(path, **options)
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
        deadline = time.monotonic() + 5
        for handler in server.request_workers:
            handler.join(max(0, deadline - time.monotonic()))
        if worker.is_alive() or any(
            handler.is_alive() for handler in server.request_workers
        ):
            raise AssertionError("Unix HTTP peer did not settle")
        if server.errors:
            raise AssertionError(server.errors)


class NativeUnixValidationTests(unittest.TestCase):
    def test_native_path_validation_is_independent_and_redacted(self):
        for invalid in (
            {"unix_socket": ""},
            {"public_only": None},
            {"unix_socket": b"private"},
            {"unix_socket": "private\x00path"},
            {"unix_socket": "private\ud800"},
            {"interface": "x", "unix_socket": "é" * 32768},
            {"unix_socket": "private", "public_only": "extra"},
        ):
            fields = SimpleNamespace(
                host_overrides=(),
                local_addresses=(),
                interface=None,
                unix_socket=None,
                public_only=False,
            )
            fields.__dict__.update(invalid)
            with (
                self.subTest(fields=tuple(invalid)),
                self.assertRaises(_native.NativeError) as caught,
            ):
                _native.NativeClient(PROFILE, "h1", network=fields)
            self.assertEqual(caught.exception.args[0], "input")
            self.assertNotIn("private", str(caught.exception))

    if os.name != "posix":

        def test_unsupported_platform_is_typed_before_any_connection(self):
            with self.assertRaises(Error) as caught:
                Client(
                    profile=PROFILE,
                    protocol="h1",
                    network=NetworkOptions(unix_socket="/private/socket"),
                )
            self.assertEqual(
                (caught.exception.category, caught.exception.kind),
                ("input", "unsupported_platform"),
            )
            self.assertNotIn("private", str(caught.exception))


if os.name == "posix":

    class UnixClientTests(unittest.TestCase):
        def test_authority_order_reuse_fork_and_checkpoint_rejection(self):
            with tempfile.TemporaryDirectory(prefix="phu-", dir="/tmp") as temporary:
                path = Path(temporary) / "s"
                with unix_peer(path) as origin:
                    with Client(
                        profile=PROFILE,
                        protocol="h1",
                        context="raw",
                        timeout_ms=5000,
                        network=NetworkOptions(unix_socket=str(path)),
                    ) as client:
                        for _ in range(2):
                            with client.request(
                                "GET",
                                origin.url + "/path",
                                headers=[
                                    ("X-A", b"one"),
                                    ("X-B", b"middle"),
                                    ("X-A", b"last"),
                                ],
                            ) as response:
                                self.assertEqual(response.read(max_bytes=5), b"hello")
                        self.assertEqual(origin.accepted, 1)
                        key = b"x" * 32
                        with Client(profile=PROFILE, protocol="h1") as direct:
                            snapshot = direct.export_session(key)
                        for operation in (
                            lambda: client.export_session(key),
                            lambda: client.restore_session(snapshot, key),
                        ):
                            with self.assertRaises(SessionSnapshotError) as caught:
                                operation()
                            self.assertEqual(caught.exception.kind, "unsupported")
                        with client.fork() as child:
                            client.close()
                            with child.request("GET", origin.url + "/fork") as response:
                                self.assertEqual(response.read(max_bytes=5), b"hello")
                        with (
                            client.fork() as after_close,
                            after_close.request(
                                "GET", origin.url + "/closed-fork"
                            ) as response,
                        ):
                            self.assertEqual(response.read(max_bytes=5), b"hello")
                    self.assertEqual(origin.accepted, 3)
                    self.assertEqual(
                        [row[0] for row in origin.requests],
                        ["/path", "/path", "/fork", "/closed-fork"],
                    )
                    for _, _, headers, _ in origin.requests[:2]:
                        self.assertEqual(
                            dict(headers)["Host"], "unresolved.invalid:4321"
                        )
                        self.assertEqual(
                            [
                                (name, value)
                                for name, value in headers
                                if name.startswith("X-")
                            ],
                            [("X-A", "one"), ("X-B", "middle"), ("X-A", "last")],
                        )

        def test_verified_tls_keeps_sni_and_host_and_rejects_wrong_identity(self):
            for failure in (None, "hostname", "trust"):
                with (
                    self.subTest(failure=failure),
                    tempfile.TemporaryDirectory(prefix="phu-", dir="/tmp") as temporary,
                ):
                    path = Path(temporary) / "s"
                    with unix_peer(path, tls=True) as origin:
                        with Client(
                            profile=PROFILE,
                            protocol="h1",
                            context="raw",
                            timeout_ms=5000,
                            trust=Trust(roots=(ROOT,)) if failure != "trust" else None,
                            network=NetworkOptions(unix_socket=str(path)),
                        ) as client:
                            url = (
                                "https://wrong.invalid/"
                                if failure == "hostname"
                                else origin.url + "/tls"
                            )
                            if failure is not None:
                                with self.assertRaises(Error) as caught:
                                    client.request("GET", url)
                                self.assertEqual(caught.exception.kind, "tls")
                            else:
                                with client.request("GET", url) as response:
                                    self.assertEqual(
                                        response.read(max_bytes=5), b"hello"
                                    )
                                self.assertEqual(
                                    dict(origin.requests[0][2])["Host"], "localhost"
                                )
                        self.assertEqual(
                            origin.server_names,
                            ["wrong.invalid" if failure == "hostname" else "localhost"],
                        )
                        self.assertEqual(
                            len(origin.requests), 0 if failure is not None else 1
                        )

        def test_missing_socket_does_not_fall_back_to_tcp_and_conflicts_reject(self):
            with tempfile.TemporaryDirectory(prefix="phu-", dir="/tmp") as temporary:
                path = str(Path(temporary) / "missing")
                with peer() as tcp:
                    with Client(
                        profile=PROFILE,
                        protocol="h1",
                        timeout_ms=5000,
                        network=NetworkOptions(unix_socket=path),
                    ) as client:
                        with self.assertRaises(Error) as caught:
                            client.request("GET", tcp.url)
                        self.assertEqual(caught.exception.kind, "connect")
                        self.assertNotIn(path, str(caught.exception))
                    self.assertEqual(tcp.requests, [])
                for network, proxy in (
                    (
                        NetworkOptions(
                            unix_socket=path, local_addresses=("127.0.0.1",)
                        ),
                        None,
                    ),
                    (NetworkOptions(unix_socket=path, interface="lo"), None),
                    (
                        NetworkOptions(
                            unix_socket=path,
                            host_overrides=(HostOverride("host.invalid"),),
                        ),
                        None,
                    ),
                    (NetworkOptions(unix_socket=path), "http://127.0.0.1:9"),
                ):
                    with (
                        self.subTest(network=network),
                        self.assertRaises(Error) as caught,
                    ):
                        Client(
                            profile=PROFILE, protocol="h1", network=network, proxy=proxy
                        )
                    self.assertEqual(
                        caught.exception.kind, "invalid_client_configuration"
                    )
                with Client(
                    profile=PROFILE,
                    protocol="h3",
                    network=NetworkOptions(unix_socket=path),
                ) as client:
                    with self.assertRaises(Error) as caught:
                        client.request("GET", "https://localhost/")
                    self.assertEqual(caught.exception.kind, "protocol_unavailable")

    class AsyncUnixClientTests(unittest.IsolatedAsyncioTestCase):
        async def test_verified_h2_body_cancellation_preserves_live_sibling_and_connection(
            self,
        ):
            with tempfile.TemporaryDirectory(prefix="phu-", dir="/tmp") as temporary:
                path = Path(temporary) / "s"
                with H2Peer(tls=True, socket_path=path) as origin:
                    names = []
                    origin.tls.set_servername_callback(
                        lambda _socket, name, _context: names.append(name)
                    )
                    async with AsyncClient(
                        profile=PROFILE,
                        protocol="h2",
                        context="raw",
                        timeout_ms=5000,
                        trust=Trust(roots=(ROOT,)),
                        network=NetworkOptions(unix_socket=str(path)),
                    ) as client:
                        selected = await client.request(
                            "GET",
                            origin.url + "/stall",
                            timeouts=TimeoutOverrides(
                                total=None, connect=5, response_head=5
                            ),
                        )
                        async with selected:
                            self.assertEqual(await selected.read_chunk(1), b"a")
                            healthy = await client.request(
                                "GET",
                                origin.url + "/healthy",
                                timeouts=TimeoutOverrides(
                                    total=None, connect=5, response_head=5
                                ),
                            )
                            async with healthy:
                                reading = asyncio.create_task(
                                    selected.read(max_bytes=5)
                                )
                                await asyncio.sleep(0)
                                reading.cancel()
                                with self.assertRaises(asyncio.CancelledError):
                                    await reading
                                self.assertTrue(
                                    await asyncio.to_thread(origin.reset.wait, 5)
                                )
                                self.assertEqual(origin.reset_code, 8)
                                self.assertEqual(
                                    origin.reset_stream, origin.requests[0][0]
                                )
                                self.assertEqual(
                                    await healthy.read(max_bytes=5), b"hello"
                                )
                            async with await client.request(
                                "GET", origin.url + "/reuse"
                            ) as reused:
                                self.assertEqual(
                                    await reused.read(max_bytes=5), b"hello"
                                )
                        self.assertEqual(
                            [row[1] for row in origin.requests],
                            [b"/stall", b"/healthy", b"/reuse"],
                        )
                        self.assertEqual(len({row[0] for row in origin.requests}), 3)
                        self.assertTrue(
                            all(
                                dict(headers)[b":authority"] == b"localhost"
                                for headers in origin.headers
                            )
                        )
                    self.assertEqual(names, ["localhost"])
                self.assertFalse(origin.premature_close)
