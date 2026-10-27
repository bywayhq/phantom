"""WebSocket traffic against websockets and h2 peers, independent of Phantom."""

import asyncio
import socket
import ssl
import threading
import unittest
from contextlib import contextmanager

from phantom_http import (
    AsyncClient,
    AsyncResponse,
    Client,
    Response,
    TimeoutError,
    Trust,
    WebSocketClosed,
    WebSocketError,
    WebSocketLimits,
    WebSocketPing,
    WebSocketRetry,
)
from test_http2 import H2Peer
from test_settings_transport import FIXTURES, ROOT
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response as PeerResponse
from websockets.sync.server import serve

PROFILE = "chrome-154-windows"


@contextmanager
def stalled_handshake():
    started = threading.Event()
    disconnected = threading.Event()
    errors = []
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(5)

        def run():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    headers = bytearray()
                    while not headers.endswith(b"\r\n\r\n"):
                        data = connection.recv(1)
                        if not data or len(headers) >= 65536:
                            raise AssertionError("opening headers were not completed")
                        headers.extend(data)
                    started.set()
                    try:
                        if connection.recv(1):
                            raise AssertionError(
                                "unexpected data before handshake response"
                            )
                    except (ConnectionAbortedError, ConnectionResetError):
                        pass
                    disconnected.set()
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        try:
            yield f"ws://127.0.0.1:{listener.getsockname()[1]}", started, disconnected
        finally:
            worker.join(6)
            if worker.is_alive():
                raise AssertionError("stalled handshake peer did not stop")
            if errors:
                raise errors[0]


@contextmanager
def peer(handler, *, tls=False, process_request=None):
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(FIXTURES / "certificate.pem", FIXTURES / "key.pem")
    errors = []
    finished = threading.Event()

    def run(connection):
        try:
            handler(connection)
        except ConnectionClosed:
            # Cancellation deliberately ends its own connection without Close.
            pass
        except Exception as error:
            errors.append(error)
        finally:
            finished.set()

    with serve(
        run,
        "127.0.0.1",
        0,
        ssl=context,
        compression=None,
        ping_interval=None,
        close_timeout=1,
        process_request=process_request,
    ) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield (
                f"{'wss' if tls else 'ws'}://127.0.0.1:{server.socket.getsockname()[1]}",
                finished,
            )
        finally:
            server.shutdown()
            worker.join(5)
            if worker.is_alive():
                raise AssertionError("WebSocket peer did not stop")
            if process_request is None and not finished.wait(6):
                raise AssertionError("WebSocket peer handler did not stop")
            if errors:
                raise errors[0]


class WebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_opening_and_handshake_timeout_release_the_transport(self):
        for operation in ("cancel", "timeout"):
            with (
                self.subTest(operation=operation),
                stalled_handshake() as (url, started, disconnected),
            ):
                async with AsyncClient(profile=PROFILE, context="raw") as client:
                    opening = asyncio.ensure_future(
                        client.websocket(
                            url,
                            protocol="h1",
                            handshake_timeout_ms=None if operation == "cancel" else 500,
                        )
                    )
                    self.assertTrue(await asyncio.to_thread(started.wait, 5))
                    if operation == "cancel":
                        opening.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await opening
                    else:
                        with self.assertRaises(TimeoutError) as failure:
                            await opening
                        self.assertEqual(
                            failure.exception.timeout_phase, "websocket_handshake"
                        )
                    self.assertTrue(await asyncio.to_thread(disconnected.wait, 5))

    async def test_zero_handshake_timeout_rejects_before_opening(self):
        openings = []

        def observe(connection, request):
            openings.append(request.path)
            return connection.respond(400, "unexpected opening")

        with peer(lambda _: None, process_request=observe) as (url, _):
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                with self.assertRaisesRegex(ValueError, "positive"):
                    client.websocket(url, handshake_timeout_ms=0)
        self.assertEqual(openings, [])

    async def test_graceful_close_shares_a_pending_reader_and_sends_empty_close(self):
        observed = []

        def wait_for_close(connection):
            try:
                connection.recv(timeout=5)
            except ConnectionClosed as closed:
                observed.append(closed.rcvd.code)

        with peer(wait_for_close) as (url, finished):
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                socket = await client.websocket(url)
                reading = asyncio.create_task(socket.recv())
                # Let recv acquire the single reader before close starts.
                await asyncio.sleep(0)
                await socket.aclose(None, timeout_ms=5000)
                with self.assertRaises(WebSocketClosed) as closed:
                    await reading
                self.assertIsNone(closed.exception.code)
                self.assertTrue(socket.is_closed)
                self.assertTrue(await asyncio.to_thread(finished.wait, 5))
        self.assertEqual(observed, [1005])

    async def test_setup_retries_do_not_retry_an_http_rejection(self):
        attempts = []

        def reject(connection, request):
            attempts.append(request.path)
            return connection.respond(403, "denied")

        with peer(lambda _: None, process_request=reject) as (url, _):
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                with self.assertRaises(WebSocketError) as failure:
                    await client.websocket(
                        url, retry=WebSocketRetry(maximum=2, delay_ms=1)
                    )
                response = failure.exception.response
                self.assertIsNotNone(response)
                await response.read(max_bytes=6)
        self.assertEqual(attempts, ["/"])

    async def test_verified_tls_profile_handshake_text_binary_and_ordered_headers(self):
        observed = []

        def echo(connection):
            observed.append(list(connection.request.headers.raw_items()))
            connection.send(connection.recv(timeout=5))
            connection.send(connection.recv(timeout=5))
            connection.close(1000, "done")

        with peer(echo, tls=True) as (url, finished):
            async with (
                AsyncClient(
                    profile=PROFILE, context="raw", trust=Trust(roots=(ROOT,))
                ) as client,
                client.websocket(
                    url,
                    headers=[("X-Ordered", "first"), ("X-Ordered", "second")],
                    handshake_timeout_ms=5000,
                ) as socket,
            ):
                self.assertEqual((socket.status, socket.protocol), (101, "h1"))
                await socket.send("héllo")
                self.assertEqual(await socket.recv(), "héllo")
                await socket.send(b"\x00\xff")
                self.assertEqual(await socket.recv(), b"\x00\xff")
                with self.assertRaises(WebSocketClosed) as closed:
                    await socket.recv()
                self.assertEqual(
                    (closed.exception.code, closed.exception.reason), (1000, "done")
                )
            self.assertTrue(await asyncio.to_thread(finished.wait, 5))
        self.assertEqual(
            [value for name, value in observed[0] if name.lower() == "x-ordered"],
            ["first", "second"],
        )

    async def test_pending_receive_allows_send_and_automatic_pong(self):
        pong_received = threading.Event()

        def exchange(connection):
            waiter = connection.ping(b"probe")
            connection.send("ready")
            if not waiter.wait(5):
                raise AssertionError("Phantom did not answer Ping")
            pong_received.set()
            connection.send(connection.recv(timeout=5))

        with peer(exchange) as (url, _):
            async with (
                AsyncClient(profile=PROFILE, context="raw") as client,
                client.websocket(url, protocol="h1") as socket,
            ):
                self.assertEqual(await socket.receive(), WebSocketPing(b"probe"))
                self.assertEqual(await socket.recv(), "ready")
                self.assertTrue(await asyncio.to_thread(pong_received.wait, 5))
                waiting = asyncio.create_task(socket.recv())
                await asyncio.sleep(0)
                with self.assertRaises(WebSocketError) as concurrent:
                    await socket.receive()
                self.assertEqual(concurrent.exception.kind, "concurrent_receive")
                self.assertFalse(socket.is_closed)
                await socket.send("unblock")
                self.assertEqual(await asyncio.wait_for(waiting, 5), "unblock")

    async def test_message_limit_rejects_before_another_message_is_sent(self):
        received = []

        def echo(connection):
            received.append(connection.recv(timeout=5))
            connection.send(received[-1])

        with peer(echo) as (url, _):
            async with (
                AsyncClient(profile=PROFILE, context="raw") as client,
                client.websocket(
                    url, limits=WebSocketLimits(4, 4), protocol="h1"
                ) as socket,
            ):
                with self.assertRaises(WebSocketError) as overflow:
                    await socket.send(b"12345")
                self.assertEqual(overflow.exception.kind, "capacity")
                await socket.send(b"1234")
                self.assertEqual(await socket.recv(), b"1234")
        self.assertEqual(received, [b"1234"])

    async def test_incoming_message_limit_ends_only_the_owned_socket(self):
        def oversized(connection):
            connection.send(b"12345")

        with peer(oversized) as (url, _):
            async with (
                AsyncClient(profile=PROFILE, context="raw") as client,
                client.websocket(url, limits=WebSocketLimits(4, 4)) as socket,
            ):
                with self.assertRaises(WebSocketError) as overflow:
                    await socket.recv()
                self.assertEqual(overflow.exception.kind, "capacity")
                self.assertTrue(socket.is_closed)

    async def test_cancel_receive_releases_h2_stream_and_keeps_shared_connection(self):
        with H2Peer(tls=True, websocket=True) as server:
            async with AsyncClient(
                profile=PROFILE,
                context="raw",
                trust=Trust(roots=(ROOT,)),
                timeout_ms=5000,
            ) as client:
                first = await client.get(server.url + "/first")
                self.assertEqual(await first.read(max_bytes=5), b"hello")
                socket = await client.websocket(
                    server.url.replace("https:", "wss:") + "/events", protocol="profile"
                )
                self.assertEqual(socket.protocol, "h2")
                waiting = asyncio.create_task(socket.recv())
                healthy = await client.get(server.url + "/healthy")
                reading = asyncio.create_task(healthy.read(max_bytes=5))
                waiting.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await waiting
                self.assertTrue(await asyncio.to_thread(server.reset.wait, 5))
                self.assertEqual(server.reset_stream, server.websocket_stream)
                self.assertEqual(server.reset_code, 8)
                self.assertEqual(await asyncio.wait_for(reading, 5), b"hello")
                after = await client.get(server.url + "/after")
                self.assertEqual(await after.read(max_bytes=5), b"hello")
        self.assertFalse(server.premature_close)

    async def test_rejected_handshake_keeps_a_bounded_readable_response(self):
        def reject(_, request):
            return PeerResponse(
                403, "Forbidden", Headers({"Content-Length": "6"}), b"denied"
            )

        with peer(lambda _: None, process_request=reject) as (url, _):
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                with self.assertRaises(WebSocketError) as failure:
                    await client.websocket(url, protocol="h1")
                self.assertEqual(failure.exception.kind, "handshake_rejected")
                response = failure.exception.response
                self.assertIsInstance(response, AsyncResponse)
                self.assertEqual(response.status, 403)
                self.assertEqual(await response.read(max_bytes=6), b"denied")


class SyncWebSocketTests(unittest.TestCase):
    def test_sync_context_text_binary_and_close(self):
        def echo(connection):
            connection.send(connection.recv(timeout=5))

        with peer(echo) as (url, finished):
            with Client(profile=PROFILE, context="raw") as client:
                with client.websocket(url) as socket:
                    socket.send("hello")
                    self.assertEqual(socket.recv(), "hello")
                self.assertTrue(socket.is_closed)
            self.assertTrue(finished.wait(5))

    def test_sync_handshake_rejection_owns_a_sync_response(self):
        def reject(_, request):
            return PeerResponse(
                403, "Forbidden", Headers({"Content-Length": "6"}), b"denied"
            )

        with (
            peer(lambda _: None, process_request=reject) as (url, _),
            Client(profile=PROFILE, context="raw") as client,
        ):
            with self.assertRaises(WebSocketError) as failure:
                client.websocket(url)
            response = failure.exception.response
            self.assertIsInstance(response, Response)
            self.assertEqual(response.read(max_bytes=6), b"denied")
