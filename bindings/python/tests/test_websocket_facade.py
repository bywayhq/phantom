"""WebSocket facade contracts without loading the extension."""

import asyncio
import threading
import unittest

from test_upload_errors import FACADE


class Socket:
    status = 101
    protocol = "h1"
    selected_protocol = "chat"
    headers = [("X-Reply", b"one", False), ("X-Reply", b"two", False)]

    def __init__(self):
        self.is_closed = False
        self.sent = []
        self.events = []
        self.waiting = asyncio.Event()
        self.close_wait = None
        self.close_error = None
        self.reply_on_close = True
        self.close_ping = False
        self.incoming = asyncio.Queue()

    async def send(self, data):
        self.sent.append(data)

    async def receive(self):
        if self.events:
            message = self.events.pop(0)
        else:
            self.waiting.set()
            message = await self.incoming.get()
        if message[0] == "close":
            self.is_closed = True
        return message

    async def ping(self, data):
        self.sent.append(("ping", data))

    async def pong(self, data):
        self.sent.append(("pong", data))

    async def close(self, code, reason):
        self.sent.append(("close", code, reason))
        if self.close_error:
            raise self.close_error
        if self.close_wait:
            await self.close_wait
        if self.close_ping:
            self.incoming.put_nowait(("ping", b"before-close", None))
        if self.reply_on_close:
            self.incoming.put_nowait(
                ("close", reason if code is not None else None, code)
            )

    def abort(self):
        self.is_closed = True


class NativeClient:
    cookies = object()
    is_closed = False

    def __init__(self):
        self.sockets = []
        self.calls = []

    async def websocket(self, *arguments):
        self.calls.append(arguments)
        socket = Socket()
        self.sockets.append(socket)
        return socket

    async def shutdown(self, _):
        self.is_closed = True


class WebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_await_and_context_preserve_profile_headers_and_limits(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        limits = FACADE.WebSocketLimits(8, 16, 4)
        opening = client.websocket(
            "ws://localhost/events",
            headers=[("X-One", "a"), FACADE.Header("X-Two", b"b", sensitive=True)],
            limits=limits,
            handshake_timeout_ms=500,
        )
        async with opening as socket:
            self.assertEqual(socket.headers.get_list("x-reply"), [b"one", b"two"])
            self.assertEqual(socket.selected_protocol, "chat")
            await socket.send("hello")
            await socket.send(b"hello")
            await socket.ping(b"p")
            await socket.pong(b"q")
            self.assertEqual(
                native.sockets[0].sent,
                ["hello", b"hello", ("ping", b"p"), ("pong", b"q")],
            )
        self.assertEqual(
            native.calls,
            [
                (
                    "ws://localhost/events",
                    "h1",
                    [("X-One", b"a", False), ("X-Two", b"b", True)],
                    8,
                    16,
                    4,
                    False,
                    500,
                    None,
                    0,
                )
            ],
        )
        self.assertTrue(socket.is_closed)
        with self.assertRaisesRegex(RuntimeError, "only be awaited once"):
            await opening

    async def test_receive_exposes_controls_recv_skips_them_and_close_is_typed(self):
        native = NativeClient()
        socket = await FACADE.AsyncClient._from_native(native).websocket("ws://local")
        native.sockets[0].events = [
            ("ping", b"p", None),
            ("pong", b"q", None),
            ("text", "hello", None),
            ("close", "done", 1000),
        ]
        self.assertEqual(await socket.receive(), FACADE.WebSocketPing(b"p"))
        self.assertEqual(await socket.recv(), "hello")
        with self.assertRaises(FACADE.WebSocketClosed) as closed:
            await socket.recv()
        self.assertEqual(
            (closed.exception.code, closed.exception.reason), (1000, "done")
        )
        self.assertNotIn("done", repr(closed.exception))
        with self.assertRaises(StopAsyncIteration):
            await socket.__anext__()
        socket.abort()

    async def test_cancel_receive_aborts_only_its_socket(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        first = await client.websocket("ws://first")
        second = await client.websocket("ws://second")
        pending = asyncio.create_task(first.recv())
        await native.sockets[0].waiting.wait()
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertTrue(first.is_closed)
        self.assertFalse(second.is_closed)
        await second.send("still open")
        await second.aclose()

    async def test_close_timeout_aborts_and_keeps_a_distinct_timeout_phase(self):
        native = NativeClient()
        socket = await FACADE.AsyncClient._from_native(native).websocket("ws://local")
        native.sockets[0].close_wait = asyncio.Future()
        with self.assertRaises(FACADE.TimeoutError) as failure:
            await socket.aclose(timeout_ms=1)
        self.assertEqual(failure.exception.timeout_phase, "websocket_close")
        self.assertTrue(socket.is_closed)

    async def test_context_cleanup_failure_preserves_consumer_exception(self):
        native = NativeClient()
        socket = await FACADE.AsyncClient._from_native(native).websocket("ws://local")
        native.sockets[0].close_error = FACADE._native.NativeError(
            "websocket", "io", "h1", None
        )
        failure = ValueError("consumer")
        with self.assertRaises(ValueError) as observed:
            async with socket:
                raise failure
        self.assertIs(observed.exception, failure)
        self.assertTrue(socket.is_closed)

    async def test_close_coexists_with_pending_receive_and_preserves_empty_frame(self):
        native = NativeClient()
        socket = await FACADE.AsyncClient._from_native(native).websocket("ws://local")
        native.sockets[0].close_ping = True
        pending = asyncio.create_task(socket.recv())
        await native.sockets[0].waiting.wait()
        await socket.aclose(None)
        with self.assertRaises(FACADE.WebSocketClosed) as closed:
            await pending
        self.assertIsNone(closed.exception.code)
        self.assertEqual(native.sockets[0].sent, [("close", None, "")])
        self.assertTrue(socket.is_closed)

    async def test_close_waits_for_peer_and_cancellation_releases_socket(self):
        for operation in ("timeout", "cancel"):
            with self.subTest(operation=operation):
                native = NativeClient()
                socket = await FACADE.AsyncClient._from_native(native).websocket(
                    "ws://local"
                )
                native.sockets[0].reply_on_close = False
                closing = asyncio.create_task(
                    socket.aclose(timeout_ms=10 if operation == "timeout" else 5000)
                )
                await native.sockets[0].waiting.wait()
                if operation == "cancel":
                    closing.cancel()
                    expected = asyncio.CancelledError
                else:
                    expected = FACADE.TimeoutError
                with self.assertRaises(expected):
                    await closing
                self.assertTrue(socket.is_closed)

    async def test_send_close_flushes_without_consuming_peer_close(self):
        native = NativeClient()
        socket = await FACADE.AsyncClient._from_native(native).websocket("ws://local")
        with self.assertRaises(ValueError):
            await socket.send_close(None, "requires status")
        self.assertFalse(socket.is_closed)
        self.assertEqual(native.sockets[0].sent, [])
        await socket.send_close(None)
        self.assertFalse(socket.is_closed)
        self.assertEqual(await socket.receive(), FACADE.WebSocketClose(None))

    async def test_opening_options_distinguish_inherit_disabled_and_finite_timer(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        for timeout, expected in (
            (FACADE.INHERIT, (True, None)),
            (None, (False, None)),
            (500, (False, 500)),
        ):
            socket = await client.websocket(
                "ws://local",
                handshake_timeout_ms=timeout,
                retry=FACADE.WebSocketRetry(maximum=2, delay_ms=20),
            )
            self.assertEqual(native.calls[-1][-4:], (*expected, 2, 20))
            socket.abort()
        with self.assertRaises(ValueError):
            FACADE.WebSocketRetry(maximum=0)
        with self.assertRaises(ValueError):
            FACADE.WebSocketRetry(maximum=1, delay_ms=True)
        with self.assertRaises(TypeError):
            client.websocket("ws://local", retry={})

    async def test_invalid_limits_and_options_never_start_a_handshake(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        for values in ((0, 1, 1), (2, 1, 1), (1, 1, True)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                FACADE.WebSocketLimits(*values)
        for options in (
            {"protocol": "negotiated"},
            {"handshake_timeout_ms": True},
            {"handshake_timeout_ms": 0},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                client.websocket("ws://local", **options)
        self.assertEqual(native.calls, [])


class SynchronousWebSocketTests(unittest.TestCase):
    def test_sync_socket_uses_its_clients_existing_loop(self):
        native = NativeClient()
        client = object.__new__(FACADE.Client)
        client._thread = threading.get_ident()
        client._loop = asyncio.new_event_loop()
        client._async = FACADE.AsyncClient._from_native(native)
        try:
            with client.websocket("ws://local", protocol="h1") as socket:
                socket.send("hello")
                native.sockets[0].events = [("binary", b"world", None)]
                self.assertEqual(socket.recv(), b"world")
                self.assertIs(socket._socket._loop, client._loop)
            self.assertTrue(socket.is_closed)
        finally:
            client.close()
