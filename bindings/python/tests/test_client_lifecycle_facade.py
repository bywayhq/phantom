"""Failed synchronous shutdown preserves the loop needed by active owners."""

import asyncio
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE, NativeResponse
from test_upload_pump import Native as NativeUpload
from test_websocket_facade import NativeClient as SocketClient


class NativeClient(SocketClient):
    def __init__(self):
        super().__init__()
        self.shutdown_calls = 0

    async def shutdown(self, _):
        self.is_closed = True
        self.shutdown_calls += 1
        if self.shutdown_calls == 1:
            raise FACADE._native.NativeError("input", "shutdown_timeout", None, None)


class SyncLifecycleTests(unittest.TestCase):
    def test_shutdown_timeout_keeps_response_readable_until_retry(self):
        native = NativeClient()
        asynchronous = FACADE.AsyncClient._from_native(native)
        with patch.object(FACADE, "AsyncClient", return_value=asynchronous):
            client = FACADE.Client(profile="exact")
            response = FACADE.Response(client, FACADE.AsyncResponse(NativeResponse()))
            try:
                with self.assertRaises(FACADE.TimeoutError):
                    client.close(timeout_ms=0)
                self.assertTrue(client.is_closed)
                self.assertFalse(client._loop.is_closed())
                self.assertEqual(response.read(max_bytes=4), b"body")
                client.close()
                self.assertTrue(client._loop.is_closed())
                self.assertEqual(native.shutdown_calls, 2)
            finally:
                response.close()
                client.close()

    def test_shutdown_timeout_keeps_socket_usable_until_retry(self):
        native = NativeClient()
        asynchronous = FACADE.AsyncClient._from_native(native)
        with patch.object(FACADE, "AsyncClient", return_value=asynchronous):
            client = FACADE.Client(profile="exact")
            socket = client.websocket("ws://localhost/")
            try:
                with self.assertRaises(FACADE.TimeoutError):
                    client.close(timeout_ms=0)
                self.assertFalse(client._loop.is_closed())
                socket.send("still usable")
                self.assertEqual(native.sockets[0].sent, ["still usable"])
                socket.close()
                client.close()
                self.assertTrue(socket.is_closed)
                self.assertTrue(client._loop.is_closed())
            finally:
                socket.abort()
                client.close()

    def test_cancelled_shutdown_preserves_loop_for_later_close(self):
        class CancelledClient(SocketClient):
            def __init__(self):
                super().__init__()
                self.first = True

            async def shutdown(self, _):
                self.is_closed = True
                if self.first:
                    self.first = False
                    raise asyncio.CancelledError

        native = CancelledClient()
        asynchronous = FACADE.AsyncClient._from_native(native)
        with patch.object(FACADE, "AsyncClient", return_value=asynchronous):
            client = FACADE.Client(profile="exact")
            try:
                with self.assertRaises(asyncio.CancelledError):
                    client.close()
                self.assertFalse(client._loop.is_closed())
                client.close()
                self.assertTrue(client._loop.is_closed())
            finally:
                client.close()


class AsyncUploadLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_shutdown_bounds_do_not_abort_or_close_admission(self):
        class Native:
            cookies = object()
            is_closed = False

            def abort(self):
                self.is_closed = True

            async def shutdown(self, _):
                self.is_closed = True

        for method in ("close", "abort"):
            for value in (-1, 2**64, True, 1.5):
                with self.subTest(method=method, value=value):
                    client = FACADE.AsyncClient._from_native(Native())
                    with self.assertRaises((TypeError, ValueError)):
                        await getattr(client, method)(timeout_ms=value)
                    self.assertFalse(client.is_closed)

    async def test_abort_from_producer_cleanup_fails_before_closing_admission(self):
        with patch.object(
            FACADE._upload._native, "NativeUpload", NativeUpload, create=True
        ):

            class Native:
                cookies = object()
                is_closed = False

                def abort(self):
                    self.is_closed = True

                async def shutdown(self, _):
                    self.is_closed = True

            client = FACADE.AsyncClient._from_native(Native())

            class Source:
                def __aiter__(self):
                    return self

                async def __anext__(self):
                    raise ValueError("producer failed")

                async def aclose(self):
                    await client.abort()

            pump = FACADE._upload.Upload(Source(), None)
            client._uploads.add(pump)
            pump.settled.add_done_callback(lambda _: client._uploads.discard(pump))
            pump.native.credits.put_nowait(True)
            self.assertTrue(await pump.wait())
            self.assertIsInstance(pump.cleanup_error, RuntimeError)
            self.assertIn("own cleanup", str(pump.cleanup_error))
            self.assertFalse(client.is_closed)
            await client.abort()

    async def test_graceful_timeout_and_cancellation_preserve_upload(self):
        for operation in ("timeout", "cancel"):
            with (
                self.subTest(operation=operation),
                patch.object(
                    FACADE._upload._native, "NativeUpload", NativeUpload, create=True
                ),
            ):
                started = asyncio.Event()

                class Native:
                    cookies = object()
                    is_closed = False

                    async def shutdown(self, _, started=started):
                        self.is_closed = True
                        started.set()

                client = FACADE.AsyncClient._from_native(Native())
                entered = asyncio.Event()
                release = asyncio.Event()
                cleaned = asyncio.Event()

                async def source(entered=entered, release=release, cleaned=cleaned):
                    try:
                        entered.set()
                        await release.wait()
                        yield b"body"
                    finally:
                        cleaned.set()

                pump = FACADE._upload.Upload(source(), 4)
                client._uploads.add(pump)
                pump.settled.add_done_callback(
                    lambda _, client=client, pump=pump: client._uploads.discard(pump)
                )
                pump.native.credits.put_nowait(True)
                await entered.wait()
                try:
                    if operation == "timeout":
                        with self.assertRaises(FACADE.TimeoutError):
                            await client.close(timeout_ms=0)
                    else:
                        closing = asyncio.create_task(client.close())
                        await started.wait()
                        closing.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await closing
                    self.assertFalse(pump.closing)
                    self.assertFalse(pump.native.aborted)
                    self.assertFalse(cleaned.is_set())
                    release.set()
                    await pump.native.writes.get()
                    pump.native.credits.put_nowait(True)
                    await client.close()
                    self.assertTrue(cleaned.is_set())
                    self.assertTrue(pump.native.finished)
                finally:
                    release.set()
                    pump.close()
                    await pump.wait()

    async def test_abort_keeps_noncooperative_cleanup_owned_until_retry(self):
        with patch.object(
            FACADE._upload._native, "NativeUpload", NativeUpload, create=True
        ):

            class Native:
                cookies = object()
                is_closed = False

                def abort(self):
                    self.is_closed = True

                async def shutdown(self, _):
                    self.is_closed = True

            client = FACADE.AsyncClient._from_native(Native())
            entered = asyncio.Event()
            cleaning = asyncio.Event()
            release = asyncio.Event()

            class Source:
                def __aiter__(self):
                    return self

                async def __anext__(self):
                    entered.set()
                    await asyncio.Future()

                async def aclose(self):
                    cleaning.set()
                    await release.wait()

            pump = FACADE._upload.Upload(Source(), None)
            client._uploads.add(pump)
            pump.settled.add_done_callback(lambda _: client._uploads.discard(pump))
            pump.native.credits.put_nowait(True)
            await entered.wait()
            try:
                with self.assertRaises(FACADE.TimeoutError):
                    await client.abort(timeout_ms=0)
                await cleaning.wait()
                self.assertFalse(pump.settled.done())
                self.assertIn(pump, client._uploads)
                release.set()
                await client.abort()
                self.assertTrue(pump.settled.done())
            finally:
                release.set()
                await client.abort()
