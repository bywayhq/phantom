"""Failed synchronous shutdown preserves the loop needed by active owners."""

import asyncio
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE, NativeResponse
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
