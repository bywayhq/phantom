"""Graceful shutdown retains response and WebSocket owners until they finish."""

import asyncio
import unittest

from phantom_http import (
    AsyncClient,
    Client,
    ClientClosed,
    TimeoutError,
    WebSocketError,
)
from test_client import server
from test_websocket import PROFILE, peer
from websockets.datastructures import Headers
from websockets.http11 import Response as PeerResponse


def echo_until_close(connection):
    connection.send(connection.recv(timeout=5))
    connection.recv(timeout=5)


def reject(_, request):
    return PeerResponse(403, "Forbidden", Headers({"Content-Length": "6"}), b"denied")


class SyncLifecycleTests(unittest.TestCase):
    def test_body_remains_readable_after_shutdown_times_out(self):
        with server() as (_, url):
            client = Client(profile=PROFILE, protocol="h1", context="raw")
            response = client.get(url)
            try:
                with self.assertRaises(TimeoutError):
                    client.close(timeout_ms=0)
                self.assertTrue(client.is_closed)
                with self.assertRaises(ClientClosed):
                    client.get(url)
                self.assertEqual(response.read(max_bytes=5), b"hello")
                client.close()
            finally:
                response.close()
                client.close()

    def test_websocket_remains_usable_after_shutdown_times_out(self):
        with peer(echo_until_close) as (url, finished):
            client = Client(profile=PROFILE, context="raw")
            socket = client.websocket(url)
            try:
                with self.assertRaises(TimeoutError):
                    client.close(timeout_ms=0)
                self.assertTrue(client.is_closed)
                with self.assertRaises(WebSocketError) as stopped:
                    client.websocket(url)
                self.assertEqual(stopped.exception.kind, "client_closed")
                socket.send("still usable")
                self.assertEqual(socket.recv(), "still usable")
                socket.close()
                client.close()
                self.assertTrue(finished.wait(5))
            finally:
                socket.abort()
                client.close()

    def test_rejected_handshake_body_remains_readable_after_shutdown_times_out(self):
        with peer(lambda _: None, process_request=reject) as (url, _):
            client = Client(profile=PROFILE, context="raw")
            with self.assertRaises(WebSocketError) as rejected:
                client.websocket(url)
            response = rejected.exception.response
            self.assertIsNotNone(response)
            try:
                with self.assertRaises(TimeoutError):
                    client.close(timeout_ms=0)
                self.assertEqual(response.read(max_bytes=6), b"denied")
                client.close()
            finally:
                response.close()
                client.close()


class AsyncLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def interrupt_shutdown(self, client, operation):
        if operation == "timeout":
            with self.assertRaises(TimeoutError):
                await client.close(timeout_ms=0)
        else:
            closing = asyncio.create_task(client.close())
            try:
                with self.assertRaises(TimeoutError):
                    await client.close(timeout_ms=0)
                self.assertFalse(closing.done())
            finally:
                closing.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await closing
        self.assertTrue(client.is_closed)

    async def test_body_survives_timeout_and_cancelled_shutdown(self):
        for operation in ("timeout", "cancel"):
            with self.subTest(operation=operation), server() as (_, url):
                client = AsyncClient(profile=PROFILE, protocol="h1", context="raw")
                fork = client.fork()
                response = await client.get(url)
                try:
                    await self.interrupt_shutdown(client, operation)
                    with self.assertRaises(ClientClosed):
                        await client.get(url)
                    self.assertFalse(fork.is_closed)
                    independent = await fork.get(url)
                    self.assertEqual(await independent.read(max_bytes=5), b"hello")
                    self.assertEqual(await response.read(max_bytes=5), b"hello")
                    await client.close()
                finally:
                    await response.aclose()
                    await client.close()
                    await fork.close()

    async def test_websocket_survives_timeout_and_cancelled_shutdown(self):
        for operation in ("timeout", "cancel"):
            with (
                self.subTest(operation=operation),
                peer(echo_until_close) as (url, done),
            ):
                client = AsyncClient(profile=PROFILE, context="raw")
                socket = await client.websocket(url)
                try:
                    await self.interrupt_shutdown(client, operation)
                    with self.assertRaises(WebSocketError) as stopped:
                        await client.websocket(url)
                    self.assertEqual(stopped.exception.kind, "client_closed")
                    await socket.send("still usable")
                    self.assertEqual(await socket.recv(), "still usable")
                    await socket.aclose()
                    await client.close()
                    self.assertTrue(await asyncio.to_thread(done.wait, 5))
                finally:
                    socket.abort()
                    await client.close()

    async def test_rejected_body_survives_timeout_and_cancelled_shutdown(self):
        for operation in ("timeout", "cancel"):
            with (
                self.subTest(operation=operation),
                peer(lambda _: None, process_request=reject) as (url, _),
            ):
                client = AsyncClient(profile=PROFILE, context="raw")
                with self.assertRaises(WebSocketError) as rejected:
                    await client.websocket(url)
                response = rejected.exception.response
                self.assertIsNotNone(response)
                try:
                    await self.interrupt_shutdown(client, operation)
                    self.assertEqual(await response.read(max_bytes=6), b"denied")
                    await client.close()
                finally:
                    await response.aclose()
                    await client.close()
