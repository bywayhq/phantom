"""Graceful shutdown retains response and WebSocket owners until they finish."""

import asyncio
import unittest

from phantom_http import (
    AsyncClient,
    Client,
    ClientClosed,
    Error,
    TimeoutError,
    WebSocketError,
)
from test_client import server
from test_uploads import server as upload_server
from test_websocket import PROFILE, peer, stalled_handshake
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
                with self.assertRaises(ClientClosed) as stopped:
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
    async def test_closed_body_reports_an_error_but_completed_body_stays_at_eof(self):
        with server() as (_, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                complete = await client.get(url)
                self.assertEqual(await complete.read(max_bytes=5), b"hello")
                self.assertEqual(await complete.read(max_bytes=5), b"")
                self.assertIsNone(await complete.read_chunk())

                closed = await client.get(url)
                await closed.aclose()
                for read in (lambda: closed.read(max_bytes=5), closed.read_chunk):
                    with self.assertRaises(Error) as failure:
                        await read()
                    self.assertEqual(failure.exception.kind, "body_closed")

    async def test_abort_stops_pending_upload_and_settles_its_source(self):
        with upload_server() as (_, url):
            client = AsyncClient(profile=PROFILE, protocol="h1", context="raw")
            entered = asyncio.Event()
            cleaned = asyncio.Event()

            async def source():
                try:
                    entered.set()
                    await asyncio.Future()
                    yield b"unreachable payload"
                finally:
                    cleaned.set()

            request = asyncio.create_task(
                client.post(url, body=source(), body_length=7)
            )
            try:
                await asyncio.wait_for(entered.wait(), 5)
                await client.abort()
                with self.assertRaises(Error):
                    await request
                self.assertTrue(cleaned.is_set())
                self.assertFalse(client._uploads)
            finally:
                await client.abort()
                if not request.done():
                    request.cancel()
                await asyncio.gather(request, return_exceptions=True)

    async def test_abort_releases_rejected_handshake_body(self):
        with peer(lambda _: None, process_request=reject) as (url, _):
            client = AsyncClient(profile=PROFILE, context="raw")
            with self.assertRaises(WebSocketError) as rejected:
                await client.websocket(url)
            response = rejected.exception.response
            self.assertIsNotNone(response)
            try:
                await client.abort()
                with self.assertRaises(Error) as closed:
                    await response.read(max_bytes=6)
                self.assertEqual(closed.exception.kind, "body_closed")
            finally:
                await response.aclose()
                await client.abort()

    async def test_upload_can_finish_after_timeout_and_cancelled_shutdown(self):
        for operation in ("timeout", "cancel"):
            with self.subTest(operation=operation), upload_server() as (origin, url):
                client = AsyncClient(profile=PROFILE, protocol="h1", context="raw")
                entered = asyncio.Event()
                release = asyncio.Event()
                cleaned = asyncio.Event()

                async def source(entered=entered, release=release, cleaned=cleaned):
                    try:
                        entered.set()
                        await release.wait()
                        yield b"payload"
                    finally:
                        cleaned.set()

                request = asyncio.create_task(
                    client.post(url, body=source(), body_length=7)
                )
                await asyncio.wait_for(entered.wait(), 5)
                try:
                    await self.interrupt_shutdown(client, operation)
                    self.assertFalse(request.done())
                    self.assertFalse(cleaned.is_set())
                    with self.assertRaises(ClientClosed):
                        await client.get(url)
                    release.set()
                    response = await asyncio.wait_for(request, 5)
                    self.assertEqual(await response.read(max_bytes=7), b"payload")
                    await client.close()
                    self.assertTrue(cleaned.is_set())
                    self.assertEqual(
                        [record[2] for record in origin.records], [b"payload"]
                    )
                finally:
                    release.set()
                    await client.abort()
                    if not request.done():
                        request.cancel()
                    await asyncio.gather(request, return_exceptions=True)

    async def test_graceful_shutdown_does_not_cancel_admitted_handshake(self):
        with stalled_handshake() as (url, started, disconnected):
            client = AsyncClient(profile=PROFILE, context="raw")
            opening = asyncio.ensure_future(
                client.websocket(url, handshake_timeout_ms=None)
            )
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 5))
                await self.interrupt_shutdown(client, "cancel")
                self.assertFalse(opening.done())
                self.assertFalse(disconnected.is_set())
                await client.abort()
                with self.assertRaises(ClientClosed) as stopped:
                    await opening
                self.assertEqual(stopped.exception.kind, "client_closed")
                self.assertTrue(await asyncio.to_thread(disconnected.wait, 5))
            finally:
                await client.abort()
                if not opening.done():
                    opening.cancel()
                await asyncio.gather(opening, return_exceptions=True)

    async def test_abort_releases_bodies_and_sockets_but_not_independent_fork(self):
        with server() as (_, url), peer(echo_until_close) as (socket_url, finished):
            client = AsyncClient(profile=PROFILE, protocol="h1", context="raw")
            fork = client.fork()
            response = await client.get(url)
            socket = await client.websocket(socket_url)
            try:
                await client.abort()
                self.assertTrue(client.is_closed)
                self.assertTrue(socket.is_closed)
                with self.assertRaises(Error) as closed:
                    await response.read(max_bytes=5)
                self.assertEqual(closed.exception.kind, "body_closed")
                self.assertFalse(fork.is_closed)
                independent = await fork.get(url)
                self.assertEqual(await independent.read(max_bytes=5), b"hello")
                self.assertTrue(await asyncio.to_thread(finished.wait, 5))
            finally:
                await response.aclose()
                socket.abort()
                await client.abort()
                await fork.close()

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
                    with self.assertRaises(ClientClosed) as stopped:
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
