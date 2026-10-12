"""Observe actual socket-hook origin owners before explicit test backups."""

import asyncio
import errno
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from scripts.capture import socket_hooks as hooks
from scripts.capture.browser_failures import BrowserLaunchFailures

DEADLINE = 5.0


class OriginLoopback:
    def __init__(self):
        self.stack = ExitStack()
        self.server = None
        self.origin = None
        self.reader = None
        self.writer = None
        self.server_reader = None
        self.server_writer = None
        self.task = None
        self.entered = asyncio.Event()
        self.completed = asyncio.Event()
        self.actual_start_server = asyncio.start_server
        self.injected = None
        self.read_error = None
        self.caller_error = None

    def connected(self, callback, reader, writer):
        self.origin = callback.__self__
        self.server_reader = reader
        self.server_writer = writer
        actual_read = reader.readuntil

        async def readuntil(separator):
            if self.task is None:
                self.task = asyncio.current_task()
                self.task.add_done_callback(lambda completed: self.completed.set())

            self.entered.set()
            try:
                return await actual_read(separator)
            except BaseException as error:
                self.read_error = error
                raise

        self.stack.enter_context(patch.object(reader, "readuntil", readuntil))
        return callback(reader, writer)

    async def connect(self):
        port = self.server.sockets[0].getsockname()[1]
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.wait_for(self.entered.wait(), DEADLINE)
        if self.task is None or self.task.done():
            raise AssertionError("original accepted serving task was not pending")

        pending = self.server_reader._waiter
        if pending is None or pending.done():
            raise AssertionError("actual original request-head read was not pending")

    async def start(self):
        self.origin = hooks.Origin(hooks.SCENARIOS["single"])
        callback = self.origin.handle
        self.server = await self.actual_start_server(
            lambda reader, writer: self.connected(callback, reader, writer),
            "127.0.0.1",
            0,
            limit=64 * 1024,
        )
        self.origin.port = self.server.sockets[0].getsockname()[1]
        await self.connect()

    def install_run(self):
        async def start_server(callback, *args, **kwargs):
            self.server = await self.actual_start_server(
                lambda reader, writer: self.connected(callback, reader, writer),
                *args,
                **kwargs,
            )
            actual_serving = self.server.start_serving

            async def start_serving():
                await actual_serving()
                await self.connect()
                if self.injected is not None:
                    self.server_reader.set_exception(self.injected)
                    await asyncio.wait_for(self.completed.wait(), DEADLINE)

            self.stack.enter_context(
                patch.object(self.server, "start_serving", start_serving)
            )
            return self.server

        self.stack.enter_context(
            patch.object(hooks.asyncio, "start_server", start_server)
        )

    async def call_run(self, failure):
        try:
            with patch.object(hooks.tempfile, "mkdtemp", side_effect=failure):
                await hooks.run_once(
                    hooks.SCENARIOS["single"], Path("unused-browser"), ()
                )
        except BaseException as error:
            self.caller_error = error

    async def send(self, head):
        self.writer.write(head)
        await self.writer.drain()

    async def response(self):
        head = await asyncio.wait_for(self.reader.readuntil(b"\r\n\r\n"), DEADLINE)
        size = next(
            int(line.partition(b":")[2])
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"content-length:")
        )
        body = await asyncio.wait_for(self.reader.readexactly(size), DEADLINE)
        return head, body

    async def backup(self):
        failures = []
        if self.server is not None:
            try:
                self.server.close()
            except BaseException as error:
                failures.append(error)

            try:
                await asyncio.wait_for(self.server.wait_closed(), DEADLINE)
            except BaseException as error:
                failures.append(error)

        if self.task is not None:
            requested = not self.task.done() and self.task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self.task), DEADLINE)
            except asyncio.CancelledError as error:
                if not requested and error is not self.read_error:
                    failures.append(error)
            except BaseException as error:
                if error is not self.read_error:
                    failures.append(error)

        for writer in (self.server_writer, self.writer):
            if writer is None:
                continue

            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            except BaseException as error:
                if error is not self.injected:
                    failures.append(error)

        self.stack.close()
        if failures:
            failure = AssertionError(f"original origin backup failed: {failures!r}")
            failure.failures = tuple(failures)
            raise failure from failures[0]


class OriginOwnershipTests(unittest.IsolatedAsyncioTestCase):
    def peer(self):
        peer = OriginLoopback()
        self.addAsyncCleanup(peer.backup)
        return peer

    async def assert_closed(self, peer):
        self.assertTrue(peer.task.done())
        self.assertTrue(peer.server_writer.is_closing())
        self.assertEqual(await asyncio.wait_for(peer.reader.read(1), DEADLINE), b"")

    async def test_profile_creation_failure_closes_its_actual_pending_origin_handler(
        self,
    ):
        peer = self.peer()
        peer.install_run()
        failure = LookupError("controlled original profile creation failure")

        await peer.call_run(failure)

        self.assertIs(peer.caller_error, failure)
        await self.assert_closed(peer)
        self.assertEqual(peer.origin.open_count, 0)

    async def test_completed_original_read_failure_survives_profile_creation_failure(
        self,
    ):
        peer = self.peer()
        peer.install_run()
        peer.injected = OSError(
            errno.EIO, "controlled original accepted reader failure"
        )
        failure = LookupError("controlled original profile creation failure")

        await peer.call_run(failure)

        self.assertIs(peer.read_error, peer.injected)
        self.assertTrue(peer.completed.is_set())
        self.assertTrue(peer.task.done())

        self.assertIsInstance(peer.caller_error, BrowserLaunchFailures)
        self.assertIs(peer.caller_error.primary, failure)
        self.assertIn(peer.injected, peer.caller_error.cleanup)
        await self.assert_closed(peer)

    async def test_malformed_original_request_line_gets_no_success_response(self):
        peer = self.peer()
        await peer.start()

        await peer.send(b"GET\r\n\r\n")
        response = await asyncio.wait_for(peer.reader.read(4096), DEADLINE)

        self.assertEqual(response, b"")
        await self.assert_closed(peer)
        self.assertFalse(peer.origin.connections[0].requests)

    async def test_completed_request_head_next_byte_is_rejected_at_64_kib(self):
        peer = self.peer()
        await peer.start()
        prefix = b"GET /close HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Padding: "
        suffix = b"\r\n\r\n"
        head = prefix + b"a" * (65537 - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(head), 65537)

        await peer.send(head)
        response = await asyncio.wait_for(peer.reader.read(4096), DEADLINE)

        self.assertEqual(response, b"")
        await self.assert_closed(peer)
        self.assertFalse(peer.origin.connections[0].requests)

    async def test_exact_64_kib_head_keeps_the_original_close_response(self):
        peer = self.peer()
        await peer.start()
        prefix = b"GET /close HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Padding: "
        suffix = b"\r\n\r\n"
        head = prefix + b"a" * (65536 - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(head), 65536)

        await peer.send(head)
        response, body = await peer.response()
        await asyncio.wait_for(peer.completed.wait(), DEADLINE)

        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"Connection: close\r\n", response)
        self.assertEqual(body, b"ok\n")
        await self.assert_closed(peer)
        self.assertEqual(
            peer.origin.connections[0].requests[0][1:], ("127.0.0.1", "/close")
        )
        self.assertEqual(peer.origin.open_count, 0)

    async def test_done_then_close_keeps_the_original_response_and_observations(self):
        peer = self.peer()
        await peer.start()

        await peer.send(b"GET /done HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        done_head, done_body = await peer.response()
        await peer.send(b"GET /close HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        close_head, close_body = await peer.response()
        await asyncio.wait_for(peer.completed.wait(), DEADLINE)

        self.assertIn(b"Connection: keep-alive\r\n", done_head)
        self.assertIn(b"Connection: close\r\n", close_head)
        self.assertEqual((done_body, close_body), (b"ok\n", b"ok\n"))
        self.assertTrue(peer.origin.done.is_set())
        self.assertEqual(
            [entry[2] for entry in peer.origin.connections[0].requests],
            ["/done", "/close"],
        )
        await self.assert_closed(peer)
        self.assertEqual(peer.origin.open_count, 0)
