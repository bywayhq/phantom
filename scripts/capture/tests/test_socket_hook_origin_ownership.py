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
        self.accepted = asyncio.Queue()
        self.server_writers = []
        self.client_writers = []
        self.serving_tasks = []
        self.read_errors = {}

    def connected(self, callback, reader, writer):
        self.origin = callback.__self__
        if self.server_reader is None:
            self.server_reader = reader
            self.server_writer = writer

        self.server_writers.append(writer)
        self.accepted.put_nowait((reader, writer))
        actual_read = reader.readuntil

        async def readuntil(separator):
            task = asyncio.current_task()
            if task not in self.serving_tasks:
                self.serving_tasks.append(task)

            if self.task is None:
                self.task = asyncio.current_task()
                self.task.add_done_callback(lambda completed: self.completed.set())

            self.entered.set()
            try:
                return await actual_read(separator)
            except BaseException as error:
                self.read_error = error
                self.read_errors[task] = error
                raise

        self.stack.enter_context(patch.object(reader, "readuntil", readuntil))
        return callback(reader, writer)

    async def connect(self):
        port = self.server.sockets[0].getsockname()[1]
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", port)
        self.client_writers.append(self.writer)
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
            start_serving=False,
        )
        self.origin.port = self.server.sockets[0].getsockname()[1]
        await self.origin.listen(self.server)
        await self.server.start_serving()
        await self.connect()

    async def another(self):
        port = self.origin.port
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.client_writers.append(writer)
        accepted = await asyncio.wait_for(self.accepted.get(), DEADLINE)
        return reader, writer, accepted

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

        for task in self.serving_tasks:
            requested = not task.done() and task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), DEADLINE)
            except asyncio.CancelledError as error:
                origin_cancelled = any(
                    owner.serving is task and owner.cancel_requested
                    for owner in getattr(self.origin, "_peers", ())
                )
                if not requested and not origin_cancelled:
                    failures.append(error)
            except BaseException as error:
                origin_observed = any(
                    owner.serving is task
                    and owner.serving_observed
                    and owner.serving_error is error
                    for owner in getattr(self.origin, "_peers", ())
                )
                if error is not self.read_errors.get(task) and not origin_observed:
                    failures.append(error)

        for writer in (*self.server_writers, *self.client_writers):
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            except BaseException as error:
                if error is not self.injected:
                    failures.append(error)

        for owner in getattr(self.origin, "_listeners", ()):
            if owner.waiter is None:
                continue

            try:
                await asyncio.wait_for(asyncio.shield(owner.waiter), DEADLINE)
            except BaseException as error:
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

    async def test_delayed_actual_accepted_writer_is_observed_before_run_failure_returns(
        self,
    ):
        peer = self.peer()
        accepted = asyncio.Event()
        finishing = asyncio.Event()
        delivery = []
        primary = LookupError("controlled original profile creation failure")
        failure = RuntimeError("controlled original delayed writer close failure")
        peer.injected = failure
        actual_finish = hooks.Origin.finish

        def connected(callback, reader, writer):
            peer.origin = callback.__self__
            peer.server_reader, peer.server_writer = reader, writer
            peer.server_writers.append(writer)
            delivery.append((callback, reader, writer))
            actual_wait = writer.wait_closed

            async def wait_closed():
                await actual_wait()
                raise failure

            peer.stack.enter_context(patch.object(writer, "wait_closed", wait_closed))
            accepted.set()

        async def start_server(callback, *args, **kwargs):
            peer.server = await peer.actual_start_server(
                lambda reader, writer: connected(callback, reader, writer),
                *args,
                **kwargs,
            )
            actual_serving = peer.server.start_serving

            async def start_serving():
                await actual_serving()
                port = peer.server.sockets[0].getsockname()[1]
                peer.reader, peer.writer = await asyncio.open_connection(
                    "127.0.0.1", port
                )
                peer.client_writers.append(peer.writer)
                await asyncio.wait_for(accepted.wait(), DEADLINE)

            peer.stack.enter_context(
                patch.object(peer.server, "start_serving", start_serving)
            )
            return peer.server

        async def finish(origin, deadline, initiating):
            self.assertIs(initiating, primary)
            finishing.set()
            return await actual_finish(origin, deadline, initiating)

        peer.stack.enter_context(
            patch.object(hooks.asyncio, "start_server", start_server)
        )
        peer.stack.enter_context(patch.object(hooks.Origin, "finish", finish))
        caller = asyncio.create_task(peer.call_run(primary))

        def deliver():
            if delivery:
                callback, reader, writer = delivery.pop()
                callback(reader, writer)

        async def finish_run():
            deliver()
            await asyncio.wait_for(asyncio.shield(caller), DEADLINE)

        self.addAsyncCleanup(finish_run)
        await asyncio.wait_for(finishing.wait(), DEADLINE)

        self.assertFalse(caller.done())
        self.assertFalse(peer.origin._peers)
        listener = peer.origin._listeners[0]
        self.assertIs(listener.listener, peer.server)
        self.assertFalse(listener.waiter.done())
        self.assertFalse(peer.server_writer.is_closing())
        self.assertFalse(peer.server.is_serving())

        deliver()
        await asyncio.wait_for(asyncio.shield(caller), DEADLINE)

        self.assertIsInstance(peer.caller_error, BrowserLaunchFailures)
        self.assertIs(peer.caller_error.primary, primary)
        self.assertEqual(peer.caller_error.cleanup, (failure,))
        self.assertTrue(listener.observed)
        self.assertTrue(peer.server_writer.is_closing())
        self.assertEqual(await asyncio.wait_for(peer.reader.read(1), DEADLINE), b"")
        original = peer.origin._peers[0]
        self.assertIs(original.writer, peer.server_writer)
        self.assertIs(original.wait_error, failure)
        self.assertTrue(original.closing_observed)

    async def test_malformed_original_request_line_gets_no_success_response(self):
        peer = self.peer()
        await peer.start()

        await peer.send(b"GET\r\n\r\n")
        response = await asyncio.wait_for(peer.reader.read(4096), DEADLINE)

        self.assertEqual(response, b"")
        await self.assert_closed(peer)
        self.assertFalse(peer.origin.connections[0].requests)

    async def test_empty_fragment_delimiter_gets_no_success_response(self):
        peer = self.peer()
        await peer.start()

        await peer.send(b"GET /# HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        response = await asyncio.wait_for(peer.reader.read(4096), DEADLINE)

        self.assertEqual(response, b"")
        await self.assert_closed(peer)
        self.assertFalse(peer.origin.connections[0].requests)

    async def test_malformed_host_authorities_get_no_success_response(self):
        for host in (
            b"127.0.0.1?",
            b"127.0.0.1#",
            b"[::1]junk",
            b"[::1]junk:80",
            b"junk[::1]",
            b"[::1]:",
            b"[::1]:+80",
        ):
            with self.subTest(host=host):
                peer = self.peer()
                await peer.start()

                await peer.send(b"GET /close HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
                response = await asyncio.wait_for(peer.reader.read(4096), DEADLINE)

                self.assertEqual(response, b"")
                await self.assert_closed(peer)
                self.assertFalse(peer.origin.connections[0].requests)

    async def test_valid_host_authorities_keep_original_close_response(self):
        for host in (
            b"localhost",
            b"127.0.0.1",
            b"127.0.0.1.nip.io",
            b"127.0.0.1:80",
            b"[::1]",
            b"[::1]:80",
        ):
            with self.subTest(host=host):
                peer = self.peer()
                await peer.start()

                await peer.send(b"GET /close HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
                response, body = await peer.response()
                await asyncio.wait_for(peer.completed.wait(), DEADLINE)

                self.assertTrue(response.startswith(b"HTTP/1.1 200 OK\r\n"))
                self.assertIn(b"Connection: close\r\n", response)
                self.assertEqual(body, b"ok\n")
                await self.assert_closed(peer)
                self.assertEqual(
                    peer.origin.connections[0].requests[0][1:],
                    (host.decode("ascii"), "/close"),
                )

    async def test_failed_original_listener_registration_keeps_fallback_unfenced(self):
        peer = self.peer()
        peer.origin = hooks.Origin(hooks.SCENARIOS["single"])
        peer.server = await peer.actual_start_server(
            peer.origin.handle, "127.0.0.1", 0, start_serving=False
        )
        sockets = tuple(peer.server.sockets)
        failure = RuntimeError("controlled original listener waiter submission failure")
        actual_wait = peer.server.wait_closed
        actual_create = hooks.asyncio.create_task
        waits = []
        rejected = []

        async def wait_closed():
            await actual_wait()
            waits.append(peer.server)

        def create_task(operation, *args, **kwargs):
            if not rejected:
                rejected.append(operation)
                raise failure

            return actual_create(operation, *args, **kwargs)

        peer.stack.enter_context(patch.object(peer.server, "wait_closed", wait_closed))
        with patch.object(hooks.asyncio, "create_task", create_task):
            with self.assertRaises(RuntimeError) as raised:
                await peer.origin.listen(peer.server)

            self.assertIs(raised.exception, failure)
            owner = peer.origin._listeners[0]
            self.assertIs(owner.listener, peer.server)
            self.assertIsNone(owner.waiter)
            self.assertEqual(owner.errors, [failure])

            errors = await peer.origin.finish(
                asyncio.get_running_loop().time() + DEADLINE, failure
            )

        self.assertEqual(waits, [peer.server])
        self.assertTrue(owner.observed)
        self.assertTrue(owner.waiter.done())
        self.assertTrue(all(sock.fileno() == -1 for sock in sockets))
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RuntimeError)
        self.assertEqual(
            str(errors[0]), "socket hook origin listener closed before registration"
        )
        self.assertEqual(owner.errors, [failure, errors[0]])

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

    async def test_pending_original_reader_error_survives_local_cleanup_cancellation(
        self,
    ):
        peer = self.peer()
        await peer.start()
        failure = OSError(errno.EIO, "controlled unread original origin error")
        peer.injected = failure
        peer.server_reader.set_exception(failure)

        errors = await peer.origin.finish(
            asyncio.get_running_loop().time() + DEADLINE, None
        )

        self.assertIn(failure, errors)
        self.assertIs(peer.server_reader.exception(), failure)
        await self.assert_closed(peer)
        self.assertEqual(peer.origin.open_count, 0)

    async def test_original_wait_closed_failure_is_retained_after_native_close(self):
        peer = self.peer()
        await peer.start()
        failure = RuntimeError("controlled original accepted writer close failure")
        actual_wait = peer.server_writer.wait_closed

        async def wait_closed():
            await actual_wait()
            raise failure

        with patch.object(peer.server_writer, "wait_closed", wait_closed):
            errors = await peer.origin.finish(
                asyncio.get_running_loop().time() + DEADLINE, None
            )

        self.assertEqual(errors, (failure,))
        await self.assert_closed(peer)
        self.assertEqual(peer.origin.open_count, 0)

    async def test_peer_error_class_does_not_hide_an_unrelated_original_io_code(self):
        cases = (
            (ConnectionResetError(errno.ECONNRESET, "controlled peer reset"), False),
            (
                ConnectionResetError(errno.EIO, "controlled unrelated read failure"),
                True,
            ),
        )
        for failure, fatal in cases:
            with self.subTest(errno=failure.errno):
                peer = self.peer()
                await peer.start()
                peer.injected = failure
                peer.server_reader.set_exception(failure)

                errors = await peer.origin.finish(
                    asyncio.get_running_loop().time() + DEADLINE, None
                )

                self.assertEqual(errors, (failure,) if fatal else ())
                await self.assert_closed(peer)
                self.assertEqual(peer.origin.open_count, 0)

    async def test_held_original_close_retains_its_owner_and_late_failure(self):
        peer = self.peer()
        await peer.start()
        entered = asyncio.Event()
        release = asyncio.Event()
        failure = RuntimeError("controlled original late close failure")
        primary = LookupError("controlled initiating capture failure")
        actual_wait = peer.server_writer.wait_closed
        contexts = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda loop, context: contexts.append(context))
        self.addCleanup(loop.set_exception_handler, previous)

        async def release_close():
            release.set()
            for owner in tuple(peer.origin._peers):
                if owner.closing is None:
                    continue

                try:
                    await asyncio.wait_for(asyncio.shield(owner.closing), DEADLINE)
                except BaseException as error:
                    if error is not failure:
                        raise

        self.addAsyncCleanup(release_close)

        async def wait_closed():
            await actual_wait()
            entered.set()
            await release.wait()
            raise failure

        with patch.object(peer.server_writer, "wait_closed", wait_closed):
            errors = await peer.origin.finish(loop.time() + 0.05, primary)
            await asyncio.wait_for(entered.wait(), DEADLINE)
            pending = next(
                error
                for error in errors
                if isinstance(error, hooks._SocketHookOriginPending)
            )

            self.assertIs(pending.owner, peer.origin)
            self.assertEqual(len(pending.pending), 1)
            original = pending.pending[0]
            self.assertIs(original.writer, peer.server_writer)
            self.assertFalse(original.closing.done())
            await self.assert_closed(peer)

            release.set()
            with self.assertRaises(RuntimeError) as raised:
                await asyncio.wait_for(asyncio.shield(original.closing), DEADLINE)

        self.assertIs(raised.exception, failure)
        self.assertIs(original.wait_error, failure)
        self.assertTrue(original.closing_observed)
        self.assertTrue(
            any(
                context.get("exception") is failure
                and context.get("primary") is primary
                and context.get("owner") is peer.origin
                for context in contexts
            )
        )

    async def test_33rd_actual_active_connection_stops_admission_without_a_record(self):
        peer = self.peer()
        await peer.start()
        await peer.accepted.get()
        for _ in range(31):
            await peer.another()

        reader, _, (_, rejected) = await peer.another()
        eof = await asyncio.wait_for(reader.read(1), DEADLINE)

        self.assertEqual(eof, b"")
        self.assertTrue(rejected.is_closing())
        self.assertFalse(peer.server.is_serving())
        self.assertTrue(peer.origin.done.is_set())
        self.assertEqual(len(peer.origin.connections), 32)
        self.assertEqual(peer.origin.max_open, 32)

        errors = await peer.origin.finish(
            asyncio.get_running_loop().time() + DEADLINE, None
        )

        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ValueError)
        self.assertEqual(peer.origin.open_count, 0)
        self.assertTrue(all(writer.is_closing() for writer in peer.server_writers))

    async def test_129th_actual_connection_stops_lifetime_record_growth(self):
        peer = self.peer()
        await peer.start()
        await peer.accepted.get()
        for index in range(128):
            if index:
                peer.reader, peer.writer, _ = await peer.another()

            await peer.send(b"GET /close HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            head, body = await peer.response()
            self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
            self.assertEqual(body, b"ok\n")
            self.assertEqual(await asyncio.wait_for(peer.reader.read(1), DEADLINE), b"")

        reader, _, (_, rejected) = await peer.another()
        self.assertEqual(await asyncio.wait_for(reader.read(1), DEADLINE), b"")
        self.assertTrue(rejected.is_closing())
        self.assertFalse(peer.server.is_serving())
        self.assertEqual(len(peer.origin.connections), 128)

        errors = await peer.origin.finish(
            asyncio.get_running_loop().time() + DEADLINE, None
        )

        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ValueError)
        self.assertEqual(peer.origin.open_count, 0)

    async def test_513th_actual_request_gets_no_response_or_record(self):
        peer = self.peer()
        await peer.start()
        for _ in range(512):
            await peer.send(b"GET /fast HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            head, body = await peer.response()
            self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
            self.assertEqual(body, b"ok\n")

        await peer.send(b"GET /fast HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        self.assertEqual(await asyncio.wait_for(peer.reader.read(1), DEADLINE), b"")
        await asyncio.wait_for(peer.completed.wait(), DEADLINE)

        self.assertFalse(peer.server.is_serving())
        self.assertTrue(peer.origin.done.is_set())
        self.assertEqual(len(peer.origin.connections[0].requests), 512)

        errors = await peer.origin.finish(
            asyncio.get_running_loop().time() + DEADLINE, None
        )

        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ValueError)
        await self.assert_closed(peer)
