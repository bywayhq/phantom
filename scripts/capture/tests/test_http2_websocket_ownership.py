"""Listener, accepted callback and publication ownership on real loopback peers."""

import argparse
import asyncio
import contextlib
import errno
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from scripts.capture import http2_websocket
from scripts.capture.http2_session import (
    HOSTNAME,
    CaptureFailures,
    CaptureLimitError,
    CaptureProtocol,
    CaptureRun,
    CaptureServer,
    Http1Session,
    PlainChannel,
    generate_certificate,
    raise_capture_failures,
)

CERTIFICATE = generate_certificate()
DEADLINE = 10.0
DISCONNECTS = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)
NOT_FOUND = (
    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\ncache-control: no-store\r\n\r\n"
)
DONE = (
    b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\ncache-control: no-store\r\n\r\n"
)


class AcceptedConnection:
    def __init__(self, writer) -> None:
        self.writer = writer
        self.task = asyncio.current_task()
        self.reader = None
        self.reading = asyncio.Event()
        self.read_failure = None


class ObservedServer(CaptureServer):
    def __init__(self) -> None:
        super().__init__(CERTIFICATE)
        self.accepted = asyncio.Event()
        self.connections = []

    def accept(self, listener, writer):
        accepted = super().accept(listener, writer)
        if accepted is not None:
            self.connections.append(AcceptedConnection(writer))
            self.accepted.set()
        return accepted


class BackupFailures(Exception):
    def __init__(self, failures) -> None:
        self.failures = tuple(failures)
        super().__init__("websocket ownership control backup failed")


class WebSocketCaptureOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = ObservedServer()
        self.clients = []
        self.client_readers = []
        self.listeners = []
        self.bind_failures = []
        self.blockers = []
        self.expected_failures = []
        self.expected_cancellations = set()
        self.backup_failures = []
        self.patches = contextlib.ExitStack()
        self.directory = tempfile.TemporaryDirectory(prefix="websocket-owner-")
        original_start = asyncio.BaseEventLoop.create_server
        original_read = PlainChannel.read_raw

        async def start(loop, *args, **kwargs):
            try:
                listener = await original_start(loop, *args, **kwargs)
            except OSError as error:
                self.bind_failures.append(error)
                raise

            self.listeners.append(listener)
            return listener

        async def read(channel):
            connection = next(
                entry
                for entry in self.server.connections
                if entry.writer is channel.writer
            )
            connection.reader = channel.reader
            asyncio.get_running_loop().call_soon(connection.reading.set)
            try:
                return await original_read(channel)
            except BaseException as error:
                connection.read_failure = error
                raise

        self.patches.enter_context(
            patch.object(asyncio.BaseEventLoop, "create_server", start)
        )
        self.patches.enter_context(patch.object(PlainChannel, "read_raw", read))

    async def asyncTearDown(self) -> None:
        # Restore faults before backup; none of these actions is a target oracle.
        self.patches.close()
        failures = []
        for blocker in self.blockers:
            try:
                blocker.close()
            except BaseException as error:
                failures.append(error)

        for listener in self.listeners:
            try:
                listener.close()
            except BaseException as error:
                failures.append(error)

        writers = [*self.clients, *(entry.writer for entry in self.server.connections)]
        for writer in writers:
            try:
                writer.close()
            except BaseException as error:
                failures.append(error)
                try:
                    writer.transport.abort()
                except BaseException as error:
                    failures.append(error)

        tasks = {entry.task for entry in self.server.connections}
        locally_cancelled = set()
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=DEADLINE)
            for task in pending:
                locally_cancelled.add(task)
                task.cancel()
            if pending:
                _, remaining = await asyncio.wait(pending, timeout=DEADLINE)
                if remaining:
                    failures.append(TimeoutError("accepted callback backup deadline"))
            for task in tasks:
                if not task.done():
                    continue
                try:
                    task.result()
                except asyncio.CancelledError as error:
                    if (
                        task not in locally_cancelled
                        and task not in self.expected_cancellations
                    ):
                        failures.append(error)
                except BaseException as error:
                    self.backup_failures.append(error)
                    expected = any(
                        error is candidate for candidate in self.expected_failures
                    )
                    if isinstance(error, CaptureFailures) and error.cleanup:
                        expected = (
                            error.primary is not None
                            and any(
                                error.primary is entry.read_failure
                                for entry in self.server.connections
                            )
                            and all(
                                any(cause is item for item in self.expected_failures)
                                for cause in error.cleanup
                            )
                        )
                    if not expected:
                        failures.append(error)

        for writer in writers:
            try:
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            except DISCONNECTS:
                pass
            except BaseException as error:
                failures.append(error)

        for listener in self.listeners:
            try:
                await asyncio.wait_for(listener.wait_closed(), DEADLINE)
            except BaseException as error:
                failures.append(error)

        try:
            self.directory.cleanup()
        except BaseException as error:
            failures.append(error)

        if failures:
            raise BackupFailures(failures)

    def occupy_second_port(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.blockers.append(blocker)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        return blocker.getsockname()[1]

    async def connect(self, listener="plain"):
        self.server.accepted.clear()
        options = {}
        if listener == "tls":
            context = ssl.create_default_context(
                cadata=CERTIFICATE.certificate_pem.decode("ascii")
            )
            context.set_alpn_protocols(["http/1.1"])
            options = {"ssl": context, "server_hostname": HOSTNAME}

        address = getattr(self.server, f"{listener}_address")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", address[1], **options), DEADLINE
        )
        self.clients.append(writer)
        self.client_readers.append(reader)
        await asyncio.wait_for(self.server.accepted.wait(), DEADLINE)
        return reader, writer, self.server.connections[-1]

    async def request(self, reader, writer, target, expected):
        writer.write(f"GET {target} HTTP/1.1\r\nHost: {HOSTNAME}\r\n\r\n".encode())
        await asyncio.wait_for(writer.drain(), DEADLINE)
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), DEADLINE)
        self.assertEqual(head, expected)

    async def pending_read(self, connection):
        await asyncio.wait_for(connection.reading.wait(), DEADLINE)
        self.assertFalse(connection.task.done())
        self.assertIsNotNone(connection.reader._waiter)
        self.assertFalse(connection.reader._waiter.done())

    async def completed_callback(self, connection):
        _, pending = await asyncio.wait({connection.task}, timeout=DEADLINE)
        self.assertEqual(pending, set(), "original accepted callback did not finish")

    def assert_causes(self, error, *expected):
        self.assertIsNotNone(error, "capture published without its original failure")
        found = []
        remaining = [error]
        while remaining:
            item = remaining.pop()
            if item is None or any(item is seen for seen in found):
                continue

            found.append(item)
            remaining.extend((item.__cause__, item.__context__))
            remaining.append(getattr(item, "primary", None))
            remaining.extend(getattr(item, "cleanup", ()))
            remaining.extend(getattr(item, "failures", ()))

        for cause in expected:
            if not any(cause is item for item in found):
                raise self.failureException(
                    f"capture lost original {type(cause).__name__} object"
                ) from error

    def driver(self, listener="plain", *, on_exit=None, close_client=False):
        @contextlib.asynccontextmanager
        async def drive(url):
            reader, writer, connection = await self.connect(listener)
            await self.request(reader, writer, "/missing", NOT_FOUND)
            connection.reading.clear()
            token = parse_qs(urlsplit(url).query)["run"][0]
            await self.request(reader, writer, f"/done?run={token}&code=1000", DONE)
            await self.pending_read(connection)

            try:
                yield
            finally:
                if on_exit is not None:
                    await on_exit(connection)
                if close_client:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), DEADLINE)
                    await self.completed_callback(connection)

        return drive

    async def capture(self, drive):
        return await http2_websocket.capture_scenario(
            self.server,
            http2_websocket.SCENARIOS["h1-accept"],
            repeat=1,
            run_timeout=DEADLINE,
            observation_seconds=0.0,
            drive=drive,
        )

    async def publish(self, drive):
        args = argparse.Namespace(
            browser="manual",
            listen="127.0.0.1",
            tls_port=0,
            plain_port=0,
            android_entry="intent",
            scenario=["h1-accept"],
            output_dir=Path(self.directory.name),
            repeat=1,
            run_timeout=DEADLINE,
            observation=0.0,
            client="ownership control",
            client_version="0",
            operating_system="test",
        )
        with (
            patch.object(
                http2_websocket, "generate_certificate", return_value=CERTIFICATE
            ),
            patch.object(http2_websocket, "CaptureServer", return_value=self.server),
            patch.object(
                http2_websocket, "BrowserDriver", side_effect=lambda _, url: drive(url)
            ),
        ):
            await asyncio.wait_for(http2_websocket.run(args), DEADLINE)

    async def test_failed_second_bind_closes_actual_first_listener(self):
        port = self.occupy_second_port()
        with self.assertRaises(OSError) as caught:
            await self.server.start("127.0.0.1", plain_port=port)

        self.assertIs(caught.exception, self.bind_failures[0])
        self.assertEqual(len(self.listeners), 1)
        self.assertFalse(self.listeners[0].is_serving())

    async def test_failed_bind_and_original_listener_wait_are_both_retained(self):
        port = self.occupy_second_port()
        wait_failure = RuntimeError("injected acquired listener wait failure")
        original_start = asyncio.BaseEventLoop.create_server
        waited = asyncio.Event()

        async def start(loop, *args, **kwargs):
            listener = await original_start(loop, *args, **kwargs)
            original_wait = listener.wait_closed

            async def wait_closed():
                await original_wait()
                waited.set()
                raise wait_failure

            self.patches.enter_context(
                patch.object(listener, "wait_closed", wait_closed)
            )
            return listener

        error = None
        with patch.object(asyncio.BaseEventLoop, "create_server", start):
            try:
                await self.server.start("127.0.0.1", plain_port=port)
            except BaseException as caught:
                error = caught

        self.assertEqual(len(self.bind_failures), 1)
        self.assert_causes(error, self.bind_failures[0], wait_failure)
        self.assertTrue(waited.is_set())
        self.assertFalse(self.listeners[0].is_serving())

    async def check_pending_callback(self, listener):
        await self.server.start("127.0.0.1")
        runs = await self.capture(self.driver(listener))

        self.assertEqual(len(runs), 1)
        self.assertEqual([request.status for request in runs[0].requests], [404, 204])

        [connection] = self.server.connections
        self.assertTrue(
            connection.task.done(), "run returned before its accepted callback"
        )
        self.assertTrue(connection.writer.is_closing())

        try:
            closed = await asyncio.wait_for(self.client_readers[0].read(1), DEADLINE)
        except DISCONNECTS:
            closed = b""
        self.assertEqual(closed, b"")

    async def test_plain_pending_callback_finishes_before_run_return(self):
        await self.check_pending_callback("plain")

    async def test_authenticated_tls_pending_callback_finishes_before_run_return(self):
        await self.check_pending_callback("tls")

    async def test_late_original_reader_failure_prevents_fixture_publication(self):
        failure = OSError(5, "injected accepted reader failure")

        async def fail(connection):
            connection.reader.set_exception(failure)
            await self.completed_callback(connection)
            self.assertIs(connection.read_failure, failure)

        error = None
        try:
            await self.publish(self.driver(on_exit=fail))
        except BaseException as caught:
            error = caught

        self.assert_causes(error, failure)
        self.assertFalse((Path(self.directory.name) / "h1-accept.txt").exists())

    async def test_failed_release_keeps_writer_and_both_original_causes(self):
        await self.server.start("127.0.0.1")
        self.server.run = CaptureRun(
            "0123456789abcdef", http2_websocket.SCENARIOS["h1-accept"].policy, {}
        )
        reader, writer, connection = await self.connect()
        await self.request(reader, writer, "/missing", NOT_FOUND)
        await self.pending_read(connection)

        read_failure = OSError(5, "injected original serving read failure")
        close_failure = RuntimeError("injected actual accepted writer close failure")
        self.expected_failures.append(close_failure)

        def fail_close():
            raise close_failure

        self.patches.enter_context(patch.object(connection.writer, "close", fail_close))
        connection.reader.set_exception(read_failure)
        await self.completed_callback(connection)
        self.assertIs(connection.read_failure, read_failure)
        self.assertIn(connection.writer, self.server.writers)

        error = None
        try:
            await asyncio.wait_for(self.server.close(), DEADLINE)
        except BaseException as caught:
            error = caught
        self.assert_causes(error, read_failure, close_failure)

    async def test_driver_abort_and_listener_wait_failures_do_not_skip_cleanup(self):
        primary = PermissionError("injected original driver exit failure")
        abort_failure = RuntimeError("injected accepted transport abort failure")
        wait_failure = RuntimeError("injected first listener wait failure")
        abort_called = asyncio.Event()
        wait_called = asyncio.Event()
        original_listener_wait = asyncio.Server.wait_closed

        async def wait_closed(listener):
            await original_listener_wait(listener)
            if listener is self.listeners[0]:
                wait_called.set()
                raise wait_failure

        self.patches.enter_context(
            patch.object(asyncio.Server, "wait_closed", wait_closed)
        )

        async def fail(connection):
            original_abort = connection.writer.transport.abort

            def abort():
                if not abort_called.is_set():
                    abort_called.set()
                    raise abort_failure

                original_abort()

            self.patches.enter_context(
                patch.object(connection.writer.transport, "abort", abort)
            )
            raise primary

        error = None
        try:
            await self.publish(self.driver(on_exit=fail))
        except BaseException as caught:
            error = caught

        self.assert_causes(error, primary, abort_failure, wait_failure)
        try:
            self.assertTrue(abort_called.is_set())
            self.assertTrue(wait_called.is_set())
            self.assertTrue(
                all(not listener.is_serving() for listener in self.listeners)
            )
            self.assertTrue(all(entry.task.done() for entry in self.server.connections))
            self.assertFalse((Path(self.directory.name) / "h1-accept.txt").exists())
        except AssertionError as validation:
            raise validation from error

    async def test_driver_and_actual_accepted_writer_wait_causes_both_survive(self):
        primary = PermissionError("injected original driver exit failure")
        wait_failure = ConnectionResetError(
            errno.EIO, "injected local writer wait failure"
        )
        waited = asyncio.Event()
        original_wait = asyncio.StreamWriter.wait_closed

        async def wait_closed(writer):
            await original_wait(writer)
            if any(writer is entry.writer for entry in self.server.connections):
                waited.set()
                raise wait_failure

        async def fail(_):
            raise primary

        error = None
        with patch.object(asyncio.StreamWriter, "wait_closed", wait_closed):
            try:
                await self.publish(self.driver(on_exit=fail))
            except BaseException as caught:
                error = caught

        self.assert_causes(error, primary, wait_failure)
        self.assertTrue(waited.is_set())
        self.assertTrue(all(entry.task.done() for entry in self.server.connections))
        self.assertFalse((Path(self.directory.name) / "h1-accept.txt").exists())

    async def test_healthy_peer_shutdown_keeps_ordinary_fixture_contract(self):
        await self.publish(self.driver(close_client=True))

        text = (Path(self.directory.name) / "h1-accept.txt").read_text(encoding="utf-8")
        self.assertIn("format=phantom-http2-websocket-v1\n", text)
        self.assertIn("repeat_count=1\n", text)
        self.assertIn("run_0_result_0=code=1000\n", text)

        self.assertEqual(len(self.server.connections), 1)
        self.assertTrue(self.server.connections[0].task.done())
        self.assertTrue(all(not listener.is_serving() for listener in self.listeners))

    async def test_local_request_error_with_peer_errno_keeps_its_original_cause(self):
        await self.server.start("127.0.0.1")
        self.server.begin_run(
            CaptureRun("local", http2_websocket.SCENARIOS["h1-accept"].policy, {})
        )
        _, writer, connection = await self.connect()
        failure = ConnectionResetError(
            errno.ECONNRESET, "original local request failure"
        )
        self.expected_failures.append(failure)
        with patch.object(Http1Session, "respond", side_effect=failure):
            writer.write(b"GET /missing HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n")
            await asyncio.wait_for(writer.drain(), DEADLINE)
            await self.completed_callback(connection)
        self.assertIs(connection.task.exception(), failure)
        self.server.run = None
        with self.assertRaises(ConnectionResetError) as caught:
            await self.server.close()
        self.assertIs(caught.exception, failure)

    async def test_cleanup_keeps_external_handler_cancellation_and_its_local_cause(
        self,
    ):
        await self.server.start("127.0.0.1")
        self.server.begin_run(
            CaptureRun("cancel", http2_websocket.SCENARIOS["h1-accept"].policy, {})
        )
        original_read = PlainChannel.read_raw
        interrupted = asyncio.Event()
        release = asyncio.Event()
        original = []
        secondary = []
        owned = []
        local = OSError(errno.EIO, "original cancellation cleanup failure")

        async def read(channel):
            try:
                return await original_read(channel)
            except asyncio.CancelledError as error:
                if not owned or channel.writer is not owned[0].writer:
                    raise
                original.append(error)
                interrupted.set()
                try:
                    await release.wait()
                except asyncio.CancelledError as cleanup:
                    secondary.append(cleanup)
                    raise_capture_failures(error, (cleanup, local))
                raise_capture_failures(error, (local,))

        try:
            with patch.object(PlainChannel, "read_raw", read):
                _, _, connection = await self.connect()
                owned.append(connection)
                await self.pending_read(connection)
                self.expected_cancellations.add(connection.task)
                connection.task.cancel("external cancellation")
                await asyncio.wait_for(interrupted.wait(), DEADLINE)
                self.assertIs(connection.read_failure, original[0])
                self.assertFalse(connection.task.done())

                with self.assertRaises(asyncio.CancelledError) as caught:
                    await self.server.stop_connections()
                self.assertIs(caught.exception, original[0])
                self.assertEqual(len(secondary), 1)
                self.assert_causes(caught.exception, original[0], secondary[0], local)
                self.assertTrue(connection.task.done())
        finally:
            release.set()
            self.server.run = None
            await self.server.close()

    async def test_delayed_native_callback_is_drained_before_the_next_run(self):
        await self.server.start("127.0.0.1")
        old = CaptureRun("old", http2_websocket.SCENARIOS["h1-accept"].policy, {})
        self.server.begin_run(old)
        delivered = asyncio.Event()
        stopping = asyncio.Event()
        held = []
        original_made = CaptureProtocol.connection_made
        original_stop = self.server._stop_connections

        def hold(protocol, transport):
            held.append((protocol, transport))
            delivered.set()

        async def stop():
            asyncio.get_running_loop().call_soon(stopping.set)
            return await original_stop()

        with patch.object(CaptureProtocol, "connection_made", hold):
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(*self.server.plain_address), DEADLINE
            )
            self.clients.append(writer)
            await asyncio.wait_for(delivered.wait(), DEADLINE)

        protocol, transport = held[0]
        self.server.run = None
        with patch.object(self.server, "_stop_connections", stop):
            cleanup = asyncio.create_task(self.server.stop_connections())
            try:
                await asyncio.wait_for(stopping.wait(), DEADLINE)
                self.assertTrue(protocol.stopping)
                self.assertFalse(cleanup.done())
                self.assertFalse(protocol.retired.done())
            finally:
                # Deliver the original callback before any backup can run.
                original_made(protocol, transport)
                await asyncio.wait_for(cleanup, DEADLINE)

        self.assertTrue(protocol.retired.done())
        self.assertEqual(old.connections, [])
        new = CaptureRun("new", http2_websocket.SCENARIOS["h1-accept"].policy, {})
        self.server.begin_run(new)
        reader, writer, connection = await self.connect()
        await self.request(reader, writer, "/missing", NOT_FOUND)
        self.assertEqual(len(new.connections), 1)
        self.assertEqual(old.connections, [])
        self.server.run = None
        await self.server.close()
        self.assertTrue(connection.task.done())

    async def test_native_pipelined_requests_stop_at_the_run_retention_limit(self):
        await self.server.start("127.0.0.1")
        run = CaptureRun("limit", http2_websocket.SCENARIOS["h1-accept"].policy, {})
        self.server.begin_run(run)
        _, writer, connection = await self.connect()
        request = b"GET /missing HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
        writer.write(request * 1025)
        await asyncio.wait_for(writer.drain(), DEADLINE)
        await self.completed_callback(connection)
        original = connection.task.exception()
        self.expected_failures.append(original)
        self.assertIsInstance(original, CaptureLimitError)
        self.assertEqual(len(run.requests), 1024)
        self.assertEqual(run.request_count, 1024)
        self.assertTrue(all(not listener.is_serving() for listener in self.listeners))
        self.server.run = None
        with self.assertRaises(CaptureLimitError) as caught:
            await self.server.close()
        self.assertIs(caught.exception, original)

    async def test_native_malformed_tls_remains_partial_capture_evidence(self):
        await self.server.start("127.0.0.1")
        run = self.server.run = CaptureRun(
            "0123456789abcdef", http2_websocket.SCENARIOS["h1-accept"].policy, {}
        )
        self.server.accepted.clear()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", self.server.tls_address[1]), DEADLINE
        )
        self.clients.append(writer)
        await asyncio.wait_for(self.server.accepted.wait(), DEADLINE)

        writer.write(b"not a TLS record")
        await asyncio.wait_for(writer.drain(), DEADLINE)
        await self.completed_callback(self.server.connections[0])

        await asyncio.wait_for(self.server.close(), DEADLINE)
        self.assertEqual(run.connections[0].failure, "SSLError")
        self.assertTrue(self.server.connections[0].task.done())
        self.assertTrue(all(not listener.is_serving() for listener in self.listeners))


if __name__ == "__main__":
    unittest.main()
