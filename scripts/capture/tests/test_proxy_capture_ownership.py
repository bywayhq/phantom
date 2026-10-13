"""Original proxy listener, connection task and cleanup failure ownership."""

import asyncio
import contextlib
import ssl
import unittest
from unittest.mock import patch

from h2.config import H2Configuration
from h2.connection import H2Connection

from scripts.capture.proxy_route import (
    PROXY_HOST,
    CaptureFailures,
    CaptureRun,
    CaptureServer,
    capture_scenario,
    generate_certificate,
)

CERTIFICATE = generate_certificate(PROXY_HOST)
DEADLINE = 10.0


class AcceptedServer(CaptureServer):
    """Observe the canonical callback without replacing its connection worker."""

    def __init__(self) -> None:
        super().__init__(CERTIFICATE)
        self.accepted = asyncio.Event()
        self.connections = []

    def accept(self, listener, reader, writer) -> None:
        reading = asyncio.Event()
        original = reader.read

        async def read(size=-1):
            reading.set()
            return await original(size)

        reader.read = read
        before = set(self.handlers)
        super().accept(listener, reader, writer)
        self.connections.append((reader, writer, set(self.handlers) - before, reading))
        self.accepted.set()


class CaptureOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = AcceptedServer()
        self.clients = []

    async def asyncTearDown(self) -> None:
        # Backups follow each captured target; they are not its exit oracle.
        for writer in self.clients:
            writer.close()
        for writer in self.clients:
            with contextlib.suppress(
                ConnectionResetError, ConnectionAbortedError, BrokenPipeError
            ):
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
        await self.server.close()

    async def connect(self, listener="http-proxy"):
        self.server.accepted.clear()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", self.server.addresses[listener][1]),
            DEADLINE,
        )
        self.clients.append(writer)
        await asyncio.wait_for(self.server.accepted.wait(), DEADLINE)
        accepted_reader, accepted_writer, tasks, reading = self.server.connections[-1]
        self.assertEqual(len(tasks), 1)
        await asyncio.wait_for(reading.wait(), DEADLINE)
        self.assertIsNotNone(accepted_reader._waiter)
        return reader, accepted_reader, accepted_writer, tasks.pop()

    async def start(self) -> None:
        await self.server.start("127.0.0.1")
        self.server.run = CaptureRun("0123456789abcdef", "http-proxy-hostname")

    async def test_partial_listener_acquisition_closes_original_listener(self) -> None:
        original = asyncio.start_server
        acquired = []
        failure = PermissionError("second listener acquisition")

        async def acquire(*args, **kwargs):
            if acquired:
                raise failure
            server = await original(*args, **kwargs)
            acquired.append(server)
            return server

        with (
            patch("asyncio.start_server", side_effect=acquire),
            self.assertRaises(PermissionError) as caught,
        ):
            await self.server.start("127.0.0.1")

        self.assertIs(caught.exception, failure)
        self.assertEqual(len(acquired), 1)
        self.assertFalse(acquired[0].is_serving())
        self.assertEqual(self.server.servers, [])
        self.assertEqual(self.server.listener_waits, {})

    async def test_acquisition_and_listener_cleanup_keep_original_causes(self) -> None:
        original = asyncio.start_server
        acquired = []
        primary = PermissionError("second listener acquisition")
        cleanup = RuntimeError("original listener cleanup")

        async def acquire(*args, **kwargs):
            if acquired:
                raise primary
            server = await original(*args, **kwargs)
            acquired.append(server)
            wait_closed = server.wait_closed

            async def fail_after_close():
                await wait_closed()
                raise cleanup

            patches.enter_context(patch.object(server, "wait_closed", fail_after_close))
            return server

        with (
            contextlib.ExitStack() as patches,
            patch("asyncio.start_server", side_effect=acquire),
            self.assertRaises(CaptureFailures) as caught,
        ):
            await self.server.start("127.0.0.1")

        self.assertIs(caught.exception.primary, primary)
        self.assertEqual(caught.exception.cleanup, (cleanup,))
        self.assertFalse(acquired[0].is_serving())

    async def test_pending_original_tls_handler_and_socket_stop_before_return(
        self,
    ) -> None:
        await self.start()
        reader, _, writer, task = await self.connect("https-proxy")
        self.assertFalse(task.done())

        await self.server.stop_connections()
        self.assertTrue(task.done())
        self.assertTrue(writer.is_closing())
        try:
            closed = await asyncio.wait_for(reader.read(1), DEADLINE)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            closed = b""
        self.assertEqual(closed, b"")
        self.assertEqual(self.server.handlers, {})
        self.assertEqual(self.server.writer_waits, {})

    async def test_two_completed_original_reader_failures_are_both_observed(
        self,
    ) -> None:
        await self.start()
        first = await self.connect()
        second = await self.connect()
        failures = (PermissionError("first reader"), RuntimeError("second reader"))
        for connection, failure in zip((first, second), failures, strict=True):
            connection[1].set_exception(failure)
        tasks = {first[3], second[3]}
        _, pending = await asyncio.wait(tasks, timeout=DEADLINE)
        self.assertEqual(pending, set())

        with self.assertRaises(CaptureFailures) as caught:
            await self.server.stop_connections()
        self.assertIsNone(caught.exception.primary)
        self.assertEqual(caught.exception.cleanup, failures)
        self.assertEqual(self.server.handlers, {})
        self.assertEqual(self.server.writer_waits, {})

    async def test_completed_foreign_handler_cancellation_is_not_local_cleanup(
        self,
    ) -> None:
        await self.start()
        _, _, _, task = await self.connect()
        task.cancel()
        _, pending = await asyncio.wait({task}, timeout=DEADLINE)
        self.assertEqual(pending, set())
        self.assertTrue(task.cancelled())

        with self.assertRaises(asyncio.CancelledError):
            await self.server.stop_connections()
        self.assertEqual(self.server.handlers, {})
        self.assertEqual(self.server.writer_waits, {})

    async def test_capture_does_not_return_runs_with_unobserved_handler_failure(
        self,
    ) -> None:
        await self.server.start("127.0.0.1")
        failure = PermissionError("actual accepted reader")
        owner = self

        class Driver:
            async def __aenter__(self):
                _, reader, _, task = await owner.connect()
                reader.set_exception(failure)
                _, pending = await asyncio.wait({task}, timeout=DEADLINE)
                owner.assertEqual(pending, set())
                owner.server.run.done.set()
                return self

            async def __aexit__(self, *details):
                pass

        with self.assertRaises(PermissionError) as caught:
            await capture_scenario(
                self.server,
                "http-proxy-hostname",
                repeat=1,
                run_timeout=DEADLINE,
                observation_seconds=0.0,
                drive=lambda _: Driver(),
            )
        self.assertIs(caught.exception, failure)
        self.assertIsNone(self.server.run)
        self.assertEqual(self.server.handlers, {})

    async def test_capture_operation_and_original_handler_failure_both_survive(
        self,
    ) -> None:
        await self.server.start("127.0.0.1")
        primary = PermissionError("driver operation")
        cleanup = RuntimeError("actual accepted reader")
        owner = self

        class Driver:
            async def __aenter__(self):
                _, reader, _, task = await owner.connect()
                reader.set_exception(cleanup)
                _, pending = await asyncio.wait({task}, timeout=DEADLINE)
                owner.assertEqual(pending, set())
                raise primary

            async def __aexit__(self, *details):
                pass

        with self.assertRaises(CaptureFailures) as caught:
            await capture_scenario(
                self.server,
                "http-proxy-hostname",
                repeat=1,
                run_timeout=DEADLINE,
                observation_seconds=0.0,
                drive=lambda _: Driver(),
            )
        self.assertIs(caught.exception.primary, primary)
        self.assertEqual(caught.exception.cleanup, (cleanup,))
        self.assertEqual(self.server.handlers, {})

    async def test_capture_timeout_keeps_partial_evidence_and_stops_actual_task(
        self,
    ) -> None:
        await self.server.start("127.0.0.1")
        owner = self
        accepted = []

        class Driver:
            async def __aenter__(self):
                accepted.append(await owner.connect("https-proxy"))
                return self

            async def __aexit__(self, *details):
                pass

        runs = await capture_scenario(
            self.server,
            "http-proxy-hostname",
            repeat=1,
            run_timeout=0.02,
            observation_seconds=0.0,
            drive=lambda _: Driver(),
        )
        self.assertEqual(len(runs), 1)
        self.assertTrue(runs[0].timed_out)
        self.assertEqual(len(runs[0].connections), 1)
        self.assertTrue(accepted[0][3].done())
        self.assertEqual(self.server.handlers, {})
        self.assertEqual(self.server.writer_waits, {})

    async def test_cleanup_deadline_retains_original_wait_owner_until_collection(
        self,
    ) -> None:
        await self.start()
        _, _, writer, task = await self.connect()
        wait_closed = writer.wait_closed
        completed_close = asyncio.Event()
        release = asyncio.Event()

        async def hold_after_original_close():
            await wait_closed()
            completed_close.set()
            await release.wait()

        with (
            patch.object(writer, "wait_closed", hold_after_original_close),
            patch("scripts.capture.proxy_route.CONNECTION_CLEANUP_SECONDS", 0.05),
        ):
            with self.assertRaises(asyncio.TimeoutError):
                await self.server.stop_connections()
            self.assertTrue(completed_close.is_set())
            self.assertTrue(task.done())
            self.assertTrue(writer.is_closing())
            self.assertEqual(len(self.server.writer_waits), 1)

            release.set()
            await self.server.stop_connections()
        self.assertEqual(self.server.writer_waits, {})

    async def test_native_peer_tls_rejection_remains_recorded_partial_evidence(
        self,
    ) -> None:
        await self.start()
        _, _, _, task = await self.connect("https-proxy")
        client = self.clients[-1]
        client.write(b"not a TLS record")
        await client.drain()
        _, pending = await asyncio.wait({task}, timeout=DEADLINE)
        self.assertEqual(pending, set())

        await self.server.stop_connections()
        self.assertEqual(self.server.run.connections[0].failure, "SSLError")
        self.assertEqual(self.server.handlers, {})

    async def test_accepted_task_acquisition_failure_closes_socket_and_keeps_cause(
        self,
    ) -> None:
        await self.start()
        failure = RuntimeError("original task acquisition")
        with patch(
            "scripts.capture.proxy_route.asyncio.create_task", side_effect=failure
        ):
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1", self.server.addresses["http-proxy"][1]
                ),
                DEADLINE,
            )
            self.clients.append(writer)
            await asyncio.wait_for(self.server.accepted.wait(), DEADLINE)

        self.assertEqual(self.server.accept_failures, [failure])
        self.assertEqual(self.server.handlers, {})
        with self.assertRaises(RuntimeError) as caught:
            await self.server.stop_connections()
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.server.writer_waits, {})
        self.assertEqual(self.server.writers, set())

    async def test_locally_cancelled_handler_keeps_its_original_close_failure(
        self,
    ) -> None:
        await self.start()
        _, _, writer, task = await self.connect()
        failure = RuntimeError("handler writer close")
        original_close = writer.close

        def close_then_fail():
            original_close()
            raise failure

        with (
            # Exercise the handler's actual close rather than the earlier abort.
            patch.object(writer.transport, "abort", return_value=None),
            patch.object(writer, "close", close_then_fail),
            self.assertRaises(RuntimeError) as caught,
        ):
            await self.server.stop_connections()

        self.assertIs(caught.exception, failure)
        self.assertTrue(task.done())
        self.assertEqual(self.server.handlers, {})
        self.assertEqual(self.server.writer_waits, {})

    async def test_actual_http2_request_reset_remains_expected_peer_behavior(
        self,
    ) -> None:
        await self.start()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2"])
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1",
                self.server.addresses["https-proxy"][1],
                ssl=context,
                server_hostname=PROXY_HOST,
            ),
            DEADLINE,
        )
        self.clients.append(writer)
        connection = H2Connection(H2Configuration(client_side=True))
        connection.initiate_connection()
        connection.send_headers(
            1,
            [
                (":method", "GET"),
                (":authority", "origin.phantom.test:9"),
                (":scheme", "http"),
                (":path", "/page?run=0123456789abcdef"),
            ],
            end_stream=True,
        )
        connection.reset_stream(1)
        writer.write(connection.data_to_send())
        await writer.drain()
        # The actual server settings prove the negotiated H2 worker ran.
        settings = await asyncio.wait_for(reader.read(65536), DEADLINE)
        self.assertTrue(settings)
        writer.close()
        tasks = self.server.connections[-1][2]
        self.assertEqual(len(tasks), 1)
        _, pending = await asyncio.wait(tasks, timeout=DEADLINE)
        self.assertEqual(pending, set())
        self.assertEqual(len(self.server.run.requests), 1)

        await self.server.stop_connections()
        self.assertEqual(self.server.run.connections[0].protocol, "h2")
        self.assertIn(
            self.server.run.connections[0].failure, (None, "StreamClosedError")
        )
        self.assertEqual(self.server.handlers, {})
