"""Race error controls retain real TLS/H2 traffic and original causes."""

import asyncio
import ssl
import traceback
import unittest
from unittest.mock import patch

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_accepted_lifecycle import AcceptedResources
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import (
    DATAGRAM,
    DEADLINE,
    HOST,
)


class LocalReadFailure(RuntimeError):
    pass


class ClassificationPeer:
    """Retain one actual H2 client alongside the existing resource backup."""

    def __init__(self):
        self.owners = AcceptedResources()
        self.resources = self.owners.resources
        self.peer = None
        self.reader = None
        self.writer = None
        self.client = None
        self.connections = {}
        self.exchanges = []
        self.failure = None
        self.capture_failure_traceback = ()
        self.reset = None
        self.closed_response = None
        self.reset_received = asyncio.Event()
        self.response_abandoned = asyncio.Event()
        self.window_received = asyncio.Event()
        self.send_failed = asyncio.Event()
        self.local_failure = LocalReadFailure("controlled accepted read failure")

    @property
    def connection(self):
        return self.connections[self.peer.task]

    def install(self):
        self.owners.install()
        actual_connection = race.H2Connection
        actual_receive = actual_connection.receive_data
        actual_headers = actual_connection.send_headers
        actual_data = actual_connection.send_data

        def observe_connection(config):
            connection = actual_connection(config)
            self.connections[asyncio.current_task()] = connection
            return connection

        def observe_receive(connection, data):
            events = actual_receive(connection, data)
            if self.peer is not None and connection is self.connection:
                for event in events:
                    if (
                        isinstance(event, h2.events.StreamReset)
                        and event.stream_id == 3
                    ):
                        self.reset = event
                        self.reset_received.set()
                    if (
                        isinstance(event, h2.events.RemoteSettingsChanged)
                        and connection.remote_settings.initial_window_size == 1
                    ):
                        self.window_received.set()
            return events

        def observe_headers(connection, stream_id, *args, **kwargs):
            try:
                return actual_headers(connection, stream_id, *args, **kwargs)
            except h2.exceptions.StreamClosedError as error:
                if (
                    self.peer is not None
                    and connection is self.connection
                    and stream_id == 3
                ):
                    self.closed_response = error
                    self.response_abandoned.set()
                raise

        def observe_data(connection, stream_id, *args, **kwargs):
            try:
                return actual_data(connection, stream_id, *args, **kwargs)
            except h2.exceptions.FlowControlError as error:
                if (
                    self.peer is not None
                    and connection is self.connection
                    and stream_id == 3
                ):
                    self.failure = error
                    self.resources.primary = error
                    self.send_failed.set()
                raise

        stack = self.resources.stack
        stack.enter_context(patch.object(race, "H2Connection", observe_connection))
        stack.enter_context(
            patch.object(actual_connection, "receive_data", observe_receive)
        )
        stack.enter_context(
            patch.object(actual_connection, "send_headers", observe_headers)
        )
        stack.enter_context(patch.object(actual_connection, "send_data", observe_data))

    async def open(self):
        server = self.resources.tcp[0]
        context = ssl.create_default_context()
        context.load_verify_locations(
            cadata=server.certificate.certificate_pem.decode()
        )
        context.set_alpn_protocols(["h2"])
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                HOST, server.origin.port, ssl=context, server_hostname=race.HOSTNAME
            ),
            DEADLINE,
        )
        self.resources.writers.append(self.writer)
        if self.writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
            raise AssertionError("retained client did not negotiate H2")
        address = self.writer.get_extra_info("sockname")

        async def accepted():
            while True:
                for peer in self.owners.peers:
                    if (
                        peer.writer.get_extra_info("peername") == address
                        and peer.task in self.connections
                    ):
                        return peer
                await asyncio.sleep(0)

        self.peer = await asyncio.wait_for(accepted(), DEADLINE)
        self.client = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True, header_encoding=None)
        )
        self.client.initiate_connection()
        await self.request(1, "/r/retained")
        await self.response(1, "/r/retained")
        if self.exchanges != [("/r/retained", b"200", b"ok")]:
            raise AssertionError(
                "retained H2 peer did not receive the literal response"
            )

    async def flush(self):
        self.writer.write(self.client.data_to_send())
        await asyncio.wait_for(self.writer.drain(), DEADLINE)

    async def request(self, stream_id, path):
        self.client.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (
                    b":authority",
                    f"{race.HOSTNAME}:{self.resources.tcp[0].origin.port}".encode(),
                ),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        await self.flush()

    async def response(self, stream_id, path):
        status = None
        body = bytearray()
        ended = False
        while not ended:
            data = await asyncio.wait_for(self.reader.read(65536), DEADLINE)
            if not data:
                raise EOFError("retained H2 response ended before END_STREAM")
            for event in self.client.receive_data(data):
                if isinstance(event, h2.events.DataReceived):
                    self.client.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    if event.stream_id == stream_id:
                        body.extend(event.data)
                elif (
                    isinstance(event, h2.events.ResponseReceived)
                    and event.stream_id == stream_id
                ):
                    status = dict(event.headers)[b":status"]
                elif (
                    isinstance(event, h2.events.StreamEnded)
                    and event.stream_id == stream_id
                ):
                    ended = True
            await self.flush()
        self.exchanges.append((path, status, bytes(body)))

    async def pending_read(self):
        async def inspect():
            while True:
                peer = self.peer
                if peer.task.done():
                    raise AssertionError(
                        "retained H2 handler ended before pending read"
                    )
                waiter = peer.reader._waiter
                if waiter is not None and not waiter.done() and not peer.reader._buffer:
                    return waiter
                await asyncio.sleep(0)

        return await asyncio.wait_for(inspect(), DEADLINE)

    async def capture(self, operation):
        self.owners.wrap_driver(operation)
        self.resources.capture = asyncio.create_task(self.resources.capture_run())
        result = None
        observed = None
        try:
            result = await asyncio.wait_for(self.resources.capture, 15)
        except BaseException as error:
            observed = error
            # A later backup await can replace the task exception's traceback.
            self.capture_failure_traceback = tuple(
                traceback.format_exception(type(error), error, error.__traceback__)
            )
        closed = await self.resources.closed_before_backup()
        return result, observed, closed

    async def backup(self):
        failures = []
        capture = self.resources.capture
        if capture is not None and not capture.done():
            capture.cancel()
            try:
                await asyncio.wait_for(capture, DEADLINE)
            except asyncio.CancelledError as error:
                self.resources.cancelled = error
            except BaseException as error:
                if error is not self.failure:
                    failures.append(error)

        if self.peer is not None and self.failure is not None:
            task = self.peer.task
            requested_abort = not task.done()
            if requested_abort:
                task.cancel()
            try:
                await asyncio.wait_for(task, DEADLINE)
            except asyncio.CancelledError as error:
                if not requested_abort:
                    failures.append(error)
            except BaseException as error:
                if error is self.failure:
                    # Only this exact observed task/cause leaves the backup roster.
                    self.resources.handlers[:] = [
                        handler
                        for handler in self.resources.handlers
                        if handler is not task
                    ]
                else:
                    failures.append(error)

        try:
            await self.owners.backup()
        except BaseException as error:
            failures.append(error)
        if failures:
            failure = AssertionError(
                f"classification resource backup failed: {failures!r}"
            )
            failure.failures = tuple(failures)
            raise failure from failures[0]


class ErrorClassificationTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self):
        controls = ClassificationPeer()
        self.addAsyncCleanup(controls.backup)
        controls.install()
        return controls

    def assert_traffic_and_cleanup(self, controls, closed):
        self.assertEqual(controls.exchanges, [("/r/retained", b"200", b"ok")])
        self.assertEqual(
            controls.resources.h2_exchanges,
            [("/r/startup", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
            "".join(controls.capture_failure_traceback),
        )
        self.assertEqual(
            controls.resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )
        self.assertEqual(controls.peer.record.alpn, "h2")
        self.assertIsNotNone(controls.peer.record.tls_ms)
        self.assertTrue(controls.peer.task.done())
        self.assertIsNotNone(controls.peer.record.closed_ms)
        self.assertTrue(controls.peer.writer.is_closing())
        self.assertFalse(controls.resources.tcp[0].handlers)
        self.assertFalse(controls.resources.tcp[0].writer_closures)
        self.assertTrue(closed, "capture left actual acquired listener resources open")
        self.assertIs(
            asyncio.get_running_loop().get_exception_handler(),
            controls.resources.previous_handler,
        )

    async def test_healthy_retained_h2_peer_finishes_without_a_capture_failure(self):
        controls = self.acquire()
        result, observed, closed = await controls.capture(controls.open)

        self.assert_traffic_and_cleanup(controls, closed)
        self.assertIsNone(observed)
        self.assertTrue(result.run.done.is_set())
        self.assertEqual(result.run.page_results, [])
        self.assertIsNone(controls.peer.record.failure)

    async def test_reset_held_stream_abandons_only_its_closed_response(self):
        controls = self.acquire()

        async def reset_peer():
            await controls.open()
            await controls.request(3, "/hold")

            async def held():
                origin = controls.resources.tcp[0].origin
                while not origin.holds:
                    if controls.peer.task.done():
                        raise AssertionError("held stream did not retain its response")
                    await asyncio.sleep(0)

            await asyncio.wait_for(held(), DEADLINE)
            controls.client.reset_stream(3)
            await controls.flush()
            await asyncio.wait_for(controls.reset_received.wait(), DEADLINE)

        result, observed, closed = await controls.capture(reset_peer)

        self.assert_traffic_and_cleanup(controls, closed)
        self.assertIsNotNone(controls.reset)
        self.assertTrue(controls.reset.remote_reset)
        self.assertEqual(controls.reset.stream_id, 3)
        self.assertTrue(controls.response_abandoned.is_set())
        self.assertIsInstance(controls.closed_response, h2.exceptions.StreamClosedError)
        self.assertEqual(controls.closed_response.stream_id, 3)
        self.assertEqual(
            [
                request.connection
                for request in result.run.requests
                if request.path == "/hold"
            ],
            [controls.peer.record.index],
        )
        self.assertIsNone(observed)
        self.assertTrue(result.run.done.is_set())
        self.assertIsNone(controls.peer.record.failure)

    async def test_unexpected_pending_read_failure_retains_its_original_cause(self):
        controls = self.acquire()
        read_waiter = []

        async def fail_read():
            await controls.open()
            waiter = await controls.pending_read()
            self.assertFalse(waiter.done())
            self.assertIs(controls.peer.task._fut_waiter, waiter)
            self.assertEqual(controls.peer.record.alpn, "h2")
            self.assertIsNotNone(controls.peer.record.tls_ms)
            self.assertIs(
                controls.resources.tcp[0].handlers[controls.peer.task],
                controls.peer.writer,
            )
            read_waiter.append(waiter)
            controls.failure = controls.local_failure
            controls.resources.primary = controls.failure
            controls.peer.reader.set_exception(controls.failure)
            await asyncio.wait_for(controls.peer.done.wait(), DEADLINE)

        _, observed, closed = await controls.capture(fail_read)

        self.assert_traffic_and_cleanup(controls, closed)
        self.assertEqual(len(read_waiter), 1)
        self.assertTrue(read_waiter[0].done())
        self.assertIs(controls.peer.reader.exception(), controls.local_failure)
        self.assertIs(
            observed,
            controls.local_failure,
            "capture discarded its actual pending-read failure",
        )

    async def test_legal_small_window_retains_the_actual_response_send_failure(self):
        controls = self.acquire()
        limited_request = []

        async def fail_send():
            await controls.open()
            controls.client.update_settings(
                {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1}
            )
            await controls.request(3, "/r/limited")
            await asyncio.wait_for(controls.window_received.wait(), DEADLINE)
            await asyncio.wait_for(controls.send_failed.wait(), DEADLINE)
            self.assertEqual(controls.connection.remote_settings.initial_window_size, 1)
            self.assertEqual(controls.connection.local_flow_control_window(3), 1)
            self.assertIsInstance(controls.failure, h2.exceptions.FlowControlError)
            self.assertIs(
                controls.resources.tcp[0].handlers[controls.peer.task],
                controls.peer.writer,
            )
            limited_request.extend(
                request
                for request in controls.resources.tcp[0].origin.run.requests
                if request.path == "/r/limited"
            )

        _, observed, closed = await controls.capture(fail_send)

        self.assert_traffic_and_cleanup(controls, closed)
        self.assertEqual(len(limited_request), 1)
        self.assertEqual(limited_request[0].connection, controls.peer.record.index)
        self.assertIsInstance(controls.failure, h2.exceptions.FlowControlError)
        self.assertIs(
            observed,
            controls.failure,
            "capture discarded the actual H2 response flow-control failure",
        )
        self.assertIsNotNone(controls.peer.record.failure)
