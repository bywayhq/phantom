"""Per-run proxy bounds and retirement of actual HTTP/2 tunnels."""

import asyncio
import contextlib
import ssl
import unittest
from unittest.mock import patch

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded

from scripts.capture.proxy_route import (
    MAX_RUN_CONNECTIONS,
    MAX_RUN_REMOTE_EVENTS,
    MAX_RUN_REQUESTS,
    MAX_RUN_RESULTS,
    PROXY_HOST,
    WEBSOCKET_MESSAGE,
    CaptureFailures,
    CaptureLimitError,
    CaptureRun,
    Http2Proxy,
    capture_scenario,
)
from scripts.capture.tests.test_proxy_capture_ownership import (
    DEADLINE,
    AcceptedServer,
)
from scripts.capture.tests.test_proxy_route import read_response, upgrade_request


class ProxyAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = AcceptedServer()
        self.clients = []
        await self.server.start("127.0.0.1")

    async def asyncTearDown(self) -> None:
        for writer in self.clients:
            writer.close()
        for writer in self.clients:
            with contextlib.suppress(
                ConnectionResetError, ConnectionAbortedError, BrokenPipeError
            ):
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
        await self.server.close()

    async def connect(self, listener="http-proxy", **options):
        self.server.accepted.clear()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1", self.server.addresses[listener][1], **options
            ),
            DEADLINE,
        )
        self.clients.append(writer)
        await asyncio.wait_for(self.server.accepted.wait(), DEADLINE)
        return reader, writer

    async def test_connection_saturation_closes_before_creating_a_handler(self) -> None:
        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        self.server.run = run
        for _ in range(MAX_RUN_CONNECTIONS):
            await self.connect()
            accepted_reader, _, tasks, reading = self.server.connections[-1]
            self.assertEqual(len(tasks), 1)
            await asyncio.wait_for(reading.wait(), DEADLINE)
            self.assertIsNotNone(accepted_reader._waiter)

        reader, _ = await self.connect()
        _, rejected, tasks, _ = self.server.connections[-1]
        self.assertEqual(tasks, set())
        self.assertNotIn(rejected, self.server.writers)
        with contextlib.suppress(
            ConnectionResetError, ConnectionAbortedError, BrokenPipeError
        ):
            self.assertEqual(await asyncio.wait_for(reader.read(1), DEADLINE), b"")
        self.assertTrue(rejected.is_closing())
        self.assertEqual(len(self.server.handlers), MAX_RUN_CONNECTIONS)
        self.assertEqual(len(self.server.writers), MAX_RUN_CONNECTIONS)
        self.assertEqual(len(run.connections), MAX_RUN_CONNECTIONS)
        self.assertEqual(run.admitted_connections, MAX_RUN_CONNECTIONS)
        self.assertIsInstance(run.limit_failure, CaptureLimitError)
        self.assertTrue(run.done.is_set())
        self.assertTrue(all(not server.is_serving() for server in self.server.servers))

    async def test_saturated_run_is_not_returned_as_a_capture(self) -> None:
        observed = []

        @contextlib.asynccontextmanager
        async def drive(_):
            observed.append(self.server.run)
            for _ in range(MAX_RUN_CONNECTIONS + 1):
                await self.connect()
            yield None

        with self.assertRaises(CaptureLimitError) as caught:
            await asyncio.wait_for(
                capture_scenario(
                    self.server,
                    "http-proxy-hostname",
                    repeat=1,
                    run_timeout=DEADLINE,
                    observation_seconds=0,
                    drive=drive,
                ),
                DEADLINE,
            )
        self.assertIs(caught.exception, observed[0].limit_failure)
        self.assertIsNone(self.server.run)
        self.assertEqual(self.server.handlers, {})
        self.assertEqual(self.server.writers, set())

    async def test_failed_rejection_keeps_the_socket_and_original_close_causes(
        self,
    ) -> None:
        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        self.server.run = run
        for _ in range(MAX_RUN_CONNECTIONS):
            await self.connect()

        listener_error = PermissionError("original admission close failure")
        abort_error = RuntimeError("original rejected socket abort failure")
        close_error = ValueError("original rejected writer close failure")
        accept = self.server.accept
        rejected = []
        listener = self.server.servers[0]

        def fail_rejection(name, reader, writer):
            rejected.append(writer)
            with (
                patch.object(listener, "close", side_effect=listener_error),
                patch.object(writer.transport, "abort", side_effect=abort_error),
                patch.object(writer, "close", side_effect=close_error),
            ):
                accept(name, reader, writer)

        with patch.object(self.server, "accept", side_effect=fail_rejection):
            reader, _ = await self.connect()

        self.assertEqual(len(rejected), 1)
        self.assertIn(rejected[0], self.server.writers)
        self.assertFalse(rejected[0].is_closing())
        self.assertTrue(listener.is_serving())
        self.assertEqual(len(self.server.handlers), MAX_RUN_CONNECTIONS)
        self.assertIs(self.server.admission_failure, listener_error)
        self.assertIs(self.server.rejection_failure, abort_error)
        self.assertIs(self.server.rejection_close_failure, close_error)

        with self.assertRaises(CaptureFailures) as caught:
            await asyncio.wait_for(self.server.stop_connections(), DEADLINE)
        self.assertIsNone(caught.exception.primary)
        self.assertEqual(len(caught.exception.cleanup), 3)
        for actual, original in zip(
            caught.exception.cleanup,
            (listener_error, abort_error, close_error),
            strict=True,
        ):
            self.assertIs(actual, original)
        self.assertTrue(rejected[0].is_closing())
        self.assertFalse(listener.is_serving())
        with contextlib.suppress(
            ConnectionResetError, ConnectionAbortedError, BrokenPipeError
        ):
            self.assertEqual(await asyncio.wait_for(reader.read(1), DEADLINE), b"")
        self.assertEqual(self.server.handlers, {})
        self.assertEqual(self.server.writers, set())

    async def test_request_limit_stops_the_original_http1_worker(self) -> None:
        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        self.server.run = run
        reader, writer = await self.connect()
        request = b"GET /x HTTP/1.1\r\nHost: origin.phantom.test:9\r\n\r\n"
        writer.write(request * MAX_RUN_REQUESTS)
        await asyncio.wait_for(writer.drain(), DEADLINE)
        for _ in range(MAX_RUN_REQUESTS):
            head, _ = await asyncio.wait_for(read_response(reader), DEADLINE)
            self.assertTrue(head.startswith(b"HTTP/1.1 404"))
        self.assertEqual(len(run.requests), MAX_RUN_REQUESTS)
        self.assertIsNone(run.limit_failure)

        writer.write(request)
        await asyncio.wait_for(writer.drain(), DEADLINE)
        self.assertEqual(await asyncio.wait_for(reader.read(1), DEADLINE), b"")
        self.assertEqual(len(run.requests), MAX_RUN_REQUESTS)
        self.assertIsInstance(run.limit_failure, CaptureLimitError)
        self.assertTrue(run.done.is_set())

        with self.assertRaises(CaptureLimitError) as caught:
            await self.server.stop_connections()
        self.assertIs(caught.exception, run.limit_failure)

    async def test_result_and_remote_event_records_stop_at_their_limits(self) -> None:
        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        for _ in range(MAX_RUN_RESULTS):
            run.finish({"websocket": "message"})
        with self.assertRaises(CaptureLimitError) as caught:
            run.finish({"websocket": "overflow"})
        self.assertIs(caught.exception, run.limit_failure)
        self.assertEqual(len(run.results), MAX_RUN_RESULTS)
        self.assertTrue(run.done.is_set())

        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        for _ in range(MAX_RUN_REMOTE_EVENTS):
            run.note("event:Fetch.authRequired,source:Proxy")
        with self.assertRaises(CaptureLimitError) as caught:
            run.note("overflow")
        self.assertIs(caught.exception, run.limit_failure)
        self.assertEqual(len(run.remote_events), MAX_RUN_REMOTE_EVENTS)
        self.assertTrue(run.done.is_set())

    async def test_request_limit_stops_the_original_http2_worker(self) -> None:
        run = CaptureRun("0123456789abcdef", "https-proxy-hostname")
        self.server.run = run
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2"])
        reader, writer = await self.connect(
            "https-proxy", ssl=context, server_hostname=PROXY_HOST
        )
        client = H2Connection(H2Configuration(client_side=True, header_encoding=None))
        client.initiate_connection()
        writer.write(client.data_to_send())

        async def exchange_requests():
            for index in range(MAX_RUN_REQUESTS):
                stream = index * 2 + 1
                client.send_headers(
                    stream,
                    [
                        (b":method", b"GET"),
                        (b":authority", b"origin.phantom.test:9"),
                        (b":scheme", b"http"),
                        (b":path", b"/x"),
                    ],
                    end_stream=True,
                )
                writer.write(client.data_to_send())
                completed = False
                while not completed:
                    data = await reader.read(65536)
                    self.assertTrue(data)
                    for event in client.receive_data(data):
                        if isinstance(event, ResponseReceived):
                            self.assertEqual(dict(event.headers)[b":status"], b"404")
                        elif (
                            isinstance(event, StreamEnded) and event.stream_id == stream
                        ):
                            completed = True

        await asyncio.wait_for(exchange_requests(), DEADLINE)
        self.assertEqual(len(run.requests), MAX_RUN_REQUESTS)
        self.assertIsNone(run.limit_failure)

        client.send_headers(
            MAX_RUN_REQUESTS * 2 + 1,
            [
                (b":method", b"GET"),
                (b":authority", b"origin.phantom.test:9"),
                (b":scheme", b"http"),
                (b":path", b"/x"),
            ],
            end_stream=True,
        )
        writer.write(client.data_to_send())
        self.assertEqual(await asyncio.wait_for(reader.read(1), DEADLINE), b"")
        self.assertEqual(len(run.requests), MAX_RUN_REQUESTS)
        self.assertIsInstance(run.limit_failure, CaptureLimitError)

        with self.assertRaises(CaptureLimitError) as caught:
            await self.server.stop_connections()
        self.assertIs(caught.exception, run.limit_failure)

    async def test_http2_end_and_reset_retire_tunnels_after_their_actual_writes(
        self,
    ) -> None:
        run = CaptureRun("0123456789abcdef", "https-proxy-hostname")
        self.server.run = run
        instances = []

        def observe(*args):
            proxy = Http2Proxy(*args)
            instances.append(proxy)
            return proxy

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2"])
        with patch("scripts.capture.proxy_route.Http2Proxy", side_effect=observe):
            reader, writer = await self.connect(
                "https-proxy", ssl=context, server_hostname=PROXY_HOST
            )
            client = H2Connection(
                H2Configuration(client_side=True, header_encoding=None)
            )
            client.initiate_connection()
            client.send_headers(
                1, [(b":method", b"CONNECT"), (b":authority", b"origin.phantom.test:9")]
            )
            client.send_headers(
                3,
                [(b":method", b"CONNECT"), (b":authority", b"background.example:443")],
            )
            writer.write(client.data_to_send())
            statuses = {}

            async def read_statuses():
                while len(statuses) < 2:
                    data = await reader.read(65536)
                    self.assertTrue(data)
                    for event in client.receive_data(data):
                        if isinstance(event, ResponseReceived):
                            statuses[event.stream_id] = dict(event.headers)[b":status"]

            await asyncio.wait_for(read_statuses(), DEADLINE)
            self.assertEqual(statuses, {1: b"200", 3: b"200"})
            self.assertEqual(set(instances[0].tunnels), {1, 3})

            client.send_data(
                1, upgrade_request(b"origin.phantom.test:9", run.token), end_stream=True
            )
            client.reset_stream(3)
            client.send_headers(
                5,
                [
                    (b":method", b"GET"),
                    (b":authority", b"origin.phantom.test:9"),
                    (b":scheme", b"http"),
                    (b":path", b"/x"),
                ],
                end_stream=True,
            )
            writer.write(client.data_to_send())
            body = bytearray()
            ended = set()

            async def read_completed():
                while not {1, 5}.issubset(ended):
                    data = await reader.read(65536)
                    self.assertTrue(data)
                    for event in client.receive_data(data):
                        if isinstance(event, DataReceived) and event.stream_id == 1:
                            body.extend(event.data)
                        elif isinstance(event, StreamEnded):
                            ended.add(event.stream_id)

            await asyncio.wait_for(read_completed(), DEADLINE)
            self.assertTrue(body.startswith(b"HTTP/1.1 101"))
            self.assertTrue(body.endswith(WEBSOCKET_MESSAGE))
            self.assertEqual(instances[0].tunnels, {})
            self.assertEqual(
                [request.stream_id for request in run.requests], [1, 3, 1, 5]
            )
