"""Authenticated H3 callbacks keep deferred failures on their actual owner."""

import asyncio
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

import h2.exceptions
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, FrameUnexpected, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_deferred_response_classification import (
    DeferredPeer,
)
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import (
    DATAGRAM,
    DEADLINE,
    HOST,
    ORIGINAL_UDP,
)


class H3ResponseClient(QuicConnectionProtocol):
    def __init__(self, connection, owner):
        super().__init__(connection)
        self.owner = owner
        owner.client = self
        self.handshake = None
        self.http = H3Connection(self._quic)
        self.responses = {}
        self.waiters = {}

    def connection_made(self, transport):
        self.owner.client_transport = transport
        super().connection_made(transport)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = event
        for received in self.http.handle_event(event):
            if not isinstance(received, (HeadersReceived, DataReceived)):
                continue
            response = self.responses.get(received.stream_id)
            if response is None:
                continue
            if isinstance(received, HeadersReceived):
                response[0] = dict(received.headers).get(b":status")
            else:
                response[1].extend(received.data)
            waiter = self.waiters[received.stream_id]
            if received.stream_ended and not waiter.done():
                waiter.set_result(None)

    async def get(self, port, path):
        stream_id = self.request(port, path)

        return await self.response(stream_id, path)

    def request(self, port, path):
        stream_id = self._quic.get_next_available_stream_id()
        response = [None, bytearray()]
        self.responses[stream_id] = response
        waiter = asyncio.get_running_loop().create_future()
        self.waiters[stream_id] = waiter
        self.http.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", f"{race.HOSTNAME}:{port}".encode()),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        self.transmit()
        return stream_id

    async def response(self, stream_id, path):
        waiter = self.waiters[stream_id]
        await asyncio.wait_for(waiter, DEADLINE)

        response = self.responses[stream_id]
        result = (path, response[0], bytes(response[1]))
        self.owner.h3_exchanges.append(result)
        return result


class H3DeferredPeer:
    def __init__(self):
        self.deferred = DeferredPeer()
        self.client = None
        self.client_socket = None
        self.client_transport = None
        self.connection_task = None
        self.connection_waiter = None
        self.server_protocols = []
        self.h3_exchanges = []
        self.contexts = []
        self.normal_client_closed = False
        self.normal_server_closed = False
        self.h3_failure = None
        self.h3_failure_received = asyncio.Event()
        self.h3_fault_calls = []
        self.h3_held_callback = None

    @property
    def peer(self):
        return self.deferred.peer

    def install(self):
        self.deferred.install()
        observed_udp = race.UdpAlternative
        actual_protocol = race.Http3Protocol
        controls = self

        class ValidOriginUdp(observed_udp):
            async def start(alternative, sock):
                if alternative.mode == "serve":
                    await ORIGINAL_UDP.start(alternative, sock)
                else:
                    await super().start(sock)

        class ObservedProtocol(actual_protocol):
            def __init__(protocol, *args, **kwargs):
                super().__init__(*args, **kwargs)
                controls.server_protocols.append(protocol)

        loop = asyncio.get_running_loop()
        actual_report = loop.call_exception_handler

        def observe_report(context):
            self.contexts.append(context)
            actual_report(context)

        stack = self.peer.resources.stack
        stack.enter_context(patch.object(race, "UdpAlternative", ValidOriginUdp))
        stack.enter_context(patch.object(race, "Http3Protocol", ObservedProtocol))
        stack.enter_context(
            patch.object(loop, "call_exception_handler", observe_report)
        )

    async def open_h3(self):
        server = self.peer.resources.tcp[0]
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            server_name=race.HOSTNAME,
            verify_mode=ssl.CERT_REQUIRED,
            cadata=server.certificate.certificate_pem,
        )
        connection = QuicConnection(configuration=configuration)
        self.client_socket = await race.bind_udp(HOST)
        transport, protocol = await asyncio.wait_for(
            asyncio.get_running_loop().create_datagram_endpoint(
                lambda: H3ResponseClient(connection, self), sock=self.client_socket
            ),
            DEADLINE,
        )
        if transport is not self.client_transport or protocol is not self.client:
            raise AssertionError(
                "actual client handles were not retained during acquisition"
            )
        protocol.connect((HOST, server.origin.port))
        self.connection_task = asyncio.create_task(protocol.wait_connected())
        await asyncio.sleep(0)
        self.connection_waiter = protocol._connected_waiter
        await asyncio.wait_for(self.connection_task, DEADLINE)
        response = await protocol.get(server.origin.port, "/r/h3")
        if response != ("/r/h3", b"200", b"ok"):
            raise AssertionError("actual trusted H3 peer did not receive 200/ok")

    async def close_h3(self):
        failures = []
        client = self.client
        transport = self.client_transport
        if client is not None and transport is not None:
            try:
                client.close()
            except BaseException as error:
                failures.append(error)
            try:
                await asyncio.wait_for(client.wait_closed(), DEADLINE)
            except BaseException as error:
                failures.append(error)
            try:
                for protocol in self.server_protocols:
                    try:
                        await asyncio.wait_for(protocol.wait_closed(), DEADLINE)
                    except BaseException as error:
                        failures.append(error)
            finally:
                try:
                    transport.close()
                except BaseException as error:
                    failures.append(error)
        self.normal_client_closed = client is not None and client._closed.is_set()
        self.normal_server_closed = bool(self.server_protocols) and all(
            protocol._closed.is_set() for protocol in self.server_protocols
        )
        if failures:
            failure = AssertionError(f"actual H3 client close failed: {failures!r}")
            failure.failures = tuple(failures)
            raise failure from failures[0]

    async def capture(self, limited):
        resources = self.peer.resources
        controls = self

        class H3Driver:
            browser = None

            def __init__(driver, plan, url):
                driver.plan = plan
                driver.url = url

            async def __aenter__(driver):
                await controls.deferred.hold(limited)
                if controls.deferred.read_waiter.done():
                    raise AssertionError("held H2 read completed before H3 release")
                if (
                    controls.peer.peer.task._fut_waiter
                    is not controls.deferred.read_waiter
                ):
                    raise AssertionError(
                        "canonical H2 task did not own its pending read"
                    )
                await resources.h2_exchange(resources.tcp[0], "/r/releaser")
                await controls.open_h3()
                if controls.peer.send_failed.is_set() or controls.deferred.releases:
                    raise AssertionError(
                        "held response failed or released before H3 /done"
                    )
                response = await controls.client.get(
                    resources.tcp[0].origin.port, "/done?results=%5B%5D"
                )
                if response != ("/done?results=%5B%5D", b"204", b""):
                    raise AssertionError("actual H3 release did not receive 204")
                if controls.deferred.response_task is not None:
                    await asyncio.wait_for(controls.deferred.response_task, DEADLINE)
                return driver

            async def __aexit__(driver, *details):
                await controls.close_h3()

        resources.stack.enter_context(patch.object(race, "BrowserDriver", H3Driver))
        return await self.capture_driver()

    async def capture_held_h3(self, case):
        resources = self.peer.resources
        controls = self
        actual_data = H3Connection.send_data
        actual_event = H3Connection.handle_event
        actual_request = race.Origin.request
        held_received = asyncio.Event()

        def observed_request(origin, transport, connection, target, respond, retire):
            result = actual_request(
                origin, transport, connection, target, respond, retire
            )
            if transport == "h3" and target == "/hold":
                held_received.set()
            return result

        def observed_data(http, stream_id, data, end_stream):
            protocol = (
                controls.server_protocols[0] if controls.server_protocols else None
            )
            if (
                protocol is not None
                and http is protocol.http
                and data == race.HOLD_BODY
            ):
                controls.h3_fault_calls.append(
                    (protocol, stream_id, protocol.origin.run.done.is_set())
                )
                if case == "held-failure":
                    # Send real trailing HEADERS, then let the real DATA validator fail.
                    http.send_headers(stream_id, [(b"x-end", b"closed")])

            try:
                return actual_data(http, stream_id, data, end_stream)
            except FrameUnexpected as error:
                if protocol is not None and http is protocol.http:
                    controls.h3_failure = error
                    resources.primary = error
                    controls.h3_failure_received.set()
                raise

        def observed_event(http, event):
            events = actual_event(http, event)
            protocol = (
                controls.server_protocols[0] if controls.server_protocols else None
            )
            if (
                case == "callback-failure"
                and protocol is not None
                and http is protocol.http
            ):
                for received in events:
                    if (
                        isinstance(received, HeadersReceived)
                        and dict(received.headers).get(b":path") == b"/r/callback-fault"
                    ):
                        error = OSError("controlled authenticated H3 event callback")
                        controls.h3_failure = error
                        resources.primary = error
                        controls.h3_fault_calls.append((protocol, received, False))
                        controls.h3_failure_received.set()
                        raise error

            return events

        resources.stack.enter_context(
            patch.object(H3Connection, "send_data", observed_data)
        )
        resources.stack.enter_context(
            patch.object(H3Connection, "handle_event", observed_event)
        )
        resources.stack.enter_context(
            patch.object(race.Origin, "request", observed_request)
        )

        class HeldH3Driver:
            browser = None

            def __init__(driver, plan, url):
                driver.plan = plan
                driver.url = url

            async def __aenter__(driver):
                await controls.open_h3()
                origin = resources.tcp[0].origin
                if case == "callback-failure":
                    controls.client.request(origin.port, "/r/callback-fault")
                    await asyncio.wait_for(
                        controls.h3_failure_received.wait(), DEADLINE
                    )
                    return driver

                stream_id = controls.client.request(origin.port, "/hold")

                await asyncio.wait_for(held_received.wait(), DEADLINE)
                if len(origin.holds) != 1:
                    raise AssertionError("actual H3 hold did not retain one callback")
                controls.h3_held_callback = origin.holds[0]
                if controls.client.waiters[stream_id].done() or controls.h3_fault_calls:
                    raise AssertionError(
                        "actual H3 held response completed before /done"
                    )

                response = await controls.client.get(
                    origin.port, "/done?results=%5B%5D"
                )
                if response != ("/done?results=%5B%5D", b"204", b""):
                    raise AssertionError("actual H3 release did not receive 204")

                if case == "healthy":
                    response = await controls.client.response(stream_id, "/hold")
                    if response != ("/hold", b"200", race.HOLD_BODY):
                        raise AssertionError(
                            "actual H3 hold did not receive its literal body"
                        )
                else:
                    await asyncio.wait_for(
                        controls.h3_failure_received.wait(), DEADLINE
                    )

                return driver

            async def __aexit__(driver, *details):
                await controls.close_h3()

        resources.stack.enter_context(patch.object(race, "BrowserDriver", HeldH3Driver))
        return await self.capture_driver()

    async def capture_driver(self):
        resources = self.peer.resources
        scenario = race.Scenario(
            "h3-release", "H3 held response", "serve", (), ("blackhole", "blackhole")
        )

        async def actual_capture():
            try:
                return await race.capture_run(
                    scenario,
                    listen_host=HOST,
                    browser="chrome",
                    executable=None,
                    headless=True,
                    netlog=Path("controlled-h3-release-netlog.json"),
                    timeout=DEADLINE,
                )
            except BaseException as error:
                resources.outcome = error
                raise

        resources.capture = asyncio.create_task(actual_capture())
        result = None
        observed = None
        try:
            result = await asyncio.wait_for(resources.capture, 20)
        except BaseException as error:
            observed = error
        closed = await resources.closed_before_backup()
        return result, observed, closed

    async def backup(self):
        failures = []
        try:
            await self.close_h3()
        except BaseException as error:
            failures.append(error)
        if self.client is not None:
            for handle in (self.client._timer, self.client._transmit_task):
                if handle is not None:
                    try:
                        handle.cancel()
                    except BaseException as error:
                        failures.append(error)
            for waiter in getattr(self.client, "waiters", {}).values():
                if not waiter.done():
                    try:
                        waiter.cancel()
                    except BaseException as error:
                        failures.append(error)
        for protocol in self.server_protocols:
            for handle in (protocol._timer, protocol._transmit_task):
                if handle is not None:
                    try:
                        handle.cancel()
                    except BaseException as error:
                        failures.append(error)
        if self.connection_task is not None:
            requested_abort = not self.connection_task.done()
            if requested_abort:
                self.connection_task.cancel()
            try:
                await asyncio.wait_for(self.connection_task, DEADLINE)
            except asyncio.CancelledError as error:
                if not requested_abort:
                    failures.append(error)
            except BaseException as error:
                failures.append(error)
        if (
            self.connection_waiter is not None
            and self.connection_waiter.done()
            and not self.connection_waiter.cancelled()
        ):
            error = self.connection_waiter.exception()
            if error is not None:
                failures.append(error)
        try:
            await self.deferred.backup()
        except BaseException as error:
            failures.append(error)
        if failures:
            failure = AssertionError(
                f"H3 deferred response backup failed: {failures!r}"
            )
            failure.failures = tuple(failures)
            raise failure from failures[0]


class H3DeferredResponseClassificationTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self):
        controls = H3DeferredPeer()
        self.addAsyncCleanup(controls.backup)
        controls.install()
        return controls

    def assert_trigger_and_cleanup(self, controls, closed):
        peer = controls.peer
        server = peer.resources.tcp[0]
        self.assertEqual(len(controls.deferred.releases), 1)
        origin, transport, connection, task, callbacks = controls.deferred.releases[0]
        self.assertIs(origin, server.origin)
        self.assertEqual(transport, "h3")
        self.assertIsNone(task)
        self.assertEqual(callbacks, (controls.deferred.held_callback,))
        self.assertEqual(len(controls.server_protocols), 1)
        protocol = controls.server_protocols[0]
        self.assertIs(protocol.origin, origin)
        self.assertIsNot(protocol.peer, peer.peer.record)
        self.assertEqual(protocol.peer.index, connection)
        self.assertEqual(protocol.peer.listener, "origin")
        self.assertIsNotNone(protocol.peer.handshake_ms)
        self.assertIsNotNone(protocol.peer.closed_ms)
        self.assertEqual(protocol.peer.close_reason, "0x0")
        self.assertIsNotNone(controls.client.handshake)
        self.assertIn(controls.client.handshake.alpn_protocol, H3_ALPN)
        self.assertEqual(protocol.peer.requests, 2)
        self.assertGreater(protocol.peer.datagrams, 0)
        self.assertIs(
            origin.run.udp[("origin", protocol._quic._network_paths[0].addr[:2])],
            protocol.peer,
        )
        self.assertEqual(
            controls.h3_exchanges,
            [("/r/h3", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
        )
        self.assertEqual(
            peer.resources.h2_exchanges,
            [("/r/startup", b"200", b"ok"), ("/r/releaser", b"200", b"ok")],
        )
        self.assertEqual(
            peer.resources.received,
            {name: [DATAGRAM] for name in ("earlier-0", "earlier-1")},
        )
        self.assertEqual(
            [
                (request.path, request.transport, request.connection)
                for request in origin.run.requests
                if request.path in {"/hold", "/done"}
            ],
            [("/hold", "h2", peer.peer.record.index), ("/done", "h3", connection)],
        )
        self.assertFalse(origin.holds)
        self.assertTrue(controls.normal_client_closed)
        self.assertTrue(controls.normal_server_closed)
        self.assertTrue(controls.client_transport.is_closing())
        self.assertEqual(controls.client_socket.fileno(), -1)
        self.assertTrue(peer.resources.udp[0].server._transport.is_closing())
        self.assertTrue(peer.peer.task.done())
        self.assertTrue(controls.deferred.read_waiter.done())
        self.assertEqual(peer.peer.record.alpn, "h2")
        self.assertIsNotNone(peer.peer.record.tls_ms)
        self.assertIsNotNone(peer.peer.record.closed_ms)
        self.assertTrue(peer.peer.writer.is_closing())
        self.assertFalse(server.handlers)
        self.assertFalse(server.writer_closures)
        self.assertTrue(
            any(owner is server for owner, _ in controls.deferred.collected)
        )
        self.assertTrue(closed)
        self.assertTrue(
            all(
                isinstance(
                    context.get("exception"),
                    (ConnectionResetError, ConnectionAbortedError),
                )
                for context in controls.contexts
            )
        )
        self.assertIs(
            asyncio.get_running_loop().get_exception_handler(),
            peer.resources.previous_handler,
        )
        return server

    async def test_h3_done_releases_the_original_healthy_held_h2_response(self):
        controls = self.acquire()
        result, observed, closed = await controls.capture(limited=False)

        self.assert_trigger_and_cleanup(controls, closed)
        self.assertEqual(
            controls.peer.exchanges,
            [("/r/retained", b"200", b"ok"), ("/hold", b"200", race.HOLD_BODY)],
        )
        self.assertIsNone(observed)
        self.assertTrue(result.run.done.is_set())
        self.assertIsNone(controls.peer.peer.record.failure)

    async def test_h3_done_keeps_the_actual_held_h2_send_failure_on_its_original_owner(
        self,
    ):
        controls = self.acquire()
        _, observed, closed = await controls.capture(limited=True)

        server = self.assert_trigger_and_cleanup(controls, closed)
        self.assertEqual(controls.peer.exchanges, [("/r/retained", b"200", b"ok")])
        self.assertTrue(controls.peer.send_failed.is_set())
        self.assertIsInstance(controls.peer.failure, h2.exceptions.FlowControlError)
        self.assertEqual(controls.peer.connection.local_flow_control_window(3), 1)
        self.assertIs(
            observed,
            controls.peer.failure,
            "H3 release lost the original H2 response cause",
        )
        self.assertEqual(controls.peer.peer.record.failure, "FlowControlError")
        self.assertEqual(
            sum(
                error is controls.peer.failure
                for owner, failures in controls.deferred.collected
                if owner is server
                for error in failures
            ),
            1,
        )
        self.assertFalse(server.response_failures)

    def assert_h3_owner_cleanup(self, controls, closed):
        resources = controls.peer.resources
        self.assertTrue(closed)
        self.assertTrue(controls.normal_client_closed)
        self.assertTrue(controls.normal_server_closed)
        self.assertEqual(controls.client_socket.fileno(), -1)
        self.assertTrue(controls.client_transport.is_closing())
        self.assertTrue(resources.udp[0].server._transport.is_closing())
        self.assertFalse(resources.tcp[0].handlers)
        self.assertFalse(resources.tcp[0].writer_closures)

        self.assertEqual(resources.h2_exchanges, [("/r/startup", b"200", b"ok")])

        self.assertEqual(len(controls.server_protocols), 1)
        protocol = controls.server_protocols[0]
        self.assertIsNotNone(protocol.peer.handshake_ms)
        self.assertIsNotNone(protocol.peer.closed_ms)
        self.assertEqual(protocol.peer.close_reason, "0x0")
        self.assertIsNone(protocol._timer)
        self.assertIsNone(protocol._transmit_task)
        self.assertIn(controls.client.handshake.alpn_protocol, H3_ALPN)

        self.assertTrue(
            all(
                isinstance(
                    context.get("exception"),
                    (ConnectionResetError, ConnectionAbortedError),
                )
                for context in controls.contexts
            )
        )
        self.assertIs(
            asyncio.get_running_loop().get_exception_handler(),
            resources.previous_handler,
        )
        return protocol

    async def test_h3_done_releases_the_actual_healthy_held_h3_body(self):
        controls = self.acquire()
        result, observed, closed = await controls.capture_held_h3("healthy")

        protocol = self.assert_h3_owner_cleanup(controls, closed)
        self.assertIsNone(observed)
        self.assertTrue(result.run.done.is_set())
        self.assertEqual(
            controls.h3_exchanges,
            [
                ("/r/h3", b"200", b"ok"),
                ("/done?results=%5B%5D", b"204", b""),
                ("/hold", b"200", race.HOLD_BODY),
            ],
        )
        self.assertEqual(controls.h3_fault_calls, [(protocol, 4, True)])
        self.assertEqual(controls.deferred.releases[0][4], (controls.h3_held_callback,))
        self.assertFalse(protocol.origin.holds)

    async def test_h3_done_retains_the_original_h3_data_failure_after_page_completion(
        self,
    ):
        controls = self.acquire()
        result, observed, closed = await controls.capture_held_h3("held-failure")

        self.assertIsNone(result)
        self.assertIs(observed, controls.h3_failure)
        self.assertIsInstance(observed, FrameUnexpected)
        self.assertEqual(
            observed.reason_phrase, "DATA frame is not allowed in this state"
        )

        protocol = self.assert_h3_owner_cleanup(controls, closed)
        self.assertTrue(protocol.origin.run.done.is_set())
        self.assertEqual(controls.h3_fault_calls, [(protocol, 4, True)])
        self.assertEqual(
            controls.h3_exchanges,
            [("/r/h3", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
        )
        self.assertEqual(controls.deferred.releases[0][4], (controls.h3_held_callback,))
        self.assertFalse(protocol.origin.holds)

    async def test_authenticated_h3_callback_failure_wakes_capture_without_page_completion(
        self,
    ):
        controls = self.acquire()
        result, observed, closed = await controls.capture_held_h3("callback-failure")

        self.assertIsNone(result)
        self.assertIs(observed, controls.h3_failure)
        self.assertIsInstance(observed, OSError)

        protocol = self.assert_h3_owner_cleanup(controls, closed)
        self.assertFalse(protocol.origin.run.done.is_set())
        self.assertEqual(controls.h3_exchanges, [("/r/h3", b"200", b"ok")])

        self.assertEqual(len(controls.h3_fault_calls), 1)
        owner, request, completed = controls.h3_fault_calls[0]
        self.assertIs(owner, protocol)
        self.assertEqual(dict(request.headers)[b":path"], b"/r/callback-fault")
        self.assertFalse(completed)
