"""Run quotas guard actual accepted peers, routed requests and page results."""

import asyncio
import json
import ssl
import unittest
from unittest.mock import patch
from urllib.parse import quote

import h2.settings
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_h3_deferred_response_classification import (
    H3DeferredPeer,
)
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import DEADLINE, HOST


class LimitedCapture(H3DeferredPeer):
    def __init__(self):
        super().__init__()
        self.failure_received = asyncio.Event()
        self.failure = None
        self.accepts = []
        self.datagrams = []
        self.probe_datagram = None
        self.probe_sender = None
        self.datagram_received = asyncio.Event()
        self.before = None
        self.after = None
        self.rejected_reader = None
        self.rejected_writer = None
        self.rejected_eof = False
        self.pending_initial = None

    def install(self):
        super().install()
        actual_fail = race.Origin.fail
        actual_accept = race.Http2Origin.accept

        def observe_fail(origin, error):
            actual_fail(origin, error)
            self.failure = origin.failure
            self.peer.resources.primary = origin.failure
            self.failure_received.set()

        def observe_accept(server, reader, writer):
            self.accepts.append((server, reader, writer))
            actual_accept(server, reader, writer)

        stack = self.peer.resources.stack
        stack.enter_context(patch.object(race.Origin, "fail", observe_fail))
        stack.enter_context(patch.object(race.Http2Origin, "accept", observe_accept))

    def retained(self):
        resources = self.peer.resources
        origin = resources.tcp[0].origin
        alternative = resources.udp[0]
        return (
            origin.connections,
            len(origin.run.tcp),
            len(origin.run.udp),
            len(origin.run.requests),
            len(origin.holds),
            len(resources.tcp[0].handlers),
            len(resources.tcp[0].writer_closures),
            len(alternative.recorder.protocols),
            len(alternative.server._protocols),
            len(alternative.recorder.failures),
        )

    def observe_udp(self):
        server = self.peer.resources.udp[0].server
        actual_receive = server.datagram_received

        def observe(data, address):
            actual_receive(data, address)
            if data == self.probe_datagram:
                self.datagrams.append((data, address))
                self.datagram_received.set()

        self.peer.resources.stack.enter_context(
            patch.object(server, "datagram_received", observe)
        )

    async def send_initial(self):
        resources = self.peer.resources
        origin = resources.tcp[0].origin
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            server_name=race.HOSTNAME,
            verify_mode=ssl.CERT_REQUIRED,
            cadata=resources.tcp[0].certificate.certificate_pem,
        )
        connection = QuicConnection(configuration=configuration)
        self.pending_initial = connection
        connection.connect((HOST, origin.port), now=asyncio.get_running_loop().time())
        datagrams = connection.datagrams_to_send(now=asyncio.get_running_loop().time())
        if len(datagrams) != 1 or len(datagrams[0][0]) < 1200:
            raise AssertionError("actual QUIC client did not produce one full Initial")

        data, address = datagrams[0]
        self.probe_datagram = data
        for _ in range(3):
            self.datagram_received.clear()
            self.client_transport.sendto(data, address)
            await asyncio.wait_for(self.datagram_received.wait(), DEADLINE)

        if [received for received, _ in self.datagrams] != [data, data, data]:
            raise AssertionError(
                "actual server did not receive the three literal Initials"
            )

    async def run_case(self, case):
        controls = self
        resources = self.peer.resources
        if case in {"h3-connection", "tcp-connection"}:
            resources.stack.enter_context(patch.object(race, "MAX_RUN_CONNECTIONS", 2))
        if case == "udp-peer":
            resources.stack.enter_context(patch.object(race, "MAX_RUN_UDP_PEERS", 3))
        if case == "request":
            resources.stack.enter_context(patch.object(race, "MAX_RUN_REQUESTS", 3))
        if case in {"results", "results-boundary"}:
            resources.stack.enter_context(patch.object(race, "MAX_PAGE_RESULTS", 3))

        if case == "target":
            actual_connection = race.H2Connection

            def boundary_connection(config):
                connection = actual_connection(config)

                # Isolate Origin's target cap from HPACK's whole-header-list cap.
                values = dict(connection.local_settings)
                values[h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE] = 128 * 1024
                connection.local_settings = h2.settings.Settings(
                    client=config.client_side, initial_values=values
                )
                connection.decoder.max_header_list_size = 128 * 1024

                return connection

            resources.stack.enter_context(
                patch.object(race, "H2Connection", boundary_connection)
            )

        class LimitDriver:
            browser = None

            def __init__(driver, plan, url):
                driver.plan = plan
                driver.url = url

            async def __aenter__(driver):
                await controls.open_h3()
                origin = resources.tcp[0].origin
                if case in {"h3-connection", "tcp-connection", "request"}:
                    controls.client.change_connection_id()
                    response = await controls.client.get(origin.port, "/r/at-limit")
                    if response != ("/r/at-limit", b"200", b"ok"):
                        raise AssertionError(
                            "actual existing H3 CID did not keep routing"
                        )

                controls.before = controls.retained()
                if case == "h3-connection":
                    controls.observe_udp()
                    await controls.send_initial()
                elif case == "tcp-connection":
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(HOST, origin.port), DEADLINE
                    )
                    controls.rejected_reader = reader
                    controls.rejected_writer = writer
                    resources.writers.append(writer)
                    await asyncio.wait_for(controls.failure_received.wait(), DEADLINE)
                    try:
                        data = await asyncio.wait_for(reader.read(1), DEADLINE)
                    except (
                        ConnectionResetError,
                        ConnectionAbortedError,
                        BrokenPipeError,
                    ):
                        controls.rejected_eof = True
                    else:
                        if data:
                            raise AssertionError(
                                "rejected TCP peer received an application byte"
                            )
                        controls.rejected_eof = True
                elif case == "udp-peer":
                    controls.observe_udp()
                    sender = await race.bind_udp(HOST)
                    resources.senders.append(sender)
                    controls.probe_sender = sender
                    controls.probe_datagram = b"literal rejected UDP peer"

                    try:
                        for _ in range(3):
                            controls.datagram_received.clear()
                            sender.sendto(controls.probe_datagram, (HOST, origin.port))
                            await asyncio.wait_for(
                                controls.datagram_received.wait(), DEADLINE
                            )
                    finally:
                        sender.close()

                    if sender.fileno() != -1:
                        raise AssertionError("actual UDP probe sender remained open")
                elif case == "request":
                    controls.client.request(origin.port, "/hold")
                elif case in {"results", "results-boundary"}:
                    count = 3 if case == "results-boundary" else 4
                    target = "/done?results=" + quote(
                        json.dumps([{} for _ in range(count)])
                    )
                    if case == "results-boundary":
                        response = await controls.client.get(origin.port, target)
                        if response != (target, b"204", b""):
                            raise AssertionError(
                                "actual boundary /done did not receive 204"
                            )
                    else:
                        controls.client.request(origin.port, target)
                elif case == "json":
                    controls.client.request(origin.port, "/done?results=%5B")
                elif case == "result-object":
                    controls.client.request(origin.port, "/done?results=%7B%7D")
                elif case == "result-member":
                    controls.client.request(origin.port, "/done?results=%5Bnull%5D")
                elif case == "target":
                    # The pinned H3 encoder rejects this size before Origin sees it.
                    await controls.peer.open()

                    target = "/r/" + "x" * (65536 - 3)
                    await controls.peer.request(3, target)
                    await controls.peer.response(3, target)

                    response = controls.peer.exchanges[-1]
                    if response != (target, b"200", b"ok"):
                        raise AssertionError(
                            "actual 64 KiB target did not receive 200/ok"
                        )

                    controls.before = controls.retained()
                    await controls.peer.request(5, target + "x")

                if case != "results-boundary":
                    await asyncio.wait_for(controls.failure_received.wait(), DEADLINE)

                controls.after = controls.retained()
                return driver

            async def __aexit__(driver, *details):
                await controls.close_h3()

        resources.stack.enter_context(patch.object(race, "BrowserDriver", LimitDriver))
        return await self.capture_driver()

    async def backup(self):
        failures = []
        for server, _, writer in self.accepts:
            if writer in server.writers or writer in server.writer_closures:
                continue

            try:
                writer.transport.abort()
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass
            except BaseException as error:
                failures.append(error)

        try:
            await super().backup()
        except BaseException as error:
            failures.append(error)

        if failures:
            failure = AssertionError(f"race limit backup failed: {failures!r}")
            failure.failures = tuple(failures)
            raise failure from failures[0]


class RaceAdmissionLimitTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self):
        controls = LimitedCapture()
        self.addAsyncCleanup(controls.backup)
        controls.install()
        return controls

    def assert_failure(self, controls, result, observed, closed, message):
        self.assertIsNone(result)
        self.assertIsNotNone(controls.failure)
        self.assertIs(observed, controls.failure)
        self.assertIsInstance(observed, ValueError)
        self.assertEqual(str(observed), message)
        self.assertTrue(closed)
        self.assertTrue(controls.normal_client_closed)
        self.assertTrue(controls.normal_server_closed)
        self.assertEqual(controls.client_socket.fileno(), -1)
        self.assertTrue(controls.client_transport.is_closing())
        self.assertFalse(controls.peer.resources.tcp[0].handlers)
        self.assertFalse(controls.peer.resources.tcp[0].writer_closures)
        self.assertTrue(controls.peer.resources.udp[0].server._transport.is_closing())
        self.assertIn(controls.client.handshake.alpn_protocol, H3_ALPN)
        self.assertEqual(len(controls.server_protocols), 1)
        self.assertFalse(controls.server_protocols[0].peers.failures)
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
            controls.peer.resources.previous_handler,
        )

    def assert_no_allocations(self, controls):
        self.assertEqual(controls.before[:8], controls.after[:8])
        self.assertLessEqual(controls.after[8], controls.before[8])
        self.assertEqual(controls.before[9], controls.after[9])

    async def test_fresh_initials_on_trusted_socket_do_not_allocate_over_quota(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("h3-connection")

        self.assert_failure(
            controls,
            result,
            observed,
            closed,
            "race capture exceeds the per-run connection limit",
        )
        self.assert_no_allocations(controls)
        self.assertEqual(controls.before[:5], (2, 1, 3, 3, 0))
        self.assertEqual(len(controls.datagrams), 3)
        self.assertEqual(
            controls.h3_exchanges,
            [("/r/h3", b"200", b"ok"), ("/r/at-limit", b"200", b"ok")],
        )

    async def test_tcp_accept_shares_h3_quota_before_allocating_a_handler(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("tcp-connection")

        self.assert_failure(
            controls,
            result,
            observed,
            closed,
            "race capture exceeds the per-run connection limit",
        )
        self.assert_no_allocations(controls)
        self.assertTrue(controls.rejected_eof)
        self.assertEqual(len(controls.accepts), 2)
        self.assertTrue(controls.accepts[-1][2].is_closing())
        self.assertEqual(controls.before[:5], (2, 1, 3, 3, 0))

    async def test_rejected_udp_peers_do_not_grow_peer_or_failure_history(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("udp-peer")

        self.assert_failure(
            controls,
            result,
            observed,
            closed,
            "race capture exceeds the UDP peer limit",
        )
        self.assert_no_allocations(controls)
        self.assertEqual(controls.before[:5], (2, 1, 3, 2, 0))
        self.assertEqual(
            [data for data, _ in controls.datagrams],
            [b"literal rejected UDP peer"] * 3,
        )

        self.assertEqual(controls.probe_sender.fileno(), -1)

    async def test_request_overflow_does_not_retain_another_hold(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("request")

        self.assert_failure(
            controls,
            result,
            observed,
            closed,
            "race capture exceeds the per-run request limit",
        )
        self.assertEqual(controls.after[:5], controls.before[:5])
        run = controls.peer.resources.tcp[0].origin.run
        self.assertEqual(
            [request.path for request in run.requests],
            ["/r/startup", "/r/h3", "/r/at-limit"],
        )
        self.assertFalse(run.done.is_set())
        self.assertIsNone(run.page_results)

    async def test_result_overflow_does_not_publish_page_completion(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("results")

        self.assert_failure(
            controls,
            result,
            observed,
            closed,
            "race page results exceed the per-run result limit",
        )
        run = controls.peer.resources.tcp[0].origin.run
        self.assertFalse(run.done.is_set())
        self.assertIsNone(run.page_results)
        self.assertEqual(controls.h3_exchanges, [("/r/h3", b"200", b"ok")])

    async def test_boundary_results_receive_204_and_publish_the_original_array(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("results-boundary")

        self.assertIsNone(observed)
        self.assertIsNone(controls.failure)
        self.assertTrue(closed)
        self.assertTrue(result.run.done.is_set())
        self.assertEqual(result.run.page_results, [{}, {}, {}])
        self.assertEqual(controls.h3_exchanges[-1][1:], (b"204", b""))

    async def test_non_array_results_do_not_publish_page_completion(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("result-object")

        self.assert_failure(
            controls,
            result,
            observed,
            closed,
            "race page results must be an array",
        )
        run = controls.peer.resources.tcp[0].origin.run
        self.assertFalse(run.done.is_set())
        self.assertIsNone(run.page_results)
        self.assertEqual(controls.h3_exchanges, [("/r/h3", b"200", b"ok")])

    async def test_non_object_result_members_do_not_publish_page_completion(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("result-member")

        self.assert_failure(
            controls,
            result,
            observed,
            closed,
            "race page results must contain objects",
        )
        run = controls.peer.resources.tcp[0].origin.run
        self.assertFalse(run.done.is_set())
        self.assertIsNone(run.page_results)
        self.assertEqual(controls.h3_exchanges, [("/r/h3", b"200", b"ok")])

    async def test_malformed_done_json_retains_the_original_decoder_cause(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("json")

        self.assertIsNone(result)
        self.assertIs(observed, controls.failure)
        self.assertIsInstance(observed, json.JSONDecodeError)
        self.assertEqual(observed.doc, "[")
        self.assertEqual(observed.pos, 1)
        self.assertTrue(closed)
        run = controls.peer.resources.tcp[0].origin.run
        self.assertFalse(run.done.is_set())
        self.assertIsNone(run.page_results)

    async def test_target_boundary_allows_64_kib_and_rejects_the_next_wire_byte(self):
        controls = self.acquire()
        result, observed, closed = await controls.run_case("target")

        self.assert_failure(
            controls,
            result,
            observed,
            closed,
            "race request target exceeds the 64 KiB limit",
        )
        self.assertEqual(controls.after[:5], controls.before[:5])
        self.assertEqual(len(controls.peer.exchanges[-1][0]), 65536)
        self.assertEqual(controls.peer.exchanges[-1][1:], (b"200", b"ok"))

        self.assertEqual(controls.peer.connection.decoder.max_header_list_size, 131072)
        self.assertEqual(
            controls.peer.client.remote_settings.max_header_list_size, 131072
        )

        run = controls.peer.resources.tcp[0].origin.run
        self.assertEqual(len(run.requests[-1].path), 65536)
        self.assertEqual(run.requests[-1].transport, "h2")
