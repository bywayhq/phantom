"""Fatal race failures stop repeated work and retain actual cleanup owners."""

import asyncio
import unittest
from unittest.mock import patch

from aioquic.h3.connection import FrameUnexpected, H3Connection

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_admission_limits import LimitedCapture
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import DEADLINE, HOST


class FailedRejection(LimitedCapture):
    def __init__(self):
        super().__init__()
        self.close_error = OSError("controlled actual listener close failure")
        self.abort_error = OSError("controlled actual rejected writer abort failure")
        self.close_calls = 0
        self.abort_calls = []
        self.rejected = []
        self.rejected_readers = []
        self.accepted = asyncio.Event()
        self.owned_before_cleanup = None
        self.errors_before_cleanup = None

    async def capture(self):
        controls = self
        resources = self.peer.resources
        resources.stack.enter_context(patch.object(race, "MAX_RUN_CONNECTIONS", 2))

        class RejectionDriver:
            browser = None

            def __init__(driver, plan, url):
                driver.plan = plan
                driver.url = url

            async def __aenter__(driver):
                await controls.open_h3()
                server = resources.tcp[0]
                actual_close = server.server.close
                actual_accept = race.Http2Origin.accept

                def close_listener():
                    controls.close_calls += 1
                    if controls.close_calls == 1:
                        raise controls.close_error

                    actual_close()

                def accept(owner, reader, writer):
                    if owner is server:
                        controls.rejected.append(writer)
                        if len(controls.rejected) <= 2:
                            actual_abort = writer.transport.abort
                            attempted = False

                            def abort():
                                nonlocal attempted
                                controls.abort_calls.append(writer)
                                if not attempted:
                                    attempted = True
                                    raise controls.abort_error

                                actual_abort()

                            resources.stack.enter_context(
                                patch.object(writer.transport, "abort", abort)
                            )

                    actual_accept(owner, reader, writer)
                    controls.accepted.set()

                resources.stack.enter_context(
                    patch.object(server.server, "close", close_listener)
                )
                resources.stack.enter_context(
                    patch.object(race.Http2Origin, "accept", accept)
                )
                for _ in range(3):
                    controls.accepted.clear()
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(HOST, server.origin.port), DEADLINE
                    )
                    controls.rejected_readers.append(reader)
                    resources.writers.append(writer)
                    await asyncio.wait_for(controls.accepted.wait(), DEADLINE)

                controls.owned_before_cleanup = tuple(
                    writer in server.writers
                    and server.writer_closures.get(writer) is not None
                    and not writer.is_closing()
                    for writer in controls.rejected[:2]
                )
                controls.errors_before_cleanup = tuple(server.accept_failures)
                if controls.close_calls != 1:
                    raise AssertionError("rejections retried the stopped listener")
                if any(
                    writer in server.handlers.values() for writer in controls.rejected
                ):
                    raise AssertionError(
                        "rejected TCP writers acquired serving handlers"
                    )
                if len(server.origin.run.tcp) != 1 or server.origin.connections != 2:
                    raise AssertionError(
                        "rejected TCP writers acquired capture records"
                    )

                return driver

            async def __aexit__(driver, *details):
                await controls.close_h3()

        resources.stack.enter_context(
            patch.object(race, "BrowserDriver", RejectionDriver)
        )
        result = await self.capture_driver()
        if result[1] is not None:
            resources.primary = result[1]

        return result


class FailedHeldResponse(LimitedCapture):
    def __init__(self):
        super().__init__()
        self.fatal_packet = None
        self.fault_calls = []
        self.cleanup_error = OSError("controlled actual UDP transport close failure")
        self.cleanup_calls = 0
        self.after_fatal = None
        self.after_repeats = None

    async def capture(self, *, cleanup_fault):
        controls = self
        resources = self.peer.resources
        actual_data = H3Connection.send_data
        actual_request = race.Origin.request
        held_received = asyncio.Event()

        def observed_request(origin, transport, connection, target, respond, retire):
            result = actual_request(
                origin, transport, connection, target, respond, retire
            )
            if transport == "h3" and target == "/hold":
                held_received.set()
            return result

        resources.stack.enter_context(
            patch.object(race.Origin, "request", observed_request)
        )

        def send_data(http, stream_id, data, end_stream):
            protocol = (
                controls.server_protocols[0] if controls.server_protocols else None
            )
            if (
                protocol is not None
                and http is protocol.http
                and data == race.HOLD_BODY
            ):
                controls.fault_calls.append((protocol, stream_id))
                http.send_headers(stream_id, [(b"x-end", b"closed")])

            return actual_data(http, stream_id, data, end_stream)

        resources.stack.enter_context(
            patch.object(H3Connection, "send_data", send_data)
        )

        class FatalDriver:
            browser = None

            def __init__(driver, plan, url):
                driver.plan = plan
                driver.url = url

            async def __aenter__(driver):
                await controls.open_h3()
                alternative = resources.udp[0]
                origin = resources.tcp[0].origin
                actual_receive = alternative.server.datagram_received

                def receive(data, address):
                    previous = alternative.recorder.fatal_failure
                    actual_receive(data, address)
                    if (
                        previous is None
                        and alternative.recorder.fatal_failure is not None
                    ):
                        controls.fatal_packet = (data, address)
                    elif (
                        controls.fatal_packet is not None
                        and data == controls.fatal_packet[0]
                    ):
                        controls.datagrams.append((data, address))
                        controls.datagram_received.set()

                resources.stack.enter_context(
                    patch.object(alternative.server, "datagram_received", receive)
                )
                stream_id = controls.client.request(origin.port, "/hold")

                await asyncio.wait_for(held_received.wait(), DEADLINE)
                if len(origin.holds) != 1 or controls.client.waiters[stream_id].done():
                    raise AssertionError(
                        "actual held H3 response did not remain pending"
                    )
                target = "/done?results=%5B%5D"
                response = await controls.client.get(origin.port, target)
                if response != (target, b"204", b""):
                    raise AssertionError(
                        "actual H3 /done did not receive its original 204"
                    )
                await asyncio.wait_for(controls.failure_received.wait(), DEADLINE)

                if controls.fatal_packet is None:
                    raise AssertionError("actual fatal H3 datagram was not observed")

                controls.after_fatal = (
                    *controls.retained(),
                    tuple(peer.datagrams for peer in origin.run.udp.values()),
                )
                data, _ = controls.fatal_packet
                for _ in range(3):
                    controls.datagram_received.clear()
                    controls.client_transport.sendto(data, (HOST, origin.port))
                    await asyncio.wait_for(controls.datagram_received.wait(), DEADLINE)

                controls.after_repeats = (
                    *controls.retained(),
                    tuple(peer.datagrams for peer in origin.run.udp.values()),
                )
                if cleanup_fault:
                    actual_close = alternative.server._transport.close

                    def close_transport():
                        controls.cleanup_calls += 1
                        actual_close()
                        if controls.cleanup_calls == 1:
                            raise controls.cleanup_error

                    resources.stack.enter_context(
                        patch.object(
                            alternative.server._transport, "close", close_transport
                        )
                    )

                return driver

            async def __aexit__(driver, *details):
                await controls.close_h3()

        resources.stack.enter_context(patch.object(race, "BrowserDriver", FatalDriver))
        result = await self.capture_driver()
        if result[1] is not None:
            resources.primary = result[1]

        return result


class RaceFatalOwnershipTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self, kind):
        controls = kind()
        self.addAsyncCleanup(controls.backup)
        controls.install()
        return controls

    async def test_failed_rejected_aborts_remain_owned_and_repeat_errors_stay_bounded(
        self,
    ):
        controls = self.acquire(FailedRejection)
        result, observed, closed = await controls.capture()

        self.assertIsNone(result)
        self.assertIsInstance(observed, race.CaptureCleanupError)
        self.assertEqual(observed.failures[1:], (controls.failure,))
        self.assertEqual(
            observed.failures[0].failures, (controls.close_error, controls.abort_error)
        )
        self.assertEqual(controls.owned_before_cleanup, (True, True))
        self.assertEqual(
            controls.errors_before_cleanup, (controls.close_error, controls.abort_error)
        )
        self.assertEqual(controls.close_calls, 2)
        self.assertEqual(len(controls.rejected), 3)
        self.assertEqual(controls.abort_calls[:2], controls.rejected[:2])
        self.assertEqual(len(controls.abort_calls), 4)
        self.assertTrue(all(writer.is_closing() for writer in controls.rejected))
        server = controls.peer.resources.tcp[0]
        self.assertFalse(server.writers)
        self.assertFalse(server.writer_closures)
        self.assertFalse(server.handlers)
        self.assertTrue(closed)
        self.assertTrue(controls.normal_client_closed)
        self.assertTrue(controls.normal_server_closed)

        for reader in controls.rejected_readers:
            try:
                data = await asyncio.wait_for(reader.read(1), DEADLINE)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                continue

            self.assertEqual(data, b"")

    def assert_fatal(self, controls, closed):
        self.assertIsInstance(controls.failure, FrameUnexpected)
        self.assertEqual(
            controls.failure.reason_phrase, "DATA frame is not allowed in this state"
        )
        self.assertEqual(len(controls.fault_calls), 1)
        self.assertEqual(controls.datagrams, [controls.fatal_packet] * 3)
        self.assertEqual(controls.after_fatal[:8], controls.after_repeats[:8])
        self.assertLessEqual(controls.after_repeats[8], controls.after_fatal[8])
        self.assertEqual(controls.after_fatal[9], controls.after_repeats[9])
        self.assertEqual(controls.after_fatal[10], controls.after_repeats[10])
        protocol = controls.server_protocols[0]
        self.assertIs(protocol.peers.fatal_failure, controls.failure)
        self.assertTrue(protocol.closing)
        self.assertEqual(protocol.peer.close_reason, "0x0")
        self.assertFalse(protocol.retirements)
        self.assertIsNone(protocol._timer)
        self.assertIsNone(protocol._transmit_task)
        self.assertTrue(closed)
        self.assertTrue(controls.normal_client_closed)
        self.assertTrue(controls.normal_server_closed)
        self.assertEqual(controls.client_socket.fileno(), -1)
        self.assertTrue(controls.client_transport.is_closing())

    async def test_actual_h3_validator_failure_stops_repeated_causal_datagrams(self):
        controls = self.acquire(FailedHeldResponse)
        result, observed, closed = await controls.capture(cleanup_fault=False)

        self.assertIsNone(result)
        self.assertIs(observed, controls.failure)
        self.assert_fatal(controls, closed)

    async def test_h3_fatal_and_original_transport_cleanup_errors_both_survive(self):
        controls = self.acquire(FailedHeldResponse)
        result, observed, closed = await controls.capture(cleanup_fault=True)

        self.assertIsNone(result)
        self.assertIsInstance(observed, race.CaptureCleanupError)
        self.assertEqual(observed.failures, (controls.cleanup_error, controls.failure))
        self.assertEqual(controls.cleanup_calls, 1)
        self.assert_fatal(controls, closed)
