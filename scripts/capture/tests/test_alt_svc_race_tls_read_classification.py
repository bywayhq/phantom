"""Real peer-close policy and controlled pending-reader failures stay distinct."""

import asyncio
import ssl
import unittest
from unittest.mock import patch

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_error_classification import (
    ClassificationPeer,
)
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import DATAGRAM, DEADLINE

INVALID_HANDSHAKE = b"GET /invalid HTTP/1.1\r\nHost: invalid\r\n\r\n"


class TlsReadPeer:
    def __init__(self):
        self.peer = ClassificationPeer()
        self.partial = None
        self.invalid_received = bytearray()
        self.invalid_consumed = asyncio.Event()
        self.native_failure = None
        self.native_failed = asyncio.Event()
        self.read_waiter = None

    def install(self):
        stream_type = race.TlsStream
        self.peer.install()
        actual_read = stream_type.read_raw
        actual_handshake = stream_type.handshake

        async def observe_read(stream):
            data = await actual_read(stream)
            if self.partial is not None and stream is self.partial.stream:
                self.invalid_received.extend(data)
                if len(self.invalid_received) >= 5 and INVALID_HANDSHAKE.startswith(
                    bytes(self.invalid_received)
                ):
                    self.invalid_consumed.set()
            return data

        async def observe_handshake(stream):
            try:
                return await actual_handshake(stream)
            except ssl.SSLError as error:
                if self.partial is not None and stream is self.partial.stream:
                    self.native_failure = error
                    self.native_failed.set()
                raise

        stack = self.peer.resources.stack
        stack.enter_context(patch.object(stream_type, "read_raw", observe_read))
        stack.enter_context(patch.object(stream_type, "handshake", observe_handshake))

    async def prefix_eof(self):
        await self.peer.open()
        _, writer, self.partial = await self.peer.owners.hold_plain(
            self.peer.resources.tcp[0]
        )
        waiter = self.partial.reader._waiter
        if waiter is None or waiter.done():
            raise AssertionError("actual TLS prefix did not leave a pending read")
        if self.partial.task._fut_waiter is not waiter:
            raise AssertionError("actual handshake did not own its reader waiter")
        self.read_waiter = waiter
        await self.peer.owners.close_plain(writer, self.partial)

    async def malformed_handshake(self):
        await self.peer.open()
        _, writer, self.partial = await self.peer.owners.open_plain(
            self.peer.resources.tcp[0]
        )
        writer.write(INVALID_HANDSHAKE)
        await asyncio.wait_for(writer.drain(), DEADLINE)
        await asyncio.wait_for(self.invalid_consumed.wait(), DEADLINE)
        await asyncio.wait_for(self.native_failed.wait(), DEADLINE)
        await asyncio.wait_for(self.partial.done.wait(), DEADLINE)
        await self.peer.owners.close_plain(writer, self.partial)

    async def fail_reader(self, failure):
        await self.peer.open()
        waiter = await self.peer.pending_read()
        if waiter.done() or self.peer.peer.reader._buffer:
            raise AssertionError("actual healthy H2 reader was not empty and pending")
        if self.peer.peer.task._fut_waiter is not waiter:
            raise AssertionError("actual accepted handler did not own the read waiter")
        server = self.peer.resources.tcp[0]
        if server.handlers.get(self.peer.peer.task) is not self.peer.peer.writer:
            raise AssertionError("canonical TCP owner did not retain the target peer")
        self.read_waiter = waiter
        self.peer.failure = failure
        self.peer.resources.primary = failure
        self.peer.peer.reader.set_exception(failure)
        await asyncio.wait_for(self.peer.peer.done.wait(), DEADLINE)


class TlsReadClassificationTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self):
        controls = TlsReadPeer()
        self.addAsyncCleanup(controls.peer.backup)
        controls.install()
        return controls

    def assert_traffic_and_cleanup(self, controls, closed):
        peer = controls.peer
        server = peer.resources.tcp[0]
        self.assertEqual(peer.exchanges, [("/r/retained", b"200", b"ok")])
        self.assertEqual(
            peer.resources.h2_exchanges,
            [("/r/startup", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
        )
        self.assertEqual(
            peer.resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )
        self.assertEqual(peer.peer.record.alpn, "h2")
        self.assertIsNotNone(peer.peer.record.tls_ms)
        self.assertTrue(peer.peer.task.done())
        self.assertTrue(peer.peer.writer.is_closing())
        self.assertIsNotNone(peer.peer.record.closed_ms)
        self.assertFalse(server.handlers)
        self.assertFalse(server.writer_closures)
        self.assertTrue(closed, "capture left actual acquired listener resources open")
        self.assertIs(
            asyncio.get_running_loop().get_exception_handler(),
            peer.resources.previous_handler,
        )

    def assert_partial_closed(self, controls):
        partial = controls.partial
        self.assertIsNot(partial.task, controls.peer.peer.task)
        self.assertNotEqual(partial.record.index, controls.peer.peer.record.index)
        self.assertIsNone(partial.record.alpn)
        self.assertIsNone(partial.record.tls_ms)
        self.assertIsNotNone(partial.record.closed_ms)
        self.assertTrue(partial.task.done())
        self.assertTrue(partial.writer.is_closing())

    async def test_actual_tls_prefix_eof_keeps_its_partial_record_without_failing_capture(
        self,
    ):
        controls = self.acquire()
        result, observed, closed = await controls.peer.capture(controls.prefix_eof)

        self.assert_traffic_and_cleanup(controls, closed)
        self.assert_partial_closed(controls)
        self.assertTrue(controls.partial.consumed.is_set())
        self.assertTrue(controls.read_waiter.done())
        self.assertEqual(controls.partial.record.failure, "ConnectionError")
        self.assertIsNone(controls.peer.peer.record.failure)
        self.assertIsNone(observed)
        self.assertTrue(result.run.done.is_set())

    async def test_actual_malformed_tls_input_keeps_the_native_failure_on_its_partial_record(
        self,
    ):
        controls = self.acquire()
        result, observed, closed = await controls.peer.capture(
            controls.malformed_handshake
        )

        self.assert_traffic_and_cleanup(controls, closed)
        self.assert_partial_closed(controls)
        self.assertGreaterEqual(len(controls.invalid_received), 5)
        self.assertTrue(INVALID_HANDSHAKE.startswith(bytes(controls.invalid_received)))
        self.assertTrue(controls.invalid_consumed.is_set())
        self.assertTrue(controls.native_failed.is_set())
        self.assertIsInstance(controls.native_failure, ssl.SSLError)
        self.assertEqual(
            controls.partial.record.failure, type(controls.native_failure).__name__
        )
        self.assertIsNone(controls.peer.peer.record.failure)
        self.assertIsNone(observed)
        self.assertTrue(result.run.done.is_set())

    async def test_pending_reader_base_connection_error_keeps_its_original_local_cause(
        self,
    ):
        controls = self.acquire()
        failure = ConnectionError("controlled local pending-reader failure")

        async def fail_read():
            await controls.fail_reader(failure)

        _, observed, closed = await controls.peer.capture(fail_read)

        self.assert_traffic_and_cleanup(controls, closed)
        self.assertTrue(controls.read_waiter.done())
        self.assertIs(controls.peer.peer.reader.exception(), failure)
        self.assertIs(
            observed, failure, "capture lost the original local ConnectionError"
        )
        self.assertEqual(controls.peer.peer.record.failure, "ConnectionError")

    async def test_pending_reader_ssl_error_keeps_its_original_local_cause(self):
        controls = self.acquire()
        failure = ssl.SSLError("controlled local pending-reader SSL failure")

        async def fail_read():
            await controls.fail_reader(failure)

        _, observed, closed = await controls.peer.capture(fail_read)

        self.assert_traffic_and_cleanup(controls, closed)
        self.assertTrue(controls.read_waiter.done())
        self.assertIs(controls.peer.peer.reader.exception(), failure)
        self.assertIs(observed, failure, "capture lost the original local SSLError")
        self.assertEqual(controls.peer.peer.record.failure, "SSLError")
