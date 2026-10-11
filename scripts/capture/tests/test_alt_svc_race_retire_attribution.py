"""Retirement writes keep their original peer when another peer requests them."""

import asyncio
import unittest
from unittest.mock import patch

import h2.connection
import h2.events
from hyperframe.frame import Frame, GoAwayFrame

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_error_classification import (
    ClassificationPeer,
)
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import DATAGRAM, DEADLINE


class LocalRetireWriteFailure(RuntimeError):
    pass


class RetirePeers:
    def __init__(self):
        self.peer = ClassificationPeer()
        self.failure = LocalRetireWriteFailure(
            "controlled original peer retirement write"
        )
        self.cause = LookupError("original retirement write cause")
        self.failure.__cause__ = self.cause
        self.fail_write = False
        self.callback = None
        self.read_waiter = None
        self.retirement = None
        self.retiring_peer = None
        self.retiring_client = None
        self.retire_headers = None
        self.writes = []
        self.goaways = []
        self.collected = []
        self.observed = None
        self.eof_removed = False

    def install(self):
        stream_type = race.TlsStream
        actual_write = stream_type.write
        self.peer.install()
        actual_request = race.Origin.request
        actual_receive = h2.connection.H2Connection.receive_data
        actual_collect = race.Http2Origin.collect_closed

        def observe_request(origin, transport, connection, target, respond, retire):
            if target == "/r/retained":
                self.callback = retire

            if target == "/retire":
                task = asyncio.current_task()
                self.retirement = (origin, transport, connection, task)
                self.retiring_peer = next(
                    peer for peer in self.peer.owners.peers if peer.task is task
                )

            return actual_request(
                origin, transport, connection, target, respond, retire
            )

        def observe_write(stream, data):
            actual_write(stream, data)
            peer = self.peer.peer
            if peer is None or stream is not peer.stream or len(data) < 9:
                return

            frame, length = Frame.parse_frame_header(memoryview(data[:9]))
            if not isinstance(frame, GoAwayFrame):
                return

            if len(data) != 9 + length:
                raise AssertionError("retirement did not write one complete GOAWAY")

            frame.parse_body(memoryview(data[9:]))
            self.writes.append((stream, asyncio.current_task(), frame))
            if self.fail_write:
                raise self.failure

        def observe_receive(connection, data):
            events = actual_receive(connection, data)
            if connection.config.client_side:
                for event in events:
                    if (
                        isinstance(event, h2.events.ResponseReceived)
                        and self.retirement is not None
                        and connection is not self.peer.client
                        and dict(event.headers)[b":status"] == b"200"
                    ):
                        self.retiring_client = connection
                        self.retire_headers = dict(event.headers)

                self.goaways.extend(
                    (connection, event)
                    for event in events
                    if isinstance(event, h2.events.ConnectionTerminated)
                )

            return events

        def observe_collect(server, failures):
            start = len(failures)
            actual_collect(server, failures)
            self.collected.append((server, tuple(failures[start:])))

        stack = self.peer.resources.stack
        stack.enter_context(patch.object(race.Origin, "request", observe_request))
        stack.enter_context(patch.object(stream_type, "write", observe_write))
        stack.enter_context(
            patch.object(h2.connection.H2Connection, "receive_data", observe_receive)
        )
        stack.enter_context(
            patch.object(race.Http2Origin, "collect_closed", observe_collect)
        )

    async def receive_original_goaway(self):
        while not any(client is self.peer.client for client, _ in self.goaways):
            data = await self.peer.reader.read(65536)
            if not data:
                raise EOFError("original peer closed before its actual GOAWAY")
            self.peer.client.receive_data(data)

    async def capture(self, case="healthy"):
        async def retire_other_peer():
            await self.peer.open()
            self.read_waiter = await self.peer.pending_read()
            original = self.peer.peer
            if original.task._fut_waiter is not self.read_waiter:
                raise AssertionError("original handler did not own its pending read")

            if self.callback not in original.server.origin.retirers:
                raise AssertionError(
                    "original peer did not retain its retirement callback"
                )

            if case == "clean-eof":
                await self.peer.owners.close_plain(self.peer.writer, original)
                self.eof_removed = self.callback not in original.server.origin.retirers
                if not self.eof_removed:
                    raise AssertionError("clean EOF retained its retirement callback")

            self.fail_write = case == "write-failure"
            result = await self.peer.resources.h2_exchange(
                original.server,
                "/retire",
                wait_for_goaway=case != "write-failure",
            )
            if result != ("/retire", b"200", b"retire"):
                raise AssertionError(
                    "other peer did not receive the retirement response"
                )

            if case != "clean-eof":
                await asyncio.wait_for(self.receive_original_goaway(), DEADLINE)
                await self.peer.owners.close_plain(self.peer.writer, original)

        if case == "write-failure":
            self.peer.resources.primary = self.failure

        result, self.observed, closed = await self.peer.capture(retire_other_peer)
        return result, self.observed, closed

    async def backup(self):
        failures = []
        peer = self.retiring_peer
        if peer is not None and peer.task.done() and self.observed is self.failure:
            try:
                error = peer.task.exception()
            except BaseException as error:
                failures.append(error)
            else:
                if error is self.failure:
                    self.peer.resources.handlers[:] = [
                        task
                        for task in self.peer.resources.handlers
                        if task is not peer.task
                    ]
                elif error is not None:
                    failures.append(error)

        try:
            await self.peer.backup()
        except BaseException as error:
            failures.append(error)

        if failures:
            backup = AssertionError("retirement peer backup failed")
            backup.failures = tuple(failures)
            if self.observed is not None:
                self.observed.test_backup_failure = backup
            raise backup from failures[0]


class RetireAttributionTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self):
        controls = RetirePeers()
        self.addAsyncCleanup(controls.backup)
        controls.install()
        return controls

    def assert_traffic_and_cleanup(self, controls, closed):
        peer = controls.peer
        original = peer.peer
        retiring = controls.retiring_peer
        server = peer.resources.tcp[0]
        origin, transport, connection, task = controls.retirement

        self.assertIs(origin, server.origin)
        self.assertEqual(transport, "h2")
        self.assertEqual(connection, retiring.record.index)
        self.assertIs(task, retiring.task)
        self.assertIsNot(task, original.task)
        self.assertIsNot(retiring.writer, original.writer)
        self.assertIsNot(retiring.record, original.record)

        self.assertIsNotNone(controls.retiring_client)
        self.assertIn(b"alt-svc", controls.retire_headers)
        self.assertEqual(controls.retire_headers[b"content-length"], b"6")

        self.assertIsNotNone(controls.read_waiter)
        self.assertTrue(controls.read_waiter.done())
        self.assertEqual(peer.exchanges, [("/r/retained", b"200", b"ok")])
        self.assertEqual(
            peer.resources.h2_exchanges,
            [
                ("/r/startup", b"200", b"ok"),
                ("/retire", b"200", b"retire"),
                ("/done?results=%5B%5D", b"204", b""),
            ],
        )
        self.assertEqual(
            peer.resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )
        self.assertTrue(server.origin.run.done.is_set())

        for accepted in (original, retiring):
            self.assertEqual(accepted.record.alpn, "h2")
            self.assertIsNotNone(accepted.record.tls_ms)
            self.assertIsNotNone(accepted.record.closed_ms)
            self.assertTrue(accepted.task.done())
            self.assertTrue(accepted.writer.is_closing())

        self.assertFalse(server.handlers)
        self.assertFalse(server.writer_closures)
        self.assertTrue(closed, "capture left actual acquired listeners open")
        self.assertIs(
            asyncio.get_running_loop().get_exception_handler(),
            peer.resources.previous_handler,
        )
        return server

    def assert_original_goaway(self, controls):
        self.assertEqual(len(controls.writes), 1)
        stream, task, frame = controls.writes[0]
        self.assertIs(stream, controls.peer.peer.stream)
        self.assertIs(task, controls.retiring_peer.task)
        self.assertEqual((frame.error_code, frame.last_stream_id), (0, 1))

        original_events = [
            event
            for client, event in controls.goaways
            if client is controls.peer.client
        ]
        self.assertEqual(len(original_events), 1)
        self.assertEqual(
            (original_events[0].error_code, original_events[0].last_stream_id), (0, 1)
        )

    async def test_other_peer_retires_two_healthy_actual_h2_connections(self):
        controls = self.acquire()
        _, observed, closed = await controls.capture()

        self.assert_traffic_and_cleanup(controls, closed)
        self.assert_original_goaway(controls)
        self.assertIsNone(observed)
        self.assertIsNone(controls.peer.peer.record.failure)
        self.assertIsNone(controls.retiring_peer.record.failure)
        self.assertIsNotNone(controls.peer.peer.record.retired_ms)
        self.assertIsNotNone(controls.retiring_peer.record.retired_ms)
        self.assertTrue(
            any(client is controls.retiring_client for client, _ in controls.goaways)
        )

    async def test_clean_eof_removes_callback_before_other_peer_retirement(self):
        controls = self.acquire()
        _, observed, closed = await controls.capture("clean-eof")

        self.assert_traffic_and_cleanup(controls, closed)
        self.assertTrue(controls.eof_removed)
        self.assertFalse(controls.writes)
        self.assertIsNone(observed)
        self.assertIsNone(controls.peer.peer.record.failure)
        self.assertIsNone(controls.peer.peer.record.retired_ms)
        self.assertIsNone(controls.retiring_peer.record.failure)
        self.assertIsNotNone(controls.retiring_peer.record.retired_ms)
        self.assertTrue(
            any(client is controls.retiring_client for client, _ in controls.goaways)
        )

    async def test_other_peer_keeps_retirement_write_failure_on_original_owner(self):
        controls = self.acquire()
        _, observed, closed = await controls.capture("write-failure")

        server = self.assert_traffic_and_cleanup(controls, closed)
        self.assert_original_goaway(controls)
        self.assertIsNotNone(controls.peer.peer.record.retired_ms)

        self.assertEqual(controls.peer.peer.record.failure, "LocalRetireWriteFailure")
        self.assertIsNone(controls.retiring_peer.record.failure)
        self.assertIsNotNone(controls.retiring_peer.record.retired_ms)
        self.assertIs(observed, controls.failure)
        self.assertIs(observed.__cause__, controls.cause)
        self.assertEqual(
            sum(
                error is controls.failure
                for owner, failures in controls.collected
                if owner is server
                for error in failures
            ),
            1,
        )
