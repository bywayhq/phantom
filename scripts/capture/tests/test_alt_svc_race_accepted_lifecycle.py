"""Accepted TCP controls use real loopback streams and a controlled driver."""

import asyncio
import unittest
from contextlib import suppress
from unittest.mock import patch

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import (
    DATAGRAM,
    DEADLINE,
    HOST,
    CaptureResources,
)


class EscapedConstructorFailure(RuntimeError):
    pass


class AcceptedPeer:
    def __init__(self, server, reader, writer):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.task = asyncio.current_task()
        self.record_index = len(server.origin.run.tcp)
        self.stream = None
        self.record = None
        self.consumed = asyncio.Event()
        self.done = asyncio.Event()
        self.task.add_done_callback(lambda _task: self.done.set())


class AcceptedResources:
    """Observe canonical accepted work; independent backup owns every peer."""

    def __init__(self):
        self.resources = CaptureResources("healthy")
        self.peers = []
        self.failure = EscapedConstructorFailure("controlled post-constructor failure")
        self.fail_constructor = False
        self.escaped = None

    def install(self):
        self.resources.install()
        server_type = race.Http2Origin
        actual_handle = server_type.handle
        stream_type = race.TlsStream
        actual_read = stream_type.read_raw

        async def observe_handle(server, reader, writer):
            self.peers.append(AcceptedPeer(server, reader, writer))
            await actual_handle(server, reader, writer)

        async def observe_read(stream):
            data = await actual_read(stream)
            if data == b"\x16":
                self.peer_for(stream.reader, stream.writer).consumed.set()
            return data

        def observe_constructor(context, reader, writer):
            stream = stream_type(context, reader, writer)
            peer = self.peer_for(reader, writer)
            peer.stream = stream
            peer.record = peer.server.origin.run.tcp[peer.record_index]
            if self.fail_constructor:
                self.fail_constructor = False
                self.escaped = peer
                raise self.failure

            return stream

        stack = self.resources.stack
        stack.enter_context(patch.object(server_type, "handle", observe_handle))
        stack.enter_context(patch.object(stream_type, "read_raw", observe_read))
        stack.enter_context(patch.object(race, "TlsStream", observe_constructor))

    def peer_for(self, reader, writer):
        return next(
            peer
            for peer in self.peers
            if peer.reader is reader and peer.writer is writer
        )

    async def open_plain(self, server):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(HOST, server.origin.port), DEADLINE
        )
        self.resources.writers.append(writer)
        address = writer.get_extra_info("sockname")

        async def accepted():
            while True:
                for peer in self.peers:
                    if peer.writer.get_extra_info("peername") == address:
                        return peer
                await asyncio.sleep(0)

        peer = await asyncio.wait_for(accepted(), DEADLINE)
        return reader, writer, peer

    async def hold_plain(self, server):
        reader, writer, peer = await self.open_plain(server)
        writer.write(b"\x16")
        await asyncio.wait_for(writer.drain(), DEADLINE)
        await asyncio.wait_for(peer.consumed.wait(), DEADLINE)

        async def pending_read():
            while True:
                waiter = peer.reader._waiter
                if waiter is not None and not waiter.done() and not peer.task.done():
                    return
                if peer.task.done():
                    raise AssertionError("literal TLS prefix did not leave a live read")
                await asyncio.sleep(0)

        await asyncio.wait_for(pending_read(), DEADLINE)
        return reader, writer, peer

    async def close_plain(self, writer, peer):
        writer.close()
        with suppress(ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            await asyncio.wait_for(writer.wait_closed(), DEADLINE)
        await asyncio.wait_for(peer.done.wait(), DEADLINE)

    async def backup(self):
        failures = []
        if self.escaped is not None:
            task = self.escaped.task
            try:
                await asyncio.wait_for(task, DEADLINE)
            except BaseException as error:
                if error is not self.failure:
                    failures.append(error)
            else:
                failures.append(AssertionError("escaped accepted task did not fail"))

            if task.done():
                # Only this observed, deliberately failed task leaves the backup list.
                self.resources.handlers[:] = [
                    handler
                    for handler in self.resources.handlers
                    if handler is not task
                ]

        try:
            await self.resources.backup()
        except BaseException as error:
            failures.append(error)

        if failures:
            raise AssertionError(
                f"accepted peer backup failed: {failures!r}"
            ) from failures[0]

    def wrap_driver(self, before_enter):
        actual_driver = race.BrowserDriver

        class ObservedDriver(actual_driver):
            async def __aenter__(driver):
                await before_enter()
                return await super().__aenter__()

        self.resources.stack.enter_context(
            patch.object(race, "BrowserDriver", ObservedDriver)
        )


class AcceptedLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self):
        owners = AcceptedResources()
        self.addAsyncCleanup(owners.backup)
        owners.install()
        return owners

    def assert_capture_exchanges(self, owners):
        self.assertEqual(
            owners.resources.h2_exchanges,
            [("/r/startup", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
        )
        self.assertEqual(
            owners.resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )

    async def test_healthy_capture_records_an_eof_partial_tls_peer(self):
        owners = self.acquire()
        observed = []

        async def partial_peer():
            _, writer, peer = await owners.hold_plain(owners.resources.tcp[0])
            await owners.close_plain(writer, peer)
            observed.append(peer)

        owners.wrap_driver(partial_peer)
        owners.resources.capture = asyncio.create_task(owners.resources.capture_run())
        result = await asyncio.wait_for(owners.resources.capture, 15)

        self.assert_capture_exchanges(owners)
        self.assertEqual(result.run.page_results, [])
        self.assertTrue(result.run.done.is_set())
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0].task.done())
        self.assertEqual(observed[0].record.failure, "ConnectionError")
        self.assertIsNotNone(observed[0].record.closed_ms)

    async def test_direct_close_finishes_the_actual_pending_tls_reader(self):
        owners = self.acquire()
        certificate = race.generate_certificate(race.HOSTNAME)
        _, sock = owners.resources.reserve(HOST)
        scenario = race.Scenario("accepted", "accepted ownership", "blackhole", ())
        origin = race.Origin(scenario, sock.getsockname()[1])
        origin.begin(race.new_run())
        server = race.Http2Origin(origin, certificate)
        await asyncio.wait_for(server.start(sock), DEADLINE)
        self.assertEqual(owners.resources.h2_exchanges, [("/r/startup", b"200", b"ok")])
        _, writer, peer = await owners.hold_plain(server)
        self.assertFalse(writer.is_closing())
        self.assertIsNotNone(peer.stream)
        self.assertFalse(peer.task.done())

        # A direct await retains the no-yield return boundary of canonical close.
        watchdog = asyncio.get_running_loop().call_later(
            15, asyncio.current_task().cancel
        )
        try:
            await server.close()
            finished = peer.task.done()
            recorded_close = peer.record.closed_ms
        finally:
            watchdog.cancel()

        self.assertTrue(finished, "direct close returned before its accepted TLS task")
        self.assertIsNotNone(recorded_close)

    async def test_capture_observes_the_completed_escaped_constructor_failure(self):
        owners = self.acquire()
        owners.resources.primary = owners.failure

        async def failed_peer():
            owners.fail_constructor = True
            _, _, peer = await owners.open_plain(owners.resources.tcp[0])
            await asyncio.wait_for(peer.done.wait(), DEADLINE)
            self.assertIs(owners.escaped, peer)
            self.assertIsNotNone(peer.stream)
            self.assertIsNotNone(peer.record)
            self.assertTrue(peer.task.done())

        owners.wrap_driver(failed_peer)
        owners.resources.capture = asyncio.create_task(owners.resources.capture_run())
        observed = None
        try:
            await asyncio.wait_for(owners.resources.capture, 15)
        except BaseException as error:
            observed = error

        self.assert_capture_exchanges(owners)
        self.assertIsNotNone(owners.escaped)
        self.assertTrue(owners.escaped.task.done())
        self.assertIs(
            observed,
            owners.failure,
            "capture discarded its completed escaped accepted-task failure",
        )
