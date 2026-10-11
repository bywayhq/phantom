"""Held H2 responses retain their owner when another peer releases them."""

import asyncio
import unittest
from unittest.mock import patch

import h2.exceptions
import h2.settings

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_error_classification import (
    ClassificationPeer,
)
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import DATAGRAM, DEADLINE


class DeferredPeer:
    def __init__(self):
        self.peer = ClassificationPeer()
        self.response_task = None
        self.held_callback = None
        self.read_waiter = None
        self.releases = []
        self.collected = []

    def install(self):
        self.peer.install()
        actual_request = race.Origin.request
        actual_collect = race.Http2Origin.collect_closed

        def observe_request(origin, transport, connection, target, respond, retire):
            if target.startswith("/done?"):
                self.releases.append(
                    (
                        origin,
                        transport,
                        connection,
                        asyncio.current_task(),
                        tuple(origin.holds),
                    )
                )
            return actual_request(
                origin, transport, connection, target, respond, retire
            )

        def observe_collect(server, failures):
            start = len(failures)
            actual_collect(server, failures)
            self.collected.append((server, tuple(failures[start:])))

        stack = self.peer.resources.stack
        stack.enter_context(patch.object(race.Origin, "request", observe_request))
        stack.enter_context(
            patch.object(race.Http2Origin, "collect_closed", observe_collect)
        )

    async def hold(self, limited):
        await self.peer.open()
        if limited:
            self.peer.client.update_settings(
                {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1}
            )
        await self.peer.request(3, "/hold")
        if limited:
            await asyncio.wait_for(self.peer.window_received.wait(), DEADLINE)

        origin = self.peer.resources.tcp[0].origin

        async def held():
            while not origin.holds:
                if self.peer.peer.task.done():
                    raise AssertionError(
                        "held request ended before retaining its response"
                    )
                await asyncio.sleep(0)
            if len(origin.holds) != 1:
                raise AssertionError("control did not retain exactly one response")
            return origin.holds[0]

        self.held_callback = await asyncio.wait_for(held(), DEADLINE)
        self.read_waiter = await self.peer.pending_read()
        if limited:
            if self.peer.connection.local_flow_control_window(3) != 1:
                raise AssertionError("actual held response did not have window one")
        else:
            self.response_task = asyncio.create_task(self.peer.response(3, "/hold"))

    async def capture(self, limited):
        actual_driver = race.BrowserDriver
        controls = self

        class ObservedDriver(actual_driver):
            async def __aenter__(driver):
                result = await super().__aenter__()
                if controls.response_task is not None:
                    await asyncio.wait_for(controls.response_task, DEADLINE)
                return result

        self.peer.resources.stack.enter_context(
            patch.object(race, "BrowserDriver", ObservedDriver)
        )

        async def held_peer():
            await self.hold(limited)
            if self.read_waiter.done():
                raise AssertionError("held peer was not pending before its release")
            if self.peer.peer.task._fut_waiter is not self.read_waiter:
                raise AssertionError("canonical handler did not own the held read")
            if self.peer.send_failed.is_set() or self.releases:
                raise AssertionError("held response failed or released before /done")

        return await self.peer.capture(held_peer)

    async def backup(self):
        failures = []
        task = self.response_task
        if task is not None:
            requested_abort = not task.done()
            if requested_abort:
                task.cancel()
            try:
                await asyncio.wait_for(task, DEADLINE)
            except asyncio.CancelledError as error:
                if not requested_abort:
                    failures.append(error)
            except BaseException as error:
                failures.append(error)
        try:
            await self.peer.backup()
        except BaseException as error:
            failures.append(error)
        if failures:
            failure = AssertionError(f"deferred response backup failed: {failures!r}")
            failure.failures = tuple(failures)
            raise failure from failures[0]


class DeferredResponseClassificationTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self):
        controls = DeferredPeer()
        self.addAsyncCleanup(controls.backup)
        controls.install()
        return controls

    def assert_release_and_cleanup(self, controls, closed):
        peer = controls.peer
        server = peer.resources.tcp[0]
        self.assertEqual(len(controls.releases), 1)
        origin, transport, connection, task, callbacks = controls.releases[0]
        self.assertIs(origin, server.origin)
        self.assertEqual(transport, "h2")
        self.assertNotEqual(connection, peer.peer.record.index)
        self.assertIsNot(task, peer.peer.task)
        self.assertEqual(callbacks, (controls.held_callback,))
        releaser = next(
            accepted for accepted in peer.owners.peers if accepted.task is task
        )
        self.assertEqual(releaser.record.index, connection)
        self.assertIsNone(releaser.record.failure)
        self.assertEqual(releaser.record.alpn, "h2")
        self.assertIsNotNone(releaser.record.tls_ms)
        self.assertIsNotNone(releaser.record.closed_ms)
        self.assertTrue(releaser.task.done())
        self.assertTrue(releaser.writer.is_closing())
        self.assertEqual(
            [
                (request.path, request.connection)
                for request in origin.run.requests
                if request.path in {"/hold", "/done"}
            ],
            [("/hold", peer.peer.record.index), ("/done", connection)],
        )
        self.assertEqual(
            peer.resources.h2_exchanges,
            [("/r/startup", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
        )
        self.assertEqual(
            peer.resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )
        self.assertFalse(origin.holds)
        self.assertEqual(peer.peer.record.alpn, "h2")
        self.assertIsNotNone(peer.peer.record.tls_ms)
        self.assertTrue(peer.peer.task.done())
        self.assertTrue(controls.read_waiter.done())
        self.assertIsNotNone(peer.peer.record.closed_ms)
        self.assertTrue(peer.peer.writer.is_closing())
        self.assertFalse(server.handlers)
        self.assertFalse(server.writer_closures)
        self.assertTrue(any(owner is server for owner, _ in controls.collected))
        self.assertTrue(closed, "capture left actual acquired listener resources open")
        self.assertIs(
            asyncio.get_running_loop().get_exception_handler(),
            peer.resources.previous_handler,
        )
        return server

    async def test_other_h2_peer_releases_the_original_healthy_held_response(self):
        controls = self.acquire()
        result, observed, closed = await controls.capture(limited=False)

        server = self.assert_release_and_cleanup(controls, closed)
        self.assertEqual(
            controls.peer.exchanges,
            [("/r/retained", b"200", b"ok"), ("/hold", b"200", race.HOLD_BODY)],
        )
        self.assertTrue(controls.response_task.done())
        self.assertIsNone(observed)
        self.assertTrue(result.run.done.is_set())
        self.assertIsNone(controls.peer.peer.record.failure)
        self.assertTrue(
            all(
                not failures
                for owner, failures in controls.collected
                if owner is server
            )
        )

    async def test_other_h2_peer_keeps_a_held_response_failure_on_its_original_owner(
        self,
    ):
        controls = self.acquire()
        _, observed, closed = await controls.capture(limited=True)

        server = self.assert_release_and_cleanup(controls, closed)
        self.assertEqual(controls.peer.exchanges, [("/r/retained", b"200", b"ok")])
        self.assertTrue(controls.peer.send_failed.is_set())
        self.assertIsInstance(controls.peer.failure, h2.exceptions.FlowControlError)
        self.assertEqual(
            controls.peer.connection.remote_settings.initial_window_size, 1
        )
        self.assertEqual(controls.peer.connection.local_flow_control_window(3), 1)
        self.assertIs(
            observed,
            controls.peer.failure,
            "capture lost the original held-response cause",
        )
        self.assertEqual(controls.peer.peer.record.failure, "FlowControlError")
        self.assertEqual(
            sum(
                error is controls.peer.failure
                for owner, failures in controls.collected
                if owner is server
                for error in failures
            ),
            1,
        )
        self.assertFalse(server.response_failures)
