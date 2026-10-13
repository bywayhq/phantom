"""Cleanup interruption controls with actual datagram and H2 listeners."""

import asyncio
import unittest
from unittest.mock import patch

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import (
    DATAGRAM,
    CaptureResources,
    CleanupFailure,
    contains_identity,
)


class CaptureCleanupInterruptionTests(unittest.IsolatedAsyncioTestCase):
    async def run_capture(self, origin_failure=None, earlier_failure=None):
        resources = CaptureResources("healthy")
        self.addAsyncCleanup(resources.backup)
        resources.install()
        actual_close = race.UdpAlternative.close
        raised = []

        def close(owner):
            actual_close(owner)
            name = owner.recorder.listener
            if name == "origin":
                failure = origin_failure
            elif name == "earlier-0":
                failure = earlier_failure
            else:
                failure = None
            if failure is not None:
                raised.append(failure)
                raise failure

        resources.stack.enter_context(patch.object(race.UdpAlternative, "close", close))
        caller = asyncio.current_task()
        self.assertIsNotNone(caller)
        timed_out = False
        requested_cancel = False

        def expire():
            nonlocal timed_out, requested_cancel
            timed_out = True
            requested_cancel = caller.cancel()

        watchdog = resources.loop.call_later(15, expire)
        result = observed = None
        try:
            # A child Task propagates KeyboardInterrupt/SystemExit through its runner.
            result = await resources.capture_run()
        except BaseException as error:
            observed = error
        finally:
            watchdog.cancel()
            uncancel = getattr(caller, "uncancel", None)
            if requested_cancel and uncancel is not None:
                uncancel()

        closed = await resources.closed_before_backup()
        self.assertFalse(timed_out, "capture exceeded the caller watchdog")
        self.assertEqual(
            resources.h2_exchanges,
            [("/r/startup", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
        )
        self.assertEqual(
            resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )
        self.assertEqual(
            resources.cleanup_calls, ["origin", "earlier-0", "earlier-1", "tcp"]
        )
        self.assertEqual(len(resources.sockets), 4)
        self.assertEqual(len(resources.udp), 3)
        self.assertEqual(len(resources.tcp), 1)
        self.assertTrue(closed, "capture left actual listener resources open")
        expected = [
            error for error in (origin_failure, earlier_failure) if error is not None
        ]
        self.assertEqual(len(raised), len(expected))
        for actual, error in zip(raised, expected, strict=True):
            self.assertIs(actual, error)
        self.assertIs(resources.outcome, observed)
        self.assertFalse(contains_identity(observed, resources.primary))
        return resources, result, observed

    async def assert_interruption(self, interruption, *, ordinary_first=False):
        ordinary = CleanupFailure("controlled independent alternative close")
        first, second = (
            (ordinary, interruption) if ordinary_first else (interruption, ordinary)
        )
        _, result, observed = await self.run_capture(first, second)

        self.assertIsNone(result)
        self.assertIs(
            observed,
            interruption,
            "cleanup replaced the exact control-flow interruption",
        )
        self.assertIs(type(observed), type(interruption))
        self.assertIs(observed.capture_cleanup_failure, ordinary)
        self.assertTrue(contains_identity(observed, ordinary))

    async def test_healthy_capture_closes_actual_listeners_without_cleanup_failure(
        self,
    ):
        _, result, observed = await self.run_capture()

        self.assertIsNone(observed)
        self.assertEqual(result.run.page_results, [])
        self.assertTrue(result.run.done.is_set())

    async def test_cleanup_keeps_cancelled_error_and_later_owner_failure(self):
        await self.assert_interruption(
            asyncio.CancelledError("controlled close cancel")
        )

    async def test_cleanup_keeps_keyboard_interrupt_and_later_owner_failure(self):
        await self.assert_interruption(KeyboardInterrupt("controlled close interrupt"))

    async def test_cleanup_keeps_system_exit_and_later_owner_failure(self):
        await self.assert_interruption(SystemExit("controlled close exit"))

    async def test_cleanup_keeps_later_cancellation_and_earlier_owner_failure(self):
        await self.assert_interruption(
            asyncio.CancelledError("controlled later close cancel"), ordinary_first=True
        )
