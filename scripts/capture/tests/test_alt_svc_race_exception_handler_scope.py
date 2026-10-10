"""Capture handler controls retain actual loop callback contexts before backup."""

import asyncio
import unittest
from unittest.mock import patch

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import (
    DATAGRAM,
    DEADLINE,
    CaptureResources,
)


class ExceptionHandlerScopeTests(unittest.IsolatedAsyncioTestCase):
    def acquire(self, case):
        resources = CaptureResources(case)
        self.addAsyncCleanup(resources.backup)
        resources.install()
        reports = []

        def previous_handler(loop, context):
            reports.append((loop, context))

        resources.loop.set_exception_handler(previous_handler)
        return resources, previous_handler, reports

    def assert_healthy_exchanges(self, resources, result, closed):
        self.assertEqual(
            resources.h2_exchanges,
            [("/r/startup", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
        )
        self.assertEqual(
            resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )
        self.assertEqual(result.run.page_results, [])
        self.assertTrue(result.run.done.is_set())
        self.assertTrue(closed, "actual healthy capture resources remained open")

    async def test_healthy_capture_restores_the_exact_previous_loop_handler(self):
        resources, previous, _ = self.acquire("healthy")
        resources.capture = asyncio.create_task(resources.capture_run())
        result = await asyncio.wait_for(resources.capture, 15)
        restored = resources.loop.get_exception_handler()
        closed = await resources.closed_before_backup()

        self.assert_healthy_exchanges(resources, result, closed)
        self.assertIs(restored, previous, "healthy capture retained its loop override")

    async def test_active_capture_delegates_the_actual_non_reset_callback_context(self):
        resources, previous, reports = self.acquire("healthy")
        default_reports = []
        dispatched = []
        actual_dispatch = resources.loop.call_exception_handler

        def observe_dispatch(context):
            dispatched.append((resources.loop.get_exception_handler(), context))
            actual_dispatch(context)

        resources.stack.enter_context(
            patch.object(resources.loop, "call_exception_handler", observe_dispatch)
        )
        resources.stack.enter_context(
            patch.object(
                resources.loop, "default_exception_handler", default_reports.append
            )
        )
        failure = RuntimeError("controlled non-reset callback failure")
        reset = ConnectionResetError("controlled active peer reset")
        handles = {}

        async def dispatch_callback(error):
            fired = asyncio.Event()

            def raise_callback():
                try:
                    raise error
                finally:
                    fired.set()

            handle = resources.loop.call_soon(raise_callback)
            resources.stack.callback(handle.cancel)
            await asyncio.wait_for(fired.wait(), DEADLINE)
            handles[error] = handle

        actual_driver = race.BrowserDriver

        class ObservedDriver(actual_driver):
            async def __aenter__(driver):
                await dispatch_callback(failure)
                await dispatch_callback(reset)
                return await super().__aenter__()

        resources.stack.enter_context(
            patch.object(race, "BrowserDriver", ObservedDriver)
        )
        resources.capture = asyncio.create_task(resources.capture_run())
        result = await asyncio.wait_for(resources.capture, 15)
        original_contexts = list(dispatched)
        previous_reports = list(reports)
        defaults = list(default_reports)
        closed = await resources.closed_before_backup()

        self.assert_healthy_exchanges(resources, result, closed)
        contexts = {}
        for error in (failure, reset):
            matching = [
                (handler, context)
                for handler, context in original_contexts
                if context.get("exception") is error
            ]
            self.assertEqual(len(matching), 1, "actual Handle context was not observed")
            handler, context = matching[0]
            self.assertIsNot(
                handler, previous, "callback ran outside the active override"
            )
            self.assertIs(context["exception"], error)
            self.assertIs(context["handle"], handles[error])
            contexts[error] = context

        self.assertFalse(
            any(context.get("exception") is reset for _, context in previous_reports)
        )
        self.assertFalse(any(context.get("exception") is reset for context in defaults))
        forwarded = [
            (loop, context)
            for loop, context in previous_reports
            if context.get("exception") is failure
        ]
        self.assertEqual(
            len(forwarded), 1, "active capture bypassed the previous loop handler"
        )
        loop, context = forwarded[0]
        self.assertIs(loop, resources.loop)
        self.assertIs(context, contexts[failure])
        self.assertEqual(defaults, [])

    async def test_startup_failure_restores_the_exact_previous_loop_handler(self):
        resources, previous, _ = self.acquire("tcp-start")
        resources.capture = asyncio.create_task(resources.capture_run())
        observed = None
        try:
            await asyncio.wait_for(resources.capture, 15)
        except BaseException as error:
            observed = error
        restored = resources.loop.get_exception_handler()
        closed = await resources.closed_before_backup()

        self.assertEqual(resources.h2_exchanges, [("/r/startup", b"200", b"ok")])
        self.assertEqual(
            resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )
        self.assertIs(observed, resources.primary)
        self.assertIs(resources.outcome, resources.primary)
        self.assertIsNotNone(resources.tcp[0].server)
        self.assertTrue(closed, "actual startup failure resources remained open")
        self.assertIs(restored, previous, "startup failure retained the loop override")

    async def test_cancellation_restores_the_exact_previous_loop_handler(self):
        resources, previous, _ = self.acquire("cancel-start")
        resources.capture = asyncio.create_task(resources.capture_run())
        await asyncio.wait_for(resources.entered.wait(), DEADLINE)
        self.assertEqual(
            resources.received, {"origin": [DATAGRAM], "earlier-0": [DATAGRAM]}
        )
        resources.capture.cancel()
        observed = None
        try:
            await asyncio.wait_for(resources.capture, DEADLINE)
        except asyncio.CancelledError as error:
            observed = error
        restored = resources.loop.get_exception_handler()
        closed = await resources.closed_before_backup()

        self.assertIsNotNone(resources.cancelled)
        self.assertIsInstance(observed, asyncio.CancelledError)
        self.assertIs(resources.outcome, resources.cancelled)
        self.assertTrue(closed, "actual cancellation resources remained open")
        self.assertIs(restored, previous, "cancellation retained the loop override")
