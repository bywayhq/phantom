import asyncio
import threading
import unittest
from unittest import mock

from scripts.capture import browser_launch
from scripts.capture.tests.test_browser_launch_lifecycle import (
    BackupFailures,
    LaunchContext,
    TreeFailure,
)

WAIT_SECONDS = 20


class ThreadedLaunchContext(LaunchContext):
    def __init__(
        self, case: unittest.TestCase, loop: asyncio.AbstractEventLoop
    ) -> None:
        super().__init__(case)
        self.loop = loop
        self.ready = asyncio.Event()
        self.completed = asyncio.Event()
        self.release = threading.Event()
        self.future: asyncio.Future | None = None
        self.caller: asyncio.Task | None = None
        self.cancellation: asyncio.CancelledError | None = None
        self.cancellation_requested = False
        self.reports: list[dict] = []
        self.previous_handler = loop.get_exception_handler()
        self.actual_executor = loop.run_in_executor

    def prepare(self) -> None:
        super().prepare()
        self.loop.set_exception_handler(self.record_exception)
        self.patches.enter_context(
            mock.patch.object(self.loop, "run_in_executor", self.record_executor)
        )
        self.patches.enter_context(
            mock.patch.object(
                browser_launch.LaunchPlan, "takes_turns", property(lambda _: True)
            )
        )

    def record_executor(self, executor, function, *arguments):
        self.case.assertIsNone(self.future)
        future = self.actual_executor(executor, function, *arguments)
        self.future = future
        future.add_done_callback(lambda _: self.completed.set())
        return future

    def record_exception(self, _loop, details: dict) -> None:
        self.reports.append(dict(details))

    def checkpoint(self, profile, process) -> None:
        super().checkpoint(profile, process)
        self.loop.call_soon_threadsafe(self.ready.set)
        if not self.release.wait(WAIT_SECONDS):
            raise TimeoutError("threaded launch control checkpoint was not released")

    async def enter(self) -> None:
        try:
            await browser_launch.enter_browser(self.browser)
        except asyncio.CancelledError as error:
            # Capture the canonical escape before Task cancellation reconstruction.
            self.cancellation = error
            raise

    async def cancel_held_entry(self) -> None:
        self.caller = asyncio.create_task(self.enter())
        await asyncio.wait_for(self.ready.wait(), WAIT_SECONDS)
        self.case.assertIsNotNone(self.future)
        self.case.assertFalse(self.future.done())
        self.case.assertEqual(self.checkpoints, 1)
        self.case.assertIsNone(self.processes[0].poll())
        self.case.assertTrue(self.profile.is_dir())
        self.cancellation_requested = self.caller.cancel(
            "controlled pending launch cancellation"
        )
        self.case.assertTrue(self.cancellation_requested)

        with self.case.assertRaises(asyncio.CancelledError):
            await self.caller

        self.case.assertTrue(self.caller.cancelled())
        self.case.assertIsInstance(self.cancellation, asyncio.CancelledError)
        self.case.assertFalse(self.future.done())
        self.case.assertEqual(self.tree_attempts, 0)
        self.case.assertEqual(self.sweep_attempts, 0)

    async def complete_and_snapshot(
        self,
    ) -> tuple[tuple[dict, ...], tuple[bool, ...], bool]:
        self.release.set()
        await asyncio.wait_for(self.completed.wait(), WAIT_SECONDS)
        self.case.assertIsNotNone(self.future)
        self.case.assertTrue(self.future.done())

        reports = tuple(dict(details) for details in self.reports)
        ended, removed = self.snapshot()
        return reports, ended, removed

    async def finish(self) -> None:
        self.release.set()
        errors = []
        if self.caller is not None:
            requested = False
            if not self.caller.done():
                requested = self.caller.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self.caller), WAIT_SECONDS)
            except asyncio.CancelledError as error:
                if not (requested or self.cancellation_requested):
                    errors.append(error)
            except BaseException as error:
                errors.append(error)

        if self.future is not None:
            try:
                await asyncio.wait_for(asyncio.shield(self.future), WAIT_SECONDS)
            except BaseException as error:
                if error is not self.tree_failure:
                    errors.append(error)

        try:
            super().backup()
        except BaseException as error:
            errors.append(error)
        finally:
            self.loop.set_exception_handler(self.previous_handler)

        if errors:
            raise BackupFailures(tuple(errors))


class BrowserLaunchThreadedLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.context = ThreadedLaunchContext(self, asyncio.get_running_loop())
        self.addAsyncCleanup(self.context.finish)
        self.context.prepare()

    async def test_cancelled_held_launch_finishes_healthy_worker_cleanup(self) -> None:
        context = self.context
        await context.cancel_held_entry()
        reports, ended, removed = await context.complete_and_snapshot()

        self.assertEqual(ended, (True,))
        self.assertTrue(removed)
        self.assertEqual(context.tree_attempts, 1)
        self.assertEqual(context.sweep_attempts, 1)
        self.assertIsNone(context.future.exception())
        self.assertIs(context.future.result(), context.browser)
        self.assertEqual(reports, ())

    async def test_cancelled_held_launch_reports_its_completed_cleanup_failure(
        self,
    ) -> None:
        context = self.context
        failure = TreeFailure("controlled actual threaded cleanup failure")
        context.tree_failure = failure
        await context.cancel_held_entry()
        reports, ended, removed = await context.complete_and_snapshot()

        self.assertEqual(ended, (True,))
        self.assertFalse(removed)
        self.assertIs(context.browser.process, context.processes[0])
        self.assertIs(context.browser.profile, context.profile)
        self.assertEqual(context.tree_attempts, 1)
        self.assertEqual(context.sweep_attempts, 1)
        self.assertIs(context.future.exception(), failure)

        self.assertEqual(
            len(reports), 1, "cancelled launch lost its completed worker failure"
        )
        self.assertIs(reports[0].get("exception"), failure)
        self.assertIs(reports[0].get("future"), context.future)
        self.assertIs(reports[0].get("cancellation"), context.cancellation)

        with mock.patch.object(context, "tree_failure", None):
            context.browser.__exit__(None, None, None)
        ended, removed = context.snapshot()

        self.assertEqual(ended, (True,))
        self.assertTrue(removed)
        self.assertEqual(context.tree_attempts, 2)
        self.assertEqual(context.sweep_attempts, 2)
        self.assertIs(context.future.exception(), failure)
        self.assertEqual(tuple(context.reports), reports)
