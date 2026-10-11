import asyncio
import unittest

from scripts.capture import browser_launch
from scripts.capture.tests.test_android_browser_async_lifecycle import (
    OPEN,
    PROGRESS_SECONDS,
    READY_SECONDS,
    WAIT_SECONDS,
    AndroidAsyncResources,
    HostChildFailures,
)


class AndroidCleanupFailure(RuntimeError):
    pass


class AndroidEntryCancellation:
    def __init__(self, resources: AndroidAsyncResources) -> None:
        self.resources = resources
        self.case = resources.case
        self.driver = resources.driver()
        self.caller: asyncio.Task | None = None
        self.cancellation: asyncio.CancelledError | None = None
        self.cancellation_requested = False

    async def enter(self) -> None:
        try:
            await self.driver.__aenter__()
        except asyncio.CancelledError as failure:
            self.cancellation = failure
            raise

    async def wait_for_observation(self) -> None:
        await self.resources.monitor.observed.wait()

    async def cancel_held_entry(
        self, cleanup_failure: BaseException | None = None
    ) -> None:
        resources = self.resources
        resources.arm(OPEN, monitor=True, hold_after_progress=True)
        self.caller = asyncio.create_task(self.enter())
        await asyncio.wait_for(
            self.wait_for_observation(), READY_SECONDS + PROGRESS_SECONDS + 1
        )

        monitor = resources.monitor
        command = resources.command
        self.case.assertFalse(resources.backup_started)
        self.case.assertFalse(resources.device.backup_started)
        self.case.assertIsNone(monitor.failure)
        self.case.assertEqual(monitor.ready_observation["pid"], command.process.pid)
        self.case.assertEqual(monitor.ready_observation["arguments"], list(OPEN))
        self.case.assertTrue(monitor.child_alive_before_release)
        self.case.assertTrue(monitor.gate_closed_before_release)
        self.case.assertTrue(
            monitor.progress_before_release,
            "Android entry did not keep its loop running before cancellation",
        )

        self.case.assertFalse(monitor.done.is_set())
        self.case.assertFalse(command.release.exists())
        self.case.assertIsNone(command.process.poll())
        self.case.assertEqual(len(resources.workers), 1)
        worker = resources.workers[0]
        self.case.assertFalse(worker.future.done())
        self.case.assertFalse(worker.exited.is_set())
        self.case.assertFalse(self.caller.done())

        resources.device.cleanup_failure = cleanup_failure
        resources.expected_worker_failure = cleanup_failure
        self.cancellation_requested = self.caller.cancel(
            "controlled pending Android entry cancellation"
        )
        self.case.assertTrue(self.cancellation_requested)

        with self.case.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(self.caller), WAIT_SECONDS)

        self.case.assertTrue(self.caller.cancelled())
        self.case.assertIsInstance(self.cancellation, asyncio.CancelledError)
        self.case.assertEqual(
            self.cancellation.args, ("controlled pending Android entry cancellation",)
        )
        self.case.assertFalse(worker.future.done())
        self.case.assertFalse(worker.exited.is_set())
        self.case.assertFalse(command.release.exists())
        self.case.assertIsNone(command.process.poll())

    async def complete_worker(self) -> None:
        resources = self.resources
        resources.monitor.stop.set()
        await asyncio.wait_for(resources.workers[0].completed.wait(), WAIT_SECONDS)
        await asyncio.sleep(0)

        self.case.assertTrue(resources.monitor.done.is_set())
        self.case.assertIsNone(resources.monitor.failure)
        self.case.assertIsNone(resources.monitor.release_failure)

    async def finish(self) -> None:
        resources = self.resources
        failures = []
        if resources.command is not None:
            try:
                resources.command.allow_completion()
            except BaseException as failure:
                failures.append(failure)
        if resources.monitor is not None:
            resources.monitor.stop.set()

        if self.caller is not None:
            requested = False
            if not self.caller.done():
                requested = self.caller.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self.caller), WAIT_SECONDS)
            except asyncio.CancelledError as failure:
                if not (requested or self.cancellation_requested):
                    failures.append(failure)
            except BaseException as failure:
                failures.append(failure)

        if self.driver.browser is not None:
            try:
                await self.driver.__aexit__(None, None, None)
            except BaseException as failure:
                failures.append(failure)

        if failures:
            raise HostChildFailures(None, failures)


class AndroidBrowserEntryCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.resources = AndroidAsyncResources(self)
        self.addAsyncCleanup(self.resources.finish)
        self.resources.prepare()
        self.entry = AndroidEntryCancellation(self.resources)
        self.addAsyncCleanup(self.entry.finish)

    async def test_cancelled_android_entry_finishes_its_healthy_worker(self) -> None:
        resources = self.resources
        entry = self.entry
        await entry.cancel_held_entry()
        await entry.complete_worker()

        resources.assert_completed_before_backup()
        worker = resources.workers[0]
        browser = worker.future.result()
        self.assertIsInstance(browser, browser_launch.LaunchedBrowser)
        self.assertIsNone(browser.session)
        self.assertIsNone(resources.device.cleanup_raised)
        self.assertEqual(resources.reports, [])

    async def test_cancelled_android_entry_reports_its_exact_cleanup_failure(
        self,
    ) -> None:
        resources = self.resources
        entry = self.entry
        failure = AndroidCleanupFailure("controlled completed Android cleanup failure")
        cause = LookupError("original Android cleanup cause")
        failure.__cause__ = cause
        await entry.cancel_held_entry(failure)
        await entry.complete_worker()

        resources.assert_completed_before_backup(expected_failure=failure)
        worker = resources.workers[0]
        self.assertIs(resources.device.cleanup_raised, failure)
        self.assertIs(failure.__cause__, cause)
        self.assertEqual(
            len(resources.reports), 1, "Android entry lost its completed worker failure"
        )
        self.assertIs(resources.reports[0].get("exception"), failure)
        self.assertIs(resources.reports[0].get("future"), worker.future)
        self.assertIs(resources.reports[0].get("cancellation"), entry.cancellation)
