import asyncio
import unittest
from unittest.mock import patch

from scripts.capture import browser_launch
from scripts.capture.browser_failures import BrowserLaunchFailures
from scripts.capture.tests.test_android_browser_async_lifecycle import (
    PROGRESS_SECONDS,
    READY_SECONDS,
    STOP,
    WAIT_SECONDS,
    AndroidAsyncResources,
    HostChildFailures,
)
from scripts.capture.tests.test_android_browser_exit_cancellation import (
    AndroidExitCancellation,
    AndroidExitFailure,
)
from scripts.capture.tests.test_android_device_lifecycle import (
    CONFIGURATION,
    OPEN,
    PACKAGE,
)


class CompletedAndroidEntry(AndroidExitCancellation):
    def __init__(self, resources: AndroidAsyncResources) -> None:
        super().__init__(resources)
        self.driver = resources.driver()
        self.cleanup_driver = resources.driver()
        self.entry_future: asyncio.Future | None = None
        self.registered_pending = False
        self.observer_completed = asyncio.Event()
        self.observer_failure: BaseException | None = None
        self.delivered = False
        self.cleanup_failure: BaseException | None = None
        self.rejection: BaseException | None = None
        self.rejected_operation = None
        self.rejected_arguments = None
        self.recovery_caller: asyncio.Task | None = None

    def submit(self, executor, operation, *arguments):
        if self.entry_future is not None and self.rejection is not None:
            self.rejected_operation = operation
            self.rejected_arguments = arguments
            raise self.rejection

        future = self.resources.submit(executor, operation, *arguments)
        if self.entry_future is None:
            self.entry_future = future
            self.entry_workers = (self.resources.workers[-1],)
            self.registered_pending = not future.done()
            # Register before the canonical shield can schedule caller delivery.
            future.add_done_callback(self.completed_entry)
        return future

    def completed_entry(self, future: asyncio.Future) -> None:
        try:
            self.browser = future.result()
            self.cleanup_driver.browser = self.browser
            self.checkpoint = len(self.resources.device.commands)
            self.resources.device.cleanup_failure = self.cleanup_failure
            self.resources.expected_worker_failure = self.cleanup_failure
            self.resources.arm(STOP, monitor=True, hold_after_progress=True)
            self.cancellation_requested = self.caller.cancel(
                "controlled completed Android entry cancellation"
            )
        except BaseException as failure:
            self.observer_failure = failure
        finally:
            self.observer_completed.set()

    async def enter_caller(self) -> None:
        try:
            await self.driver.__aenter__()
            self.delivered = True
        except asyncio.CancelledError as failure:
            self.cancellation = failure
            raise

    async def cancel_completed_entry(self) -> None:
        self.resources.patches.enter_context(
            patch.object(self.resources.loop, "run_in_executor", new=self.submit)
        )
        self.caller = asyncio.create_task(self.enter_caller())
        await asyncio.wait_for(self.observer_completed.wait(), WAIT_SECONDS)

        self.case.assertFalse(self.resources.backup_started)
        self.case.assertIsNone(self.observer_failure)
        self.case.assertTrue(self.registered_pending)
        self.case.assertIs(self.entry_future, self.entry_workers[0].future)
        self.assert_worker(self.entry_workers[0], None)
        self.case.assertIs(self.entry_future.result(), self.browser)
        self.case.assertIsInstance(self.browser, browser_launch.LaunchedBrowser)
        self.case.assertTrue(self.browser.plan.android)
        self.case.assertFalse(self.browser.plan.takes_turns)
        self.case.assertTrue(self.cancellation_requested)

        with self.case.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(self.caller), PROGRESS_SECONDS)

        self.case.assertTrue(self.caller.cancelled())
        self.case.assertIsInstance(self.cancellation, asyncio.CancelledError)
        self.case.assertEqual(
            self.cancellation.args,
            ("controlled completed Android entry cancellation",),
        )
        self.case.assertFalse(self.delivered)
        self.case.assertIsNone(self.driver.browser)
        self.case.assertEqual(self.resources.device.commands.count(OPEN), 1)
        self.case.assertEqual(len(self.resources.device.pushes), 1)
        local, remote, payload = self.resources.device.pushes[0]
        self.case.assertEqual((remote, payload), (CONFIGURATION, b"_ --disable-fre\n"))
        self.case.assertFalse(local.exists())
        self.case.assertFalse(local.parent.exists())

    async def assert_held_cleanup(self) -> None:
        resources = self.resources
        await asyncio.wait_for(
            resources.monitor.observed.wait(), READY_SECONDS + PROGRESS_SECONDS + 1
        )

        self.case.assertFalse(resources.backup_started)
        self.case.assertFalse(resources.device.backup_started)
        self.case.assertIsNone(resources.monitor.failure)
        self.case.assertEqual(
            resources.monitor.ready_observation["pid"], resources.command.process.pid
        )
        self.case.assertEqual(
            resources.monitor.ready_observation["arguments"], list(STOP)
        )
        self.case.assertTrue(resources.monitor.child_alive_before_release)
        self.case.assertTrue(resources.monitor.gate_closed_before_release)
        self.case.assertTrue(
            resources.monitor.progress_before_release,
            "completed-entry cleanup blocked progress while its real command was held",
        )
        self.case.assertFalse(resources.monitor.done.is_set())
        self.case.assertFalse(resources.command.release.exists())
        self.case.assertIsNone(resources.command.process.poll())
        self.case.assertEqual(resources.device.commands[self.checkpoint :], [])
        self.case.assertEqual(
            resources.device.files, {CONFIGURATION: b"_ --disable-fre\n"}
        )
        self.case.assertEqual(resources.device.ports, {"tcp:9450", "tcp:9451"})
        self.case.assertEqual(resources.device.debug_app, PACKAGE)
        self.case.assertTrue(resources.device.running)
        self.case.assertIsNotNone(self.browser.session)
        self.case.assertEqual(len(resources.workers), 2)
        self.worker = resources.workers[1]
        self.case.assertIsNot(self.worker.future, self.entry_future)
        self.case.assertIs(self.browser._exit_future, self.worker.future)
        self.case.assertFalse(self.worker.future.done())
        self.case.assertFalse(self.worker.future.cancelled())
        self.case.assertFalse(self.worker.exited.is_set())
        self.case.assertEqual(resources.reports, [])

    async def finish(self) -> None:
        failures = []
        try:
            await super().finish()
        except BaseException as failure:
            failures.append(failure)
        if self.recovery_caller is not None:
            requested = False
            if not self.recovery_caller.done():
                requested = self.recovery_caller.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.shield(self.recovery_caller), WAIT_SECONDS
                )
            except asyncio.CancelledError as failure:
                if not requested:
                    failures.append(failure)
            except BaseException as failure:
                failures.append(failure)
        try:
            with patch.object(
                self.resources.loop, "run_in_executor", new=self.resources.submit
            ):
                if self.cleanup_driver.browser is not None:
                    await asyncio.wait_for(
                        self.cleanup_driver.__aexit__(None, None, None), WAIT_SECONDS
                    )
        except BaseException as failure:
            failures.append(failure)
        if self.observer_failure is not None:
            failures.append(self.observer_failure)
        if failures:
            raise HostChildFailures(None, failures)


class AdditionalAndroidExitCallers:
    def __init__(
        self, resources: AndroidAsyncResources, owner: AndroidExitCancellation
    ) -> None:
        self.resources = resources
        self.owner = owner
        self.callers: list[asyncio.Task] = []
        self.entered: list[asyncio.Event] = []

    def start(self) -> None:
        entered = asyncio.Event()

        async def exit_again() -> None:
            entered.set()
            await self.owner.driver.__aexit__(None, None, None)

        self.entered.append(entered)
        self.callers.append(asyncio.create_task(exit_again()))

    async def finish(self) -> None:
        failures = []
        if self.resources.command is not None:
            try:
                self.resources.command.allow_completion()
            except BaseException as failure:
                failures.append(failure)
        if self.resources.monitor is not None:
            self.resources.monitor.stop.set()
        for caller in self.callers:
            requested = False
            if not caller.done():
                requested = caller.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(caller), WAIT_SECONDS)
            except asyncio.CancelledError as failure:
                if not requested:
                    failures.append(failure)
            except BaseException as failure:
                if failure is not self.resources.expected_worker_failure:
                    failures.append(failure)
        if failures:
            raise HostChildFailures(None, failures)


class AndroidBrowserWorkerHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.resources = AndroidAsyncResources(self)
        self.addAsyncCleanup(self.resources.finish)
        self.resources.prepare()

    async def completed_entry(self, failure: BaseException | None) -> None:
        owner = CompletedAndroidEntry(self.resources)
        self.addAsyncCleanup(owner.finish)
        owner.cleanup_failure = failure
        await owner.cancel_completed_entry()
        await owner.assert_held_cleanup()
        await owner.complete_worker()

        owner.assert_completed(failure)
        self.assertEqual(len(self.resources.workers), 2)
        self.assertIs(self.resources.workers[0].future, owner.entry_future)
        self.assertIs(self.resources.workers[1].future, owner.worker.future)

    async def shared_cleanup(self, failure: BaseException | None) -> None:
        resources = self.resources
        owner = AndroidExitCancellation(resources)
        self.addAsyncCleanup(owner.finish)
        callers = AdditionalAndroidExitCallers(resources, owner)
        self.addAsyncCleanup(callers.finish)
        await owner.enter(proxy=False)
        await owner.cancel_held_exit(failure)

        callers.start()
        await asyncio.wait_for(callers.entered[0].wait(), PROGRESS_SECONDS)
        callers.start()
        await asyncio.wait_for(callers.entered[1].wait(), PROGRESS_SECONDS)
        progressed = asyncio.Event()
        resources.loop.call_soon(progressed.set)
        await asyncio.wait_for(progressed.wait(), PROGRESS_SECONDS)

        self.assertFalse(resources.backup_started)
        self.assertTrue(owner.caller.cancelled())
        self.assertTrue(all(not caller.done() for caller in callers.callers))
        self.assertFalse(resources.command.release.exists())
        self.assertIsNone(resources.command.process.poll())
        self.assertEqual(resources.device.commands[owner.checkpoint :], [])
        self.assertEqual(resources.workers[len(owner.entry_workers) :], [owner.worker])
        self.assertIs(owner.browser._exit_future, owner.worker.future)
        self.assertFalse(owner.worker.future.done())
        self.assertFalse(owner.worker.future.cancelled())
        self.assertFalse(owner.worker.exited.is_set())
        self.assertEqual(resources.reports, [])

        await owner.complete_worker()
        owner.assert_completed(failure)

        for caller in callers.callers:
            if failure is None:
                self.assertIsNone(await asyncio.wait_for(caller, WAIT_SECONDS))
            else:
                with self.assertRaises(type(failure)) as raised:
                    await asyncio.wait_for(caller, WAIT_SECONDS)
                self.assertIs(raised.exception, failure)
        self.assertEqual(resources.workers[len(owner.entry_workers) :], [owner.worker])
        self.assertFalse(resources.backup_started)

    async def test_completed_entry_cancellation_finishes_healthy_cleanup(self) -> None:
        await self.completed_entry(None)

    async def test_completed_entry_cancellation_reports_original_cleanup_failure(
        self,
    ) -> None:
        failure = AndroidExitFailure("controlled completed-entry cleanup failure")
        cause = LookupError("original completed-entry cleanup cause")
        failure.__cause__ = cause
        await self.completed_entry(failure)
        self.assertIs(failure.__cause__, cause)

    async def test_repeated_concurrent_exit_calls_share_healthy_pending_cleanup(
        self,
    ) -> None:
        await self.shared_cleanup(None)

    async def test_repeated_concurrent_exit_calls_share_original_cleanup_failure(
        self,
    ) -> None:
        failure = AndroidExitFailure("controlled shared cleanup failure")
        cause = LookupError("original shared cleanup cause")
        failure.__cause__ = cause
        await self.shared_cleanup(failure)
        self.assertIs(failure.__cause__, cause)

    async def test_completed_entry_retains_owner_when_cleanup_submission_is_rejected(
        self,
    ) -> None:
        resources = self.resources
        owner = CompletedAndroidEntry(resources)
        self.addAsyncCleanup(owner.finish)
        rejection = RuntimeError("controlled cleanup executor submission rejection")
        cause = LookupError("original submission rejection cause")
        rejection.__cause__ = cause
        owner.rejection = rejection
        await owner.cancel_completed_entry()

        self.assertFalse(resources.backup_started)
        self.assertEqual(len(resources.workers), 1)
        self.assertIs(owner.rejected_operation.__self__, owner.browser)
        self.assertIs(
            owner.rejected_operation.__func__, browser_launch.LaunchedBrowser.__exit__
        )
        self.assertEqual(owner.rejected_arguments, (None, None, None))
        self.assertIsNone(owner.browser._exit_future)
        self.assertIsNotNone(owner.browser.session)
        self.assertIsNone(resources.command.process)
        self.assertEqual(resources.device.commands[owner.checkpoint :], [])

        composition = owner.cancellation.__cause__
        self.assertIsInstance(composition, BrowserLaunchFailures)
        self.assertIs(composition.primary, owner.cancellation)
        self.assertEqual(len(composition.cleanup), 1)
        recovery = composition.cleanup[0]
        self.assertIsInstance(recovery, browser_launch.BrowserExitSubmissionFailure)
        self.assertIs(recovery.browser, owner.browser)
        self.assertIs(recovery.submission_error, rejection)
        self.assertIs(recovery.__cause__, rejection)
        self.assertIs(rejection.__cause__, cause)

        with patch.object(resources.loop, "run_in_executor", new=resources.submit):
            owner.recovery_caller = asyncio.create_task(
                owner.cleanup_driver.__aexit__(None, None, None)
            )
            await owner.assert_held_cleanup()
            resources.monitor.stop.set()
            await asyncio.wait_for(asyncio.shield(owner.recovery_caller), WAIT_SECONDS)

        await owner.complete_worker()
        owner.assert_completed()
        self.assertIsNone(owner.browser.session)
        self.assertIs(composition.primary, owner.cancellation)
        self.assertIs(recovery.browser, owner.browser)
        self.assertIs(recovery.submission_error, rejection)
        self.assertIs(rejection.__cause__, cause)
