import asyncio
import unittest

from scripts.capture.tests.test_android_browser_async_lifecycle import (
    PROGRESS_SECONDS,
    READY_SECONDS,
    STOP,
    WAIT_SECONDS,
    AndroidAsyncResources,
    HostChildFailures,
)
from scripts.capture.tests.test_android_device_lifecycle import (
    CLEANUP_COMMANDS,
    CONFIGURATION,
    OPEN,
    PACKAGE,
)


class AndroidExitFailure(RuntimeError):
    pass


class AndroidExitCancellation:
    def __init__(self, resources: AndroidAsyncResources) -> None:
        self.resources = resources
        self.case = resources.case
        self.driver = None
        self.browser = None
        self.caller: asyncio.Task | None = None
        self.cancellation: asyncio.CancelledError | None = None
        self.cancellation_requested = False
        self.entry_workers = ()
        self.worker = None
        self.checkpoint = 0

    async def enter(self, *, proxy: bool) -> None:
        resources = self.resources
        self.driver = resources.driver(proxy=proxy)
        entered = await asyncio.wait_for(self.driver.__aenter__(), WAIT_SECONDS)

        self.case.assertIs(entered, self.driver)
        self.browser = self.driver.browser
        self.case.assertIsNotNone(self.browser)
        self.case.assertTrue(self.browser.plan.android)
        self.case.assertFalse(self.browser.plan.takes_turns)
        self.case.assertIsNotNone(self.browser.session)
        self.case.assertFalse(resources.backup_started)
        self.case.assertFalse(resources.device.backup_started)
        self.case.assertEqual(resources.device.commands.count(OPEN), 1)
        self.case.assertEqual(
            resources.device.files, {CONFIGURATION: b"_ --disable-fre\n"}
        )
        self.case.assertEqual(resources.device.ports, {"tcp:9450", "tcp:9451"})
        self.case.assertEqual(resources.device.debug_app, PACKAGE)
        self.case.assertTrue(resources.device.running)
        self.case.assertEqual(len(resources.device.pushes), 1)
        local, remote, payload = resources.device.pushes[0]
        self.case.assertEqual((remote, payload), (CONFIGURATION, b"_ --disable-fre\n"))
        self.case.assertFalse(local.exists())
        self.case.assertFalse(local.parent.exists())

        self.entry_workers = tuple(resources.workers)
        for worker in self.entry_workers:
            await asyncio.wait_for(worker.completed.wait(), WAIT_SECONDS)
            self.assert_worker(worker, None)

        self.case.assertEqual(resources.reports, [])
        self.checkpoint = len(resources.device.commands)

    async def exit(self) -> None:
        try:
            await self.driver.__aexit__(None, None, None)
        except asyncio.CancelledError as failure:
            self.cancellation = failure
            raise

    async def cancel_held_exit(self, failure: BaseException | None = None) -> None:
        resources = self.resources
        resources.arm(STOP, monitor=True, hold_after_progress=True)
        self.caller = asyncio.create_task(self.exit())
        await asyncio.wait_for(
            resources.monitor.observed.wait(), READY_SECONDS + PROGRESS_SECONDS + 1
        )

        monitor = resources.monitor
        command = resources.command
        self.case.assertFalse(resources.backup_started)
        self.case.assertFalse(resources.device.backup_started)
        self.case.assertIsNone(monitor.failure)
        self.case.assertEqual(monitor.ready_observation["pid"], command.process.pid)
        self.case.assertEqual(monitor.ready_observation["arguments"], list(STOP))
        self.case.assertTrue(monitor.child_alive_before_release)
        self.case.assertTrue(monitor.gate_closed_before_release)
        self.case.assertTrue(
            monitor.progress_before_release,
            "Android exit did not keep its loop running before cancellation",
        )

        self.case.assertFalse(monitor.done.is_set())
        self.case.assertFalse(command.release.exists())
        self.case.assertIsNone(command.process.poll())
        self.case.assertEqual(resources.device.commands[self.checkpoint :], [])
        for worker in self.entry_workers:
            self.assert_worker(worker, None)

        workers = resources.workers[len(self.entry_workers) :]
        self.case.assertEqual(len(workers), 1)
        self.worker = workers[0]
        self.case.assertFalse(self.worker.future.done())
        self.case.assertFalse(self.worker.exited.is_set())
        self.case.assertFalse(self.caller.done())

        resources.device.cleanup_failure = failure
        resources.expected_worker_failure = failure
        self.cancellation_requested = self.caller.cancel(
            "controlled pending Android exit cancellation"
        )
        self.case.assertTrue(self.cancellation_requested)

        with self.case.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(self.caller), PROGRESS_SECONDS)

        self.case.assertTrue(self.caller.cancelled())
        self.case.assertIsInstance(self.cancellation, asyncio.CancelledError)
        self.case.assertEqual(
            self.cancellation.args, ("controlled pending Android exit cancellation",)
        )
        self.case.assertFalse(self.worker.future.done())
        self.case.assertFalse(self.worker.future.cancelled())
        self.case.assertFalse(self.worker.exited.is_set())
        self.case.assertFalse(command.release.exists())
        self.case.assertIsNone(command.process.poll())

    async def complete_worker(self) -> None:
        self.resources.monitor.stop.set()
        await asyncio.wait_for(self.worker.completed.wait(), WAIT_SECONDS)
        self.resources.monitor.finish()
        await asyncio.sleep(0)

    def assert_worker(self, worker, failure: BaseException | None) -> None:
        self.case.assertTrue(worker.exited.is_set())
        self.case.assertTrue(worker.future.done())
        self.case.assertFalse(worker.future.cancelled())
        self.case.assertIs(worker.failure, failure)
        self.case.assertIs(worker.future.exception(), failure)

    def assert_completed(self, failure: BaseException | None = None) -> None:
        resources = self.resources
        command = resources.command
        self.case.assertFalse(resources.backup_started)
        self.case.assertFalse(resources.device.backup_started)
        self.case.assertTrue(resources.device.selected)
        self.case.assertTrue(command.finished.is_set())
        self.case.assertEqual(command.process.poll(), 0)
        self.case.assertEqual(command.output, b"host-command-complete\n")
        self.case.assertEqual(command.error_output, b"")
        self.case.assertTrue(command.process.stdout.closed)
        self.case.assertTrue(command.process.stderr.closed)
        self.case.assertEqual(
            resources.device.commands[self.checkpoint :], CLEANUP_COMMANDS
        )
        self.case.assertEqual(resources.device.files, {})
        self.case.assertEqual(resources.device.ports, set())
        self.case.assertIsNone(resources.device.debug_app)
        self.case.assertFalse(resources.device.running)

        if failure is None:
            self.case.assertEqual(resources.reports, [])
            self.case.assertIsNone(self.browser.session)
            self.case.assertIsNone(resources.device.cleanup_raised)
        else:
            self.case.assertIs(resources.device.cleanup_raised, failure)
            self.case.assertEqual(
                len(resources.reports), 1, "Android exit lost its worker failure"
            )
            report = resources.reports[0]
            self.case.assertIs(report.get("exception"), failure)
            self.case.assertIs(report.get("future"), self.worker.future)
            self.case.assertIs(report.get("cancellation"), self.cancellation)

        for worker in self.entry_workers:
            self.assert_worker(worker, None)
        self.assert_worker(self.worker, failure)

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

        for worker in tuple(resources.workers):
            try:
                await asyncio.wait_for(asyncio.shield(worker.future), WAIT_SECONDS)
            except BaseException as failure:
                if failure is not resources.expected_worker_failure:
                    failures.append(failure)

        if self.driver is not None and self.driver.browser is not None:
            try:
                await asyncio.wait_for(
                    self.driver.__aexit__(None, None, None), WAIT_SECONDS
                )
            except BaseException as failure:
                failures.append(failure)

        if failures:
            raise HostChildFailures(None, failures)


class AndroidBrowserExitCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.resources = AndroidAsyncResources(self)
        self.addAsyncCleanup(self.resources.finish)
        self.exit_owner = AndroidExitCancellation(self.resources)
        self.addAsyncCleanup(self.exit_owner.finish)
        self.resources.prepare()

    async def healthy_exit(self, *, proxy: bool) -> None:
        owner = self.exit_owner
        await owner.enter(proxy=proxy)
        await owner.cancel_held_exit()
        await owner.complete_worker()

        owner.assert_completed()

    async def failed_exit(self, *, proxy: bool) -> None:
        owner = self.exit_owner
        failure = AndroidExitFailure("controlled completed Android exit failure")
        cause = LookupError("original Android exit cause")
        failure.__cause__ = cause
        await owner.enter(proxy=proxy)
        await owner.cancel_held_exit(failure)
        await owner.complete_worker()

        owner.assert_completed(failure)
        self.assertIs(failure.__cause__, cause)

    async def test_cancelled_android_exit_finishes_its_healthy_worker(self) -> None:
        await self.healthy_exit(proxy=False)

    async def test_cancelled_android_exit_reports_its_exact_worker_failure(
        self,
    ) -> None:
        await self.failed_exit(proxy=False)

    async def test_cancelled_android_proxy_exit_finishes_its_healthy_worker(
        self,
    ) -> None:
        await self.healthy_exit(proxy=True)

    async def test_cancelled_android_proxy_exit_reports_its_exact_worker_failure(
        self,
    ) -> None:
        await self.failed_exit(proxy=True)
