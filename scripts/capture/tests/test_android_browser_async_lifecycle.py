import asyncio
import contextlib
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture import browser_launch
from scripts.capture.android_device import ANDROID_BROWSERS, AndroidLaunch
from scripts.capture.proxy_route import ProxyBrowserDriver
from scripts.capture.tests.test_android_device_lifecycle import (
    CLEANUP_COMMANDS,
    OPEN,
    STOP,
    URL,
    OfflineDevice,
)

WAIT_SECONDS = 25
READY_SECONDS = 10
PROGRESS_SECONDS = 2
COMMAND_CHILD = """
import json
import os
import sys
import time
from pathlib import Path

ready, release, arguments = sys.argv[1:]
pending = Path(ready).with_suffix(".tmp")
pending.write_text(json.dumps({"pid": os.getpid(), "arguments": json.loads(arguments)}))
pending.replace(ready)
deadline = time.monotonic() + 20
while not Path(release).exists():
    if time.monotonic() >= deadline:
        raise SystemExit(70)
    time.sleep(0.01)
sys.stdout.buffer.write(b"host-command-complete\\n")
"""


class HostChildFailures(Exception):
    def __init__(
        self, primary: BaseException | None, cleanup: list[BaseException]
    ) -> None:
        self.primary = primary
        self.cleanup = tuple(cleanup)
        super().__init__("offline command child cleanup failed")


class HostCommand:
    def __init__(self, directory: Path, arguments: tuple[str, ...]) -> None:
        self.arguments = arguments
        self.ready = directory / "ready.json"
        self.release = directory / "release"
        self.process: subprocess.Popen[bytes] | None = None
        self.output: bytes | None = None
        self.error_output: bytes | None = None
        self.finished = threading.Event()
        self.actual_popen = subprocess.Popen

    def allow_completion(self) -> None:
        self.release.touch()

    def invoke(self) -> None:
        primary = None
        cleanup = []
        try:
            process = self.actual_popen(
                [
                    sys.executable,
                    "-u",
                    "-c",
                    COMMAND_CHILD,
                    str(self.ready),
                    str(self.release),
                    json.dumps(self.arguments),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.process = process
            self.output, self.error_output = process.communicate(timeout=WAIT_SECONDS)
            if process.returncode != 0:
                raise RuntimeError("offline command child did not finish normally")
        except BaseException as failure:
            primary = failure
        finally:
            try:
                self.close_child()
            except BaseException as failure:
                cleanup.append(failure)
            self.finished.set()

        if cleanup:
            failure = HostChildFailures(primary, cleanup)
            if primary is not None and not isinstance(primary, Exception):
                raise primary from failure
            raise failure from primary
        if primary is not None:
            raise primary

    def close_child(self) -> None:
        process = self.process
        if process is None:
            return
        failures = []
        if process.poll() is None:
            try:
                process.kill()
                process.communicate(timeout=5)
            except BaseException as failure:
                failures.append(failure)
        if process.poll() is None:
            failures.append(TimeoutError("offline command child remains alive"))
        else:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as failure:
                        failures.append(failure)

        if failures:
            raise HostChildFailures(None, failures)


class CommandDevice(OfflineDevice):
    def __init__(self) -> None:
        super().__init__()
        self.command: HostCommand | None = None
        self.selected = False

    def run(self, *arguments: str, check: bool = True) -> str:
        command = self.command
        if command is not None and arguments == command.arguments and not self.selected:
            self.selected = True
            command.invoke()
        return super().run(*arguments, check=check)


class ProgressMonitor:
    def __init__(self, loop: asyncio.AbstractEventLoop, command: HostCommand) -> None:
        self.loop = loop
        self.command = command
        self.callback = threading.Event()
        self.done = threading.Event()
        self.stop = threading.Event()
        self.progress_before_release = False
        self.child_alive_before_release = False
        self.gate_closed_before_release = False
        self.ready_observation: dict | None = None
        self.failure: BaseException | None = None
        self.release_failure: BaseException | None = None
        self.thread = threading.Thread(
            target=self.observe, name="android-command-progress"
        )

    def start(self) -> None:
        self.thread.start()

    def observe(self) -> None:
        try:
            deadline = time.monotonic() + READY_SECONDS
            while not self.command.ready.exists():
                if self.stop.wait(0.01):
                    return
                if time.monotonic() >= deadline:
                    raise TimeoutError("offline command child did not become ready")
            self.ready_observation = json.loads(self.command.ready.read_text())
            self.loop.call_soon_threadsafe(self.callback.set)
            self.progress_before_release = self.callback.wait(PROGRESS_SECONDS)
            process = self.command.process
            self.child_alive_before_release = (
                process is not None and process.poll() is None
            )
            self.gate_closed_before_release = not self.command.release.exists()
        except BaseException as failure:
            self.failure = failure
        finally:
            try:
                self.command.allow_completion()
            except BaseException as failure:
                self.release_failure = failure
            self.done.set()

    def finish(self) -> None:
        self.stop.set()
        release_failure = None
        try:
            self.command.allow_completion()
        except BaseException as failure:
            release_failure = failure
        self.thread.join(READY_SECONDS + PROGRESS_SECONDS + 1)
        if self.thread.is_alive():
            raise TimeoutError("offline command progress monitor did not stop")
        if release_failure is not None:
            raise HostChildFailures(self.failure, [release_failure])
        if self.release_failure is not None:
            raise HostChildFailures(self.failure, [self.release_failure])
        if self.failure is not None:
            raise self.failure


class SubmittedWorker:
    def __init__(self) -> None:
        self.exited = threading.Event()
        self.future: asyncio.Future | None = None
        self.failure: BaseException | None = None


class AndroidAsyncResources:
    def __init__(self, case: unittest.TestCase) -> None:
        self.case = case
        self.loop = asyncio.get_running_loop()
        self.directory: tempfile.TemporaryDirectory | None = None
        self.device = CommandDevice()
        self.launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"],
            URL,
            ("--disable-fre",),
            entry="intent",
            settle=0,
            typing_attempts=1,
            reverse=(9451,),
        )
        self.patches = contextlib.ExitStack()
        self.command: HostCommand | None = None
        self.monitor: ProgressMonitor | None = None
        self.workers: list[SubmittedWorker] = []
        self.reports: list[dict] = []
        self.previous_handler = self.loop.get_exception_handler()
        self.actual_executor = self.loop.run_in_executor
        self.backup_started = False

    def prepare(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="android-host-command-")
        self.patches.enter_context(
            patch("scripts.capture.browser_launch.AdbDevice", return_value=self.device)
        )
        self.patches.enter_context(
            patch.object(
                browser_launch.LaunchedBrowser,
                "android_launch",
                return_value=self.launch,
            )
        )
        self.patches.enter_context(
            patch.object(self.loop, "run_in_executor", self.submit)
        )
        self.loop.set_exception_handler(self.report)

    def submit(self, executor, operation, *arguments):
        worker = SubmittedWorker()
        self.workers.append(worker)

        def observe():
            try:
                return operation(*arguments)
            except BaseException as failure:
                worker.failure = failure
                raise
            finally:
                worker.exited.set()

        worker.future = self.actual_executor(executor, observe)
        return worker.future

    def report(self, loop, details: dict) -> None:
        self.reports.append(dict(details))
        if not any(details.get("future") is worker.future for worker in self.workers):
            if self.previous_handler is None:
                loop.default_exception_handler(details)
            else:
                self.previous_handler(loop, details)

    def driver(self, *, proxy: bool = False):
        plan = browser_launch.LaunchPlan("chrome-android", Path("offline-adb"), False)
        if proxy:
            return ProxyBrowserDriver(plan, URL, auth=False)
        return browser_launch.BrowserDriver(plan, URL)

    def arm(self, arguments: tuple[str, ...], *, monitor: bool) -> None:
        self.case.assertIsNone(self.command)
        self.case.assertIsNotNone(self.directory)
        self.command = HostCommand(Path(self.directory.name), arguments)
        self.device.command = self.command
        if monitor:
            self.monitor = ProgressMonitor(self.loop, self.command)
            self.monitor.start()
        else:
            self.command.allow_completion()

    def assert_completed_before_backup(self) -> None:
        self.case.assertFalse(self.backup_started)
        self.case.assertFalse(self.device.backup_started)
        command = self.command
        self.case.assertIsNotNone(command)
        self.case.assertTrue(self.device.selected)
        self.case.assertTrue(command.finished.is_set())
        self.case.assertIsNotNone(command.process)
        self.case.assertEqual(command.process.poll(), 0)
        self.case.assertEqual(command.output, b"host-command-complete\n")
        self.case.assertEqual(command.error_output, b"")
        self.case.assertTrue(command.process.stdout.closed)
        self.case.assertTrue(command.process.stderr.closed)

        for worker in self.workers:
            self.case.assertTrue(worker.exited.is_set())
            self.case.assertTrue(worker.future.done())
            self.case.assertFalse(worker.future.cancelled())
            self.case.assertIsNone(worker.failure)
            self.case.assertIsNone(worker.future.exception())

        self.case.assertEqual(self.device.commands[-5:], CLEANUP_COMMANDS)
        self.case.assertEqual(self.device.files, {})
        self.case.assertEqual(self.device.ports, set())
        self.case.assertIsNone(self.device.debug_app)
        self.case.assertFalse(self.device.running)
        self.case.assertEqual(self.reports, [])

    def assert_progress(self) -> None:
        monitor = self.monitor
        self.case.assertIsNotNone(monitor)
        self.case.assertTrue(monitor.done.is_set())
        self.case.assertIsNone(monitor.failure)
        self.case.assertIsNone(monitor.release_failure)
        self.case.assertEqual(
            monitor.ready_observation["pid"], self.command.process.pid
        )
        self.case.assertEqual(
            monitor.ready_observation["arguments"], list(self.command.arguments)
        )
        self.case.assertTrue(monitor.child_alive_before_release)
        self.case.assertTrue(monitor.gate_closed_before_release)
        self.case.assertTrue(
            monitor.progress_before_release,
            "canonical Android operation blocked loop progress "
            "while its actual command child was held",
        )

    async def finish(self) -> None:
        self.backup_started = True
        failures = []
        if self.command is not None:
            try:
                self.command.allow_completion()
            except BaseException as failure:
                failures.append(failure)
        if self.monitor is not None:
            try:
                self.monitor.finish()
            except BaseException as failure:
                failures.append(failure)

        for worker in self.workers:
            try:
                await asyncio.wait_for(asyncio.shield(worker.future), WAIT_SECONDS)
            except BaseException as failure:
                failures.append(failure)
        if self.command is not None and self.device.selected:
            try:
                if not self.command.finished.is_set():
                    process = self.command.process
                    if process is not None and process.poll() is None:
                        process.kill()
                    if not self.command.finished.wait(5):
                        raise TimeoutError("offline command operation did not exit")
                self.command.close_child()
            except BaseException as failure:
                failures.append(failure)

        try:
            self.loop.set_exception_handler(self.previous_handler)
        except BaseException as failure:
            failures.append(failure)
        try:
            self.patches.close()
        except BaseException as failure:
            failures.append(failure)
        self.device.backup()
        if self.directory is not None:
            try:
                self.directory.cleanup()
            except BaseException as failure:
                failures.append(failure)
        if failures:
            raise HostChildFailures(None, failures)


class AndroidBrowserAsyncLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.resources = AndroidAsyncResources(self)
        self.addAsyncCleanup(self.resources.finish)
        self.resources.prepare()

    async def test_healthy_android_context_finishes_its_actual_host_command(
        self,
    ) -> None:
        resources = self.resources
        resources.arm(OPEN, monitor=False)
        async with resources.driver():
            self.assertTrue(resources.device.running)

        resources.assert_completed_before_backup()

    async def test_android_startup_keeps_the_loop_running_before_command_release(
        self,
    ) -> None:
        resources = self.resources
        resources.arm(OPEN, monitor=True)
        async with resources.driver():
            self.assertTrue(resources.device.running)

        resources.assert_completed_before_backup()
        resources.assert_progress()

    async def test_android_shutdown_keeps_the_loop_running_before_command_release(
        self,
    ) -> None:
        resources = self.resources
        async with resources.driver():
            self.assertTrue(resources.device.running)
            resources.arm(STOP, monitor=True)

        resources.assert_completed_before_backup()
        resources.assert_progress()

    async def test_android_proxy_shutdown_keeps_loop_progress_before_command_release(
        self,
    ) -> None:
        resources = self.resources
        async with resources.driver(proxy=True):
            self.assertTrue(resources.device.running)
            resources.arm(STOP, monitor=True)

        resources.assert_completed_before_backup()
        resources.assert_progress()
