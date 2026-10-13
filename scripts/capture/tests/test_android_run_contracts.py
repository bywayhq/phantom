import io
import os
import shlex
import subprocess
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest.mock import patch

from scripts.capture import android_run, browser_launch
from scripts.capture.android_device import (
    ALLOW_COLD_BOOT_VARIABLE,
    SNAPSHOT_PROPERTY,
    AndroidSession,
    ColdBootRefused,
)
from scripts.capture.tests.test_android_cleanup_status import (
    ADB,
    CleanupStatusBackupFailures,
    CleanupStatusCommands,
)
from scripts.capture.tests.test_android_device_lifecycle import (
    CLEAR_DEBUG,
    CONFIGURATION,
    OPEN,
    REMOVE_FILE,
    REMOVE_FIRST,
    STOP,
    URL,
    failure_from,
)

ARGUMENTS = [
    "--browser=chrome-android",
    f"--adb={ADB}",
    f"--url={URL}",
    "--entry=intent",
    "--switch=--disable-quic",
    "--switch=--lang=en-US",
]
SNAPSHOT = ("shell", "getprop", SNAPSHOT_PROPERTY)
CLEANUP = [STOP, REMOVE_FIRST, REMOVE_FILE, CLEAR_DEBUG]


class AndroidCliCommands(CleanupStatusCommands):
    def __init__(self) -> None:
        super().__init__()
        self.snapshot = b"onboarded\r\n"

    def run(self, argv, *, stdin, capture_output, check, timeout):
        result = super().run(
            argv,
            stdin=stdin,
            capture_output=capture_output,
            check=check,
            timeout=timeout,
        )
        if tuple(argv[1:]) == SNAPSHOT:
            result = subprocess.CompletedProcess(argv, 0, self.snapshot, b"")
            self.results[-1] = result

        return result


class AndroidCliRun:
    def __init__(self) -> None:
        self.commands = AndroidCliCommands()
        self.patches = ExitStack()
        self.output = io.StringIO()
        self.error_output = io.StringIO()
        self.browsers: list[browser_launch.LaunchedBrowser] = []
        self.attempted: list[tuple[browser_launch.LaunchPlan, str]] = []
        self.sleeps: list[float] = []
        self.holds: list[tuple[float, AndroidSession | None, int]] = []
        self.forbidden = RuntimeError("controlled forbidden Android launch")
        self.forbid_launch = False
        self.backup_started = False

    def prepare(self, environment: dict[str, str]) -> None:
        self.patches.enter_context(patch.dict(os.environ, environment, clear=True))
        self.patches.enter_context(self.commands.observe())
        self.patches.enter_context(
            patch.object(android_run, "LaunchedBrowser", new=self.launch)
        )
        self.patches.enter_context(
            patch.object(android_run.time, "sleep", new=self.sleep)
        )
        self.patches.enter_context(redirect_stdout(self.output))
        self.patches.enter_context(redirect_stderr(self.error_output))

    def launch(self, plan, url):
        self.attempted.append((plan, url))
        if self.forbid_launch:
            raise self.forbidden

        browser = browser_launch.LaunchedBrowser(plan, url)
        self.browsers.append(browser)
        return browser

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if self.commands.running:
            self.holds.append(
                (seconds, self.browsers[-1].session, len(self.commands.commands))
            )

    def finish(self) -> None:
        self.backup_started = True
        failures = []
        for browser in self.browsers:
            try:
                browser.__exit__(None, None, None)
            except BaseException as failure:
                failures.append(failure)

        try:
            self.commands.backup()
        except BaseException as failure:
            failures.append(failure)

        try:
            self.patches.close()
        except BaseException as failure:
            failures.append(failure)

        if failures:
            raise CleanupStatusBackupFailures(tuple(failures))


class AndroidRunContractsTests(unittest.TestCase):
    def resources(self, environment: dict[str, str] | None = None) -> AndroidCliRun:
        resources = AndroidCliRun()
        self.addCleanup(resources.finish)
        resources.prepare({} if environment is None else environment)
        return resources

    def assert_invalid_hold(self, value: str) -> None:
        resources = self.resources()
        resources.forbid_launch = True
        failure = failure_from(
            lambda: android_run.main([*ARGUMENTS, f"--hold={value}"])
        )

        self.assertFalse(resources.backup_started)
        self.assertIsInstance(failure, SystemExit)
        self.assertEqual(failure.code, 2)
        self.assertIsNot(failure, resources.forbidden)
        self.assertIn("--hold", resources.error_output.getvalue())
        self.assertEqual(resources.attempted, [])
        self.assertEqual(resources.commands.commands, [])
        self.assertEqual(resources.commands.materials, [])
        self.assertEqual(resources.sleeps, [])
        self.assertEqual(resources.output.getvalue(), "")
        self.assertEqual(dict(os.environ), {})

    def assert_launched(self, resources: AndroidCliRun, seconds: float) -> None:
        commands = resources.commands
        self.assertFalse(resources.backup_started)
        self.assertFalse(commands.backup_started)
        self.assertEqual(resources.sleeps, [1.0, seconds])
        self.assertEqual(len(resources.holds), 1)
        observed, session, checkpoint = resources.holds[0]
        self.assertEqual(observed, seconds)
        self.assertIsNotNone(session)
        self.assertIsInstance(session, AndroidSession)
        self.assertEqual(session.launch.entry, "intent")
        self.assertEqual(session.launch.url, URL)
        self.assertEqual(
            session.launch.arguments[-2:], ("--disable-quic", "--lang=en-US")
        )
        self.assertEqual(commands.commands.count(OPEN), 1)
        self.assertEqual(commands.commands[checkpoint:], CLEANUP)
        self.assertEqual(len(commands.pushes), 1)
        local, remote, payload = commands.pushes[0]
        self.assertEqual(remote, CONFIGURATION)
        self.assertTrue(payload.endswith(b"--disable-quic --lang=en-US\n"))
        self.assertFalse(local.exists())
        self.assertFalse(local.parent.exists())
        self.assertEqual(commands.files, {})
        self.assertEqual(commands.ports, set())
        self.assertIsNone(commands.debug_app)
        self.assertFalse(commands.running)
        self.assertIsNone(resources.browsers[0].session)
        self.assertEqual(resources.attempted[0][1], URL)
        self.assertEqual(
            resources.attempted[0][0].extra_arguments,
            ("--disable-quic", "--lang=en-US"),
        )
        self.assertTrue(all(result.returncode == 0 for result in commands.results))
        self.assertTrue(
            all(
                options == (subprocess.DEVNULL, True, False, 120)
                for options in commands.options
            )
        )

    def assert_hold(self, arguments: list[str], seconds: float) -> None:
        resources = self.resources()
        self.assertIsNone(
            failure_from(lambda: android_run.main([*ARGUMENTS, *arguments]))
        )

        self.assert_launched(resources, seconds)
        self.assertEqual(dict(os.environ), {})

    def assert_print_only(self, environment: dict[str, str]) -> None:
        resources = self.resources(environment)
        resources.forbid_launch = True
        failure = failure_from(
            lambda: android_run.main(
                [*ARGUMENTS, "--allow-cold-boot", "--print-arguments"]
            )
        )

        self.assertFalse(resources.backup_started)
        self.assertIsNone(failure)
        self.assertEqual(resources.attempted, [])
        self.assertEqual(resources.commands.commands, [])
        self.assertEqual(resources.commands.materials, [])
        self.assertEqual(resources.sleeps, [])
        self.assertEqual(
            shlex.split(resources.output.getvalue())[-3:],
            ["--disable-quic", "--lang=en-US", URL],
        )
        self.assertEqual(dict(os.environ), environment)

    def test_negative_hold_is_rejected_before_launch(self) -> None:
        self.assert_invalid_hold("-1")

    def test_nan_hold_is_rejected_before_launch(self) -> None:
        self.assert_invalid_hold("nan")

    def test_infinite_hold_is_rejected_before_launch(self) -> None:
        self.assert_invalid_hold("inf")

    def test_negative_infinite_hold_is_rejected_before_launch(self) -> None:
        self.assert_invalid_hold("-inf")

    def test_default_hold_preserves_eight_seconds_after_entry(self) -> None:
        self.assert_hold([], 8.0)

    def test_zero_hold_is_allowed_after_entry(self) -> None:
        self.assert_hold(["--hold=0"], 0.0)

    def test_positive_hold_preserves_its_literal_duration(self) -> None:
        self.assert_hold(["--hold=0.25"], 0.25)

    def test_print_only_flag_preserves_absent_cold_boot_environment(self) -> None:
        self.assert_print_only({"ANDROID_SERIAL": "controlled-emulator"})

    def test_print_only_flag_preserves_explicit_cold_boot_refusal(self) -> None:
        self.assert_print_only({ALLOW_COLD_BOOT_VARIABLE: "0"})

    def test_print_only_flag_preserves_explicit_ambient_cold_boot_permission(
        self,
    ) -> None:
        self.assert_print_only({ALLOW_COLD_BOOT_VARIABLE: "1"})

    def test_flag_allows_one_launch_then_default_refuses_missing_snapshot(self) -> None:
        resources = self.resources()
        resources.commands.snapshot = b""
        failure = failure_from(
            lambda: android_run.main([*ARGUMENTS, "--hold=0", "--allow-cold-boot"])
        )

        self.assertIsNone(failure)
        self.assert_launched(resources, 0.0)
        self.assertNotIn(SNAPSHOT, resources.commands.commands)
        checkpoint = len(resources.commands.commands)
        material_count = len(resources.commands.materials)
        failure = failure_from(lambda: android_run.main([*ARGUMENTS, "--hold=0"]))

        self.assertFalse(resources.backup_started)
        self.assertIsInstance(failure, ColdBootRefused)
        self.assertIn(SNAPSHOT_PROPERTY, str(failure))
        self.assertEqual(
            resources.commands.commands[checkpoint:],
            [("shell", "getprop", "ro.kernel.qemu"), SNAPSHOT],
        )
        self.assertEqual(len(resources.commands.materials), material_count)
        self.assertEqual(resources.commands.commands.count(OPEN), 1)
        self.assertEqual(resources.sleeps, [1.0, 0.0])
        self.assertEqual(dict(os.environ), {})

    def test_default_missing_snapshot_refuses_before_device_mutation(self) -> None:
        resources = self.resources()
        resources.commands.snapshot = b""
        failure = failure_from(lambda: android_run.main([*ARGUMENTS, "--hold=0"]))

        self.assertFalse(resources.backup_started)
        self.assertIsInstance(failure, ColdBootRefused)
        self.assertIn(SNAPSHOT_PROPERTY, str(failure))
        self.assertEqual(
            resources.commands.commands,
            [("shell", "getprop", "ro.kernel.qemu"), SNAPSHOT],
        )
        self.assertEqual(resources.commands.materials, [])
        self.assertEqual(resources.commands.pushes, [])
        self.assertEqual(resources.sleeps, [])
        self.assertEqual(dict(os.environ), {})

    def test_explicit_ambient_permission_allows_default_launch(self) -> None:
        resources = self.resources({ALLOW_COLD_BOOT_VARIABLE: "1"})
        resources.commands.snapshot = b""
        self.assertIsNone(
            failure_from(lambda: android_run.main([*ARGUMENTS, "--hold=0"]))
        )

        self.assert_launched(resources, 0.0)
        self.assertNotIn(SNAPSHOT, resources.commands.commands)
        self.assertEqual(dict(os.environ), {ALLOW_COLD_BOOT_VARIABLE: "1"})
