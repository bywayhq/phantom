import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture.android_device import (
    ANDROID_BROWSERS,
    SNAPSHOT_PROPERTY,
    AdbDevice,
    AndroidLaunch,
    ColdBootRefused,
    PhysicalDeviceRefused,
)
from scripts.capture.tests.test_android_cleanup_status import (
    ADB,
    CleanupStatusCommands,
)
from scripts.capture.tests.test_android_device_lifecycle import (
    CLEANUP_COMMANDS,
    CONFIGURATION,
    OPEN,
    PACKAGE,
    URL,
    ObservedSession,
    failure_from,
)

FIRST_EMULATOR = ("shell", "getprop", "ro.kernel.qemu")
SECOND_EMULATOR = ("shell", "getprop", "ro.boot.qemu")
SNAPSHOT = ("shell", "getprop", SNAPSHOT_PROPERTY)
DIAGNOSTIC = b"controlled required device observation failed\n"


class RequiredObservationCommands(CleanupStatusCommands):
    def __init__(self) -> None:
        super().__init__()
        self.observations = {
            FIRST_EMULATOR: (0, b"1\r\n"),
            SECOND_EMULATOR: (0, b""),
            SNAPSHOT: (0, b"onboarded\r\n"),
        }
        self.query_results: list[subprocess.CompletedProcess] = []

    def run(self, argv, *, stdin, capture_output, check, timeout):
        result = super().run(
            argv,
            stdin=stdin,
            capture_output=capture_output,
            check=check,
            timeout=timeout,
        )
        command = tuple(argv[1:])
        if command not in self.observations:
            return result

        status, output = self.observations[command]
        result = subprocess.CompletedProcess(
            argv, status, output, DIAGNOSTIC if status else b""
        )
        self.results[-1] = result
        self.query_results.append(result)
        return result


class ObservedAdbDevice(AdbDevice):
    def __init__(self) -> None:
        super().__init__(ADB)
        self.errors: list[tuple[tuple[str, ...], BaseException]] = []

    def run(self, *arguments: str, check: bool = True) -> str:
        try:
            return super().run(*arguments, check=check)
        except BaseException as failure:
            self.errors.append((arguments, failure))
            raise


class RequiredObservationBackupFailures(Exception):
    def __init__(self, failures: tuple[BaseException, ...]) -> None:
        self.failures = failures
        super().__init__("required observation control backup failed")


class AndroidRequiredDeviceObservationTests(unittest.TestCase):
    def resources(
        self,
    ) -> tuple[RequiredObservationCommands, ObservedAdbDevice, ObservedSession]:
        commands = RequiredObservationCommands()
        device = ObservedAdbDevice()
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"],
            URL,
            ("--disable-fre",),
            entry="intent",
            settle=0,
            typing_attempts=1,
            reverse=(9451,),
        )
        session = ObservedSession(device, launch)

        def backup() -> None:
            commands.backup_started = True
            failures = []
            try:
                with commands.observe():
                    session.__exit__()
            except BaseException as failure:
                failures.append(failure)
            try:
                commands.backup()
            except BaseException as failure:
                failures.append(failure)
            if failures:
                raise RequiredObservationBackupFailures(tuple(failures))

        self.addCleanup(backup)
        return commands, device, session

    def assert_queries(self, commands, expected) -> None:
        self.assertFalse(commands.backup_started)
        self.assertEqual(
            [tuple(result.args[1:]) for result in commands.query_results], expected
        )
        for result in commands.query_results:
            self.assertTrue(any(result is observed for observed in commands.results))
        self.assertTrue(
            all(
                options == (subprocess.DEVNULL, True, False, 120)
                for options in commands.options
            )
        )

    def assert_no_mutation(self, commands, expected) -> None:
        self.assertFalse(commands.backup_started)
        self.assertEqual(commands.commands, expected)
        self.assertEqual(commands.materials, [])
        self.assertEqual(commands.pushes, [])
        self.assertEqual(commands.files, {})
        self.assertEqual(commands.ports, set())
        self.assertIsNone(commands.debug_app)
        self.assertFalse(commands.running)

    def assert_failed_required_query(self, command, output, expected) -> None:
        commands, device, session = self.resources()
        commands.observations[command] = (7, output)
        with patch.dict("os.environ", {}, clear=True), commands.observe():
            failure = failure_from(session.__enter__)

            self.assertFalse(commands.backup_started)
            self.assertEqual(
                [tuple(result.args[1:]) for result in commands.query_results][
                    : len(expected)
                ],
                expected,
            )
            result = commands.query_results[len(expected) - 1]
            self.assertTrue(any(result is observed for observed in commands.results))
            self.assertEqual(tuple(result.args[1:]), command)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, output)
            self.assertEqual(result.stderr, DIAGNOSTIC)
            self.assertTrue(
                all(
                    options == (subprocess.DEVNULL, True, False, 120)
                    for options in commands.options
                )
            )

            self.assertIsInstance(failure, RuntimeError)
            self.assertEqual(len(device.errors), 1)
            self.assertEqual(device.errors[0][0], command)
            self.assertIs(device.errors[0][1], failure)
            self.assertIs(session.original_entry_failure, failure)
            self.assertIsNone(failure.__context__)
            self.assertIn("adb " + " ".join(command), str(failure))
            self.assertIn(DIAGNOSTIC.decode().strip(), str(failure))
            self.assert_no_mutation(commands, expected)

    def assert_healthy_entry(self, *, first_property_missing: bool) -> None:
        commands, device, session = self.resources()
        expected = [FIRST_EMULATOR, SNAPSHOT]
        if first_property_missing:
            commands.observations[FIRST_EMULATOR] = (0, b"")
            commands.observations[SECOND_EMULATOR] = (0, b"1\r\n")
            expected = [FIRST_EMULATOR, SECOND_EMULATOR, SNAPSHOT]

        with patch.dict("os.environ", {}, clear=True), commands.observe():
            with session as entered:
                self.assertIs(entered, session)
                self.assert_queries(commands, expected)
                self.assertEqual(commands.commands[: len(expected)], expected)
                self.assertTrue(
                    all(result.returncode == 0 for result in commands.query_results)
                )
                self.assertEqual(device.errors, [])
                self.assertIsNone(session.original_entry_failure)
                self.assertEqual(len(commands.pushes), 1)
                self.assertEqual(len(commands.materials), 1)
                local, remote, payload = commands.pushes[0]
                self.assertEqual(local.parent, Path(commands.materials[0].name))
                self.assertEqual(
                    (remote, payload), (CONFIGURATION, b"_ --disable-fre\n")
                )
                self.assertFalse(local.exists())
                self.assertFalse(local.parent.exists())
                self.assertEqual(commands.files, {CONFIGURATION: payload})
                self.assertEqual(commands.ports, {"tcp:9450", "tcp:9451"})
                self.assertEqual(commands.debug_app, PACKAGE)
                self.assertTrue(commands.running)
                self.assertEqual(commands.commands.count(OPEN), 1)
                checkpoint = len(commands.commands)

            self.assertFalse(commands.backup_started)
            self.assertEqual(commands.commands[checkpoint:], CLEANUP_COMMANDS)
            self.assertEqual(commands.files, {})
            self.assertEqual(commands.ports, set())
            self.assertIsNone(commands.debug_app)
            self.assertFalse(commands.running)
            self.assertTrue(all(result.returncode == 0 for result in commands.results))

    def test_failed_emulator_query_rejects_success_shaped_stdout_before_mutation(
        self,
    ) -> None:
        self.assert_failed_required_query(FIRST_EMULATOR, b"1\r\n", [FIRST_EMULATOR])

    def test_failed_snapshot_query_rejects_success_shaped_stdout_before_mutation(
        self,
    ) -> None:
        self.assert_failed_required_query(
            SNAPSHOT, b"onboarded\r\n", [FIRST_EMULATOR, SNAPSHOT]
        )

    def test_successful_required_queries_allow_entry_and_owned_cleanup(self) -> None:
        self.assert_healthy_entry(first_property_missing=False)

    def test_missing_first_emulator_property_uses_successful_second_property(
        self,
    ) -> None:
        self.assert_healthy_entry(first_property_missing=True)

    def test_successful_missing_emulator_properties_refuse_before_mutation(
        self,
    ) -> None:
        commands, device, session = self.resources()
        commands.observations[FIRST_EMULATOR] = (0, b"")
        expected = [FIRST_EMULATOR, SECOND_EMULATOR]
        with patch.dict("os.environ", {}, clear=True), commands.observe():
            failure = failure_from(session.__enter__)

            self.assert_queries(commands, expected)
            self.assertTrue(all(result.returncode == 0 for result in commands.results))
            self.assertIsInstance(failure, PhysicalDeviceRefused)
            self.assertIs(session.original_entry_failure, failure)
            self.assertEqual(device.errors, [])
            self.assertIn("not an emulator", str(failure))
            self.assert_no_mutation(commands, expected)

    def test_successful_missing_snapshot_marker_refuses_before_mutation(self) -> None:
        commands, device, session = self.resources()
        commands.observations[SNAPSHOT] = (0, b"\r\n")
        expected = [FIRST_EMULATOR, SNAPSHOT]
        with patch.dict("os.environ", {}, clear=True), commands.observe():
            failure = failure_from(session.__enter__)

            self.assert_queries(commands, expected)
            self.assertTrue(all(result.returncode == 0 for result in commands.results))
            self.assertIsInstance(failure, ColdBootRefused)
            self.assertIs(session.original_entry_failure, failure)
            self.assertEqual(device.errors, [])
            self.assertIn(SNAPSHOT_PROPERTY, str(failure))
            self.assert_no_mutation(commands, expected)
