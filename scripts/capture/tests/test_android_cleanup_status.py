import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from scripts.capture.android_device import (
    ANDROID_BROWSERS,
    SNAPSHOT_PROPERTY,
    AdbDevice,
    AndroidLaunch,
    AndroidSession,
)
from scripts.capture.browser_failures import BrowserLaunchFailures
from scripts.capture.tests.test_android_device_lifecycle import (
    CLEANUP_COMMANDS,
    CLEAR_DEBUG,
    CONFIGURATION,
    OPEN,
    PACKAGE,
    REMOVE_FILE,
    REMOVE_FIRST,
    STOP,
    URL,
    failure_from,
)

ADB = Path("offline-adb")
DIAGNOSTIC = b"controlled device rejected this cleanup command\n"
RETAINED_STATE = {
    STOP: ({}, set(), None, True),
    REMOVE_FIRST: ({}, {"tcp:9450"}, None, False),
    REMOVE_FILE: ({CONFIGURATION: b"_ --disable-fre\n"}, set(), None, False),
    CLEAR_DEBUG: ({}, set(), PACKAGE, False),
}


class CleanupStatusBackupFailures(Exception):
    def __init__(self, failures: tuple[BaseException, ...]) -> None:
        self.failures = failures
        super().__init__("cleanup status control backup failed")


class CleanupStatusCommands:
    """Model subprocess results while canonical adb command handling runs."""

    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.options: list[tuple[object, bool, bool, int]] = []
        self.results: list[subprocess.CompletedProcess] = []
        self.files: dict[str, bytes] = {}
        self.ports: set[str] = set()
        self.debug_app: str | None = None
        self.running = False
        self.pushes: list[tuple[Path, str, bytes]] = []
        self.fail_command: tuple[str, ...] | None = None
        self.failed_result: subprocess.CompletedProcess | None = None
        self.materials: list[tempfile.TemporaryDirectory] = []
        self.actual_init = tempfile.TemporaryDirectory.__init__
        self.actual_cleanup = tempfile.TemporaryDirectory.cleanup
        self.backup_started = False

    @contextmanager
    def observe(self):
        def initialize(material, *arguments, **options):
            self.actual_init(material, *arguments, **options)
            self.materials.append(material)

        with (
            patch("scripts.capture.android_device.subprocess.run", new=self.run),
            patch.object(tempfile.TemporaryDirectory, "__init__", new=initialize),
        ):
            yield

    def run(self, argv, *, stdin, capture_output, check, timeout):
        command = tuple(argv[1:])
        self.commands.append(command)
        self.options.append((stdin, capture_output, check, timeout))
        if argv[0] != str(ADB):
            raise AssertionError(f"unexpected executable: {argv[0]}")

        if command == self.fail_command:
            self.fail_command = None
            result = subprocess.CompletedProcess(
                argv, 7, b"controlled cleanup stdout\n", DIAGNOSTIC
            )
            self.failed_result = result
            self.results.append(result)
            return result

        output = b""
        if command == ("shell", "getprop", "ro.kernel.qemu"):
            output = b"1\r\n"
        elif command == ("shell", "getprop", SNAPSHOT_PROPERTY):
            output = b"onboarded\r\n"
        elif command[0] == "push":
            local = Path(command[1])
            payload = local.read_bytes()
            self.files[command[2]] = payload
            self.pushes.append((local, command[2], payload))
        elif command[0] == "reverse":
            if command[1] == "--remove":
                self.ports.discard(command[2])
            else:
                self.ports.add(command[1])
        elif command[:3] == ("shell", "am", "set-debug-app"):
            self.debug_app = command[-1]
        elif command == CLEAR_DEBUG:
            self.debug_app = None
        elif command == REMOVE_FILE:
            self.files.pop(CONFIGURATION, None)
        elif command == OPEN:
            self.running = True
        elif command == STOP:
            self.running = False

        result = subprocess.CompletedProcess(argv, 0, output, b"")
        self.results.append(result)
        return result

    def backup(self) -> None:
        self.backup_started = True
        failures = []
        for material in self.materials:
            try:
                self.actual_cleanup(material)
            except BaseException as failure:
                failures.append(failure)

        self.files.clear()
        self.ports.clear()
        self.debug_app = None
        self.running = False
        if failures:
            raise CleanupStatusBackupFailures(tuple(failures))


class ObservedCleanupSession(AndroidSession):
    def __init__(self, device: AdbDevice, launch: AndroidLaunch) -> None:
        super().__init__(device, launch)
        self.cleanup_observations: list[tuple[BaseException, ...]] = []

    def _cleanup(self) -> tuple[BaseException, ...]:
        failures = super()._cleanup()
        self.cleanup_observations.append(failures)
        return failures


class AndroidCleanupStatusTests(unittest.TestCase):
    def resources(self) -> tuple[CleanupStatusCommands, ObservedCleanupSession]:
        commands = CleanupStatusCommands()
        self.addCleanup(commands.backup)
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"],
            URL,
            ("--disable-fre",),
            entry="intent",
            settle=0,
            typing_attempts=1,
            reverse=(9451,),
        )
        session = ObservedCleanupSession(AdbDevice(ADB), launch)
        return commands, session

    def assert_acquired(self, commands: CleanupStatusCommands) -> None:
        self.assertFalse(commands.backup_started)
        self.assertEqual(len(commands.materials), 1)
        self.assertEqual(len(commands.pushes), 1)
        local, remote, payload = commands.pushes[0]
        self.assertEqual(local.parent, Path(commands.materials[0].name))
        self.assertEqual((remote, payload), (CONFIGURATION, b"_ --disable-fre\n"))
        self.assertFalse(local.exists())
        self.assertFalse(local.parent.exists())
        self.assertEqual(commands.files, {CONFIGURATION: payload})
        self.assertEqual(commands.ports, {"tcp:9450", "tcp:9451"})
        self.assertEqual(commands.debug_app, PACKAGE)
        self.assertTrue(commands.running)
        self.assertEqual(commands.commands.count(OPEN), 1)
        self.assertTrue(all(result.returncode == 0 for result in commands.results))
        self.assertTrue(
            all(
                options == (subprocess.DEVNULL, True, False, 120)
                for options in commands.options
            )
        )

    def assert_released(self, commands: CleanupStatusCommands) -> None:
        self.assertFalse(commands.backup_started)
        self.assertEqual(commands.files, {})
        self.assertEqual(commands.ports, set())
        self.assertIsNone(commands.debug_app)
        self.assertFalse(commands.running)

    def assert_nonzero_cleanup(
        self, command: tuple[str, ...], *, primary: BaseException | None = None
    ) -> None:
        commands, session = self.resources()
        with commands.observe():
            checkpoints = []

            def body() -> None:
                with session as entered:
                    self.assertIs(entered, session)
                    self.assert_acquired(commands)
                    checkpoints.append(len(commands.commands))
                    commands.fail_command = command

                    if primary is not None:
                        raise primary

            failure = failure_from(body)

            self.assertFalse(commands.backup_started)
            self.assertEqual(len(checkpoints), 1)
            self.assertEqual(commands.commands[checkpoints[0] :], CLEANUP_COMMANDS)
            result = commands.failed_result
            self.assertIsNotNone(result)
            self.assertEqual(tuple(result.args[1:]), command)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, b"controlled cleanup stdout\n")
            self.assertEqual(result.stderr, DIAGNOSTIC)
            self.assertIsNone(commands.fail_command)
            self.assertEqual(len(session.cleanup_observations), 1)
            observed = session.cleanup_observations[0]
            self.assertEqual(
                (commands.files, commands.ports, commands.debug_app, commands.running),
                RETAINED_STATE[command],
            )

            self.assertEqual(len(observed), 1)
            original = observed[0]
            self.assertIsInstance(original, RuntimeError)
            self.assertIn("adb " + " ".join(command), str(original))
            self.assertIn(DIAGNOSTIC.decode().strip(), str(original))

            if primary is None:
                self.assertIs(failure, original)
            else:
                self.assertIsInstance(failure, BrowserLaunchFailures)
                self.assertIs(failure.primary, primary)
                self.assertEqual(len(failure.cleanup), 1)
                self.assertIs(failure.cleanup[0], original)
                self.assertIs(failure.previous_cause, primary.__cause__)
                self.assertIs(original.__context__, primary)

            checkpoint = len(commands.commands)
            self.assertIsNone(failure_from(session.__exit__))

            self.assertEqual(commands.commands[checkpoint:], [command])
            self.assert_released(commands)
            checkpoint = len(commands.commands)
            self.assertIsNone(failure_from(session.__exit__))

            self.assertEqual(commands.commands[checkpoint:], [])
            self.assertEqual(session.cleanup_observations[1:], [(), ()])

    def test_nonzero_stop_status_is_reported_and_only_stop_is_retried(self) -> None:
        self.assert_nonzero_cleanup(STOP)

    def test_nonzero_reverse_status_is_reported_and_only_reverse_is_retried(
        self,
    ) -> None:
        self.assert_nonzero_cleanup(REMOVE_FIRST)

    def test_nonzero_remove_status_is_reported_and_only_remove_is_retried(self) -> None:
        self.assert_nonzero_cleanup(REMOVE_FILE)

    def test_nonzero_debug_status_is_reported_and_only_debug_is_retried(self) -> None:
        self.assert_nonzero_cleanup(CLEAR_DEBUG)

    def test_body_primary_retains_canonical_nonzero_cleanup_error(self) -> None:
        primary = OSError("controlled body primary")
        primary.__cause__ = RuntimeError("pre-existing body cause")
        self.assert_nonzero_cleanup(CLEAR_DEBUG, primary=primary)

    def test_zero_cleanup_statuses_release_all_owned_slots_once(self) -> None:
        commands, session = self.resources()
        with commands.observe():
            self.assertIs(session.__enter__(), session)
            self.assert_acquired(commands)
            checkpoint = len(commands.commands)

            failure = failure_from(session.__exit__)

            self.assertIsNone(failure)
            self.assertEqual(commands.commands[checkpoint:], CLEANUP_COMMANDS)
            self.assertEqual(session.cleanup_observations, [()])
            self.assertTrue(all(result.returncode == 0 for result in commands.results))
            self.assert_released(commands)
            checkpoint = len(commands.commands)
            self.assertIsNone(failure_from(session.__exit__))

            self.assertEqual(commands.commands[checkpoint:], [])
            self.assertEqual(session.cleanup_observations, [(), ()])
