import asyncio
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

from scripts.capture.android_device import (
    ANDROID_BROWSERS,
    AdbDevice,
    AndroidLaunch,
    AndroidSession,
    ColdBootRefused,
    PhysicalDeviceRefused,
)
from scripts.capture.browser_launch import (
    BrowserLaunchFailures,
    LaunchedBrowser,
    LaunchPlan,
)
from scripts.capture.tests.test_android_device import RecordingDevice

URL = "http://127.0.0.1:9450/a?b=1&c=2"
PACKAGE = "com.android.chrome"
CONFIGURATION = "/data/local/tmp/chrome-command-line"
STOP = ("shell", "am", "force-stop", PACKAGE)
REMOVE_FIRST = ("reverse", "--remove", "tcp:9450")
REMOVE_SECOND = ("reverse", "--remove", "tcp:9451")
REMOVE_FILE = ("shell", "rm", "-f", CONFIGURATION)
CLEAR_DEBUG = ("shell", "am", "clear-debug-app")
CLEANUP_COMMANDS = [STOP, REMOVE_FIRST, REMOVE_SECOND, REMOVE_FILE, CLEAR_DEBUG]
OPEN = (
    "shell",
    "am",
    "start",
    "-W",
    "-a",
    "android.intent.action.VIEW",
    "-d",
    "'http://127.0.0.1:9450/a?b=1&c=2'",
    "-p",
    PACKAGE,
)


class OfflineDevice(AdbDevice):
    """Model the command boundary; retain canonical shell and push_text."""

    def __init__(self, *, emulator: bool = True, snapshot: str = "onboarded"):
        super().__init__(Path("offline-adb"))
        self.recording = RecordingDevice(emulator=emulator, snapshot=snapshot)
        self.files: dict[str, bytes] = {}
        self.ports: set[str] = set()
        self.debug_app: str | None = None
        self.running = False
        self.pushes: list[tuple[Path, str, bytes]] = []
        self.faults: dict[tuple[str, ...], BaseException] = {}
        self.raised: list[BaseException] = []
        self.stop_after_open_failure: BaseException | None = None
        self.backup_started = False

    @property
    def commands(self) -> list[tuple[str, ...]]:
        return self.recording.commands

    def run(self, *arguments: str, check: bool = True) -> str:
        result = self.recording.run(*arguments, check=check)
        failure = self.faults.pop(arguments, None)
        if failure is not None:
            if arguments == OPEN and self.stop_after_open_failure is not None:
                self.faults[STOP] = self.stop_after_open_failure
            self.raised.append(failure)
            raise failure

        if arguments[0] == "push":
            local = Path(arguments[1])
            payload = local.read_bytes()
            self.files[arguments[2]] = payload
            self.pushes.append((local, arguments[2], payload))
        elif arguments[0] == "reverse":
            if arguments[1] == "--remove":
                self.ports.discard(arguments[2])
            else:
                self.ports.add(arguments[1])
        elif arguments[:3] == ("shell", "am", "set-debug-app"):
            self.debug_app = arguments[-1]
        elif arguments == CLEAR_DEBUG:
            self.debug_app = None
        elif arguments == REMOVE_FILE:
            self.files.pop(CONFIGURATION, None)
        elif arguments == OPEN:
            self.running = True
        elif arguments == STOP:
            self.running = False
        return result

    def backup(self) -> None:
        self.backup_started = True
        self.files.clear()
        self.ports.clear()
        self.debug_app = None
        self.running = False


class ObservedSession(AndroidSession):
    def __init__(self, device: AdbDevice, launch: AndroidLaunch):
        super().__init__(device, launch)
        self.original_entry_failure: BaseException | None = None

    def _start(self) -> None:
        try:
            super()._start()
        except BaseException as failure:
            self.original_entry_failure = failure
            raise


def failure_from(operation: Callable[[], object]) -> BaseException | None:
    try:
        operation()
    except BaseException as failure:
        return failure
    return None


class AndroidLifecycleTests(unittest.TestCase):
    def device(self, **options: object) -> OfflineDevice:
        device = OfflineDevice(**options)
        self.addCleanup(device.backup)
        return device

    def launch(self, *, attempts: int = 1) -> AndroidLaunch:
        return AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"],
            URL,
            ("--disable-fre",),
            entry="intent",
            settle=0,
            typing_attempts=attempts,
            reverse=(9451,),
        )

    def assert_acquired(self, device: OfflineDevice) -> None:
        self.assertEqual(device.files, {CONFIGURATION: b"_ --disable-fre\n"})
        self.assertEqual(device.ports, {"tcp:9450", "tcp:9451"})
        self.assertEqual(device.debug_app, PACKAGE)
        self.assertTrue(device.running)
        self.assertFalse(device.backup_started)

    def assert_empty(self, device: OfflineDevice) -> None:
        self.assertEqual(device.files, {})
        self.assertEqual(device.ports, set())
        self.assertIsNone(device.debug_app)
        self.assertFalse(device.running)
        self.assertFalse(device.backup_started)

    def assert_refused_readonly(self, device: OfflineDevice, kind: type) -> None:
        session = ObservedSession(device, self.launch())
        with patch.dict("os.environ", {}, clear=True):
            failure = failure_from(session.__enter__)

        self.assertIsInstance(session.original_entry_failure, kind)
        self.assertIs(failure, session.original_entry_failure)
        self.assertFalse(device.backup_started)
        self.assertTrue(device.commands)
        self.assertTrue(
            all(command[:2] == ("shell", "getprop") for command in device.commands),
            device.commands,
        )
        self.assert_empty(device)

    def test_physical_refusal_runs_only_readonly_commands(self) -> None:
        self.assert_refused_readonly(self.device(emulator=False), PhysicalDeviceRefused)

    def test_cold_boot_refusal_runs_only_readonly_commands(self) -> None:
        self.assert_refused_readonly(self.device(snapshot=""), ColdBootRefused)

    def test_successful_push_is_removed_when_chmod_fails(self) -> None:
        device = self.device()
        original = OSError("controlled post-push chmod failure")
        device.faults[("shell", "chmod", "644", CONFIGURATION)] = original
        session = ObservedSession(device, self.launch())

        failure = failure_from(session.__enter__)

        self.assertIs(session.original_entry_failure, original)
        self.assertIs(failure, original)
        self.assertEqual(len(device.pushes), 1)
        local, remote, payload = device.pushes[0]
        self.assertEqual((remote, payload), (CONFIGURATION, b"_ --disable-fre\n"))
        self.assertFalse(local.exists())
        self.assertIs(device.raised[0], original)
        self.assertFalse(device.backup_started)
        self.assertNotIn(CONFIGURATION, device.files)
        self.assertIn(REMOVE_FILE, device.commands)

    def assert_later_cleanup_attempted(self, command: tuple[str, ...]) -> None:
        device = self.device()
        session = ObservedSession(device, self.launch())
        session.__enter__()
        self.assert_acquired(device)
        start = len(device.commands)
        original = OSError("controlled cleanup command failure")
        device.faults[command] = original

        failure = failure_from(session.__exit__)

        self.assertFalse(device.backup_started)
        self.assertEqual(device.commands[start:], CLEANUP_COMMANDS)
        self.assertEqual(len(device.raised), 1)
        self.assertIs(device.raised[0], original)
        self.assertIs(failure, original)

    def test_stop_failure_does_not_skip_reverse_or_configuration_cleanup(self) -> None:
        self.assert_later_cleanup_attempted(STOP)

    def test_first_reverse_failure_does_not_skip_later_cleanup(self) -> None:
        self.assert_later_cleanup_attempted(REMOVE_FIRST)

    def test_second_reverse_failure_does_not_skip_configuration_cleanup(self) -> None:
        self.assert_later_cleanup_attempted(REMOVE_SECOND)

    def test_remove_failure_does_not_skip_clear_debug_app(self) -> None:
        self.assert_later_cleanup_attempted(REMOVE_FILE)

    def test_clear_debug_failure_preserves_the_original_object(self) -> None:
        self.assert_later_cleanup_attempted(CLEAR_DEBUG)

    def test_multiple_cleanup_faults_are_attempted_in_owner_order(self) -> None:
        device = self.device()
        session = ObservedSession(device, self.launch())
        session.__enter__()
        self.assert_acquired(device)
        start = len(device.commands)
        first = OSError("controlled stop failure")
        second = OSError("controlled later reverse failure")
        device.faults.update({STOP: first, REMOVE_SECOND: second})

        failure = failure_from(session.__exit__)

        self.assertFalse(device.backup_started)
        self.assertEqual(device.commands[start:], CLEANUP_COMMANDS)
        self.assertEqual(len(device.raised), 2)
        self.assertIs(device.raised[0], first)
        self.assertIs(device.raised[1], second)
        self.assertIsNotNone(failure)

    def test_entry_failure_preserves_primary_when_cleanup_succeeds(self) -> None:
        device = self.device()
        primary = OSError("controlled opening failure")
        previous = RuntimeError("pre-existing cause")
        primary.__cause__ = previous
        device.faults[OPEN] = primary
        session = ObservedSession(device, self.launch())

        failure = failure_from(session.__enter__)

        self.assertIs(session.original_entry_failure, primary)
        self.assertIs(failure, primary)
        self.assertIs(primary.__cause__, previous)
        self.assertEqual(device.commands[-5:], CLEANUP_COMMANDS)
        self.assert_empty(device)

    def test_entry_cleanup_fault_does_not_skip_other_owned_actions(self) -> None:
        device = self.device()
        primary = OSError("controlled opening failure")
        cleanup = OSError("controlled entry cleanup failure")
        device.faults[OPEN] = primary
        device.stop_after_open_failure = cleanup
        session = ObservedSession(device, self.launch())

        failure = failure_from(session.__enter__)

        self.assertIs(session.original_entry_failure, primary)
        self.assertEqual(len(device.raised), 2)
        self.assertIs(device.raised[0], primary)
        self.assertIs(device.raised[1], cleanup)
        self.assertFalse(device.backup_started)
        self.assertEqual(device.commands[-5:], CLEANUP_COMMANDS)
        self.assertIsNotNone(failure)

    def test_body_primary_survives_healthy_cleanup(self) -> None:
        device = self.device()
        session = ObservedSession(device, self.launch())
        primary = OSError("controlled body failure")
        previous = RuntimeError("pre-existing cause")
        primary.__cause__ = previous

        def body() -> None:
            with session:
                self.assert_acquired(device)
                raise primary

        failure = failure_from(body)

        self.assertIs(failure, primary)
        self.assertIs(primary.__cause__, previous)
        self.assert_empty(device)

    def test_browser_boundary_retains_body_primary_and_cleanup_cause(self) -> None:
        device = self.device()
        plan = LaunchPlan("chrome-android", Path("offline-adb"), False)
        browser = LaunchedBrowser(plan, URL)
        primary = OSError("controlled body failure")
        previous = RuntimeError("pre-existing cause")
        cleanup = OSError("controlled stop failure")
        primary.__cause__ = previous

        def body() -> None:
            with browser:
                self.assert_acquired(device)
                device.faults[STOP] = cleanup
                raise primary

        with (
            patch("scripts.capture.browser_launch.AdbDevice", return_value=device),
            patch.object(browser, "android_launch", return_value=self.launch()),
        ):
            failure = failure_from(body)

        self.assertFalse(device.backup_started)
        self.assertEqual(device.commands[-5:], CLEANUP_COMMANDS)
        self.assertIsInstance(failure, BrowserLaunchFailures)
        self.assertIs(failure.primary, primary)
        self.assertEqual(len(failure.cleanup), 1)
        self.assertIs(failure.cleanup[0], cleanup)
        self.assertIs(failure.previous_cause, previous)

    def test_cleanup_interruption_does_not_skip_later_owned_actions(self) -> None:
        device = self.device()
        session = ObservedSession(device, self.launch())
        session.__enter__()
        self.assert_acquired(device)
        start = len(device.commands)
        ordinary = OSError("controlled first cleanup failure")
        interruption = asyncio.CancelledError("controlled command interruption")
        device.faults.update({STOP: ordinary, REMOVE_FIRST: interruption})

        failure = failure_from(session.__exit__)

        self.assertFalse(device.backup_started)
        self.assertEqual(device.commands[start:], CLEANUP_COMMANDS)
        self.assertEqual(len(device.raised), 2)
        self.assertIs(device.raised[0], ordinary)
        self.assertIs(device.raised[1], interruption)
        self.assertIs(failure, interruption)

    def assert_invalid_attempts(self, attempts: int) -> None:
        device = self.device()

        def open_page() -> None:
            ObservedSession(device, self.launch(attempts=attempts)).__enter__()

        failure = failure_from(open_page)

        self.assertFalse(device.backup_started)
        self.assertIsInstance(failure, ValueError)
        self.assertEqual(device.commands, [])
        self.assert_empty(device)

    def test_zero_attempts_are_rejected_before_device_commands(self) -> None:
        self.assert_invalid_attempts(0)

    def test_negative_attempts_are_rejected_before_device_commands(self) -> None:
        self.assert_invalid_attempts(-1)

    def test_one_attempt_opens_once_and_normal_exit_cleans_owned_state(self) -> None:
        device = self.device()
        session = ObservedSession(device, self.launch(attempts=1))

        with session:
            self.assert_acquired(device)
            self.assertEqual(device.commands.count(OPEN), 1)
            self.assertEqual(len(device.pushes), 1)

        self.assertEqual(device.commands[-5:], CLEANUP_COMMANDS)
        self.assert_empty(device)
