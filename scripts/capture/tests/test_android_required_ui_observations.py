import subprocess
import unittest
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from unittest.mock import patch

from scripts.capture.android_device import (
    ANDROID_BROWSERS,
    WINDOW_DUMP,
    AdbDevice,
    AndroidLaunch,
    AndroidSession,
    TypingFailed,
)
from scripts.capture.tests.test_android_device import screen
from scripts.capture.tests.test_android_device_lifecycle import URL, failure_from

ADB = Path("offline-adb")
FOCUS = ("shell", "dumpsys", "window")
DUMP = ("shell", "uiautomator", "dump", WINDOW_DUMP)
READ = ("shell", "cat", WINDOW_DUMP)
ENTER = ("shell", "input", "keyevent", "66")
FOCUS_BAR = ("shell", "input", "keycombination", "113", "40")
TYPE_FIRST = ("shell", "input", "text", "http:/")
TAP = ("shell", "input", "tap", "50", "50")
DIAGNOSTIC = b"controlled required UI observation failed\n"
LAST_ONBOARDING = (
    '<hierarchy><node text="Start browsing" bounds="[0,0][100,100]" /></hierarchy>'
)
WAIT_DIALOG = (
    '<hierarchy><node text="Wait" resource-id="android:id/aerr_wait" '
    'bounds="[0,0][100,100]" /></hierarchy>'
)


class UICommandResults:
    def __init__(self, xml: str) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.results: list[subprocess.CompletedProcess] = []
        self.options: list[tuple[object, bool, bool, int]] = []
        self.responses = {
            FOCUS: (
                0,
                b"mCurrentFocus= com.opera.android.startup.WelcomeActivity\n",
            ),
            DUMP: (0, b"UI hierarchy dumped\n"),
            READ: (0, xml.encode()),
        }
        self.backup_started = False

    @contextmanager
    def observe(self):
        with (
            patch("scripts.capture.android_device.subprocess.run", new=self.run),
            patch("scripts.capture.android_device.time.sleep", return_value=None),
        ):
            yield

    def run(self, argv, *, stdin, capture_output, check, timeout):
        if argv[0] != str(ADB):
            raise AssertionError(f"unexpected executable: {argv[0]}")

        command = tuple(argv[1:])
        self.commands.append(command)
        self.options.append((stdin, capture_output, check, timeout))
        if len(self.commands) > 32:
            raise AssertionError("UI command control exceeded its finite budget")

        if command in self.responses:
            status, output = self.responses[command]
        elif command[:2] in (("shell", "input"), ("shell", "am")):
            status, output = 0, b""
        else:
            raise AssertionError(f"unexpected command: {command}")

        result = subprocess.CompletedProcess(
            argv, status, output, DIAGNOSTIC if status else b""
        )
        self.results.append(result)

        return result


class ObservedUIDevice(AdbDevice):
    def __init__(self) -> None:
        super().__init__(ADB)
        self.errors: list[tuple[tuple[str, ...], BaseException]] = []

    def run(self, *arguments: str, check: bool = True) -> str:
        try:
            return super().run(*arguments, check=check)
        except BaseException as failure:
            self.errors.append((arguments, failure))
            raise


class UIObservationBackupFailures(Exception):
    def __init__(self, failures: tuple[BaseException, ...]) -> None:
        self.failures = failures
        super().__init__("UI observation control backup failed")


class AndroidRequiredUIObservationTests(unittest.TestCase):
    def resources(
        self, *, onboarding: bool = False, xml: str = ""
    ) -> tuple[UICommandResults, ObservedUIDevice, AndroidSession]:
        owners = []

        def backup() -> None:
            failures = []
            for commands, session in owners:
                commands.backup_started = True
                try:
                    with commands.observe():
                        session.__exit__()
                except BaseException as failure:
                    failures.append(failure)
            if failures:
                raise UIObservationBackupFailures(tuple(failures))

        self.addCleanup(backup)
        commands = UICommandResults(xml)
        device = ObservedUIDevice()
        browser = ANDROID_BROWSERS["opera-android" if onboarding else "chrome-android"]
        launch = AndroidLaunch(
            browser,
            URL,
            entry="intent" if onboarding else "typed",
            settle=0,
            typing_delay=0,
            typing_timeout=0,
            typing_attempts=1,
            onboarding_delay=0,
        )
        session = AndroidSession(device, launch)
        owners.append((commands, session))

        return commands, device, session

    def start(self, package: str, *, target: str = "about:blank"):
        return (
            "shell",
            "am",
            "start",
            "-W",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            target,
            "-p",
            package,
        )

    def assert_options(self, commands) -> None:
        self.assertFalse(commands.backup_started)
        self.assertTrue(
            all(
                options == (subprocess.DEVNULL, True, False, 120)
                for options in commands.options
            )
        )
        self.assertEqual(len(commands.results), len(commands.commands))

    def assert_failed_observation(
        self, command, *, onboarding: bool, xml: str, focused_only: bool = False
    ) -> None:
        commands, device, session = self.resources(onboarding=onboarding, xml=xml)
        status, output = commands.responses[command]
        self.assertEqual(status, 0)
        commands.responses[command] = (7, output)
        package = session.launch.browser.package
        if focused_only:
            expected = [DUMP, READ]
            operation = session.focused_text
        elif onboarding:
            expected = [self.start(package), FOCUS]
            if command != FOCUS:
                expected.append(DUMP)
            if command == READ:
                expected.append(READ)
            operation = partial(session._open, package)
        else:
            expected = [self.start(package), FOCUS_BAR, TYPE_FIRST, DUMP]
            if command == READ:
                expected.append(READ)
            operation = partial(session._open, package)

        with commands.observe():
            failure = failure_from(operation)

            self.assert_options(commands)
            self.assertEqual(commands.commands[: len(expected)], expected)
            index = commands.commands.index(command)
            result = commands.results[index]
            self.assertEqual(tuple(result.args[1:]), command)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, output)
            self.assertEqual(result.stderr, DIAGNOSTIC)

            self.assertIsInstance(failure, RuntimeError)
            self.assertNotIsInstance(failure, TypingFailed)
            self.assertEqual(len(device.errors), 1)
            self.assertEqual(device.errors[0][0], command)
            self.assertIs(device.errors[0][1], failure)
            self.assertIsNone(failure.__context__)
            self.assertIn("adb " + " ".join(command), str(failure))
            self.assertIn(DIAGNOSTIC.decode().strip(), str(failure))
            self.assertEqual(commands.commands, expected)
            self.assertNotIn(ENTER, commands.commands)
            self.assertNotIn(TAP, commands.commands)

    def test_failed_window_focus_does_not_complete_onboarding(self) -> None:
        commands, device, session = self.resources(onboarding=True)
        commands.responses[FOCUS] = (7, b"mCurrentFocus= browser.MainActivity\n")
        package = session.launch.browser.package

        with commands.observe():
            failure = failure_from(lambda: session._open(package))

            self.assert_options(commands)
            self.assertEqual(commands.commands[:2], [self.start(package), FOCUS])
            result = commands.results[1]
            self.assertEqual(tuple(result.args[1:]), FOCUS)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, b"mCurrentFocus= browser.MainActivity\n")
            self.assertEqual(result.stderr, DIAGNOSTIC)

            self.assertIsInstance(failure, RuntimeError)
            self.assertEqual(len(device.errors), 1)
            self.assertEqual(device.errors[0][0], FOCUS)
            self.assertIs(device.errors[0][1], failure)
            self.assertIsNone(failure.__context__)
            self.assertIn(DIAGNOSTIC.decode().strip(), str(failure))
            self.assertEqual(commands.commands, [self.start(package), FOCUS])

    def test_failed_onboarding_dump_does_not_tap_stale_last_screen(self) -> None:
        self.assert_failed_observation(DUMP, onboarding=True, xml=LAST_ONBOARDING)

    def test_failed_onboarding_read_does_not_tap_success_shaped_xml(self) -> None:
        self.assert_failed_observation(READ, onboarding=True, xml=LAST_ONBOARDING)

    def test_failed_typed_dump_does_not_submit_stale_complete_url(self) -> None:
        self.assert_failed_observation(DUMP, onboarding=False, xml=screen(URL))

    def test_failed_typed_read_does_not_submit_success_shaped_xml(self) -> None:
        self.assert_failed_observation(READ, onboarding=False, xml=screen(URL))

    def test_failed_dialog_read_does_not_tap_success_shaped_wait_button(self) -> None:
        self.assert_failed_observation(
            READ, onboarding=False, xml=WAIT_DIALOG, focused_only=True
        )

    def test_successful_onboarding_observations_tap_then_open_requested_url(
        self,
    ) -> None:
        commands, device, session = self.resources(onboarding=True, xml=LAST_ONBOARDING)
        package = session.launch.browser.package

        with commands.observe():
            self.assertIsNone(session._open(package))

            self.assert_options(commands)
            self.assertEqual(device.errors, [])
            self.assertEqual(
                commands.commands,
                [
                    self.start(package),
                    FOCUS,
                    DUMP,
                    READ,
                    TAP,
                    self.start(package, target="'" + URL + "'"),
                ],
            )
            self.assertTrue(all(result.returncode == 0 for result in commands.results))

    def test_successful_absent_focus_keeps_two_check_onboarding_completion(
        self,
    ) -> None:
        commands, device, session = self.resources(onboarding=True)
        commands.responses[FOCUS] = (0, b"")
        package = session.launch.browser.package

        with commands.observe():
            self.assertIsNone(session._open(package))

            self.assert_options(commands)
            self.assertEqual(device.errors, [])
            self.assertEqual(
                commands.commands,
                [
                    self.start(package),
                    FOCUS,
                    FOCUS,
                    self.start(package, target="'" + URL + "'"),
                ],
            )

    def test_successful_typed_read_submits_only_the_complete_url(self) -> None:
        commands, device, session = self.resources(xml=screen(URL))
        package = session.launch.browser.package

        with commands.observe():
            self.assertIsNone(session._open(package))

            self.assert_options(commands)
            self.assertEqual(device.errors, [])
            self.assertEqual(
                commands.commands,
                [self.start(package), FOCUS_BAR, TYPE_FIRST, DUMP, READ, ENTER],
            )
            self.assertTrue(all(result.returncode == 0 for result in commands.results))

    def assert_refused_typed_observation(self, xml: str) -> None:
        commands, device, session = self.resources(xml=xml)
        package = session.launch.browser.package

        with commands.observe():
            failure = failure_from(lambda: session._open(package))

            self.assert_options(commands)
            self.assertTrue(all(result.returncode == 0 for result in commands.results))
            self.assertEqual(device.errors, [])
            self.assertIsInstance(failure, TypingFailed)
            self.assertEqual(str(failure), "the address bar never held the typed URL")
            self.assertEqual(
                commands.commands,
                [self.start(package), FOCUS_BAR, TYPE_FIRST, DUMP, READ],
            )
            self.assertNotIn(ENTER, commands.commands)

    def test_successful_malformed_xml_does_not_submit_a_url(self) -> None:
        self.assert_refused_typed_observation("ERROR: null root node")

    def test_successful_partial_url_does_not_press_enter(self) -> None:
        self.assert_refused_typed_observation(screen("htt"))

    def test_successful_dialog_read_taps_wait_without_submitting(self) -> None:
        commands, device, session = self.resources(xml=WAIT_DIALOG)

        with commands.observe():
            self.assertIsNone(session.focused_text())

            self.assert_options(commands)
            self.assertEqual(device.errors, [])
            self.assertEqual(commands.commands, [DUMP, READ, TAP])
            self.assertNotIn(ENTER, commands.commands)
