import argparse
import asyncio
import contextlib
import io
import os
import shlex
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from scripts.capture import browser_launch
from scripts.capture.browser_launch import (
    CHROMIUM_BROWSERS,
    CHROMIUM_FLAGS,
    PROFILE_PLACEHOLDER,
    LaunchedBrowser,
    LaunchPlan,
    add_android_entry_option,
    add_browser_switch_option,
    check_android_entry,
    check_browser_switches,
    chromium_arguments,
    firefox_arguments,
    firefox_user_js,
    host_chromium_flags,
    profile_process_ids,
    recorded_arguments,
    render_preferences,
    with_android_entry,
)

URL = "http://127.0.0.1:9450/run/token"


class BrowserLaunchTests(unittest.TestCase):
    def test_headless_chromium_arguments_isolate_profile_and_end_with_url(
        self,
    ) -> None:
        profile = Path("profile")

        arguments = chromium_arguments(profile, URL, headless=True)

        self.assertEqual(
            arguments,
            [
                "--headless=new",
                f"--user-data-dir={profile}",
                *CHROMIUM_FLAGS,
                *host_chromium_flags(),
                URL,
            ],
        )

    def test_browser_switches_are_chromium_only_and_must_be_switches(
        self,
    ) -> None:
        def parse(*argv: str) -> argparse.Namespace:
            parser = argparse.ArgumentParser()
            parser.add_argument("--browser")
            add_browser_switch_option(parser)
            args = parser.parse_args(argv)
            with contextlib.redirect_stderr(io.StringIO()):
                check_browser_switches(parser, args)
            return args

        args = parse("--browser", "edge", "--browser-switch=--accept-lang=en-US")
        self.assertEqual(args.browser_switch, ["--accept-lang=en-US"])
        for argv in (
            ("--browser", "firefox", "--browser-switch=--accept-lang=en-US"),
            ("--browser", "chrome", "--browser-switch=accept-lang"),
        ):
            with self.subTest(argv), self.assertRaises(SystemExit):
                parse(*argv)

    def test_only_macos_adds_the_mock_keychain_switch(self) -> None:
        self.assertEqual(host_chromium_flags("darwin"), ("--use-mock-keychain",))
        self.assertEqual(host_chromium_flags("win32"), ())
        self.assertEqual(host_chromium_flags("linux"), ())

    def test_profile_sweep_matches_only_processes_naming_the_run_profile(
        self,
    ) -> None:
        profile = Path("/Users/a/phantom-capture/tmp/phantom-capture-profile-ab12")
        listing = "\n".join(
            (
                "  101 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                f"  102 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                f" --headless=new --user-data-dir={profile} --no-first-run",
                f"  103 chrome_crashpad_handler --database={profile}/Crashpad",
                f"  104 firefox --no-remote --profile {profile}x about:blank",
                f"  105 python -m scripts.capture.client_hints {profile}",
                "  garbage",
            )
        )

        self.assertEqual(profile_process_ids(listing, profile, own_pid=105), [102, 103])

    def test_profile_sweep_of_a_job_directory_matches_the_profiles_inside_it(
        self,
    ) -> None:
        job = Path("/Users/a/phantom-capture/run/job-3/tmp")
        listing = "\n".join(
            (
                f"  201 Google Chrome --user-data-dir={job}/phantom-capture-profile-x1",
                f"  202 firefox --profile {job}4/phantom-capture-profile-x2",
                "  203 Google Chrome --user-data-dir=/Users/a/Library/Chrome",
            )
        )

        self.assertEqual(profile_process_ids(listing, job, own_pid=1), [201])

    def test_headful_chromium_arguments_omit_headless_and_keep_extra_order(
        self,
    ) -> None:
        arguments = chromium_arguments(
            Path("profile"), URL, headless=False, extra=("--b", "--a")
        )

        self.assertNotIn("--headless=new", arguments)
        self.assertEqual(arguments[-3:], ["--b", "--a", URL])

    def test_firefox_arguments_use_a_separate_profile_directory(self) -> None:
        arguments = firefox_arguments(Path("profile"), URL, headless=True)

        self.assertEqual(
            arguments,
            [
                "--headless",
                "--wait-for-browser",
                "--no-remote",
                "--profile",
                "profile",
                URL,
            ],
        )

    def test_firefox_preferences_disable_background_services(self) -> None:
        preferences = firefox_user_js()

        self.assertIn(
            'user_pref("network.captive-portal-service.enabled", false);', preferences
        )
        self.assertIn('user_pref("network.proxy.type", 0);', preferences)
        self.assertIn(
            'user_pref("browser.startup.homepage_override.mstone", "ignore");',
            preferences,
        )
        self.assertTrue(preferences.endswith(");\n"))

    def test_recorded_arguments_replace_the_machine_local_profile(self) -> None:
        profile = Path("C:/Temp/phantom-capture-profile-x")
        arguments = chromium_arguments(profile, URL, headless=True)

        recorded = recorded_arguments(arguments, profile)

        self.assertNotIn(str(profile), recorded)
        self.assertIn(f"--user-data-dir={PROFILE_PLACEHOLDER}", shlex.split(recorded))

    def test_plan_records_launch_mode_and_portable_arguments(self) -> None:
        plan = LaunchPlan("firefox", Path("firefox.exe"), headless=False)

        self.assertEqual(plan.launch_mode, "headful")
        self.assertEqual(plan.client_name, "Mozilla Firefox")
        self.assertEqual(
            shlex.split(plan.recorded_arguments(URL)),
            [
                "--wait-for-browser",
                "--no-remote",
                "--profile",
                PROFILE_PLACEHOLDER,
                URL,
            ],
        )

    def test_chromium_forks_launch_with_the_chromium_arguments(self) -> None:
        chrome = LaunchPlan("chrome", Path("chrome.exe"), headless=True)
        for browser, client in (("brave", "Brave"), ("opera", "Opera")):
            plan = LaunchPlan(browser, Path(f"{browser}.exe"), headless=True)

            self.assertIn(browser, CHROMIUM_BROWSERS)
            self.assertEqual(plan.client_name, client)
            self.assertEqual(
                plan.recorded_arguments(URL), chrome.recorded_arguments(URL)
            )

    def test_android_entry_option_switches_only_android_plans_to_intent(
        self,
    ) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("--browser")
        add_android_entry_option(parser)
        args = parser.parse_args(
            ["--browser", "chrome-android", "--android-entry", "intent"]
        )
        check_android_entry(parser, args)
        android = LaunchPlan("chrome-android", Path("adb"), headless=True)
        desktop = LaunchPlan("chrome", Path("chrome.exe"), headless=True)
        default = parser.parse_args(["--browser", "chrome-android"])

        self.assertEqual(default.android_entry, "typed")
        self.assertEqual(android.launch_mode, "android-typed")
        self.assertEqual(
            with_android_entry(android, "typed").launch_mode, "android-typed"
        )
        self.assertEqual(
            with_android_entry(android, args.android_entry).launch_mode,
            "android-intent",
        )
        self.assertIs(with_android_entry(desktop, args.android_entry), desktop)
        desktop_args = parser.parse_args(
            ["--browser", "chrome", "--android-entry", "intent"]
        )
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            check_android_entry(parser, desktop_args)

    def test_manual_plan_never_starts_a_process(self) -> None:
        plan = LaunchPlan("manual", None, headless=False)

        self.assertEqual(plan.launch_mode, "manual")
        self.assertEqual(plan.recorded_arguments(URL), "manual")
        with self.assertRaises(ValueError):
            LaunchedBrowser(plan, URL)

    def test_process_launch_requires_an_executable(self) -> None:
        with self.assertRaises(ValueError):
            LaunchedBrowser(LaunchPlan("chrome", None, headless=True), URL)

    def test_firefox_profile_receives_extra_preferences_and_files(self) -> None:
        plan = LaunchPlan(
            "firefox",
            Path(sys.executable),
            headless=True,
            firefox_preferences=(("network.dns.localDomains", "a.test"),),
            profile_files=(("cert_override.txt", "line\tvalue\n"),),
        )

        with LaunchedBrowser(plan, URL) as browser:
            preferences = (browser.profile / "user.js").read_text(encoding="utf-8")
            override = (browser.profile / "cert_override.txt").read_bytes()

        self.assertTrue(
            preferences.endswith('user_pref("network.dns.localDomains", "a.test");\n')
        )
        self.assertEqual(override, b"line\tvalue\n")
        self.assertEqual(
            render_preferences(plan.firefox_preferences),
            'network.dns.localDomains="a.test"',
        )

    def test_profile_file_names_cannot_leave_the_profile(self) -> None:
        plan = LaunchPlan(
            "chrome",
            Path(sys.executable),
            headless=True,
            profile_files=(("../escape.txt", ""),),
        )
        browser = LaunchedBrowser(plan, URL)

        with self.assertRaises(ValueError), browser:
            pass

        self.assertIsNone(browser.profile)

    def test_failed_launch_removes_the_temporary_profile(self) -> None:
        before = set(Path(tempfile.gettempdir()).glob("phantom-capture-profile-*"))
        missing = Path(tempfile.gettempdir()) / "phantom-missing-browser.exe"
        browser = LaunchedBrowser(LaunchPlan("firefox", missing, headless=True), URL)

        with self.assertRaises(OSError), browser:
            pass

        self.assertIsNone(browser.profile)
        after = set(Path(tempfile.gettempdir()).glob("phantom-capture-profile-*"))
        self.assertEqual(after, before)


class LaunchTurnTests(unittest.TestCase):
    def test_without_a_lock_directory_launches_do_not_wait(self) -> None:
        os.environ.pop(browser_launch.LAUNCH_LOCK_DIRECTORY, None)

        with browser_launch.launch_turn("firefox") as shared:
            self.assertFalse(shared)

    def test_launches_take_turns_when_a_runner_sets_the_lock_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ[browser_launch.LAUNCH_LOCK_DIRECTORY] = directory
            self.addCleanup(os.environ.pop, browser_launch.LAUNCH_LOCK_DIRECTORY, None)
            events = []
            first_holds = threading.Event()

            def second() -> None:
                first_holds.wait()
                with browser_launch.launch_turn("firefox"):
                    events.append("second")

            thread = threading.Thread(target=second)
            thread.start()
            with browser_launch.launch_turn("firefox") as shared:
                first_holds.set()
                time.sleep(0.3)
                events.append("first")
            thread.join(timeout=10)

            self.assertTrue(shared)
            self.assertEqual(events, ["first", "second"])


class FakeProcess:
    def __init__(self, code):
        self.code = code

    def poll(self):
        return self.code


class FirefoxStartTests(unittest.TestCase):
    def test_the_wait_ends_when_firefox_restores_its_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            (profile / "sessionCheckpoints.json").write_text(
                '{"final-ui-startup":true,"sessionstore-windows-restored":true}'
            )
            begin = time.monotonic()

            browser_launch.wait_for_firefox_start(profile, FakeProcess(None))

            self.assertLess(time.monotonic() - begin, 1)

    def test_the_wait_ends_when_firefox_exits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            begin = time.monotonic()

            browser_launch.wait_for_firefox_start(Path(directory), FakeProcess(0))

            self.assertLess(time.monotonic() - begin, 1)


class ExitedFirefox(LaunchedBrowser):
    """A Firefox launch whose process has already exited; nothing starts."""

    exits = 0
    exited = threading.Event()

    def _start(self, profile: Path):
        return FakeProcess(0)

    def __exit__(self, *details: object) -> None:
        type(self).exits += 1
        type(self).exited.set()
        if self.profile is not None:
            shutil.rmtree(self.profile, ignore_errors=True)


class EnterBrowserTests(unittest.TestCase):
    """A launch that waits its turn must not stall the tool's server."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        os.environ[browser_launch.LAUNCH_LOCK_DIRECTORY] = self.directory.name
        self.addCleanup(os.environ.pop, browser_launch.LAUNCH_LOCK_DIRECTORY, None)
        self.plan = LaunchPlan("firefox", Path("firefox.exe"), True)
        self.held = threading.Event()
        self.release = threading.Event()

        def hold() -> None:
            with browser_launch.launch_turn("firefox"):
                self.held.set()
                self.release.wait(10)

        self.holder = threading.Thread(target=hold)
        self.holder.start()
        self.held.wait(10)
        self.addCleanup(self.holder.join, 10)
        self.addCleanup(self.release.set)

    def test_the_server_answers_while_a_firefox_launch_waits(self) -> None:
        async def scenario() -> tuple[bytes, bool]:
            async def answer(reader, writer) -> None:
                await reader.readline()
                writer.write(b"ok\n")
                await writer.drain()
                writer.close()

            server = await asyncio.start_server(answer, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reply: list[bytes] = []

            def client() -> None:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    sock.sendall(b"page\n")
                    reply.append(sock.recv(16))
                # The lock is still held, so the launch is still waiting.
                reply.append(b"released")
                self.release.set()

            threading.Thread(target=client, daemon=True).start()
            browser = await browser_launch.enter_browser(
                ExitedFirefox(self.plan, "http://127.0.0.1/")
            )
            browser.__exit__(None, None, None)
            server.close()
            await server.wait_closed()
            return b"".join(reply[:1]), reply[-1:] == [b"released"]

        answered, released_by_client = asyncio.run(scenario())

        self.assertEqual(answered, b"ok\n")
        self.assertTrue(released_by_client)

    def test_a_cancelled_launch_is_removed_once_it_starts(self) -> None:
        ExitedFirefox.exits = 0
        ExitedFirefox.exited.clear()

        async def scenario() -> None:
            task = asyncio.create_task(
                browser_launch.enter_browser(ExitedFirefox(self.plan, "about:blank"))
            )
            await asyncio.sleep(0.2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.release.set()

        asyncio.run(scenario())

        self.assertTrue(ExitedFirefox.exited.wait(10))
        self.assertEqual(ExitedFirefox.exits, 1)


if __name__ == "__main__":
    unittest.main()
