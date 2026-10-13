import argparse
import asyncio
import contextlib
import io
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

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
    command_names_profile,
    firefox_arguments,
    firefox_user_js,
    host_chromium_flags,
    profile_process_ids,
    recorded_arguments,
    render_preferences,
    terminate_profile_processes,
    with_android_entry,
)

URL = "http://127.0.0.1:9450/run/token"


class BrowserLaunchTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows argument parser")
    def test_profile_matches_whole_paths_including_quoted_windows_paths(self) -> None:
        profile = Path("C:/Users/O'Brien/temporary profile")
        for command in [
            f'chrome --user-data-dir="{profile}"',
            f'crashpad --database="{profile}/Crashpad"',
            'firefox --profile "C:\\USERS\\O\'BRIEN\\TEMPORARY PROFILE"',
        ]:
            with self.subTest(command=command):
                self.assertTrue(command_names_profile(command, profile, windows=True))
        for suffix in [
            "x",
            "-other",
            ".other",
            "_other",
            "@other",
            ":other",
            "'other",
            " other",
        ]:
            with self.subTest(suffix=suffix):
                self.assertFalse(
                    command_names_profile(
                        f'chrome --user-data-dir="{profile}{suffix}"',
                        profile,
                        windows=True,
                    )
                )
        self.assertFalse(
            command_names_profile(
                f'chrome --user-data-dir="prefix{profile}"', profile, windows=True
            )
        )

    def test_windows_profile_sweep_uses_data_and_skips_both_supervisors(self) -> None:
        profile = Path("C:/Users/O'Brien/profile")
        document = {
            "Supervisor": 902,
            "Processes": [
                {"ProcessId": 901, "CommandLine": f'python "{profile}"'},
                {"ProcessId": 902, "CommandLine": f'powershell "{profile}"'},
                {
                    "ProcessId": 903,
                    "CommandLine": f'chrome --user-data-dir="{profile}"',
                },
                {
                    "ProcessId": 904,
                    "CommandLine": f'chrome --user-data-dir="{profile}x"',
                },
                {
                    "ProcessId": 905,
                    "CommandLine": f'crashpad --database="{profile}/Crashpad"',
                },
                {"ProcessId": 906, "CommandLine": None},
            ],
        }
        listing = subprocess.CompletedProcess([], 0, json.dumps(document).encode())
        stopped = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(browser_launch.sys, "platform", "win32"),
            mock.patch.object(browser_launch.os, "getpid", return_value=901),
            mock.patch.object(
                browser_launch,
                "_windows_arguments",
                side_effect=lambda command: [command.split('"')[1]],
            ),
            mock.patch.object(
                browser_launch.subprocess, "run", side_effect=[listing, stopped]
            ) as run,
        ):
            terminate_profile_processes(profile)
        discovery, termination = [call.args[0][-1] for call in run.call_args_list]
        self.assertNotIn(str(profile), discovery)
        self.assertIn("903,905", termination)
        for pid in [901, 902, 904, 906]:
            self.assertNotIn(str(pid), termination)

    def test_windows_profile_discovery_failure_is_not_reported_as_cleanup(self) -> None:
        with (
            mock.patch.object(browser_launch.sys, "platform", "win32"),
            mock.patch.object(
                browser_launch.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(1, "discovery"),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            terminate_profile_processes(Path("C:/profile"))

    def test_unix_profile_discovery_retains_a_real_failed_command(self) -> None:
        run_command = subprocess.run

        def failed_census(command, **options):
            self.assertEqual(command, ["ps", "-axww", "-o", "pid=,command="])
            return run_command(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stderr.buffer.write(b'census denied\\n'); raise SystemExit(23)",
                ],
                **options,
            )

        with (
            mock.patch.object(browser_launch.sys, "platform", "linux"),
            mock.patch.object(browser_launch.subprocess, "run", failed_census),
            mock.patch.object(browser_launch.os, "kill") as kill,
            self.assertRaises(subprocess.CalledProcessError) as failure,
        ):
            terminate_profile_processes(Path("unused-profile"))

        self.assertEqual(failure.exception.returncode, 23)
        self.assertEqual(failure.exception.stderr, b"census denied\n")
        kill.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Windows profile sweep")
    def test_windows_sweep_stops_exact_and_descendant_but_preserves_prefix_sibling(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.ExitStack() as cleanup,
        ):
            profile = Path(directory) / "O'Brien profile"
            targets = [str(profile), str(profile / "Crashpad"), str(profile) + "x"]
            processes = []
            for target in targets:
                process = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)", target]
                )
                processes.append(process)
                cleanup.callback(
                    lambda process=process: (
                        (process.kill(), process.wait(timeout=30))
                        if process.poll() is None
                        else None
                    )
                )
            terminate_profile_processes(profile)
            for process in processes[:2]:
                process.wait(timeout=30)
                self.assertIsNotNone(process.poll())
            self.assertIsNone(processes[2].poll())

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


class LaunchPeerFailures(Exception):
    def __init__(self, primary, cleanup, pending):
        super().__init__("launch test peer cleanup failed")
        self.primary = primary
        self.cleanup = tuple(cleanup)
        self.pending = tuple(pending)
        self.prior_cause = primary.__cause__
        self.prior_context = primary.__context__


def raise_peer_failures(primary, cleanup, pending=()):
    causes = []
    for error in cleanup:
        if error is not primary and all(error is not prior for prior in causes):
            causes.append(error)
    if primary is None and causes:
        primary = causes.pop(0)
    if primary is not None:
        if causes or pending:
            raise primary from LaunchPeerFailures(primary, causes, pending)
        raise primary


class LaunchTurnTests(unittest.TestCase):
    def test_without_a_lock_directory_launches_do_not_wait(self) -> None:
        os.environ.pop(browser_launch.LAUNCH_LOCK_DIRECTORY, None)

        with browser_launch.launch_turn("firefox") as shared:
            self.assertFalse(shared)

    def test_launches_take_turns_when_a_runner_sets_the_lock_directory(self) -> None:
        directory_owner = tempfile.TemporaryDirectory()
        pending = []
        failures = []
        primary = None
        thread = None
        try:
            directory = directory_owner.name
            os.environ[browser_launch.LAUNCH_LOCK_DIRECTORY] = directory
            self.addCleanup(os.environ.pop, browser_launch.LAUNCH_LOCK_DIRECTORY, None)
            events = []
            first_holds = threading.Event()
            stop = threading.Event()

            def second() -> None:
                try:
                    if not first_holds.wait(10):
                        raise TimeoutError("first launch never acquired its lock")
                    if not stop.is_set():
                        with browser_launch.launch_turn("firefox"):
                            events.append("second")
                except BaseException as error:
                    failures.append(error)

            thread = threading.Thread(target=second)
            try:
                thread.start()
                with browser_launch.launch_turn("firefox") as shared:
                    first_holds.set()
                    time.sleep(0.3)
                    events.append("first")
            except BaseException as error:
                primary = error
            finally:
                if primary is not None:
                    stop.set()
                first_holds.set()
                if thread.ident is not None:
                    thread.join(timeout=10)
                    if thread.is_alive():
                        failures.append(
                            TimeoutError("second launch thread did not retire")
                        )
                        pending.append(thread)
            if primary is None and not failures:
                self.assertTrue(shared)
                self.assertEqual(events, ["first", "second"])
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                failures.append(error)
        finally:
            if thread is not None and thread.is_alive():
                pending.append(directory_owner)
            else:
                try:
                    directory_owner.cleanup()
                except BaseException as error:
                    failures.append(error)
        raise_peer_failures(primary, failures, pending)


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


class WaitingLaunchPeers:
    """Own the response workers and native client for the waiting-launch test."""

    def __init__(self, release):
        self.release = release
        self.server = None
        self.responses = []
        self.writers = []
        self.closures = []
        self.worker = None
        self.reply = []
        self.failures = []
        self.pending = []
        self.closing = False

    async def start(self):
        self.server = await asyncio.start_server(self.accept, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]

        def client():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    sock.sendall(b"page\n")
                    self.reply.append(sock.recv(16))
                self.reply.append(b"released")
            except BaseException as error:
                self.failures.append(error)
            finally:
                self.release.set()

        self.worker = threading.Thread(target=client)
        self.worker.start()

    def accept(self, reader, writer):
        self.writers.append(writer)
        if self.closing:
            self.retire_writer(writer)
            return
        response = self.answer(reader, writer)
        try:
            self.responses.append(asyncio.create_task(response))
        except BaseException as error:
            response.close()
            self.failures.append(error)
            self.release.set()

    async def answer(self, reader, writer):
        await reader.readline()
        writer.write(b"ok\n")
        await writer.drain()

    async def collect(self, tasks, phase):
        if not tasks:
            return
        done, pending = await asyncio.wait(tasks, timeout=5)
        for task in done:
            try:
                task.result()
            except BaseException as error:
                self.failures.append(error)
        if pending:
            self.failures.append(TimeoutError(f"waiting launch {phase} did not retire"))
            for task in pending:
                task.cancel()
            done, pending = await asyncio.wait(pending, timeout=5)
            for task in done:
                try:
                    task.result()
                except asyncio.CancelledError:
                    pass  # Only these explicitly cancelled cleanup workers.
                except BaseException as error:
                    self.failures.append(error)
            self.pending.extend(pending)

    def retire_writer(self, writer):
        try:
            writer.close()
        except BaseException as error:
            self.failures.append(error)
            try:
                writer.transport.abort()
            except BaseException as abort_error:
                self.failures.append(abort_error)
        closure = writer.wait_closed()
        try:
            self.closures.append(asyncio.create_task(closure))
        except BaseException as error:
            closure.close()
            self.failures.append(error)
            self.pending.append(writer)

    async def close(self):
        self.closing = True
        self.release.set()
        for response in self.responses:
            if response.done():
                try:
                    response.result()
                except BaseException as error:
                    self.failures.append(error)
        if self.server is not None:
            try:
                self.server.close()
                self.closures.append(asyncio.create_task(self.server.wait_closed()))
            except BaseException as error:
                self.failures.append(error)
                self.pending.append(self.server)
        for writer in self.writers:
            self.retire_writer(writer)
        await self.collect(self.responses, "responses")
        collected = 0
        while collected < len(self.closures):
            closures = self.closures[collected:]
            collected = len(self.closures)
            await self.collect(closures, "sockets")
        if self.worker is not None and self.worker.ident is not None:
            await asyncio.to_thread(self.worker.join, 5)
            if self.worker.is_alive():
                self.failures.append(
                    TimeoutError("waiting launch client did not retire")
                )
                self.pending.append(self.worker)


class EnterBrowserTests(unittest.TestCase):
    """A launch that waits its turn must not stall the tool's server."""

    def setUp(self) -> None:
        self.holder = None
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.cleanup_directory)
        os.environ[browser_launch.LAUNCH_LOCK_DIRECTORY] = self.directory.name
        self.addCleanup(os.environ.pop, browser_launch.LAUNCH_LOCK_DIRECTORY, None)
        self.plan = LaunchPlan("firefox", Path("firefox.exe"), True)
        self.held = threading.Event()
        self.release = threading.Event()
        self.holder_failures = []

        def hold() -> None:
            try:
                with browser_launch.launch_turn("firefox"):
                    self.held.set()
                    if not self.release.wait(10):
                        raise TimeoutError("waiting launch lock was not released")
            except BaseException as error:
                self.holder_failures.append(error)
            finally:
                self.held.set()

        self.holder = threading.Thread(target=hold)
        self.addCleanup(self.collect_holder)
        self.holder.start()
        if not self.held.wait(10):
            self.collect_holder(
                TimeoutError("waiting launch holder never became ready")
            )
        if self.holder_failures:
            self.collect_holder()

    def collect_holder(self, primary=None):
        self.release.set()
        pending = []
        if self.holder.ident is not None:
            self.holder.join(10)
            if self.holder.is_alive():
                self.holder_failures.append(
                    TimeoutError("launch holder did not retire")
                )
                pending.extend([self.holder, self.directory])
        failures, self.holder_failures = self.holder_failures, []
        raise_peer_failures(primary, failures, pending)

    def cleanup_directory(self):
        # A native lock call cannot be preempted. Its failure packet retains
        # the directory until the still-owned holder thread has retired.
        if self.holder is None or not self.holder.is_alive():
            self.directory.cleanup()

    def test_the_server_answers_while_a_firefox_launch_waits(self) -> None:
        async def scenario() -> tuple[bytes, bool]:
            peers = WaitingLaunchPeers(self.release)
            primary = None
            browser = None
            try:
                await peers.start()
                browser = await browser_launch.enter_browser(
                    ExitedFirefox(self.plan, "http://127.0.0.1/")
                )
            except BaseException as error:
                primary = error
            finally:
                if browser is not None:
                    try:
                        browser.__exit__(None, None, None)
                    except BaseException as error:
                        peers.failures.append(error)
                        peers.pending.append(browser)
                cleanup = asyncio.create_task(peers.close())
                try:
                    await asyncio.shield(cleanup)
                except BaseException as error:
                    peers.failures.append(error)
                    peers.pending.extend([peers, cleanup])
                try:
                    self.collect_holder()
                except BaseException as error:
                    peers.failures.append(error)
            raise_peer_failures(primary, peers.failures, peers.pending)
            return b"".join(peers.reply[:1]), peers.reply[-1:] == [b"released"]

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
            try:
                await asyncio.sleep(0.2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            finally:
                self.release.set()
                if not task.done():
                    task.cancel()
                    # This test requested the abandoned launch cancellation.
                    with contextlib.suppress(asyncio.CancelledError):
                        await task

        asyncio.run(scenario())

        self.assertTrue(ExitedFirefox.exited.wait(10))
        self.assertEqual(ExitedFirefox.exits, 1)


if __name__ == "__main__":
    unittest.main()
