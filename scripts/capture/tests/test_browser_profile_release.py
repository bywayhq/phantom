"""Own a browser descendant even after its launcher has exited."""

import contextlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture import browser_launch, firefox_socket_hooks, process_container
from scripts.capture.browser_failures import BrowserLaunchFailures
from scripts.capture.process_container import ProcessContainer
from scripts.capture.tests.test_process_container import OwnedWindowsProcess

CHILD = """
import json, os, socket, sys
with open(os.path.join(os.environ['CAPTURE_TEST_PROFILE'], 'held.sqlite'), 'wb'):
    with socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=10) as peer:
        peer.settimeout(None)
        peer.sendall(json.dumps({'pid': os.getpid()}).encode() + b'\\n')
        peer.recv(1)
"""

LAUNCHER = """
import os, subprocess, sys
environment = dict(os.environ, CAPTURE_TEST_PROFILE=sys.argv[2])
subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1]],
                 env=environment, stdin=subprocess.DEVNULL,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
"""


@unittest.skipUnless(sys.platform == "win32", "Windows file and job ownership")
class BrowserProfileReleaseTests(unittest.TestCase):
    def browser(self) -> browser_launch.LaunchedBrowser:
        return browser_launch.LaunchedBrowser(
            browser_launch.LaunchPlan("firefox", Path(sys.executable), True),
            "http://127.0.0.1/profile-release-control",
        )

    def test_exited_launcher_descendant_releases_profile_before_removal(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="profile-release-control-") as directory,
            contextlib.ExitStack() as cleanup,
        ):
            listener = cleanup.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            profile = Path(directory) / "disposable profile"
            profile.mkdir()
            sibling = profile.with_name(profile.name + "x")
            sibling.mkdir()
            unrelated = subprocess.Popen(
                [
                    process_container._windows_interpreter(),
                    "-c",
                    CHILD,
                    str(listener.getsockname()[1]),
                ],
                env=dict(os.environ, CAPTURE_TEST_PROFILE=str(sibling)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            def stop_unrelated() -> None:
                if unrelated.poll() is None:
                    unrelated.kill()
                unrelated.wait(timeout=10)

            cleanup.callback(stop_unrelated)
            sibling_peer, _ = listener.accept()
            cleanup.enter_context(sibling_peer)
            sibling_peer.settimeout(10)
            with sibling_peer.makefile("rb") as reader:
                self.assertEqual(json.loads(reader.readline(256))["pid"], unrelated.pid)
            browser = self.browser()
            browser.profile = profile
            arguments = [
                "-c",
                LAUNCHER,
                str(listener.getsockname()[1]),
                str(profile),
                CHILD,
            ]
            with mock.patch.object(
                browser_launch, "browser_arguments", return_value=arguments
            ):
                browser.process = browser._start(profile)
            # Release an unreaped launcher even if setup or the peer fails.
            cleanup.callback(browser_launch.terminate_process_tree, browser.process)
            peer, _ = listener.accept()
            cleanup.enter_context(peer)
            peer.settimeout(10)
            with peer.makefile("rb") as reader:
                document = json.loads(reader.readline(256))
            child = OwnedWindowsProcess(document["pid"])
            cleanup.callback(child.close)
            self.assertEqual(browser.process.wait(timeout=10), 0)
            self.assertFalse(child.ended_now())
            # The child has no profile argument. It receives the path through
            # its environment, just as a browser child may inherit handles.
            held = profile / "held.sqlite"
            with self.assertRaises(PermissionError) as locked:
                held.unlink()
            self.assertEqual(locked.exception.winerror, 32)

            failure = None
            try:
                browser.__exit__(None, None, None)
            except BaseException as error:
                failure = error
            self.assertIsNone(failure, f"profile cleanup failed: {failure!r}")
            self.assertTrue(child.ended_now())
            self.assertFalse(profile.exists())
            self.assertIsNone(unrelated.poll())
            self.assertTrue((sibling / "held.sqlite").exists())

    def test_launcher_observation_uses_the_actual_tool_not_its_bootstrap(self) -> None:
        with contextlib.ExitStack() as cleanup:
            listener = cleanup.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            directory = cleanup.enter_context(
                tempfile.TemporaryDirectory(prefix="launcher-observation-")
            )
            profile = Path(directory)
            container = ProcessContainer(
                [
                    process_container._windows_interpreter(),
                    "-c",
                    CHILD,
                    str(listener.getsockname()[1]),
                ],
                env=dict(os.environ, CAPTURE_TEST_PROFILE=str(profile)),
                confirm_start=True,
            )
            cleanup.callback(container.close)
            container.start()
            peer, _ = listener.accept()
            cleanup.enter_context(peer)
            peer.settimeout(10)
            with peer.makefile("rb") as reader:
                tool_pid = json.loads(reader.readline(256))["pid"]
            browser = self.browser()
            browser.profile = profile
            self.assertIsNone(browser.launcher_pid)
            browser.process = container
            self.assertEqual(browser.launcher_pid, tool_pid)
            self.assertNotEqual(container.pid, tool_pid)
            # Exercise the real observation in work without launching a browser
            # or attaching native instrumentation. Census and attachment are
            # controlled; the launcher PID above came from the owned child.
            for selected_pid in (tool_pid, tool_pid + 1):
                with self.subTest(selected_pid=selected_pid):
                    native = firefox_socket_hooks._FirefoxNative(
                        mock.Mock(), browser.plan, browser.url, {}
                    )
                    native.browser = browser
                    native.attach_requested.set()
                    agent = mock.Mock(failure=None)
                    agent.ready = threading.Event()
                    agent.ready.set()
                    agent.attach.side_effect = native.stop_requested.set
                    listing = [
                        {
                            "ProcessId": selected_pid,
                            "ParentProcessId": 0,
                            "CommandLine": "tool",
                        }
                    ]
                    with (
                        mock.patch.object(browser, "__enter__", return_value=browser),
                        mock.patch.object(browser, "__exit__"),
                        mock.patch.object(firefox_socket_hooks, "patched_environment"),
                        mock.patch.object(
                            firefox_socket_hooks,
                            "profile_processes",
                            return_value=listing,
                        ),
                        mock.patch.object(
                            firefox_socket_hooks, "Hooks", return_value=agent
                        ),
                    ):
                        native.work()
                    self.assertEqual(native.failures, [])
                    self.assertEqual(native.launcher, selected_pid != tool_pid)
                    agent.attach.assert_called_once()
                    agent.detach.assert_called_once()

    def test_popen_launcher_observation_preserves_the_original_pid(self) -> None:
        process = subprocess.Popen([sys.executable, "-c", "pass"])
        try:
            browser = self.browser()
            browser.process = process
            self.assertEqual(browser.launcher_pid, process.pid)
            self.assertEqual(process.wait(timeout=10), 0)
            self.assertEqual(browser.launcher_pid, process.pid)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)

    def test_failed_start_closes_the_owned_gate_before_removing_profile(self) -> None:
        browser = self.browser()
        primary = OSError("controlled release failure")
        with (
            mock.patch.object(
                browser_launch, "browser_arguments", return_value=["-c", "pass"]
            ),
            mock.patch.object(ProcessContainer, "start", side_effect=primary),
            self.assertRaises(OSError) as observed,
        ):
            browser.__enter__()

        self.assertIs(observed.exception, primary)
        self.assertIsNone(browser.process)
        self.assertIsNone(browser.profile)

    def test_constructor_cleanup_failure_retains_owner_and_profile_for_retry(
        self,
    ) -> None:
        browser = self.browser()
        primary = OSError("controlled job assignment failure")
        secondary = OSError("controlled close failure")
        try:
            with (
                mock.patch.object(
                    browser_launch, "browser_arguments", return_value=["-c", "pass"]
                ),
                mock.patch(
                    "scripts.capture.process_container._windows_job",
                    side_effect=primary,
                ),
                mock.patch.object(ProcessContainer, "close", side_effect=secondary),
                self.assertRaises(BrowserLaunchFailures) as observed,
            ):
                browser.__enter__()

            self.assertIs(observed.exception.primary, primary)
            self.assertEqual(observed.exception.cleanup, (secondary,))
            self.assertIs(browser.process, primary.container)
            self.assertTrue(browser.profile.is_dir())
        finally:
            browser.__exit__(None, None, None)
        self.assertFalse(browser.profile.exists())

    def test_failed_container_close_keeps_profile_until_a_successful_retry(
        self,
    ) -> None:
        browser = self.browser()
        failure = OSError("controlled member wait failure")
        with mock.patch.object(
            browser_launch, "browser_arguments", return_value=["-c", "pass"]
        ):
            browser.__enter__()
        try:
            with (
                mock.patch.object(ProcessContainer, "close", side_effect=failure),
                self.assertRaises(OSError) as observed,
            ):
                browser.__exit__(None, None, None)
            self.assertIs(observed.exception, failure)
            self.assertTrue(browser.profile.is_dir())
            self.assertIsInstance(browser.process, ProcessContainer)
        finally:
            browser.__exit__(None, None, None)
        self.assertFalse(browser.profile.exists())


if __name__ == "__main__":
    unittest.main()
