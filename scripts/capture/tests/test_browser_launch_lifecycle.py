import asyncio
import contextlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture import browser_launch

CHILD = """
import socket
import sys

with socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=5) as peer:
    peer.settimeout(None)
    peer.sendall(b'launcher-child-ready\\n')
    peer.recv(1)
"""


class StartupFailure(Exception):
    pass


class BodyFailure(Exception):
    pass


class TreeFailure(Exception):
    pass


class SweepFailure(Exception):
    pass


class BackupFailures(Exception):
    def __init__(self, errors: tuple[BaseException, ...]) -> None:
        self.errors = errors
        super().__init__("launcher control backup failed")


class LaunchContext:
    def __init__(self, case: unittest.TestCase) -> None:
        self.case = case
        self.browser = browser_launch.LaunchedBrowser(
            browser_launch.LaunchPlan("firefox", Path(sys.executable), True),
            "http://127.0.0.1/launcher-control",
        )
        self.patches = contextlib.ExitStack()
        self.listener: socket.socket | None = None
        self.peers: list[socket.socket] = []
        self.processes: list[subprocess.Popen[bytes]] = []
        self.profile: Path | None = None
        self.start_failure: BaseException | None = None
        self.tree_failure: BaseException | None = None
        self.sweep_failure: BaseException | None = None
        self.checkpoints = 0
        self.tree_attempts = 0
        self.sweep_attempts = 0
        self.actual_tree = browser_launch.terminate_process_tree
        self.actual_sweep = browser_launch.terminate_profile_processes

    def prepare(self) -> None:
        self.listener = socket.socket()
        self.listener.settimeout(5)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)

        self.patches.enter_context(
            mock.patch.object(
                browser_launch.LaunchedBrowser, "_start", side_effect=self.start
            )
        )
        self.patches.enter_context(
            mock.patch.object(browser_launch, "launch_turn", self.turn)
        )
        self.patches.enter_context(
            mock.patch.object(browser_launch, "wait_for_firefox_start", self.checkpoint)
        )
        self.patches.enter_context(
            mock.patch.object(browser_launch, "terminate_process_tree", self.tree)
        )
        self.patches.enter_context(
            mock.patch.object(browser_launch, "terminate_profile_processes", self.sweep)
        )

    @contextlib.contextmanager
    def turn(self, name: str):
        self.case.assertEqual(name, "firefox")
        yield True

    def spawn(self, profile: Path) -> subprocess.Popen[bytes]:
        assert self.listener is not None
        options = {} if sys.platform == "win32" else {"start_new_session": True}
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                CHILD,
                str(self.listener.getsockname()[1]),
                str(profile),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **options,
        )
        self.processes.append(process)

        peer, address = self.listener.accept()
        self.peers.append(peer)
        peer.settimeout(5)
        self.case.assertEqual(address[0], "127.0.0.1")
        marker = bytearray()
        while not marker.endswith(b"\n") and len(marker) <= 64:
            part = peer.recv(64)
            if not part:
                break
            marker.extend(part)

        self.case.assertEqual(bytes(marker), b"launcher-child-ready\n")
        self.case.assertIsNone(process.poll())
        self.case.assertTrue(profile.is_dir())
        return process

    def start(self, profile: Path) -> subprocess.Popen[bytes]:
        self.profile = profile
        return self.spawn(profile)

    def checkpoint(self, profile: Path, process: subprocess.Popen[bytes]) -> None:
        self.checkpoints += 1
        self.case.assertEqual(profile, self.profile)
        self.case.assertIs(process, self.processes[0])
        self.case.assertIsNone(process.poll())
        self.case.assertTrue(profile.is_dir())
        if self.start_failure is not None:
            raise self.start_failure

    def tree(self, process: subprocess.Popen[bytes]) -> None:
        self.tree_attempts += 1
        self.case.assertIs(process, self.processes[0])
        self.actual_tree(process)
        if self.tree_failure is not None:
            raise self.tree_failure

    def sweep(self, profile: Path) -> None:
        self.sweep_attempts += 1
        self.case.assertEqual(profile, self.profile)
        self.actual_sweep(profile)
        if self.sweep_failure is not None:
            raise self.sweep_failure

    def second_process(self) -> None:
        assert self.profile is not None
        second = self.spawn(self.profile)
        self.case.assertNotEqual(second.pid, self.processes[0].pid)
        self.case.assertIsNone(self.processes[0].poll())
        if sys.platform != "win32":
            self.case.assertEqual(os.getpgid(second.pid), second.pid)
            self.case.assertNotEqual(os.getpgid(second.pid), self.processes[0].pid)

    def snapshot(self) -> tuple[tuple[bool, ...], bool]:
        # Retained peer sockets stay open until after these finite observations.
        ended = []
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ended.append(False)
            else:
                ended.append(True)

        assert self.profile is not None
        return tuple(ended), not self.profile.exists()

    def backup(self) -> None:
        errors = []
        for process in self.processes:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            except BaseException as error:
                errors.append(error)

        for peer in self.peers:
            try:
                peer.close()
            except BaseException as error:
                errors.append(error)
        if self.listener is not None:
            try:
                self.listener.close()
            except BaseException as error:
                errors.append(error)

        if self.profile is not None:
            try:
                target = self.profile.resolve()
                parent = Path(tempfile.gettempdir()).resolve()
                if target.parent != parent or not target.name.startswith(
                    "phantom-capture-profile-"
                ):
                    raise ValueError("launcher backup profile is outside its target")

                if target.exists():
                    shutil.rmtree(target)
            except BaseException as error:
                errors.append(error)

        try:
            self.patches.close()
        except BaseException as error:
            errors.append(error)
        if errors:
            raise BackupFailures(tuple(errors))


class BrowserLaunchLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = LaunchContext(self)
        self.addCleanup(self.context.backup)
        self.context.prepare()

    def test_healthy_exit_sweeps_the_independent_profile_process(self) -> None:
        context = self.context
        with context.browser:
            context.second_process()

        ended, removed = context.snapshot()
        self.assertEqual(context.checkpoints, 1)
        self.assertEqual(context.tree_attempts, 1)
        self.assertEqual(context.sweep_attempts, 1)
        self.assertEqual(ended, (True, True))
        self.assertTrue(removed)

    def test_failed_checkpoint_retains_its_error_after_healthy_cleanup(self) -> None:
        context = self.context
        primary = StartupFailure("controlled Firefox checkpoint failure")
        context.start_failure = primary
        with self.assertRaises(StartupFailure) as observed:
            context.browser.__enter__()

        ended, removed = context.snapshot()
        self.assertEqual(context.checkpoints, 1)
        self.assertEqual(ended, (True,))
        self.assertTrue(removed)
        self.assertIs(observed.exception, primary)

    def test_failed_checkpoint_retains_error_and_tree_cleanup_failure(self) -> None:
        context = self.context
        primary = StartupFailure("controlled Firefox checkpoint failure")
        secondary = TreeFailure("controlled completed tree cleanup failure")
        context.start_failure = primary
        context.tree_failure = secondary
        observed = None
        try:
            context.browser.__enter__()
        except BaseException as error:
            observed = error

        ended, removed = context.snapshot()
        self.assertEqual(context.checkpoints, 1)
        self.assertEqual(context.tree_attempts, 1)
        self.assertEqual(ended, (True,))
        self.assertTrue(
            removed, "tree cleanup failure skipped acquired profile removal"
        )
        self.assertIs(getattr(observed, "primary", None), primary)
        self.assertEqual(getattr(observed, "cleanup", None), (secondary,))

    def test_body_failure_and_tree_failure_still_sweep_the_profile(self) -> None:
        context = self.context
        primary = BodyFailure("controlled browser caller failure")
        secondary = TreeFailure("controlled completed tree cleanup failure")
        context.tree_failure = secondary
        observed = None
        try:
            with context.browser:
                context.second_process()
                raise primary
        except BaseException as error:
            observed = error

        ended, removed = context.snapshot()
        self.assertEqual(context.checkpoints, 1)
        self.assertEqual(context.tree_attempts, 1)
        self.assertEqual(
            ended, (True, True), "tree failure skipped the live profile process"
        )
        self.assertTrue(removed)
        self.assertEqual(context.sweep_attempts, 1)
        self.assertIs(getattr(observed, "primary", None), primary)
        self.assertEqual(getattr(observed, "cleanup", None), (secondary,))

    def test_body_failure_retains_both_ordered_cleanup_failures(self) -> None:
        context = self.context
        primary = BodyFailure("controlled browser caller failure")
        tree = TreeFailure("controlled completed tree cleanup failure")
        sweep = SweepFailure("controlled completed profile sweep failure")
        context.tree_failure = tree
        context.sweep_failure = sweep
        observed = None
        try:
            with context.browser:
                context.second_process()
                raise primary
        except BaseException as error:
            observed = error

        ended, removed = context.snapshot()
        self.assertEqual(context.checkpoints, 1)
        self.assertEqual(context.tree_attempts, 1)
        self.assertEqual(
            ended, (True, True), "tree failure skipped the live profile process"
        )
        self.assertTrue(removed)
        self.assertEqual(context.sweep_attempts, 1)
        self.assertIs(getattr(observed, "primary", None), primary)
        self.assertEqual(getattr(observed, "cleanup", None), (tree, sweep))

    def test_sweep_failure_still_removes_the_profile_and_keeps_its_cause(self) -> None:
        context = self.context
        secondary = SweepFailure("controlled completed profile sweep failure")
        context.sweep_failure = secondary
        with self.assertRaises(SweepFailure) as observed, context.browser:
            context.second_process()

        ended, removed = context.snapshot()
        self.assertEqual(context.checkpoints, 1)
        self.assertEqual(context.tree_attempts, 1)
        self.assertEqual(context.sweep_attempts, 1)
        self.assertEqual(ended, (True, True))
        self.assertTrue(removed)
        self.assertIs(observed.exception, secondary)

    def test_startup_cancellation_keeps_identity_and_finishes_profile_cleanup(
        self,
    ) -> None:
        context = self.context
        primary = asyncio.CancelledError("controlled Firefox checkpoint cancellation")
        secondary = TreeFailure("controlled completed tree cleanup failure")
        context.start_failure = primary
        context.tree_failure = secondary
        observed = None
        try:
            context.browser.__enter__()
        except BaseException as error:
            observed = error

        ended, removed = context.snapshot()
        self.assertEqual(context.checkpoints, 1)
        self.assertEqual(context.tree_attempts, 1)
        self.assertEqual(ended, (True,))
        self.assertTrue(
            removed, "cancel cleanup failure skipped acquired profile removal"
        )
        self.assertIs(observed, primary)
        self.assertIs(getattr(observed.__cause__, "primary", None), primary)
        self.assertEqual(getattr(observed.__cause__, "cleanup", None), (secondary,))
