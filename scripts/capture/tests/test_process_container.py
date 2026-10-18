import contextlib
import ctypes
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from ctypes import wintypes
from pathlib import Path
from unittest import mock

from scripts.capture import process_container
from scripts.capture.process_container import ProcessContainer, _bootstrap_command


def wait_for_file(path: Path) -> str:
    deadline = time.monotonic() + 30
    while True:
        try:
            return path.read_text()
        except (FileNotFoundError, PermissionError) as error:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "owned process did not publish a readable checkpoint"
                ) from error
            time.sleep(0.01)


class OwnedWindowsProcess:
    """Keep PID identity stable and clean only the test's held process handle."""

    def __init__(self, pid: int) -> None:
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.IsProcessInJob.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        )
        self.kernel.IsProcessInJob.restype = wintypes.BOOL
        self.kernel.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self.kernel.TerminateProcess.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.OpenProcess(0x1000 | 0x100000 | 1, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def in_job(self, job: int) -> bool:
        member = wintypes.BOOL()
        if not self.kernel.IsProcessInJob(self.handle, job, ctypes.byref(member)):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(member.value)

    def ended(self) -> bool:
        return self.kernel.WaitForSingleObject(self.handle, 30_000) == 0

    def ended_now(self) -> bool:
        return self.kernel.WaitForSingleObject(self.handle, 0) == 0

    def close(self) -> None:
        try:
            if self.kernel.WaitForSingleObject(self.handle, 0) == 258:
                if not self.kernel.TerminateProcess(self.handle, 1):
                    raise ctypes.WinError(ctypes.get_last_error())
                if not self.ended():
                    raise AssertionError("owned process did not stop")
        finally:
            self.kernel.CloseHandle(self.handle)


class ProcessContainerTests(unittest.TestCase):
    def test_checkpoint_waits_until_the_published_file_is_readable(self) -> None:
        path = mock.Mock()
        path.read_text.side_effect = [FileNotFoundError(), PermissionError(), "[1, 2]"]
        with mock.patch.object(time, "sleep"):
            self.assertEqual(wait_for_file(path), "[1, 2]")

    def test_release_failure_retains_failed_owners_and_original_causes(self) -> None:
        process = mock.Mock()
        process.poll.return_value = 0
        primary = OSError("gate write failed")
        gate_error = OSError("gate close failed")
        job_error = OSError("job close failed")
        process.stdin.write.side_effect = primary
        process.stdin.close.side_effect = [gate_error, None]
        with (
            mock.patch.object(process_container.sys, "platform", "win32"),
            mock.patch.object(
                process_container, "_bootstrap_command", return_value=["tool"]
            ),
            mock.patch.object(
                process_container.subprocess, "Popen", return_value=process
            ),
            mock.patch.object(process_container, "_windows_job", return_value=41),
            mock.patch.object(process_container, "_windows_stop_admission"),
            mock.patch.object(
                process_container, "_windows_process_ids", return_value=()
            ),
            mock.patch.object(process_container, "_windows_terminate_job"),
            mock.patch.object(
                process_container,
                "_windows_close_job",
                side_effect=[job_error, None],
            ) as close_job,
        ):
            container = ProcessContainer(["tool"])
            with self.assertRaises(OSError) as raised:
                container.start()

            self.assertIs(raised.exception, primary)
            cleanup = primary.__cause__.failures[0][1]
            self.assertEqual(
                [error for _operation, error in cleanup.failures],
                [gate_error, job_error],
            )
            self.assertIs(primary.container, container)
            self.assertIs(container._gate, process.stdin)
            self.assertEqual(container.job, 41)
            process.wait.assert_called_once_with(timeout=10)

            container.close()
            container.close()
            self.assertIsNone(container._gate)
            self.assertIsNone(container.job)
            self.assertFalse(container.start())
            self.assertEqual(close_job.call_args_list, [mock.call(41), mock.call(41)])
            self.assertEqual(process.stdin.close.call_count, 2)

    @unittest.skipUnless(sys.platform == "win32", "Windows native error conversion")
    def test_native_assignment_failure_retains_errno_and_unclosed_handles(self) -> None:
        kernel = mock.Mock()
        kernel.CreateJobObjectW.return_value = 41
        kernel.SetInformationJobObject.return_value = True
        kernel.OpenProcess.return_value = 51
        kernel.AssignProcessToJobObject.return_value = False
        kernel.CloseHandle.return_value = False
        process = mock.Mock()
        process.poll.return_value = 0
        with (
            mock.patch.object(process_container, "_kernel32", return_value=kernel),
            mock.patch.object(ctypes, "get_last_error", return_value=5),
            mock.patch.object(
                process_container, "_bootstrap_command", return_value=["tool"]
            ),
            mock.patch.object(
                process_container.subprocess, "Popen", return_value=process
            ),
            self.assertRaises(OSError) as raised,
        ):
            ProcessContainer(["tool"])

        self.assertEqual(raised.exception.winerror, 5)
        self.assertEqual(raised.exception.pending_handles, [51, 41])
        self.assertEqual(
            [
                error.winerror
                for _operation, error in raised.exception.cleanup_error.failures
            ],
            [5, 5],
        )
        self.assertEqual(
            kernel.CloseHandle.call_args_list,
            [mock.call(51), mock.call(41), mock.call(51), mock.call(41)],
        )
        owner = raised.exception.container
        self.assertIs(owner._native_handles, raised.exception.pending_handles)
        self.assertIs(
            raised.exception.__cause__.previous_cause,
            raised.exception.cleanup_error,
        )

        kernel.CloseHandle.return_value = True
        with mock.patch.object(process_container, "_kernel32", return_value=kernel):
            owner.close()
            owner.close()
        self.assertEqual(raised.exception.pending_handles, [])
        self.assertEqual(kernel.CloseHandle.call_count, 6)

    @unittest.skipIf(sys.platform == "win32", "POSIX process groups")
    def test_permission_failure_is_reported_and_can_be_retried(self) -> None:
        container = ProcessContainer([sys.executable, "-c", "pass"])
        denied = PermissionError("group termination denied")
        try:
            container.wait(timeout=30)
            with (
                mock.patch.object(os, "killpg", side_effect=denied),
                self.assertRaises(process_container.ProcessCleanupError) as raised,
            ):
                container.close()

            self.assertIs(raised.exception.failures[0][1], denied)
            self.assertIs(raised.exception.container, container)
            self.assertFalse(container._group_stopped)
            self.assertIsNone(container._process.returncode)
            self.assertIsNotNone(container._gate)
            self.assertFalse(container._gate.closed)
            self.assertFalse(container.start())
        finally:
            container.close()

    @unittest.skipIf(sys.platform == "win32", "POSIX custodian shutdown")
    def test_group_is_signalled_before_closing_its_control_pipe(self) -> None:
        container = ProcessContainer([sys.executable, "-c", "pass"])
        signal_group = os.killpg

        def signal_with_live_gate(pid: int, signum: int) -> None:
            self.assertIsNotNone(container._gate)
            self.assertFalse(container._gate.closed)
            self.assertIsNone(container._process.returncode)
            signal_group(pid, signum)

        try:
            container.start()
            container.wait(timeout=30)
            with mock.patch.object(os, "killpg", side_effect=signal_with_live_gate):
                container.close()
            self.assertIsNone(container._gate)
        finally:
            container.close()

    @unittest.skipUnless(sys.platform == "win32", "Windows native handle identity")
    def test_invalid_job_handle_is_reported_without_retrying_its_number(self) -> None:
        process = mock.Mock()
        process.poll.return_value = 0
        kernel = mock.Mock()
        kernel.CloseHandle.return_value = False
        with (
            mock.patch.object(process_container, "_kernel32", return_value=kernel),
            mock.patch.object(ctypes, "get_last_error", return_value=6),
            mock.patch.object(
                process_container, "_bootstrap_command", return_value=["tool"]
            ),
            mock.patch.object(
                process_container.subprocess, "Popen", return_value=process
            ),
            mock.patch.object(process_container, "_windows_job", return_value=41),
        ):
            container = ProcessContainer(["tool"])
            with self.assertRaises(process_container.ProcessCleanupError) as raised:
                container.close()
            original = raised.exception.failures[0][1]

            self.assertEqual(original.winerror, 6)
            self.assertIsNone(container.job)
            with self.assertRaises(process_container.ProcessCleanupError) as repeated:
                container.close()
            self.assertIs(repeated.exception.failures[0][1], original)
            kernel.CloseHandle.assert_called_once_with(41)
            self.assertFalse(container._cleanup_complete)

    @unittest.skipIf(sys.platform == "win32", "POSIX process group identity")
    def test_parent_eof_ends_custodian_and_reaped_group_is_never_signalled(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "tool-started"
            container = ProcessContainer(
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys,time; "
                    "Path(sys.argv[1]).write_text('started'); time.sleep(60)",
                    str(marker),
                ]
            )
            try:
                wait_for_file(marker)
                container._gate.close()
                container._gate = None
                # Deliberately violate private ownership after observing EOF.
                # This must leave a reported loss, never a numeric PGID retry.
                self.assertEqual(container._process.wait(timeout=30), -signal.SIGKILL)
                with mock.patch.object(os, "killpg") as kill_group:
                    with self.assertRaises(process_container.ProcessCleanupError):
                        container.close()
                    with self.assertRaises(process_container.ProcessCleanupError):
                        container.close()
                    kill_group.assert_not_called()
            finally:
                if container._process.returncode is not None:
                    with self.assertRaises(process_container.ProcessCleanupError):
                        container.close()
                else:
                    container.close()
            self.assertTrue(container._group_lost)
            self.assertFalse(container._cleanup_complete)

    @unittest.skipIf(sys.platform == "win32", "POSIX custodian launch")
    def test_tool_launch_failure_keeps_errno_and_unreaped_group_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "missing-tool")
            container = ProcessContainer([missing])
            try:
                with self.assertRaises(FileNotFoundError) as raised:
                    container.wait(timeout=10)

                self.assertEqual(raised.exception.errno, 2)
                self.assertEqual(raised.exception.filename, missing)
                self.assertIs(raised.exception.container, container)
                self.assertIsNone(container._process.returncode)
            finally:
                container.close()

    def test_containment_is_still_reported_after_close(self) -> None:
        container = ProcessContainer(
            [sys.executable, "-c", "import time; time.sleep(60)"]
        )
        try:
            container.start()
            self.assertTrue(container.contained)
        finally:
            container.close()

        self.assertTrue(container.contained)
        with self.assertRaises(process_container.ProcessContainerStopped):
            container.poll()
        self.assertFalse(container.start())

    def test_close_is_safe_after_the_process_exits(self) -> None:
        container = ProcessContainer([sys.executable, "-c", "pass"])
        container.start()
        container.wait(timeout=30)
        container.close()
        container.close()

        self.assertEqual(container.poll(), 0)

    def test_eof_or_wrong_gate_byte_never_starts_the_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "started"
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text('started')",
                str(marker),
            ]
            for token in [b"", b"X"]:
                with self.subTest(token=token):
                    with subprocess.Popen(
                        _bootstrap_command(command), stdin=subprocess.PIPE
                    ) as process:
                        process.communicate(token, timeout=30)
                        self.assertEqual(process.returncode, 125)
                    self.assertFalse(marker.exists())

    def test_the_original_tool_keeps_arguments_environment_and_exit_status(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            command = [
                sys.executable,
                "-c",
                "import json,os,sys; from pathlib import Path; "
                "Path(sys.argv[1]).write_text(json.dumps([sys.argv[2:],os.environ['PHANTOM_TEST_VALUE'],sys.executable,sys.prefix])); "
                "raise SystemExit(7)",
                str(output),
                "a b",
                "apostrophe's",
                "tail\\",
            ]
            container = ProcessContainer(
                command, env={**os.environ, "PHANTOM_TEST_VALUE": "retained"}
            )
            try:
                container.start()
                self.assertEqual(container.wait(timeout=30), 7)
                self.assertEqual(
                    json.loads(output.read_text()),
                    [
                        ["a b", "apostrophe's", "tail\\"],
                        "retained",
                        sys.executable,
                        sys.prefix,
                    ],
                )
            finally:
                container.close()

    @unittest.skipUnless(sys.platform == "win32", "Windows job boundary")
    def test_bootstrap_interpreter_is_assigned_after_it_reaches_the_gate(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.ExitStack() as cleanup,
        ):
            marker = Path(directory) / "bootstrap.pid"
            # Force the isolated interpreter to exist before assignment. A
            # venv redirector must not be mistaken for that interpreter.
            checkpoint = (
                "import os\n"
                f"with open({str(marker) + '.partial'!r}, 'w') as file: file.write(str(os.getpid()))\n"
                f"os.replace({str(marker) + '.partial'!r}, {str(marker)!r})\n"
            )
            assign = process_container._windows_job

            def after_checkpoint(pid: int):
                wait_for_file(marker)
                return assign(pid)

            with (
                mock.patch.object(
                    process_container,
                    "_BOOTSTRAP",
                    checkpoint + process_container._BOOTSTRAP,
                ),
                mock.patch.object(process_container, "_windows_job", after_checkpoint),
            ):
                container = ProcessContainer([sys.executable, "-c", "pass"])
            cleanup.callback(container.close)
            bootstrap_pid = int(wait_for_file(marker))
            bootstrap = OwnedWindowsProcess(bootstrap_pid)
            cleanup.callback(bootstrap.close)
            self.assertTrue(bootstrap.in_job(container.job))
            self.assertEqual(bootstrap_pid, container.pid)
            container.start()
            self.assertEqual(container.wait(timeout=30), 0)

    @unittest.skipUnless(sys.platform == "win32", "Windows job boundary")
    def test_site_code_and_tool_wait_until_assignment_and_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            site_marker, tool_marker = root / "site-started", root / "tool-started"
            (root / "sitecustomize.py").write_text(
                f"from pathlib import Path; Path({str(site_marker)!r}).write_text('site')"
            )
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text(str(sys.flags.no_site))",
                str(tool_marker),
            ]
            assign = process_container._windows_job

            def delayed_assignment(pid: int):
                self.assertFalse(site_marker.exists())
                self.assertFalse(tool_marker.exists())
                return assign(pid)

            with mock.patch.object(
                process_container, "_windows_job", delayed_assignment
            ):
                container = ProcessContainer(
                    command, env={**os.environ, "PYTHONPATH": str(root)}
                )
            try:
                self.assertFalse(site_marker.exists())
                self.assertFalse(tool_marker.exists())
                container.start()
                self.assertEqual(container.wait(timeout=30), 0)
                self.assertEqual(site_marker.read_text(), "site")
                self.assertEqual(tool_marker.read_text(), "0")
            finally:
                container.close()

    @unittest.skipUnless(sys.platform == "win32", "Windows job boundary")
    def test_job_refusal_fails_before_the_tool_runs_and_reaps_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "started"
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text('started')",
                str(marker),
            ]
            processes = []
            popen = subprocess.Popen

            def record(*args, **kwargs):
                process = popen(*args, **kwargs)
                processes.append(process)
                return process

            with (
                mock.patch.object(
                    process_container,
                    "_windows_job",
                    side_effect=OSError("Windows refused the capture job object"),
                ),
                mock.patch.object(subprocess, "Popen", record),
                self.assertRaisesRegex(OSError, "refused"),
            ):
                ProcessContainer(command)
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].poll())
            self.assertFalse(marker.exists())

    @unittest.skipUnless(sys.platform == "win32", "Windows DWORD exit status")
    def test_full_width_windows_exit_status_is_preserved(self) -> None:
        container = ProcessContainer(
            [sys.executable, "-c", "raise SystemExit(-1073741502)"]
        )
        try:
            container.start()
            self.assertEqual(container.wait(timeout=30), 0xC0000142)
        finally:
            container.close()

    @unittest.skipUnless(sys.platform == "win32", "Windows job boundary")
    def test_close_before_release_never_starts_the_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "started"
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text('started')",
                str(marker),
            ]
            container = ProcessContainer(command)
            container.close()
            self.assertFalse(container.start())
            self.assertFalse(marker.exists())

    @unittest.skipUnless(sys.platform == "win32", "Windows job boundary")
    def test_release_failure_closes_job_and_cannot_be_retried(self) -> None:
        container = ProcessContainer([sys.executable, "-c", "raise SystemExit(99)"])
        try:
            gate = container._gate
            container._gate = mock.Mock(wraps=gate)
            container._gate.write.side_effect = OSError("gate write failed")
            with self.assertRaisesRegex(OSError, "gate write failed"):
                container.start()
            self.assertIsNone(container.job)
            with self.assertRaises(process_container.ProcessContainerStopped):
                container.poll()
            self.assertFalse(container.start())
        finally:
            container.close()

    @unittest.skipUnless(sys.platform == "win32", "Windows job boundary")
    def test_tool_and_child_are_in_the_assigned_job_and_end_on_close(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.ExitStack() as cleanup,
        ):
            marker = Path(directory) / "pids.json"
            command = [
                sys.executable,
                "-c",
                "import json,os,subprocess,sys,time; from pathlib import Path; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                "Path(sys.argv[1]+'.partial').write_text(json.dumps([os.getpid(),child.pid])); "
                "os.replace(sys.argv[1]+'.partial',sys.argv[1]); time.sleep(60)",
                str(marker),
            ]
            container = ProcessContainer(command)
            cleanup.callback(container.close)
            container.start()
            checkpoint = wait_for_file(marker)
            processes = []
            for pid in json.loads(checkpoint):
                process = OwnedWindowsProcess(pid)
                processes.append(process)
                cleanup.callback(process.close)
                self.assertTrue(process.in_job(container.job))
            container.close()
            for process in processes:
                self.assertTrue(process.ended_now())
                self.assertTrue(process.ended())

    @unittest.skipUnless(sys.platform == "win32", "Windows member completion")
    def test_member_wait_failure_retains_original_handle_for_cleanup_retry(
        self,
    ) -> None:
        original_wait = process_container._windows_wait_process
        timeout = TimeoutError("original member wait timed out")
        observations = []

        def wait(handle, deadline):
            observations.append((handle, deadline))
            if len(observations) == 1:
                raise timeout
            original_wait(handle, deadline)

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "started"
            container = ProcessContainer(
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys,time; "
                    "pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(60)",
                    str(marker),
                ]
            )
            try:
                container.start()
                wait_for_file(marker)
                job = container.job
                with (
                    mock.patch.object(
                        process_container, "_windows_wait_process", side_effect=wait
                    ),
                    mock.patch.object(
                        process_container,
                        "_windows_process_ids",
                        wraps=process_container._windows_process_ids,
                    ) as collect,
                    mock.patch.object(
                        process_container,
                        "_windows_open_process",
                        wraps=process_container._windows_open_process,
                    ) as acquire,
                ):
                    with self.assertRaises(
                        process_container.ProcessCleanupError
                    ) as raised:
                        container.close()

                    self.assertIs(raised.exception.failures[0][1], timeout)
                    self.assertIs(raised.exception.container, container)
                    original_handle, deadline = observations[0]
                    self.assertEqual(container._windows_members, [original_handle])
                    self.assertEqual(container.job, job)
                    self.assertTrue(container._windows_snapshot_complete)
                    self.assertTrue(container._windows_terminated)
                    self.assertFalse(container._cleanup_complete)
                    self.assertTrue(all(value == deadline for _, value in observations))
                    acquisition_count = acquire.call_count

                    container.close()

                    self.assertEqual(observations[-1][0], original_handle)
                    collect.assert_called_once()
                    self.assertEqual(acquire.call_count, acquisition_count)
                    self.assertEqual(container._windows_members, [])
                    self.assertIsNone(container.job)
                    self.assertTrue(container._cleanup_complete)
                    self.assertIs(raised.exception.failures[0][1], timeout)
            finally:
                container.close()

    @unittest.skipUnless(sys.platform == "win32", "Windows member collection")
    def test_partial_member_collection_cannot_be_certified_by_later_empty_job(
        self,
    ) -> None:
        original_open = process_container._windows_open_process
        primary = PermissionError("original member handle acquisition denied")
        handles = []
        attempts = []

        def open_process(pid):
            attempts.append(pid)
            if len(attempts) == 2:
                raise primary
            handle = original_open(pid)
            handles.append(handle)
            return handle

        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.ExitStack() as cleanup,
        ):
            marker = Path(directory) / "started"
            container = ProcessContainer(
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys,time; "
                    "pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(60)",
                    str(marker),
                ]
            )
            try:
                container.start()
                wait_for_file(marker)
                # The injected collection failure deliberately loses a member.
                # Keep independent handles until every original process exits.
                original_members = []
                for pid in process_container._windows_process_ids(
                    container.job, time.monotonic() + 30
                ):
                    process = OwnedWindowsProcess(pid)
                    try:
                        self.assertTrue(process.in_job(container.job))
                    except BaseException:
                        process.kernel.CloseHandle(process.handle)
                        raise
                    original_members.append(process)
                    cleanup.callback(process.close)
                with (
                    mock.patch.object(
                        process_container,
                        "_windows_open_process",
                        side_effect=open_process,
                    ),
                    mock.patch.object(
                        process_container,
                        "_windows_wait_process",
                        wraps=process_container._windows_wait_process,
                    ) as observe,
                    mock.patch.object(
                        process_container,
                        "_windows_process_ids",
                        wraps=process_container._windows_process_ids,
                    ) as collect,
                    self.assertRaises(process_container.ProcessCleanupError) as raised,
                ):
                    container.close()

                self.assertIs(raised.exception.failures[0][1], primary)
                self.assertIs(container._windows_snapshot_error, primary)
                self.assertFalse(container._windows_snapshot_complete)
                self.assertEqual(len(handles), 1)
                self.assertEqual(observe.call_args_list[0].args[0], handles[0])
                self.assertEqual(container._windows_members, [])
                self.assertIsNone(container.job)
                self.assertFalse(container._cleanup_complete)
                collect.assert_called_once()

                with (
                    mock.patch.object(
                        process_container, "_windows_process_ids", return_value=()
                    ) as empty,
                    self.assertRaises(
                        process_container.ProcessCleanupError
                    ) as repeated,
                ):
                    container.close()

                self.assertIs(repeated.exception.failures[0][1], primary)
                self.assertFalse(container._cleanup_complete)
                empty.assert_not_called()
            finally:
                if container._windows_snapshot_error is None:
                    container.close()
                else:
                    with self.assertRaises(process_container.ProcessCleanupError):
                        container.close()
            for process in original_members:
                self.assertTrue(process.ended(), "original job member did not exit")

    @unittest.skipUnless(sys.platform == "win32", "Windows job boundary")
    def test_runner_death_before_assignment_exits_blocked_bootstrap(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.ExitStack() as cleanup,
        ):
            marker, tool_marker = (
                Path(directory) / "bootstrap.pid",
                Path(directory) / "tool-started",
            )
            source = "\n".join(
                [
                    "import os,sys,time",
                    "from pathlib import Path",
                    "from scripts.capture import process_container as pc",
                    "def assign(pid):",
                    "    Path(sys.argv[1]+'.partial').write_text(str(pid))",
                    "    os.replace(sys.argv[1]+'.partial',sys.argv[1])",
                    "    while True: time.sleep(1)",
                    "pc._windows_job=assign",
                    "pc.ProcessContainer([sys.executable,'-c',\"from pathlib import Path; import sys; Path(sys.argv[1]).write_text('started')\",sys.argv[2]])",
                ]
            )
            runner = subprocess.Popen(
                [sys.executable, "-c", source, str(marker), str(tool_marker)]
            )
            cleanup.callback(
                lambda: (
                    (runner.kill(), runner.wait(timeout=30))
                    if runner.poll() is None
                    else None
                )
            )
            bootstrap = OwnedWindowsProcess(int(wait_for_file(marker)))
            cleanup.callback(bootstrap.close)
            runner.kill()
            runner.wait(timeout=30)
            self.assertTrue(bootstrap.ended())
            self.assertFalse(tool_marker.exists())

    @unittest.skipUnless(sys.platform == "win32", "Windows job boundary")
    def test_runner_death_after_release_ends_tool_and_child(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.ExitStack() as cleanup,
        ):
            marker = Path(directory) / "pids.json"
            tool = (
                "import json,os,subprocess,sys,time; from pathlib import Path; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                "Path(sys.argv[1]+'.partial').write_text(json.dumps([os.getpid(),child.pid])); "
                "os.replace(sys.argv[1]+'.partial',sys.argv[1]); time.sleep(60)"
            )
            source = (
                "import sys,time; from scripts.capture.process_container import ProcessContainer; "
                f"container=ProcessContainer([sys.executable,'-c',{tool!r},sys.argv[1]]); "
                "container.start(); time.sleep(60)"
            )
            runner = subprocess.Popen([sys.executable, "-c", source, str(marker)])
            cleanup.callback(
                lambda: (
                    (runner.kill(), runner.wait(timeout=30))
                    if runner.poll() is None
                    else None
                )
            )
            checkpoint = wait_for_file(marker)
            processes = []
            for pid in json.loads(checkpoint):
                process = OwnedWindowsProcess(pid)
                processes.append(process)
                cleanup.callback(process.close)
            runner.kill()
            runner.wait(timeout=30)
            for process in processes:
                self.assertTrue(process.ended())


if __name__ == "__main__":
    unittest.main()
