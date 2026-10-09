import contextlib
import ctypes
import json
import os
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


def wait_for_file(path: Path) -> None:
    deadline = time.monotonic() + 30
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError("owned process did not publish its checkpoint")
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
        self.assertIsNotNone(container.process.poll())
        self.assertFalse(container.start())

    def test_close_is_safe_after_the_process_exits(self) -> None:
        container = ProcessContainer([sys.executable, "-c", "pass"])
        container.start()
        container.process.wait(timeout=30)
        container.close()
        container.close()

        self.assertEqual(container.process.returncode, 0)

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
                self.assertEqual(container.process.wait(timeout=30), 7)
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
                self.assertEqual(container.process.wait(timeout=30), 0)
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
                mock.patch.object(process_container, "_windows_job", return_value=None),
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
            self.assertEqual(container.process.wait(timeout=30), 0xC0000142)
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
            self.assertIsNotNone(container.process.poll())
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
            wait_for_file(marker)
            processes = []
            for pid in json.loads(marker.read_text()):
                process = OwnedWindowsProcess(pid)
                processes.append(process)
                cleanup.callback(process.close)
                self.assertTrue(process.in_job(container.job))
            container.close()
            for process in processes:
                self.assertTrue(process.ended())

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
            wait_for_file(marker)
            bootstrap = OwnedWindowsProcess(int(marker.read_text()))
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
            wait_for_file(marker)
            processes = []
            for pid in json.loads(marker.read_text()):
                process = OwnedWindowsProcess(pid)
                processes.append(process)
                cleanup.callback(process.close)
            runner.kill()
            runner.wait(timeout=30)
            for process in processes:
                self.assertTrue(process.ended())


if __name__ == "__main__":
    unittest.main()
