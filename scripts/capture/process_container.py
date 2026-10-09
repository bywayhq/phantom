"""Hold a capture attempt's process tree so it can be stopped as one.

On Windows a trusted bootstrap waits for release inside a kill-on-close Job
Object before starting the capture interpreter. Ordinary children inherit
that job, so runner exit also ends them. On other systems the tool leads a
new process group. browser_launch.py starts browsers in groups of their own,
so a stop also ends
every process whose command line names the attempt's temporary directory.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import BinaryIO

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
PROCESS_SET_QUOTA = 0x0100
PROCESS_TERMINATE = 0x0001


# No site or capture imports execute before the gate. The normal child keeps
# the original interpreter's environment, site/venv setup and command line.
_BOOTSTRAP = """import sys
if sys.stdin.buffer.read(1) != b'G':
    raise SystemExit(125)
sys.stdin.close()
import subprocess
code = subprocess.call(sys.argv[1:], stdin=subprocess.DEVNULL)
# Preserve the full Windows DWORD exit status through Python's signed int.
raise SystemExit(code if code < (1 << 31) else code - (1 << 32))
"""


def _bootstrap_command(command: Sequence[str]) -> list[str]:
    return [sys.executable, "-I", "-S", "-c", _BOOTSTRAP, *command]


class ProcessContainer:
    """Own an attempt before releasing its tool with `start`.

    Windows job refusal fails before the tool runs. `close` also disposes of
    an unreleased bootstrap. POSIX starts in its own group immediately.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        stdout: BinaryIO | int | None = None,
        stderr: BinaryIO | int | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._started = False
        self._closed = False
        self._gate: BinaryIO | None = None
        self.job: int | None = None
        windows = sys.platform == "win32"
        self.process = subprocess.Popen(
            _bootstrap_command(command) if windows else list(command),
            stdin=subprocess.PIPE if windows else subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=env,
            close_fds=True,
            **({"bufsize": 0} if windows else {"start_new_session": True}),
        )
        if sys.platform == "win32":
            self._gate = self.process.stdin
            try:
                self.job = _windows_job(self.process.pid)
                if self.job is None:
                    raise OSError("Windows refused the capture job object")
            except BaseException:
                self.close()
                raise
        # The assigned job or POSIX group, not a claim about external brokers.
        # Retained after close for reporting.
        self.contained = True

    def start(self) -> bool:
        """Release the assigned tool once; a closed container cannot start."""
        try:
            with self._lock:
                if self._closed:
                    return False
                if self._started:
                    return True
                gate, self._gate = self._gate, None
                if gate is not None:
                    try:
                        if gate.write(b"G") != 1:
                            raise OSError("the capture gate was not released")
                        gate.flush()
                    finally:
                        gate.close()
                self._started = True
                return True
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        """End every process still in the container. Safe to call twice."""
        with self._lock:
            self._closed = True
            job, self.job = self.job, None
            gate, self._gate = self._gate, None
            if gate is not None:
                gate.close()
        if sys.platform == "win32":
            if job is not None:
                _windows_close_job(job)
            elif self.process.poll() is None:
                # Assignment failed: only the blocked bootstrap exists.
                self.process.kill()
        else:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.process.pid, signal.SIGKILL)
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)


def stop_processes_naming(directory: Path) -> None:
    """End processes whose command line names `directory`, such as browsers.

    The browser launcher's own sweep does the matching, so
    `directory` must appear as a whole path component: a person's browser
    whose profile path merely starts with the same text is left alone.
    """
    from .browser_launch import terminate_profile_processes

    terminate_profile_processes(directory)


def _kernel32():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _windows_job(pid: int) -> int | None:
    """Create a kill-on-close job holding `pid`, or None if Windows refuses.

    The caller keeps the bootstrap behind its gate until assignment succeeds.
    """
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = _kernel32()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    process = None
    try:
        if not kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise OSError(ctypes.get_last_error())
        process = kernel32.OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid
        )
        if not process or not kernel32.AssignProcessToJobObject(job, process):
            raise OSError(ctypes.get_last_error())
    except OSError:
        kernel32.CloseHandle(job)
        return None
    except BaseException:
        kernel32.CloseHandle(job)
        raise
    finally:
        if process:
            kernel32.CloseHandle(process)
    return job


def _windows_close_job(job: int) -> None:
    kernel32 = _kernel32()
    kernel32.TerminateJobObject(job, 1)
    kernel32.CloseHandle(job)
