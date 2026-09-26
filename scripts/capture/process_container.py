"""Hold a capture attempt's process tree so it can be stopped as one.

On Windows each attempt's tool process joins a Job Object created with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Browsers the tool starts join the same
job, so closing the handle, or the runner exiting for any reason, ends every
process of the attempt. On other systems the tool leads a new process group;
browser_launch.py starts browsers in groups of their own, so a stop also ends
every process whose command line names the attempt's temporary directory.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
from pathlib import Path

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
PROCESS_SET_QUOTA = 0x0100
PROCESS_TERMINATE = 0x0001


def popen_options() -> dict[str, object]:
    """Extra `subprocess.Popen` arguments for a process to be contained."""
    if sys.platform == "win32":
        return {}
    return {"start_new_session": True}


class ProcessContainer:
    """The process tree of one attempt; `close` ends whatever still runs."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.job: int | None = None
        if sys.platform == "win32":
            self.job = _windows_job(process.pid)

    @property
    def contained(self) -> bool:
        """Whether every descendant is stopped with the container.

        False when Windows refused the Job Object; `close` then stops the
        process tree by parent and relies on the caller's profile sweep.
        """
        return sys.platform != "win32" or self.job is not None

    def close(self) -> None:
        """End every process still in the container. Safe to call twice."""
        if sys.platform == "win32":
            job, self.job = self.job, None
            if job is not None:
                _windows_close_job(job)
            elif self.process.poll() is None:
                subprocess.run(
                    ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
        else:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.process.pid, signal.SIGKILL)
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()


def stop_processes_naming(directory: Path) -> None:
    """End processes whose command line names `directory`, such as browsers.

    The browser launcher's own sweep does the matching, so outside Windows
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

    The tool is assigned just after it starts. It is a Python interpreter that
    imports its modules before it starts any browser, so no child exists yet.
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
    finally:
        if process:
            kernel32.CloseHandle(process)
    return job


def _windows_close_job(job: int) -> None:
    kernel32 = _kernel32()
    kernel32.TerminateJobObject(job, 1)
    kernel32.CloseHandle(job)
