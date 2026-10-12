"""Hold a capture attempt's process tree so it can be stopped as one.

On Windows a trusted bootstrap waits for release inside a kill-on-close Job
Object before starting the capture interpreter. Ordinary children inherit
that job, so runner exit also ends them. On other systems the tool leads a
new process group. browser_launch.py starts browsers in groups of their own,
so a stop also ends
every process whose command line names the attempt's temporary directory.
"""

from __future__ import annotations

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


class ProcessCleanupError(RuntimeError):
    """Keep each failed operation and the container that can retry cleanup."""

    def __init__(
        self,
        failures: Sequence[tuple[str, BaseException]],
        *,
        container: ProcessContainer | None = None,
        primary: BaseException | None = None,
    ) -> None:
        self.failures = tuple(failures)
        self.container = container
        self.primary = primary
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        super().__init__(
            "process cleanup failed: "
            + "; ".join(f"{operation}: {error}" for operation, error in failures)
        )


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
    # A Windows venv executable redirects to a child before Python code runs.
    # Attach the actual interpreter instead; keep the tool's command intact.
    executable = _windows_interpreter() if sys.platform == "win32" else sys.executable
    return [executable, "-I", "-S", "-c", _BOOTSTRAP, *command]


def _windows_interpreter() -> str:
    """Find this CPython process's executable, without a venv redirector."""
    import ctypes
    from ctypes import wintypes

    if sys.implementation.name != "cpython":
        raise OSError("Windows capture ownership requires CPython")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleFileNameW.argtypes = (
        wintypes.HMODULE,
        wintypes.LPWSTR,
        wintypes.DWORD,
    )
    kernel32.GetModuleFileNameW.restype = wintypes.DWORD
    path = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetModuleFileNameW(None, path, len(path))
    if not length or length >= len(path):
        raise ctypes.WinError(ctypes.get_last_error())
    return path.value


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
        self._cleanup_complete = False
        self._group_stopped = False
        self._gate: BinaryIO | None = None
        self._native_handles: list[int] = []
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
            except BaseException as error:
                self._native_handles = getattr(error, "pending_handles", [])
                error.container = self
                try:
                    self.close()
                except BaseException as cleanup:
                    raise error from ProcessCleanupError(
                        (("close after assignment failure", cleanup),),
                        container=self,
                        primary=error,
                    )
                raise
        # The assigned job or POSIX group, not a claim about external brokers.
        # Retained after close for reporting.
        self.contained = True

    def start(self) -> bool:
        """Release the assigned tool once; a closed container cannot start."""
        with self._lock:
            try:
                if self._closed:
                    return False
                if self._started:
                    return True
                gate = self._gate
                if gate is not None:
                    if gate.write(b"G") != 1:
                        raise OSError("the capture gate was not released")
                    gate.flush()
                    gate.close()
                    self._gate = None
                self._started = True
                return True
            except BaseException as error:
                error.container = self
                try:
                    self._close_locked()
                except BaseException as cleanup:
                    raise error from ProcessCleanupError(
                        (("close after release failure", cleanup),),
                        container=self,
                        primary=error,
                    )
                raise

    def close(self) -> None:
        """Stop the container, retaining failed owners for another close.

        Cleanup is serialized and waits at most twenty seconds for the process.
        Successful closure makes later calls harmless.
        """
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._cleanup_complete:
            return
        self._closed = True
        failures = []
        if self._gate is not None:
            try:
                self._gate.close()
            except BaseException as error:
                failures.append(("close launch gate", error))
            else:
                self._gate = None

        if sys.platform == "win32":
            if self.job is not None:
                try:
                    _windows_close_job(self.job)
                except BaseException as error:
                    failures.append(("close capture job", error))
                else:
                    self.job = None
            else:
                try:
                    # With no job handle left, stop the original Popen process.
                    if self.process.poll() is None:
                        self.process.kill()
                except BaseException as error:
                    failures.append(("stop bootstrap process", error))
            for handle in self._native_handles[:]:
                try:
                    _windows_close_handle(handle)
                except BaseException as error:
                    failures.append(("close temporary native handle", error))
                else:
                    self._native_handles.remove(handle)
        elif not self._group_stopped:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                self._group_stopped = True
            except BaseException as error:
                failures.append(("kill process group", error))
            else:
                self._group_stopped = True

        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired as error:
            failures.append(("wait for process", error))
            try:
                self.process.kill()
            except BaseException as error:
                failures.append(("kill process after timeout", error))
            try:
                self.process.wait(timeout=10)
            except BaseException as error:
                failures.append(("wait after process kill", error))
        except BaseException as error:
            failures.append(("wait for process", error))
        if failures:
            interruption = next(
                (
                    error
                    for _operation, error in failures
                    if not isinstance(error, Exception)
                ),
                None,
            )
            failure = ProcessCleanupError(
                failures, container=self, primary=interruption
            )
            if interruption is not None:
                raise interruption from failure
            raise failure from failures[0][1]
        self._cleanup_complete = True


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
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _windows_job(pid: int) -> int:
    """Create a kill-on-close job holding `pid`, or raise the native failure.

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

    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    kernel32 = _kernel32()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    process = None
    try:
        if not kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        process = kernel32.OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid
        )
        if not process or not kernel32.AssignProcessToJobObject(job, process):
            raise ctypes.WinError(ctypes.get_last_error())
        _windows_close_handle(process, kernel32)
        process = None
    except BaseException as error:
        failures = []
        pending = []
        for operation, handle in (
            ("close process handle", process),
            ("close job", job),
        ):
            if not handle:
                continue
            try:
                _windows_close_handle(handle, kernel32)
            except BaseException as cleanup:
                failures.append((operation, cleanup))
                pending.append(handle)
        error.pending_handles = pending
        if failures:
            cleanup = ProcessCleanupError(failures, primary=error)
            error.cleanup_error = cleanup
            raise error from cleanup
        raise
    return job


def _windows_close_job(job: int) -> None:
    # This unnamed, non-inherited handle is the job's last handle. Its
    # KILL_ON_JOB_CLOSE limit ends descendants without a second termination.
    _windows_close_handle(job)


def _windows_close_handle(handle: int, kernel32=None) -> None:
    import ctypes

    kernel32 = kernel32 if kernel32 is not None else _kernel32()
    if not kernel32.CloseHandle(handle):
        raise ctypes.WinError(ctypes.get_last_error())
