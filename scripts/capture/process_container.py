"""Hold a capture attempt's process tree so it can be stopped as one.

On Windows a trusted bootstrap waits for release inside a kill-on-close Job
Object before starting the capture interpreter. Ordinary children inherit
that job, so runner exit also ends them. On POSIX a private group leader
stays owned after the tool exits and stops its group on parent EOF.
browser_launch.py starts browsers in groups of their own, so a stop also
ends every process naming the attempt's temporary directory.
"""

from __future__ import annotations

import math
import os
import signal
import subprocess
import sys
import threading
import time
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


class ProcessContainerStopped(RuntimeError):
    """The owner stopped before observing the tool's completion status."""

    def __init__(self, container: ProcessContainer) -> None:
        self.container = container
        super().__init__("capture stopped before its tool status was observed")


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


# Keep the session/group leader owned after the tool exits. Completion is
# reported separately, and parent EOF ends the whole group even during a tool.
_POSIX_BOOTSTRAP = """import os,select,signal,subprocess,sys
try:
    status_fd = int(sys.argv[1])
    try:
        tool = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL, close_fds=True)
    except OSError as error:
        record = b'E' + error.errno.to_bytes(4, 'big', signed=True)
    else:
        while True:
            if select.select([sys.stdin.fileno()], [], [], 0.02)[0]:
                raise SystemExit(125)
            code = tool.poll()
            if code is not None:
                record = b'X' + code.to_bytes(4, 'big', signed=True)
                break

    if os.write(status_fd, record) != 5:
        raise OSError('the capture status was not published')
    os.close(status_fd)
    sys.stdin.buffer.read(1)
finally:
    os.killpg(os.getpid(), signal.SIGKILL)
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
    an unreleased bootstrap. POSIX starts the tool immediately inside an owned
    group leader. Use `wait` and `poll` to observe the tool without reaping it.
    POSIX requires default SIGCHLD handling and sole child reaping ownership.
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
        self._group_lost = False
        self._lost_failures: list[tuple[str, BaseException]] = []
        self._gate: BinaryIO | None = None
        self._native_handles: list[int] = []
        self._status_reader: int | None = None
        self._status_writer: int | None = None
        self._status = bytearray()
        self._exit_code: int | None = None
        self._completion_error: BaseException | None = None
        self._close_error: BaseException | None = None
        self._command = list(command)
        if not self._command:
            raise ValueError("capture command must not be empty")
        self._process: subprocess.Popen | None = None
        self.job: int | None = None
        windows = sys.platform == "win32"
        try:
            if windows:
                launched = _bootstrap_command(command)
                options = {}
            else:
                # A default SIGCHLD disposition leaves the owned leader
                # waitable. Ignore/reaping handlers would release its PID.
                if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
                    raise OSError(
                        "capture ownership requires default SIGCHLD handling"
                    )
                self._status_reader, self._status_writer = os.pipe()
                os.set_blocking(self._status_reader, False)
                launched = [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    _POSIX_BOOTSTRAP,
                    str(self._status_writer),
                    *command,
                ]
                options = {
                    "start_new_session": True,
                    "pass_fds": (self._status_writer,),
                }
            self._process = subprocess.Popen(
                launched,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
                env=env,
                close_fds=True,
                bufsize=0,
                **options,
            )
            self._gate = self._process.stdin
            if windows:
                self.job = _windows_job(self._process.pid)
            else:
                self._close_status_pipe("_status_writer")
        except BaseException as error:
            self._native_handles = getattr(error, "pending_handles", [])
            self._lost_failures.extend(getattr(error, "lost_handles", ()))
            error.container = self
            try:
                self.close()
            except BaseException as cleanup:
                raise error from ProcessCleanupError(
                    (("close after construction failure", cleanup),),
                    container=self,
                    primary=error,
                )
            raise
        # The assigned job or POSIX group, not a claim about external brokers.
        # Retained after close for reporting.
        self.contained = True

    @property
    def pid(self) -> int:
        """The owned group leader or Windows bootstrap PID."""
        return self._process.pid

    def poll(self) -> int | None:
        """Observe the tool's exit without releasing its process-tree owner.

        A stop before completion raises `ProcessContainerStopped`.
        """
        with self._lock:
            return self._poll_locked()

    def wait(self, *, timeout: float) -> int:
        """Wait up to `timeout` seconds for the tool's original exit status."""
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("capture wait timeout must be finite and nonnegative")
        deadline = time.monotonic() + timeout
        while True:
            code = self.poll()
            if code is not None:
                return code
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self._command, timeout)
            time.sleep(min(0.02, remaining))

    def _poll_locked(self) -> int | None:
        if self._close_error is not None:
            raise self._close_error
        if self._completion_error is not None:
            raise self._completion_error
        if self._exit_code is not None:
            return self._exit_code
        if self._closed:
            raise ProcessContainerStopped(self)
        if sys.platform == "win32":
            self._exit_code = self._process.poll()
            return self._exit_code
        try:
            fragment = os.read(self._status_reader, 5 - len(self._status))
        except BlockingIOError:
            return None
        self._status.extend(fragment)
        if len(self._status) < 5:
            if fragment:
                return None
            error = OSError("capture group leader closed without a complete tool status")
        else:
            kind = self._status[:1]
            value = int.from_bytes(self._status[1:], "big", signed=True)
            if kind == b"X" and -signal.NSIG < value <= 255:
                self._exit_code = value
                return value
            if kind == b"E" and value > 0:
                error = OSError(value, os.strerror(value), self._command[0])
            else:
                error = OSError("capture group leader published an invalid tool status")
        error.container = self
        self._completion_error = error
        raise error

    def _close_status_pipe(self, attribute: str) -> None:
        descriptor = getattr(self, attribute)
        if descriptor is None:
            return
        try:
            os.close(descriptor)
        except BaseException as error:
            # A failed close can already have invalidated/reused the FD.
            self._lost_failures.append(("close completion pipe", error))
            raise
        finally:
            setattr(self, attribute, None)

    def start(self) -> bool:
        """Release the assigned tool once; a closed container cannot start."""
        with self._lock:
            try:
                if self._closed:
                    return False
                if self._started:
                    return True
                gate = self._gate if sys.platform == "win32" else None
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
        failures = list(self._lost_failures)
        if self._gate is not None:
            try:
                self._gate.close()
            except BaseException as error:
                failures.append(("close launch gate", error))
            else:
                self._gate = None

        if self._process is not None and sys.platform == "win32":
            if self.job is not None:
                try:
                    _windows_close_job(self.job)
                except BaseException as error:
                    failures.append(("close capture job", error))
                    if getattr(error, "winerror", None) == 6:
                        self.job = None
                        self._lost_failures.append(
                            ("capture job handle identity lost", error)
                        )
                else:
                    self.job = None
            else:
                try:
                    # With no job handle left, stop the original Popen process.
                    if self._process.poll() is None:
                        self._process.kill()
                except BaseException as error:
                    failures.append(("stop bootstrap process", error))
            for handle in self._native_handles[:]:
                try:
                    _windows_close_handle(handle)
                except BaseException as error:
                    failures.append(("close temporary native handle", error))
                    if getattr(error, "winerror", None) == 6:
                        self._native_handles.remove(handle)
                        self._lost_failures.append(
                            ("temporary handle identity lost", error)
                        )
                else:
                    self._native_handles.remove(handle)
        elif (
            self._process is not None
            and not self._group_stopped
            and not self._group_lost
        ):
            try:
                # The private custodian remains alive or unreaped until this
                # group operation succeeds. Never reap after a failed signal.
                if (
                    self._process.returncode is not None
                    or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
                ):
                    self._group_lost = True
                    raise OSError("capture group leader identity was released")
                os.killpg(self._process.pid, signal.SIGKILL)
            except ProcessLookupError:
                self._group_stopped = True
            except BaseException as error:
                failures.append(("kill process group", error))
                if self._group_lost:
                    self._lost_failures.append(("process group identity lost", error))
            else:
                self._group_stopped = True

        for attribute in ("_status_writer", "_status_reader"):
            try:
                self._close_status_pipe(attribute)
            except BaseException as error:
                failures.append(("close completion pipe", error))

        if self._process is not None and (
            sys.platform == "win32" or self._group_stopped
        ):
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                failures.append(("wait for process", error))
                try:
                    self._process.kill()
                except BaseException as error:
                    failures.append(("kill process after timeout", error))
                try:
                    self._process.wait(timeout=10)
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
                self._close_error = interruption
                raise interruption from failure
            self._close_error = failure
            raise failure from failures[0][1]
        self._close_error = None
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
    lost = []
    try:
        if not kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            if error.winerror == 6:
                lost.append(("configure job handle identity lost", error))
                job = None
            raise error
        process = kernel32.OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid
        )
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.AssignProcessToJobObject(job, process):
            error = ctypes.WinError(ctypes.get_last_error())
            if error.winerror == 6:
                # This call has two handle arguments; neither identity can
                # be trusted once it reports an invalid handle.
                lost.append(("assignment handle identities lost", error))
                process = job = None
            raise error
        try:
            _windows_close_handle(process, kernel32)
        except BaseException as error:
            if getattr(error, "winerror", None) == 6:
                lost.append(("process handle identity lost", error))
                process = None
            raise
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
                if getattr(cleanup, "winerror", None) == 6:
                    lost.append((operation + " identity lost", cleanup))
                else:
                    pending.append(handle)
        error.pending_handles = pending
        error.lost_handles = lost
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
