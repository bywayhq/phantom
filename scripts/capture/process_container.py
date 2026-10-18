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
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x0008
JOB_OBJECT_BASIC_PROCESS_ID_LIST_CLASS = 3
MAX_SHUTDOWN_MEMBERS = 4096
WINDOWS_CLEANUP_SECONDS = 20.0
WINDOWS_START_SECONDS = 10.0
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x100000
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


# This optional status pipe reports CreateProcess failure before start returns.
# The child cannot inherit the pipe, so a missing report is observable as EOF.
_CONFIRMED_BOOTSTRAP = """import sys
if sys.stdin.buffer.read(1) != b'G':
    raise SystemExit(125)
sys.stdin.close()
import os, subprocess
from multiprocessing.connection import PipeConnection
status = PipeConnection(int(sys.argv[1]), readable=False)
os.set_handle_inheritable(status.fileno(), False)
try:
    try:
        tool = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL, close_fds=True)
    except OSError as error:
        record = (b'E' + error.errno.to_bytes(4, 'big', signed=True)
                  + (error.winerror or 0).to_bytes(4, 'big'))
        status.send_bytes(record)
        raise SystemExit(125)
    else:
        status.send_bytes(b'G' + tool.pid.to_bytes(4, 'big'))
finally:
    status.close()
code = tool.wait()
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
        confirm_start: bool = False,
    ) -> None:
        self._lock = threading.Lock()
        self._started = False
        self._closed = False
        self._cleanup_complete = False
        self._group_stopped = False
        self._group_lost = False
        self._lost_failures: list[tuple[str, BaseException]] = []
        self._gate: BinaryIO | None = None
        self._launch_reader = None
        self._launch_writer = None
        self._tool_pid: int | None = None
        self._native_handles: list[int] = []
        self._windows_members: list[int] = []
        self._windows_snapshot_complete = False
        self._windows_snapshot_error: BaseException | None = None
        self._windows_terminated = False
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
                if confirm_start:
                    from multiprocessing import Pipe

                    self._launch_reader, self._launch_writer = Pipe(duplex=False)
                    writer = self._launch_writer.fileno()
                    os.set_handle_inheritable(writer, True)
                    startup = subprocess.STARTUPINFO()
                    startup.lpAttributeList = {"handle_list": [writer]}
                    options["startupinfo"] = startup
                    launched = [
                        *launched[:4],
                        _CONFIRMED_BOOTSTRAP,
                        str(writer),
                        *command,
                    ]
            else:
                # A default SIGCHLD disposition leaves the owned leader
                # waitable. Ignore/reaping handlers would release its PID.
                if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
                    raise OSError("capture ownership requires default SIGCHLD handling")
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
                self._close_launch_pipe("_launch_writer")
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

    @property
    def tool_pid(self) -> int | None:
        """The confirmed Windows tool PID, distinct from the owned bootstrap.

        Available only after an opt-in successful start. It is an observation,
        not a handle that can safely authorize later cleanup by PID.
        """
        with self._lock:
            return self._tool_pid

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
            error = OSError(
                "capture group leader closed without a complete tool status"
            )
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

    def _close_launch_pipe(self, attribute: str) -> None:
        connection = getattr(self, attribute)
        if connection is None:
            return
        try:
            connection.close()
        except BaseException as error:
            # Connection.close may already have released the handle on failure.
            self._lost_failures.append(("close launch status pipe", error))
            raise
        finally:
            setattr(self, attribute, None)

    def _confirm_launch(self) -> None:
        reader = self._launch_reader
        if reader is None:
            return
        try:
            if not reader.poll(WINDOWS_START_SECONDS):
                raise TimeoutError("capture tool launch acknowledgement timed out")
            record = reader.recv_bytes(9)
        except (EOFError, BrokenPipeError) as error:
            raise OSError(
                "capture tool launch acknowledgement was not published"
            ) from error
        self._close_launch_pipe("_launch_reader")
        if len(record) == 5 and record[:1] == b"G":
            pid = int.from_bytes(record[1:], "big")
            if pid:
                self._tool_pid = pid
                return
        if len(record) == 9 and record[:1] == b"E":
            error_number = int.from_bytes(record[1:5], "big", signed=True)
            windows_error = int.from_bytes(record[5:9], "big")
            if error_number > 0:
                raise OSError(
                    error_number,
                    os.strerror(error_number),
                    None,
                    windows_error or None,
                )
        raise OSError("capture tool launch acknowledgement was invalid")

    def start(self) -> bool:
        """Release the assigned tool once; a closed container cannot start.

        On Windows, confirm_start waits up to ten seconds for actual tool
        creation and restores its OSError. The default only releases the gate.
        POSIX startup and completion reporting are unchanged.
        """
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
                self._confirm_launch()
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

        Windows closes admission and waits up to twenty seconds for members
        whose original handles it collects before termination. A member already
        exiting and absent from that snapshot is outside this completion fence.
        POSIX waits at most twenty seconds for the owned process.
        Successful closure makes later calls harmless.
        """
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._cleanup_complete:
            return
        self._closed = True
        failures = list(self._lost_failures)
        deadline = (
            time.monotonic() + WINDOWS_CLEANUP_SECONDS
            if sys.platform == "win32"
            else None
        )
        if self._process is not None and sys.platform == "win32":
            # Keep an unreleased bootstrap blocked until its handle is held.
            self._collect_windows_job(failures, deadline)
        elif (
            self._process is not None
            and not self._group_stopped
            and not self._group_lost
        ):
            try:
                # Keep the control pipe open until the parent signals the
                # owned group. EOF lets the custodian kill itself first;
                # signalling its zombie-only group can fail on macOS.
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

        if self._gate is not None and (sys.platform == "win32" or self._group_stopped):
            try:
                self._gate.close()
            except BaseException as error:
                failures.append(("close launch gate", error))
            else:
                self._gate = None

        if self._process is not None and sys.platform == "win32":
            self._close_windows_job(failures, deadline)
            if self.job is None:
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
        for attribute in ("_launch_writer", "_launch_reader"):
            try:
                self._close_launch_pipe(attribute)
            except BaseException as error:
                failures.append(("close launch status pipe", error))

        if sys.platform == "win32" or self._group_stopped or self._process is None:
            for attribute in ("_status_writer", "_status_reader"):
                try:
                    self._close_status_pipe(attribute)
                except BaseException as error:
                    failures.append(("close completion pipe", error))

        if self._process is not None and (
            sys.platform == "win32" or self._group_stopped
        ):
            try:
                timeout = (
                    10
                    if deadline is None
                    else min(10, max(0, deadline - time.monotonic()))
                )
                self._process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                failures.append(("wait for process", error))
                try:
                    self._process.kill()
                except BaseException as error:
                    failures.append(("kill process after timeout", error))
                try:
                    timeout = (
                        10
                        if deadline is None
                        else min(10, max(0, deadline - time.monotonic()))
                    )
                    self._process.wait(timeout=timeout)
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

    def _collect_windows_job(
        self, failures: list[tuple[str, BaseException]], deadline: float
    ) -> None:
        if (
            self.job is not None
            and not self._windows_snapshot_complete
            and self._windows_snapshot_error is None
        ):
            try:
                _windows_stop_admission(self.job)
                for pid in _windows_process_ids(self.job, deadline):
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            "capture job collection exceeded cleanup deadline"
                        )
                    try:
                        handle = _windows_open_process(pid)
                    except OSError as error:
                        # A snapshot member may exit before OpenProcess. Only a
                        # fresh query of this owned job can establish absence.
                        if getattr(
                            error, "winerror", None
                        ) == 87 and pid not in _windows_process_ids(self.job, deadline):
                            continue
                        raise
                    self._native_handles.append(handle)
                    try:
                        member = _windows_in_job(handle, self.job)
                    except BaseException as error:
                        if getattr(error, "winerror", None) == 6:
                            # Either argument may be invalid; retire both numbers.
                            self._native_handles.remove(handle)
                            self.job = None
                        raise
                    if not member:
                        raise OSError(
                            "capture process identity changed before collection"
                        )
                    self._native_handles.remove(handle)
                    self._windows_members.append(handle)
                self._windows_snapshot_complete = True
            except BaseException as error:
                self._windows_snapshot_error = error
                failures.append(("collect capture job members", error))
                self._lost_failures.append(("capture job snapshot incomplete", error))
                if getattr(error, "lost_job", False):
                    self.job = None

    def _close_windows_job(
        self, failures: list[tuple[str, BaseException]], deadline: float
    ) -> None:
        if self.job is not None and not self._windows_terminated:
            try:
                _windows_terminate_job(self.job)
            except BaseException as error:
                failures.append(("terminate capture job", error))
                if getattr(error, "winerror", None) == 6:
                    self.job = None
                    self._lost_failures.append(
                        ("capture job handle identity lost", error)
                    )
            else:
                self._windows_terminated = True

        # These handles survive termination removing members from the job list.
        for handle in self._windows_members[:]:
            try:
                _windows_wait_process(handle, deadline)
                _windows_close_handle(handle)
            except BaseException as error:
                failures.append(("observe capture job member", error))
                if getattr(error, "winerror", None) == 6:
                    self._windows_members.remove(handle)
                    self._lost_failures.append(
                        ("capture member handle identity lost", error)
                    )
            else:
                self._windows_members.remove(handle)

        if (
            self.job is not None
            and self._windows_terminated
            and not self._windows_members
        ):
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
    kernel32.QueryInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.IsProcessInJob.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    )
    kernel32.IsProcessInJob.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _windows_extended_limits():
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

    return ExtendedLimits()


def _windows_job(pid: int) -> int:
    """Create a kill-on-close job holding `pid`, or raise the native failure.

    The caller keeps the bootstrap behind its gate until assignment succeeds.
    """
    import ctypes

    limits = _windows_extended_limits()
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
    # Keep kill-on-close as the runner-death backup. Normal close first waits
    # the original handles collected while those members were still associated.
    _windows_close_handle(job)


def _windows_stop_admission(job: int) -> None:
    import ctypes

    kernel32 = _kernel32()
    limits = _windows_extended_limits()
    if not kernel32.QueryInformationJobObject(
        job,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
        None,
    ):
        error = ctypes.WinError(ctypes.get_last_error())
        error.lost_job = error.winerror == 6
        raise error

    limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    limits.BasicLimitInformation.ActiveProcessLimit = 0
    if not kernel32.SetInformationJobObject(
        job,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        error = ctypes.WinError(ctypes.get_last_error())
        error.lost_job = error.winerror == 6
        raise error


def _windows_process_ids(job: int, deadline: float) -> tuple[int, ...]:
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
    capacity = 32
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("capture job enumeration exceeded cleanup deadline")

        class ProcessIds(ctypes.Structure):
            _fields_ = [
                ("assigned", wintypes.DWORD),
                ("listed", wintypes.DWORD),
                ("ids", ctypes.c_size_t * capacity),
            ]

        information = ProcessIds()
        succeeded = kernel32.QueryInformationJobObject(
            job,
            JOB_OBJECT_BASIC_PROCESS_ID_LIST_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
            None,
        )
        error_code = ctypes.get_last_error() if not succeeded else 0
        if not succeeded and error_code != 234:
            error = ctypes.WinError(error_code)
            error.lost_job = error.winerror == 6
            raise error
        if information.listed > capacity or information.assigned < information.listed:
            raise OSError("capture job returned an invalid process list size")
        if succeeded and information.assigned == information.listed:
            pids = tuple(information.ids[: information.listed])
            if any(not 0 < pid <= 0xFFFFFFFF for pid in pids) or len(set(pids)) != len(
                pids
            ):
                raise OSError("capture job returned invalid process identifiers")
            return pids

        capacity = max(capacity * 2, information.assigned)
        if capacity > MAX_SHUTDOWN_MEMBERS:
            raise ValueError("capture job exceeds the shutdown member limit")


def _windows_open_process(pid: int) -> int:
    import ctypes

    handle = _kernel32().OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def _windows_in_job(handle: int, job: int) -> bool:
    import ctypes
    from ctypes import wintypes

    member = wintypes.BOOL()
    if not _kernel32().IsProcessInJob(handle, job, ctypes.byref(member)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(member.value)


def _windows_terminate_job(job: int) -> None:
    import ctypes

    if not _kernel32().TerminateJobObject(job, 1):
        raise ctypes.WinError(ctypes.get_last_error())


def _windows_wait_process(handle: int, deadline: float) -> None:
    import ctypes

    kernel32 = _kernel32()
    result = kernel32.WaitForSingleObject(handle, 0)
    if result == 258:
        remaining = max(0.0, deadline - time.monotonic())
        result = kernel32.WaitForSingleObject(handle, math.ceil(remaining * 1000))
    if result == 0:
        return
    if result == 258:
        raise TimeoutError("capture job member exceeded cleanup deadline")
    if result == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    raise OSError(f"capture process wait returned unexpected status {result}")


def _windows_close_handle(handle: int, kernel32=None) -> None:
    import ctypes

    kernel32 = kernel32 if kernel32 is not None else _kernel32()
    if not kernel32.CloseHandle(handle):
        raise ctypes.WinError(ctypes.get_last_error())
