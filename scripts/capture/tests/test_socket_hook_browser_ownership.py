"""Exercise the concrete browser owner at controlled native API boundaries."""

import asyncio
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.capture import socket_hooks as hooks
from scripts.capture.browser_failures import BrowserLaunchFailures
from scripts.capture.tests.test_socket_hook_run_ownership import RunOwners

WAIT_SECONDS = 5.0
READY = {
    "kind": "ready",
    "pid": 11,
    "arch": "x64",
    "platform": "windows",
    "modules": ["ws2_32.dll", "dnsapi.dll"],
    "slow_ipv6_refusal": False,
    "time_ms": 1,
}


class CancelledNativeCall(Exception):
    pass


class NativeCancellation:
    current = threading.local()

    def __init__(self):
        self.cancelled = threading.Event()

    @property
    def is_cancelled(self):
        return self.cancelled.is_set()

    def __enter__(self):
        if not hasattr(self.current, "stack"):
            self.current.stack = []

        self.current.stack.append(self)

    def __exit__(self, *_error):
        self.current.stack.pop()

    def cancel(self):
        self.cancelled.set()


class NativeScript:
    def __init__(self):
        self.callback = None
        self.posted = threading.Event()
        self.config = None

    def on(self, signal, callback):
        if signal != "message":
            raise AssertionError("unexpected script signal")

        self.callback = callback

    def off(self, signal, callback):
        if signal != "message" or self.callback != callback:
            raise AssertionError("original script callback was not released")

        self.callback = None

    def load(self):
        pass

    def post(self, config):
        self.config = config
        self.posted.set()

    def emit(self, payload):
        message = {"type": "send", "payload": payload}
        self.callback(message, None)
        return message


class NativeSession:
    def __init__(self, pid, script):
        self.pid = pid
        self.script = script
        self.detached = False
        self.detach_error = None
        self.block_detach = False

    def enable_child_gating(self):
        pass

    def create_script(self, source):
        if 'recv("config"' not in source:
            raise AssertionError("actual shared agent was not loaded")

        return self.script

    def detach(self):
        cancellable = NativeCancellation.current.stack[-1]
        if self.block_detach and not cancellable.cancelled.wait(WAIT_SECONDS):
            raise AssertionError("native detach did not receive deadline cancellation")

        self.detached = True
        if self.detach_error is not None:
            raise self.detach_error


class NativeProcess:
    def __init__(self, device, pid):
        self.device = device
        self.pid = pid
        self.exited = threading.Event()
        self.closed = False

    def wait(self, deadline):
        return self.exited.wait(max(0.0, deadline - time.monotonic()))

    def close(self):
        self.closed = True

    def terminate(self):
        self.device.killed.append(self.pid)
        if self.pid in self.device.kill_errors:
            raise self.device.kill_errors[self.pid]

        if self.pid not in self.device.not_retiring:
            self.exited.set()


class NativeDevice:
    def __init__(self):
        self.script = NativeScript()
        self.sessions = {pid: NativeSession(pid, self.script) for pid in (10, 11)}
        self.callback = None
        self.resumed = []
        self.killed = []
        self.child_resumed = threading.Event()
        self.attach_entered = threading.Event()
        self.release_attach = threading.Event()
        self.hold_attach = False
        self.cancel_attach = False
        self.attach_cancellable = None
        self.pending_children = []
        self.pending_queried_after_root_kill = False
        self.kill_errors = {}
        self.not_retiring = set()
        self.processes = {pid: NativeProcess(self, pid) for pid in (10, 11)}
        self.child = SimpleNamespace(
            pid=11, parent_pid=10, argv=["browser", hooks.NETWORK_SERVICE_SWITCH]
        )

    def on(self, signal, callback):
        if signal != "child-added":
            raise AssertionError("unexpected device signal")

        self.callback = callback

    def off(self, signal, callback):
        if signal != "child-added" or self.callback != callback:
            raise AssertionError("original device callback was not released")

        self.callback = None

    def spawn(self, _arguments):
        return 10

    def attach(self, pid):
        if pid == 11:
            self.attach_cancellable = NativeCancellation.current.stack[-1]
            self.attach_entered.set()
            if self.cancel_attach:
                if not self.attach_cancellable.cancelled.wait(WAIT_SECONDS):
                    raise AssertionError("held attach was never cancelled")

                raise CancelledNativeCall("held native attach cancelled")

            if self.hold_attach and not self.release_attach.wait(WAIT_SECONDS):
                raise AssertionError("late session acquisition was not released")

        return self.sessions[pid]

    def resume(self, pid):
        self.resumed.append(pid)
        if pid == 10:
            self.callback(self.child)
        elif pid == 11:
            self.child_resumed.set()

    def enumerate_pending_children(self):
        if not NativeCancellation.current.stack:
            raise AssertionError("pending children requires a cancellation context")

        self.pending_queried_after_root_kill = 10 in self.killed
        return self.pending_children


class BrowserBoundary:
    def __init__(self):
        self.stack = ExitStack()
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.device = NativeDevice()
        self.profile_cleaned = []
        self.start_error = None
        self.start_finished = threading.Event()
        self.start_thread = None
        self.stopped = False
        self.browser = hooks.HookedBrowser(
            Path("controlled-browser"),
            [],
            Path(self.directory),
            {"slow_ipv6_refusal": False},
        )
        module = SimpleNamespace(
            __version__="controlled 17.23.3 interface",
            Cancellable=NativeCancellation,
            OperationCancelledError=CancelledNativeCall,
            get_local_device=lambda: self.device,
        )
        self.stack.enter_context(patch.dict(sys.modules, {"frida": module}))
        self.stack.enter_context(
            patch.object(hooks, "_SocketHookProcess", self.process)
        )
        self.stack.enter_context(
            patch.object(
                hooks, "terminate_profile_processes", self.profile_cleaned.append
            )
        )

    def process(self, pid):
        if pid not in self.device.processes:
            self.device.processes[pid] = NativeProcess(self.device, pid)

        return self.device.processes[pid]

    def start(self):
        def run():
            try:
                self.browser.start()
            except BaseException as error:
                self.start_error = error
            finally:
                self.start_finished.set()

        self.start_thread = threading.Thread(target=run, daemon=False)
        self.start_thread.start()

    def ready(self):
        self.start()
        if not self.device.script.posted.wait(WAIT_SECONDS):
            raise AssertionError("actual owner did not post its configuration")

        self.device.script.emit(dict(READY))
        if not self.device.child_resumed.wait(WAIT_SECONDS):
            raise AssertionError("acknowledged child was not resumed")

        if not self.start_finished.wait(WAIT_SECONDS):
            raise AssertionError("acknowledged browser start did not complete")

        if self.start_error is not None:
            raise self.start_error

    def stop(self):
        try:
            self.browser.stop()
        finally:
            self.stopped = True

    def backup(self):
        self.device.release_attach.set()
        self.browser.request_stop()
        if self.start_thread is not None:
            self.start_thread.join(WAIT_SECONDS)
            if self.start_thread.is_alive():
                raise AssertionError("original browser start thread survived backup")

        try:
            if not self.stopped:
                self.stop()
        finally:
            self.stack.close()


class SocketHookBrowserOwnershipTests(unittest.TestCase):
    def boundary(self):
        boundary = BrowserBoundary()
        self.addCleanup(boundary.backup)
        return boundary

    def test_configuration_post_alone_does_not_resume_the_measured_child(self):
        boundary = self.boundary()
        boundary.start()
        self.assertTrue(boundary.device.script.posted.wait(WAIT_SECONDS))
        self.assertEqual(
            boundary.device.script.config,
            {"type": "config", "slow_ipv6_refusal": False},
        )
        self.assertFalse(boundary.device.child_resumed.wait(0.1))
        self.assertFalse(boundary.start_finished.is_set())

        boundary.device.script.emit(dict(READY))
        self.assertTrue(boundary.device.child_resumed.wait(WAIT_SECONDS))
        self.assertTrue(boundary.start_finished.wait(WAIT_SECONDS))
        self.assertIsNone(boundary.start_error)
        boundary.stop()

        self.assertEqual(boundary.browser.snapshot(), [READY])
        self.assertFalse(boundary.browser._worker.daemon)
        self.assertFalse(boundary.browser._worker.is_alive())
        self.assertTrue(
            all(session.detached for session in boundary.device.sessions.values())
        )
        self.assertEqual(set(boundary.device.killed), {10, 11})
        self.assertEqual(boundary.profile_cleaned, [boundary.browser.profile])
        self.assertTrue(
            all(process.closed for process in boundary.device.processes.values())
        )

    def test_missing_required_hook_retains_the_original_message_and_never_resumes(self):
        boundary = self.boundary()
        boundary.start()
        self.assertTrue(boundary.device.script.posted.wait(WAIT_SECONDS))
        message = boundary.device.script.emit(
            {"kind": "hook-missing", "module": "ws2_32.dll", "function": "connect"}
        )
        self.assertTrue(boundary.start_finished.wait(WAIT_SECONDS))
        self.assertIsInstance(boundary.start_error, hooks._SocketHookAgentFailure)
        self.assertIs(boundary.start_error.message, message)
        self.assertNotIn(11, boundary.device.resumed)

        with self.assertRaises(hooks._SocketHookAgentFailure) as stopped:
            boundary.stop()

        self.assertIs(stopped.exception, boundary.start_error)
        self.assertTrue(
            all(session.detached for session in boundary.device.sessions.values())
        )
        self.assertEqual(set(boundary.device.killed), {10, 11})
        with self.assertRaises(hooks._SocketHookAgentFailure) as snapshot:
            boundary.browser.snapshot()

        self.assertIs(snapshot.exception, boundary.start_error)

    def test_stop_cancels_the_original_blocked_attach_and_joins_its_worker(self):
        boundary = self.boundary()
        boundary.device.cancel_attach = True
        boundary.start()
        self.assertTrue(boundary.device.attach_entered.wait(WAIT_SECONDS))
        original = boundary.device.attach_cancellable

        boundary.browser.request_stop()
        self.assertTrue(original.is_cancelled)
        self.assertTrue(boundary.start_finished.wait(WAIT_SECONDS))
        boundary.stop()

        self.assertFalse(boundary.browser._worker.is_alive())
        self.assertNotIn(11, boundary.device.resumed)
        self.assertEqual(set(boundary.device.killed), {10, 11})

    def test_session_acquired_after_stop_is_retained_and_detached(self):
        boundary = self.boundary()
        boundary.device.hold_attach = True
        boundary.start()
        self.assertTrue(boundary.device.attach_entered.wait(WAIT_SECONDS))

        boundary.browser.request_stop()
        boundary.device.release_attach.set()
        self.assertTrue(boundary.start_finished.wait(WAIT_SECONDS))
        boundary.stop()

        child_session = boundary.device.sessions[11]
        self.assertIn(child_session, boundary.browser._sessions.values())
        self.assertTrue(child_session.detached)
        self.assertNotIn(11, boundary.device.resumed)
        self.assertFalse(boundary.browser._worker.is_alive())

    def test_independent_detach_failures_keep_original_causes_and_all_cleanup_attempts(
        self,
    ):
        boundary = self.boundary()
        boundary.ready()
        failures = [
            OSError("original root detach failure"),
            OSError("original child detach failure"),
        ]
        for session, error in zip(
            boundary.device.sessions.values(), failures, strict=True
        ):
            session.detach_error = error

        with self.assertRaises(BrowserLaunchFailures) as stopped:
            boundary.stop()

        self.assertEqual(stopped.exception.cleanup[:2], tuple(failures))
        self.assertIsInstance(
            stopped.exception.cleanup[2], hooks._SocketHookCleanupIncomplete
        )
        self.assertIs(stopped.exception.cleanup[2].owner, boundary.browser)
        self.assertTrue(
            all(session.detached for session in boundary.device.sessions.values())
        )
        self.assertEqual(set(boundary.device.killed), {10, 11})
        self.assertEqual(boundary.profile_cleaned, [boundary.browser.profile])
        with self.assertRaises(BrowserLaunchFailures) as snapshot:
            boundary.browser.snapshot()

        self.assertEqual(snapshot.exception.cleanup, tuple(failures))

    def test_invalid_architecture_acknowledgement_never_resumes_the_child(self):
        boundary = self.boundary()
        boundary.start()
        self.assertTrue(boundary.device.script.posted.wait(WAIT_SECONDS))
        message = boundary.device.script.emit({**READY, "arch": "arm64"})
        self.assertTrue(boundary.start_finished.wait(WAIT_SECONDS))
        self.assertIsInstance(boundary.start_error, hooks._SocketHookAgentFailure)
        self.assertIs(boundary.start_error.message, message)
        self.assertFalse(boundary.browser._ready.is_set())
        self.assertNotIn(11, boundary.device.resumed)
        with self.assertRaises(hooks._SocketHookAgentFailure):
            boundary.stop()

    def test_child_rejection_and_repeated_reports_do_not_grow_the_admitted_owners(self):
        boundary = self.boundary()
        boundary.ready()
        with patch.object(hooks, "_HOOK_CHILD_LIMIT", 2):
            boundary.browser._on_child_added(
                SimpleNamespace(pid=12, parent_pid=10, argv=[])
            )
            rejected = SimpleNamespace(pid=13, parent_pid=10, argv=[])
            boundary.browser._on_child_added(rejected)
            for pid in range(14, 100):
                boundary.browser._on_child_added(
                    SimpleNamespace(pid=pid, parent_pid=10, argv=[])
                )

        self.assertEqual(set(boundary.browser._children_by_pid), {11, 12})
        self.assertEqual(boundary.browser._child_count, 2)
        self.assertIsInstance(boundary.browser._failure, hooks._SocketHookChildLimit)
        self.assertIs(boundary.browser._failure.child, rejected)
        for _ in range(100):
            boundary.browser._on_message(
                {"type": "error", "description": "late event"}, None
            )

        self.assertEqual(boundary.browser.reports, [READY])
        with self.assertRaises(BrowserLaunchFailures) as stopped:
            boundary.stop()

        self.assertIs(stopped.exception.cleanup[0], boundary.browser._failure)
        self.assertNotIn(13, boundary.device.killed)
        self.assertIn(10, boundary.device.killed)
        self.assertIn(11, boundary.device.killed)
        self.assertFalse(boundary.browser._worker.is_alive())
        unknown = stopped.exception.cleanup[1]
        self.assertIsInstance(unknown, hooks._SocketHookIdentityUnknown)
        self.assertTrue(any(child is rejected for child in unknown.children))
        self.assertFalse(boundary.device.sessions[10].detached)
        self.assertFalse(boundary.browser._profile_retired)

    def test_actual_pending_roster_retains_unadmitted_run_children_only(self):
        boundary = self.boundary()
        boundary.ready()
        run_child = SimpleNamespace(pid=12, parent_pid=10, argv=[])
        unrelated = SimpleNamespace(pid=99, parent_pid=98, argv=[])
        boundary.device.pending_children = [run_child, unrelated]

        boundary.browser.request_stop()
        boundary.browser._on_child_added(run_child)
        self.assertNotIn(12, boundary.browser._children_by_pid)
        with self.assertRaises(BrowserLaunchFailures) as stopped:
            boundary.stop()

        self.assertTrue(boundary.device.pending_queried_after_root_kill)
        self.assertEqual(boundary.browser._pending_children, (run_child,))
        self.assertEqual(boundary.device.killed, [10, 11])
        self.assertNotIn(99, boundary.device.killed)
        unknown = stopped.exception.cleanup[0]
        self.assertIsInstance(unknown, hooks._SocketHookIdentityUnknown)
        self.assertEqual(unknown.children, (run_child,))
        self.assertIs(unknown.owner, boundary.browser)
        self.assertFalse(boundary.device.sessions[10].detached)
        self.assertTrue(boundary.device.sessions[11].detached)
        self.assertFalse(boundary.browser._profile_retired)

    def test_cleanup_deadline_keeps_the_original_native_cancellation_separately(self):
        boundary = self.boundary()
        boundary.ready()
        session = boundary.device.sessions[11]
        original = CancelledNativeCall("original deadline-cancelled detach")
        session.detach_error = original
        session.block_detach = True

        _, failure = boundary.browser._cleanup_native(session.detach, time.monotonic())

        self.assertIsInstance(failure, BrowserLaunchFailures)
        self.assertIs(failure.primary, original)
        self.assertEqual(len(failure.cleanup), 1)
        self.assertIsInstance(failure.cleanup[0], TimeoutError)
        self.assertTrue(session.detached)

        session.detach_error = None
        session.block_detach = False
        boundary.stop()

    def test_report_quota_keeps_the_first_failure_without_late_history_growth(self):
        boundary = self.boundary()
        boundary.ready()
        report = {"kind": "config", "slow_ipv6_refusal": False, "time_ms": 2}
        with patch.object(hooks, "_HOOK_REPORT_LIMIT", 2):
            boundary.device.script.emit(report)
            boundary.device.script.emit(report)

        original = boundary.browser._failure
        self.assertIsInstance(original, RuntimeError)
        self.assertEqual(boundary.browser.reports, [READY, report])
        for _ in range(100):
            boundary.browser._on_message(
                {"type": "error", "description": "later error"}, None
            )

        self.assertIs(boundary.browser._failure, original)
        self.assertEqual(boundary.browser.reports, [READY, report])
        with self.assertRaises(RuntimeError) as stopped:
            boundary.stop()

        self.assertIs(stopped.exception, original)
        self.assertFalse(boundary.browser._worker.is_alive())

    def test_callback_selected_before_shutdown_keeps_its_late_error_before_snapshot(
        self,
    ):
        boundary = self.boundary()
        boundary.ready()
        selected_callback = boundary.device.script.callback
        boundary.stop()
        self.assertIsNone(boundary.device.script.callback)
        message = {"type": "error", "description": "original delayed agent error"}

        selected_callback(message, None)
        with self.assertRaises(hooks._SocketHookAgentFailure) as snapshot:
            boundary.browser.snapshot()

        self.assertIs(snapshot.exception.message, message)
        self.assertEqual(boundary.browser.reports, [READY])

    def test_failed_root_kill_retains_child_gating_and_cleans_independent_owners(self):
        boundary = self.boundary()
        boundary.ready()
        original = OSError("original root kill failure")
        boundary.device.kill_errors[10] = original
        with (
            patch.object(hooks, "_HOOK_NATIVE_CLEANUP_SECONDS", 0.1),
            self.assertRaises(BrowserLaunchFailures) as stopped,
        ):
            boundary.stop()

        self.assertIs(stopped.exception.cleanup[0], original)
        pending = stopped.exception.cleanup[1]
        self.assertIsInstance(pending, hooks._SocketHookProcessPending)
        self.assertIs(pending.owner, boundary.browser)
        self.assertEqual(pending.pid, 10)
        self.assertIs(pending.process, boundary.device.processes[10])
        self.assertFalse(boundary.device.sessions[10].detached)
        self.assertTrue(boundary.device.sessions[11].detached)
        self.assertEqual(boundary.device.killed, [10, 11])
        self.assertEqual(boundary.profile_cleaned, [boundary.browser.profile])
        self.assertFalse(boundary.browser._worker.is_alive())
        self.assertFalse(boundary.browser._stopped)
        self.assertFalse(boundary.device.processes[10].closed)
        self.assertFalse(boundary.browser._profile_retired)

        with self.assertRaises(BrowserLaunchFailures) as snapshot:
            boundary.browser.snapshot()

        self.assertEqual(snapshot.exception.cleanup, stopped.exception.cleanup[:-1])
        self.assertIsInstance(snapshot.exception.cleanup[2], TimeoutError)

    def test_successful_kill_without_observed_process_exit_does_not_release_root_gate(
        self,
    ):
        boundary = self.boundary()
        boundary.ready()
        boundary.device.not_retiring.add(10)
        with (
            patch.object(hooks, "_HOOK_NATIVE_CLEANUP_SECONDS", 0.1),
            self.assertRaises(BrowserLaunchFailures) as stopped,
        ):
            boundary.stop()

        pending = stopped.exception.cleanup[0]
        self.assertIsInstance(pending, hooks._SocketHookProcessPending)
        self.assertIs(pending.process, boundary.device.processes[10])
        self.assertFalse(boundary.device.sessions[10].detached)
        self.assertTrue(boundary.device.sessions[11].detached)
        self.assertFalse(boundary.browser._stopped)
        self.assertFalse(boundary.device.processes[10].closed)

    def test_child_termination_failure_retains_its_handle_hooks_and_profile(self):
        boundary = self.boundary()
        boundary.ready()
        original = OSError("original child termination failure")
        boundary.device.kill_errors[11] = original
        with (
            patch.object(hooks, "_HOOK_NATIVE_CLEANUP_SECONDS", 0.1),
            self.assertRaises(BrowserLaunchFailures) as stopped,
        ):
            boundary.stop()

        self.assertIs(stopped.exception.cleanup[0], original)
        pending = stopped.exception.cleanup[1]
        self.assertIsInstance(pending, hooks._SocketHookProcessPending)
        self.assertEqual(pending.pid, 11)
        self.assertIs(pending.process, boundary.device.processes[11])
        self.assertFalse(boundary.device.processes[11].closed)
        self.assertTrue(boundary.device.processes[10].closed)
        self.assertFalse(boundary.device.sessions[10].detached)
        self.assertFalse(boundary.device.sessions[11].detached)
        self.assertIsNotNone(boundary.device.script.callback)
        self.assertFalse(boundary.browser._profile_retired)
        self.assertEqual(boundary.device.killed, [10, 11])
        self.assertEqual(boundary.profile_cleaned, [boundary.browser.profile])

    def test_child_handle_acquisition_failure_does_not_resume_or_kill_an_unowned_pid(
        self,
    ):
        boundary = self.boundary()
        original = OSError("original child handle acquisition failure")
        actual_process = boundary.process

        def process(pid):
            if pid == 11:
                raise original

            return actual_process(pid)

        with patch.object(hooks, "_SocketHookProcess", process):
            boundary.start()
            self.assertTrue(boundary.start_finished.wait(WAIT_SECONDS))

        self.assertIs(boundary.start_error, original)
        self.assertNotIn(11, boundary.device.resumed)
        with self.assertRaises(BrowserLaunchFailures) as stopped:
            boundary.stop()

        self.assertIs(stopped.exception.cleanup[0], original)
        unknown = stopped.exception.cleanup[1]
        self.assertIsInstance(unknown, hooks._SocketHookIdentityUnknown)
        self.assertEqual(unknown.children, (boundary.device.child,))
        self.assertEqual(boundary.device.killed, [10])
        self.assertFalse(boundary.device.sessions[10].detached)
        self.assertFalse(boundary.browser._profile_retired)


class SocketHookFailureWakeTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_browser_retirement_keeps_the_actual_profile_with_its_owner(
        self,
    ):
        owners = RunOwners()
        self.addAsyncCleanup(owners.backup)
        owners.install()
        owners.finish_page = False
        original = OSError("original browser failure during capture")
        owners.caller = asyncio.create_task(owners.call(hooks.SCENARIOS["idle"]))
        await asyncio.wait_for(owners.started.wait(), WAIT_SECONDS)
        owners.browser._profile_retired = False
        pending = hooks._SocketHookCleanupIncomplete(owners.browser)
        owners.stop_error = pending

        owners.browser._failure_notifier(original)
        with self.assertRaises(BrowserLaunchFailures) as raised:
            await asyncio.wait_for(asyncio.shield(owners.caller), WAIT_SECONDS)

        self.assertIs(raised.exception.primary, original)
        self.assertEqual(raised.exception.cleanup, (pending,))
        self.assertIs(pending.owner, owners.browser)
        self.assertEqual(pending.owner.profile, owners.profiles[0])
        self.assertTrue(pending.owner.profile.is_dir())
        self.assertFalse(owners.removed)
        self.assertTrue(all(not server.is_serving() for server in owners.servers))
        self.assertTrue(all(sock.fileno() == -1 for sock in owners.sockets))

    async def test_idle_run_leaves_its_scenario_wait_after_the_original_browser_failure(
        self,
    ):
        owners = RunOwners()
        self.addAsyncCleanup(owners.backup)
        owners.install()
        owners.finish_page = False
        original = OSError("original browser failure during idle capture")
        origins = []
        waiters = []
        actual_origin = hooks.Origin

        def origin(scenario):
            value = actual_origin(scenario)
            origins.append(value)
            actual_wait = value.done.wait

            async def wait():
                waiters.append(asyncio.current_task())
                return await actual_wait()

            value.done.wait = wait
            return value

        with patch.object(hooks, "Origin", origin):
            owners.caller = asyncio.create_task(owners.call(hooks.SCENARIOS["idle"]))
            await asyncio.wait_for(owners.started.wait(), WAIT_SECONDS)
            thread = threading.Thread(
                target=owners.browser._failure_notifier, args=(original,), daemon=False
            )
            thread.start()
            with self.assertRaises(OSError) as raised:
                await asyncio.wait_for(asyncio.shield(owners.caller), WAIT_SECONDS)

            thread.join(WAIT_SECONDS)

        self.assertIs(raised.exception, original)
        self.assertFalse(thread.is_alive())
        self.assertFalse(origins[0].done.is_set())
        self.assertEqual(len(waiters), 1)
        self.assertTrue(waiters[0].done())
        self.assertTrue(waiters[0].cancelled())
        self.assertEqual(owners.order, ["start", "started", "stop"])
        self.assertTrue(all(not server.is_serving() for server in owners.servers))
        self.assertTrue(all(sock.fileno() == -1 for sock in owners.sockets))
        self.assertEqual(owners.removed, owners.profiles)
        self.assertTrue(all(not profile.exists() for profile in owners.profiles))

    async def test_original_native_failure_wakes_the_idle_scenario_and_owns_its_waiter(
        self,
    ):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        profile = Path(directory.name) / "profile"
        profile.mkdir()
        browser = hooks.HookedBrowser(Path("controlled-browser"), [], profile, {})
        owner = hooks._SocketHookBrowserOwner(browser, profile)
        original = OSError("original post-readiness native failure")
        idle = asyncio.Event()
        done_waiter = asyncio.create_task(idle.wait())
        self.addAsyncCleanup(self.close_waiter, done_waiter)

        thread = threading.Thread(
            target=browser._retain_failure, args=(original,), daemon=False
        )
        thread.start()
        completed, _ = await asyncio.wait(
            (done_waiter, owner.failed),
            timeout=WAIT_SECONDS,
            return_when=asyncio.FIRST_COMPLETED,
        )
        thread.join(WAIT_SECONDS)

        self.assertFalse(thread.is_alive())
        self.assertIn(owner.failed, completed)
        self.assertIs(owner.failed.result(), original)
        self.assertFalse(done_waiter.done())
        self.assertFalse(idle.is_set())
        self.assertTrue(owner.stop_requested.is_set())
        self.assertIs(browser._failure, original)

    async def close_waiter(self, waiter):
        if not waiter.done():
            waiter.cancel()

        await asyncio.gather(waiter, return_exceptions=True)


class SocketHookRootProcessTests(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform == "win32", "requires a Windows kernel process handle"
    )
    def test_original_kernel_handle_distinguishes_a_live_process_from_its_observed_exit(
        self,
    ):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.close_process, process)
        owner = hooks._SocketHookProcess(process.pid)
        self.addCleanup(owner.close)
        original_handle = owner.handle

        self.assertIsNone(process.poll())
        self.assertFalse(owner.wait(time.monotonic() + 0.01))
        self.assertEqual(owner.handle, original_handle)

        owner.terminate()
        process.wait(timeout=WAIT_SECONDS)
        self.assertTrue(owner.wait(time.monotonic() + WAIT_SECONDS))
        self.assertEqual(owner.handle, original_handle)
        owner.close()
        self.assertIsNone(owner.handle)

    def close_process(self, process):
        if process.poll() is None:
            process.kill()

        process.wait(timeout=WAIT_SECONDS)
