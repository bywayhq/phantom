"""Socket-hook runs retain real listeners and independent cleanup failures."""

import asyncio
import socket
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from scripts.capture import socket_hooks as hooks
from scripts.capture.browser_failures import BrowserLaunchFailures

DEADLINE = 5.0


class RejectedSwitches(list):
    def __init__(self, error):
        super().__init__(["--controlled-switch"])
        self.error = error

    def __iter__(self):
        raise self.error


class RunOwners:
    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.stack = ExitStack()
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.servers = []
        self.sockets = []
        self.waited = []
        self.profiles = []
        self.removed = []
        self.browser = None
        self.caller = None
        self.primary = None
        self.result = None
        self.start_error = None
        self.stop_error = None
        self.profile_error = None
        self.constructor_error = None
        self.wait_errors = {}
        self.wait_cancellations = {}
        self.started = asyncio.Event()
        self.release_start = threading.Event()
        self.hold_start = False
        self.finish_page = True
        self.order = []
        self.reports = []
        self.actual_server = asyncio.start_server
        self.actual_profile = tempfile.mkdtemp
        self.actual_remove = hooks.shutil.rmtree

    def install(self):
        owners = self

        class BrowserBoundary:
            def __init__(self, executable, arguments, profile, config):
                if owners.constructor_error is not None:
                    raise owners.constructor_error

                owners.browser = self
                self.profile = profile
                self.reports = []
                self.errors = []
                self.network_service_argv = None
                self.frida_version = "controlled browser boundary"

            def start(self):
                owners.order.append("start")
                owners.loop.call_soon_threadsafe(owners.started.set)
                if owners.hold_start:
                    owners.release_start.wait()
                if owners.start_error is not None:
                    raise owners.start_error

                if not owners.hold_start and owners.finish_page:
                    visit = asyncio.run_coroutine_threadsafe(
                        asyncio.wait_for(owners.visit(), DEADLINE), owners.loop
                    )
                    visit.result(DEADLINE)

                owners.order.append("started")

            def stop(self):
                owners.order.append("stop")
                if owners.stop_error is not None:
                    raise owners.stop_error

            def snapshot(self):
                return list(self.reports)

        async def observe_server(*args, **kwargs):
            server = await self.actual_server(*args, **kwargs)
            index = len(self.servers)
            self.servers.append(server)
            self.sockets.extend(server.sockets)
            actual_wait = server.wait_closed

            async def wait_closed():
                await actual_wait()
                self.waited.append(index)
                if index in self.wait_cancellations:
                    if self.caller is None:
                        raise AssertionError("listener wait has no original caller")

                    self.caller.cancel(self.wait_cancellations[index])

                if index in self.wait_errors:
                    raise self.wait_errors[index]

            self.stack.enter_context(patch.object(server, "wait_closed", wait_closed))
            return server

        def profile(*args, **kwargs):
            value = self.actual_profile(*args, **kwargs, dir=self.directory)
            self.profiles.append(Path(value))
            return value

        def remove(path, *args, **kwargs):
            self.actual_remove(path, *args, **kwargs)
            if Path(path) in self.profiles:
                self.removed.append(Path(path))
                if self.profile_error is not None:
                    raise self.profile_error

        self.stack.enter_context(patch.object(hooks, "HookedBrowser", BrowserBoundary))
        self.stack.enter_context(
            patch.object(hooks.asyncio, "start_server", observe_server)
        )
        self.stack.enter_context(patch.object(hooks.tempfile, "mkdtemp", profile))
        self.stack.enter_context(patch.object(hooks.shutil, "rmtree", remove))

    async def visit(self):
        port = self.servers[0].sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"GET /done HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            if not head.startswith(b"HTTP/1.1 200 OK\r\n"):
                raise AssertionError("actual socket-hook origin did not return 200")

            body = await reader.readexactly(3)
            if body != b"ok\n":
                raise AssertionError("actual socket-hook origin changed its body")
        finally:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), DEADLINE)

    async def call(self, scenario, extra=()):
        try:
            self.result = await hooks.run_once(scenario, Path("controlled-browser"), extra)
        except BaseException as error:
            self.primary = error
            raise

    async def backup(self):
        failures = []
        self.release_start.set()
        if self.caller is not None and not self.caller.done():
            self.caller.cancel()
            try:
                await asyncio.wait_for(self.caller, DEADLINE)
            except asyncio.CancelledError:
                pass
            except BaseException as error:
                if error is not self.primary:
                    failures.append(error)

        pending = self.primary.__cause__ if self.primary is not None else None
        if isinstance(pending, BrowserLaunchFailures):
            for error in pending.cleanup:
                if isinstance(error, hooks._SocketHookWorkerPending):
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(error.owner.future), DEADLINE
                        )
                    except BaseException as failure:
                        failures.append(failure)

        for server in self.servers:
            try:
                server.close()
            except BaseException as error:
                failures.append(error)

        for server in self.servers:
            try:
                await asyncio.wait_for(type(server).wait_closed(server), DEADLINE)
            except BaseException as error:
                failures.append(error)

        try:
            self.stack.close()
        except BaseException as error:
            failures.append(error)

        if failures:
            failure = AssertionError(f"socket-hook owner backup failed: {failures!r}")
            failure.failures = tuple(failures)
            raise failure from failures[0]


class SocketHookRunOwnershipTests(unittest.IsolatedAsyncioTestCase):
    def owners(self):
        owners = RunOwners()
        self.addAsyncCleanup(owners.backup)
        owners.install()
        return owners

    def assert_closed(self, owners):
        self.assertTrue(owners.servers)
        self.assertTrue(all(not server.is_serving() for server in owners.servers))
        self.assertTrue(all(sock.fileno() == -1 for sock in owners.sockets))
        self.assertEqual(set(owners.waited), set(range(len(owners.servers))))

    def dual_scenario(self):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("::1", 0))
            except OSError as error:
                self.skipTest(f"native IPv6 loopback unavailable: {error}")

        return hooks.SCENARIOS["happy-eyeballs"]

    async def test_second_real_listener_bind_failure_closes_the_first_listener(self):
        owners = self.owners()
        occupied = await owners.actual_server(
            lambda reader, writer: writer.close(), "127.0.0.1", 0
        )
        self.addAsyncCleanup(occupied.wait_closed)
        self.addCleanup(occupied.close)
        port = occupied.sockets[0].getsockname()[1]
        observe_server = hooks.asyncio.start_server
        bind_errors = []

        async def collide(callback, host, selected_port, **kwargs):
            if owners.servers:
                try:
                    return await owners.actual_server(callback, host, port, **kwargs)
                except OSError as error:
                    bind_errors.append(error)
                    raise

            return await observe_server(callback, host, selected_port, **kwargs)

        with patch.object(hooks.asyncio, "start_server", collide):
            with self.assertRaises(OSError) as raised:
                await owners.call(hooks.SCENARIOS["happy-eyeballs"])

        self.assertEqual(len(bind_errors), 1)
        self.assertIs(raised.exception, bind_errors[0])
        self.assertEqual(len(owners.servers), 1)
        self.assert_closed(owners)
        self.assertFalse(owners.profiles)

    async def test_real_profile_creation_failure_closes_the_acquired_listener(self):
        owners = self.owners()
        blocked = Path(owners.directory) / "not-a-directory"
        blocked.write_bytes(b"literal occupied profile parent")
        profile_errors = []

        def blocked_profile(*args, **kwargs):
            try:
                return owners.actual_profile(*args, **kwargs, dir=blocked)
            except OSError as error:
                profile_errors.append(error)
                raise

        with patch.object(hooks.tempfile, "mkdtemp", blocked_profile):
            with self.assertRaises(OSError) as raised:
                await owners.call(hooks.SCENARIOS["single"])

        self.assertEqual(len(profile_errors), 1)
        self.assertIs(raised.exception, profile_errors[0])
        self.assert_closed(owners)
        self.assertFalse(owners.profiles)
        self.assertIsNone(owners.browser)

    async def test_argument_failure_closes_both_listeners_and_removes_the_profile(self):
        scenario = self.dual_scenario()
        owners = self.owners()
        failure = LookupError("controlled caller switch iteration failure")

        with self.assertRaises(LookupError) as raised:
            await owners.call(scenario, RejectedSwitches(failure))

        self.assertIs(raised.exception, failure)
        self.assertEqual(len(owners.servers), 2)
        self.assert_closed(owners)
        self.assertEqual(owners.removed, owners.profiles)
        self.assertTrue(all(not profile.exists() for profile in owners.profiles))
        self.assertIsNone(owners.browser)

    async def test_browser_constructor_failure_retains_profile_cleanup(self):
        owners = self.owners()
        owners.constructor_error = LookupError(
            "controlled external browser constructor failure"
        )

        with self.assertRaises(LookupError) as raised:
            await owners.call(hooks.SCENARIOS["single"])

        self.assertIs(raised.exception, owners.constructor_error)
        self.assert_closed(owners)
        self.assertEqual(owners.removed, owners.profiles)
        self.assertTrue(all(not profile.exists() for profile in owners.profiles))

    async def test_start_stop_and_independent_wait_profile_failures_keep_original_causes(self):
        scenario = self.dual_scenario()
        owners = self.owners()
        owners.start_error = LookupError("controlled original browser start failure")
        owners.stop_error = OSError("controlled original browser stop failure")
        owners.profile_error = OSError("controlled post-removal profile failure")
        owners.wait_errors = {
            0: OSError("controlled post-close primary listener wait failure"),
            1: OSError("controlled post-close target listener wait failure"),
        }

        with self.assertRaises(BrowserLaunchFailures) as raised:
            await owners.call(scenario)

        failure = raised.exception
        self.assertIs(failure.primary, owners.start_error)
        self.assertEqual(
            failure.cleanup,
            (
                owners.wait_errors[1],
                owners.wait_errors[0],
                owners.stop_error,
                owners.profile_error,
            ),
        )
        self.assertIsNone(owners.result)
        self.assert_closed(owners)
        self.assertEqual(owners.order, ["start", "stop"])
        self.assertEqual(owners.removed, owners.profiles)
        self.assertTrue(all(not profile.exists() for profile in owners.profiles))

    async def test_stop_failure_still_waits_both_listeners_and_removes_profile(self):
        scenario = self.dual_scenario()
        owners = self.owners()
        owners.stop_error = OSError("controlled original stop failure after real page")

        with self.assertRaises(OSError) as raised:
            await owners.call(scenario)

        self.assertIs(raised.exception, owners.stop_error)
        self.assertIsNone(owners.result)
        self.assert_closed(owners)
        self.assertEqual(owners.order, ["start", "started", "stop"])
        self.assertEqual(owners.removed, owners.profiles)
        self.assertTrue(all(not profile.exists() for profile in owners.profiles))

    async def test_repeated_cancellation_keeps_completed_listener_and_browser_failures(self):
        scenario = self.dual_scenario()
        owners = self.owners()
        owners.start_error = LookupError("controlled original browser start failure")
        owners.stop_error = OSError("controlled original browser stop failure")
        owners.profile_error = OSError("controlled post-removal profile failure")
        owners.wait_errors = {
            0: OSError("controlled post-close primary listener wait failure"),
            1: OSError("controlled post-close target listener wait failure"),
        }
        owners.wait_cancellations = {
            0: "controlled interruption after actual primary listener wait",
            1: "controlled interruption after actual target listener wait",
        }

        owners.caller = asyncio.create_task(owners.call(scenario))
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(owners.caller, DEADLINE)

        self.assertIsInstance(owners.primary, asyncio.CancelledError)
        composition = owners.primary.__cause__
        self.assertIsInstance(composition, BrowserLaunchFailures)
        self.assertIs(composition.primary, owners.start_error)
        self.assertEqual(len(composition.cleanup), 6)
        (
            target_interruption,
            target_wait,
            primary_interruption,
            primary_wait,
            stop,
            profile,
        ) = composition.cleanup
        self.assertIs(target_interruption, owners.primary)
        self.assertIsInstance(primary_interruption, asyncio.CancelledError)
        self.assertEqual(target_interruption.args, (owners.wait_cancellations[1],))
        self.assertEqual(primary_interruption.args, (owners.wait_cancellations[0],))
        self.assertIs(target_wait, owners.wait_errors[1])
        self.assertIs(primary_wait, owners.wait_errors[0])
        self.assertIs(stop, owners.stop_error)
        self.assertIs(profile, owners.profile_error)
        self.assertIsNone(owners.result)
        self.assert_closed(owners)
        self.assertEqual(owners.removed, owners.profiles)
        self.assertTrue(all(not path.exists() for path in owners.profiles))

    async def test_cancelled_held_start_retains_worker_until_actual_stop_and_removal(self):
        owners = self.owners()
        owners.hold_start = True
        owners.stop_error = OSError("controlled late original browser stop failure")
        self.addCleanup(
            owners.loop.set_exception_handler, owners.loop.get_exception_handler()
        )
        report_received = asyncio.Event()

        def report(loop, context):
            owners.reports.append(context)
            report_received.set()

        owners.loop.set_exception_handler(report)
        with patch.object(hooks, "_RUN_CLEANUP_SECONDS", 0.05):
            owners.caller = asyncio.create_task(owners.call(hooks.SCENARIOS["single"]))
            await asyncio.wait_for(owners.started.wait(), DEADLINE)
            owners.caller.cancel("controlled pending original browser start cancellation")
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(owners.caller, DEADLINE)

        self.assertIsInstance(owners.primary, asyncio.CancelledError)
        composition = owners.primary.__cause__
        self.assertIsInstance(composition, BrowserLaunchFailures)
        self.assertIs(composition.primary, owners.primary)
        self.assertEqual(len(composition.cleanup), 1)
        pending = composition.cleanup[0]
        self.assertIsInstance(pending, hooks._SocketHookWorkerPending)
        self.assertIsInstance(pending.__cause__, asyncio.TimeoutError)
        self.assertIs(pending.owner.browser, owners.browser)
        self.assertFalse(pending.owner.future.done())
        self.assertFalse(pending.owner.future.cancelled())
        self.assertTrue(pending.owner.profile.exists())
        self.assertEqual(owners.order, ["start"])
        self.assert_closed(owners)

        owners.release_start.set()
        await asyncio.wait_for(asyncio.shield(pending.owner.future), DEADLINE)
        await asyncio.wait_for(report_received.wait(), DEADLINE)

        self.assertEqual(owners.order, ["start", "started", "stop"])
        self.assertTrue(pending.owner.future.done())
        self.assertFalse(pending.owner.profile.exists())
        self.assertEqual(len(owners.reports), 1)
        self.assertIs(owners.reports[0]["exception"], owners.stop_error)
        self.assertEqual(owners.reports[0]["failures"], (owners.stop_error,))
        self.assertIs(owners.reports[0]["primary"], owners.primary)
        self.assertIs(owners.reports[0]["future"], pending.owner.future)

    async def test_healthy_run_keeps_the_real_done_response_and_result(self):
        owners = self.owners()

        result, arguments = await owners.call(hooks.SCENARIOS["single"])

        self.assertFalse(result.timed_out)
        self.assertTrue(result.origin.done.is_set())
        self.assertEqual(
            result.origin.connections[0].requests[0][1:], ("127.0.0.1", "/done")
        )
        self.assertTrue(arguments[-1].startswith("http://127.0.0.1:"))
        self.assert_closed(owners)
        self.assertEqual(owners.order, ["start", "started", "stop"])
        self.assertEqual(owners.removed, owners.profiles)

    async def test_expected_scenario_expiry_still_returns_its_timeout_flag(self):
        owners = self.owners()
        owners.finish_page = False
        scenario = hooks.Scenario("single", "controlled unanswered page", 0.01)

        result, _ = await owners.call(scenario)

        self.assertTrue(result.timed_out)
        self.assertFalse(result.origin.done.is_set())
        self.assert_closed(owners)
        self.assertEqual(owners.order, ["start", "started", "stop"])
        self.assertEqual(owners.removed, owners.profiles)

    async def test_rejected_worker_submission_closes_listener_and_removes_profile(self):
        owners = self.owners()
        failure = RuntimeError("controlled original executor submission rejection")
        actual_submit = owners.loop.run_in_executor

        def submit(executor, function, *args):
            if isinstance(
                getattr(function, "__self__", None), hooks._SocketHookBrowserOwner
            ):
                raise failure

            return actual_submit(executor, function, *args)

        with patch.object(owners.loop, "run_in_executor", submit):
            with self.assertRaises(RuntimeError) as raised:
                await owners.call(hooks.SCENARIOS["single"])

        self.assertIs(raised.exception, failure)
        self.assert_closed(owners)
        self.assertFalse(owners.order)
        self.assertEqual(owners.removed, owners.profiles)
        self.assertTrue(all(not profile.exists() for profile in owners.profiles))

    async def test_cancelled_real_serving_readiness_closes_the_acquired_listener(self):
        owners = self.owners()
        actual_start = asyncio.base_events.Server._start_serving
        started = []
        sockets = []

        def start(server):
            actual_start(server)
            started.append(server)
            sockets.extend(server.sockets)
            self.addAsyncCleanup(server.wait_closed)
            self.addCleanup(server.close)
            if asyncio.current_task() is not owners.caller:
                raise AssertionError("real listener readiness left the original caller")

            owners.loop.call_soon(
                owners.caller.cancel, "controlled actual serving readiness cancellation"
            )

        with patch.object(asyncio.base_events.Server, "_start_serving", start):
            owners.caller = asyncio.create_task(owners.call(hooks.SCENARIOS["single"]))
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(owners.caller, DEADLINE)

        self.assertEqual(len(started), 1)
        self.assertIsInstance(owners.primary, asyncio.CancelledError)
        self.assertEqual(
            owners.primary.args, ("controlled actual serving readiness cancellation",)
        )
        self.assertTrue(all(sock.fileno() == -1 for sock in sockets))
        self.assertFalse(started[0].is_serving())
        self.assert_closed(owners)
        self.assertFalse(owners.profiles)
        self.assertIsNone(owners.browser)

