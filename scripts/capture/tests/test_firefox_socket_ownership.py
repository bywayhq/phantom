import asyncio
import errno
import json
import subprocess
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.browser_failures import BrowserLaunchFailures
from scripts.capture.browser_launch import LaunchPlan


class ObservedEvent(asyncio.Event):
    def __init__(self) -> None:
        super().__init__()
        self.entered = asyncio.Event()

    async def wait(self) -> bool:
        self.entered.set()
        return await super().wait()


class OriginOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_websocket_ticker_failure_is_observed_with_its_original_cause(
        self,
    ) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["websocket"])
        tick_failed = asyncio.Event()
        cause = OSError(errno.EIO, "independent tick failure")
        real_sleep = asyncio.sleep

        async def sleep(seconds):
            if seconds != 5:
                await real_sleep(seconds)

        def accept(reader, writer):
            real_write = writer.write

            def write(data):
                if data == b"\x81\x04tick":
                    tick_failed.set()
                    raise cause
                real_write(data)

            writer.write = write
            owner.origins.accept_target(reader, writer)

        listener = await asyncio.start_server(accept, "127.0.0.1", 0)
        owner.origins.listeners.append(listener)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )
        try:
            with patch.object(hooks.asyncio, "sleep", side_effect=sleep):
                writer.write(
                    b"GET /ws HTTP/1.1\r\nHost: x\r\nSec-WebSocket-Key: x\r\n\r\n"
                )
                await writer.drain()
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                await asyncio.wait_for(tick_failed.wait(), 2)
                writer.write(b"\x88\x82\x00\x00\x00\x00\x03\xe8")
                await writer.drain()
                self.assertEqual(
                    await asyncio.wait_for(reader.readexactly(4), 2),
                    b"\x88\x02\x03\xe8",
                )
                await asyncio.wait_for(owner.origins.failed.wait(), 2)

                failures = await owner.finish()

            self.assertIn(cause, failures)
            self.assertFalse(owner.origins.peers)
            self.assertFalse(owner.origins.writers)
        finally:
            writer.close()
            await writer.wait_closed()
            await owner.finish()

    async def test_the_scripted_masked_close_keeps_its_original_reply_bytes(
        self,
    ) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["websocket"])
        listener = await asyncio.start_server(
            owner.origins.accept_target, "127.0.0.1", 0
        )
        owner.origins.listeners.append(listener)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )
        try:
            writer.write(
                b"GET /ws HTTP/1.1\r\nHost: x\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            self.assertIn(b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", head)

            writer.write(b"\x88\x82\x00\x00\x00\x00\x03\xe8")
            await writer.drain()
            reply = await asyncio.wait_for(reader.readexactly(4), 2)
            self.assertEqual(reply, b"\x88\x02\x03\xe8")
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")

            self.assertEqual(await owner.finish(), ())
            self.assertEqual(owner.origins.connections[0].close_kind, "websocket")
            self.assertFalse(owner.origins.peers)
        finally:
            writer.close()
            await writer.wait_closed()
            await owner.finish()

    async def test_request_limit_keeps_the_first_real_response_and_retires_the_peer(
        self,
    ) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["http1-idle"])
        listener = await asyncio.start_server(
            owner.origins.accept_target, "127.0.0.1", 0
        )
        owner.origins.listeners.append(listener)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )
        try:
            with patch.object(hooks, "MAX_REQUESTS", 1):
                writer.write(b"GET /fast HTTP/1.1\r\nHost: x\r\n\r\n" * 2)
                await writer.drain()
                await asyncio.wait_for(owner.origins.failed.wait(), 2)
                received = await asyncio.wait_for(reader.read(), 2)
                failures = await owner.finish()

            self.assertEqual(received.count(b"HTTP/1.1 200 OK"), 1)
            self.assertIsInstance(failures[0], ValueError)
            self.assertEqual(len(owner.origins.connections[0].requests), 1)
            self.assertFalse(owner.origins.peers)
        finally:
            writer.close()
            await writer.wait_closed()
            await owner.finish()

    async def test_invalid_metadata_stops_before_any_capture_acquisition(self) -> None:
        args = SimpleNamespace(
            client_version="157.0", operating_system="Windows\nextra=1", repeat=1
        )
        with patch.object(hooks, "run_once") as run, self.assertRaises(ValueError):
            await hooks.capture(args, hooks.SCENARIOS["h2"])

        run.assert_not_called()

    async def test_cleanup_collects_a_real_peer_waiting_for_go(self) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["http1-idle"])
        owner.origins.go = ObservedEvent()
        listener = await asyncio.start_server(owner.origins.accept_page, "127.0.0.1", 0)
        owner.origins.listeners.append(listener)
        port = listener.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"GET /go HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(owner.origins.go.entered.wait(), 2)
            accepted = next(iter(owner.origins.writers))
            task = next(iter(owner.origins.peers))
            self.assertFalse(task.done())

            failures = await owner.finish()

            self.assertEqual(failures, ())
            self.assertTrue(task.done())
            self.assertTrue(accepted.is_closing())
            self.assertFalse(owner.origins.peers)
            self.assertFalse(owner.origins.writers)
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        finally:
            writer.close()
            await writer.wait_closed()
            await owner.finish()

    async def test_actual_response_and_close_failures_keep_both_original_objects(
        self,
    ) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["http1-idle"])
        write_error = OSError(errno.EIO, "independent response failure")
        close_error = ValueError("independent close failure")
        accepted = {}

        def accept(reader, writer):
            accepted["writer"] = writer
            real_close = writer.close
            closed = False

            def fail_write(_data):
                raise write_error

            def close():
                nonlocal closed
                real_close()
                if not closed:
                    closed = True
                    raise close_error

            writer.write = fail_write
            writer.close = close
            owner.origins.accept_target(reader, writer)

        listener = await asyncio.start_server(accept, "127.0.0.1", 0)
        owner.origins.listeners.append(listener)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )
        try:
            writer.write(b"GET /fast HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(owner.origins.failed.wait(), 2)

            failures = await owner.finish()

            packet = next(
                error for error in failures if isinstance(error, BrowserLaunchFailures)
            )
            self.assertIs(packet.primary, write_error)
            self.assertIn(close_error, packet.cleanup)
            self.assertTrue(accepted["writer"].is_closing())
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            self.assertFalse(owner.origins.peers)
        finally:
            writer.close()
            await writer.wait_closed()
            await owner.finish()

    async def test_active_peer_limit_closes_the_listener_and_collects_rejected_writer(
        self,
    ) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["http1-idle"])
        owner.origins.go = ObservedEvent()
        listener = await asyncio.start_server(owner.origins.accept_page, "127.0.0.1", 0)
        owner.origins.listeners.append(listener)
        port = listener.sockets[0].getsockname()[1]
        clients = []
        try:
            with patch.object(hooks, "MAX_ACTIVE_PEERS", 1):
                first = await asyncio.open_connection("127.0.0.1", port)
                clients.append(first)
                first[1].write(b"GET /go HTTP/1.1\r\nHost: x\r\n\r\n")
                await first[1].drain()
                await asyncio.wait_for(owner.origins.go.entered.wait(), 2)
                clients.append(await asyncio.open_connection("127.0.0.1", port))
                await asyncio.wait_for(owner.origins.failed.wait(), 2)

                failures = await owner.finish()

            self.assertIsInstance(failures[0], ValueError)
            self.assertFalse(listener.is_serving())
            self.assertFalse(owner.origins.writers)
            self.assertFalse(owner.origins.peers)
        finally:
            for _, writer in clients:
                writer.close()
                await writer.wait_closed()
            await owner.finish()

    async def test_failure_of_second_listener_retires_the_first_listener(self) -> None:
        real_start = asyncio.start_server
        listeners = []
        cause = OSError(errno.EIO, "independent target listener failure")

        async def start(*args, **kwargs):
            if listeners:
                raise cause
            listener = await real_start(*args, **kwargs)
            listeners.append(listener)
            return listener

        with (
            patch.object(hooks.asyncio, "start_server", side_effect=start),
            self.assertRaises(OSError) as observed,
        ):
            await hooks.run_once(hooks.SCENARIOS["http1-idle"], Path("unused"))

        self.assertIs(observed.exception, cause)
        self.assertFalse(listeners[0].is_serving())


class NativeOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_interrupted_launch_retains_worker_until_actual_exit(self) -> None:
        entering = threading.Event()
        release = threading.Event()
        exited = threading.Event()
        cause = OSError(errno.EIO, "independent delayed launch failure")

        class Browser:
            def __init__(self, *_args):
                pass

            def __enter__(self):
                entering.set()
                release.wait()
                raise cause

            def __exit__(self, *_args):
                exited.set()

        owner = hooks._FirefoxRun(hooks.SCENARIOS["http1-idle"])
        with patch.object(hooks, "LaunchedBrowser", Browser):
            native = hooks._FirefoxNative(
                owner,
                LaunchPlan("firefox", Path("unused"), True),
                "http://127.0.0.1/",
                {},
            )
        owner.native = native
        native.start()
        cancellation = asyncio.CancelledError("independent caller cancellation")
        observations = []
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: observations.append(context))
        try:
            self.assertTrue(await asyncio.to_thread(entering.wait, 2))
            with patch.object(hooks, "NATIVE_CLEANUP_SECONDS", 0.02):
                failures = await owner.finish(cancellation)

            pending = next(
                error
                for error in failures
                if isinstance(error, hooks._FirefoxCapturePending)
            )
            self.assertIs(pending.owner, owner)
            self.assertFalse(native.future.cancelled())
            self.assertFalse(exited.is_set())
        finally:
            release.set()
            try:
                await asyncio.wait_for(asyncio.shield(owner.cleanup), 2)
                failures = await owner.finish(cancellation)
            finally:
                loop.set_exception_handler(previous_handler)

        self.assertIn(cause, failures)
        self.assertIs(observations[0]["exception"], cause)
        self.assertIs(observations[0]["primary"], cancellation)
        self.assertIs(observations[0]["owner"], owner)
        self.assertTrue(exited.is_set())
        self.assertTrue(native.future.done())
        self.assertFalse(native.future.cancelled())


class HookBoundaryTests(unittest.TestCase):
    def test_native_error_message_keeps_the_original_structured_message(self) -> None:
        message = {"type": "error", "description": "independent native hook failure"}
        owner = hooks.Hooks(1, {})
        owner._on_message(message, None)

        self.assertIsInstance(owner.failure, hooks._FirefoxAgentFailure)
        self.assertIs(owner.failure.message, message)
        self.assertEqual(json.loads(owner.errors[0]), message)
        self.assertTrue(owner.ready.is_set())

    def test_native_message_failure_is_retained_and_releases_the_ready_waiter(
        self,
    ) -> None:
        owner = hooks.Hooks(1, {})
        owner._on_message({"type": "send", "payload": None}, None)

        self.assertIsInstance(owner.failure, ValueError)
        self.assertTrue(owner.ready.is_set())
        self.assertEqual(owner.snapshot(), ([], []))

    def test_report_count_and_message_bytes_are_bounded_without_dropping_old_reports(
        self,
    ) -> None:
        message = {"type": "send", "payload": {"kind": "socket", "time_ms": 1}}
        owner = hooks.Hooks(1, {})
        with patch.object(hooks, "MAX_HOOK_REPORTS", 1):
            owner._on_message(message, None)
            owner._on_message(message, None)

        self.assertEqual(owner.reports, [message["payload"]])
        self.assertIsInstance(owner.failure, ValueError)

        owner = hooks.Hooks(1, {})
        with patch.object(
            hooks, "MAX_HOOK_MESSAGE_BYTES", len(json.dumps(message)) - 1
        ):
            owner._on_message(message, None)

        self.assertEqual(owner.reports, [])
        self.assertIsInstance(owner.failure, ValueError)

    def test_unexpected_detach_keeps_the_original_crash_object(self) -> None:
        crash = object()
        owner = hooks.Hooks(1, {})
        owner._on_detached("process-terminated", crash)

        self.assertIsInstance(owner.failure, hooks._FirefoxSessionDetached)
        self.assertIs(owner.failure.crash, crash)
        self.assertTrue(owner.ready.is_set())

    def test_profile_with_a_quote_is_data_rather_than_powershell_source(self) -> None:
        profile = Path("C:/Users/A'B/Temp/profile")
        result = subprocess.CompletedProcess(
            ["powershell"], 0, stdout=b"[]", stderr=b""
        )
        with patch.object(hooks.subprocess, "run", return_value=result) as run:
            self.assertEqual(hooks.profile_processes(profile), [])

        self.assertEqual(
            run.call_args.kwargs["env"]["PHANTOM_FIREFOX_PROFILE"], str(profile)
        )
        self.assertNotIn(str(profile), run.call_args.args[0][-1])

    def test_nonfinite_and_nonpositive_capture_waits_are_rejected(self) -> None:
        for value in (0, -1, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                hooks.validate_waits(
                    replace(hooks.SCENARIOS["h2"], limit_seconds=value)
                )


if __name__ == "__main__":
    unittest.main()
