"""Owning-loop callback contracts without loading native code."""

import asyncio
import contextlib
import contextvars
import types
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE

hooks_module = __import__(FACADE.__name__ + "._header_hooks", fromlist=["_"])
TRACE = contextvars.ContextVar("header-hook-trace", default=None)


class Mailbox:
    def __init__(self, count):
        self.count = count
        self.queue = asyncio.Queue()
        self.closed = asyncio.Event()
        self.reply = None
        self.serial = 0

    async def next(self):
        return await self.queue.get()

    async def terminal(self):
        await self.closed.wait()

    async def invoke(self, index, fields=()):
        self.serial += 1
        self.reply = asyncio.get_running_loop().create_future()
        self.queue.put_nowait(
            (self.serial, index, "GET", "https://local/", list(fields))
        )
        return await self.reply

    def complete(self, serial, edits):
        if self.closed.is_set() or self.reply.done() or serial != self.serial:
            raise FACADE._native.NativeError("input", "header_hook_closed", None, None)
        self.reply.set_result(edits)

    def fail(self, serial, original):
        failure = FACADE._native.NativeError("request", "header_hook", "h1", None)
        failure.original = original
        self.reply.set_exception(failure)

    def abort(self):
        self.closed.set()


class Native:
    cookies = object()
    is_closed = False

    def __init__(self, *args, **kwargs):
        self.calls = []

    async def request(self, *args, header_hooks=None, **kwargs):
        self.calls.append(header_hooks)
        if header_hooks is not None:
            try:
                for index in range(header_hooks.count):
                    await header_hooks.invoke(index)
            finally:
                header_hooks.abort()
        return types.SimpleNamespace(status=200, protocol="h1", headers=[])

    def fork(self, *args):
        return Native()

    def restore_session(self, *args):
        return Native()

    async def shutdown(self, timeout_ms):
        self.is_closed = True

    def abort(self):
        self.is_closed = True


class ContextTests(unittest.TestCase):
    def test_ordered_local_edits_bytes_sensitivity_bounds_and_closed_context(self):
        context = FACADE.HeaderHookContext(
            "POST",
            "https://local/private?canary",
            [
                ("X-First", b"one", False),
                ("X-T", b"old", False),
                ("x-t", b"duplicate", False),
                ("X-Last", b"end", False),
            ],
        )
        context.set(FACADE.Header("X-T", b"\xff", sensitive=True))
        context.append(("x-t", "last"))
        context.remove("X-FIRST")
        self.assertEqual(
            [(h.name, h.value, h.sensitive) for h in context.headers],
            [
                ("X-T", b"\xff", True),
                ("X-Last", b"end", False),
                ("x-t", b"last", False),
            ],
        )
        self.assertNotIn("canary", repr(context))
        before = context.headers
        with self.assertRaises(ValueError):
            context.append(("X", b"x" * 65536))
        self.assertEqual(context.headers, before)
        context._finish()
        for mutation in (
            lambda: context.append(("X", "a")),
            lambda: context.set(("X", "b")),
            lambda: context.remove("X"),
        ):
            with self.assertRaisesRegex(RuntimeError, "closed"):
                mutation()

    def test_callback_inventory_is_bounded_without_consuming_unlimited_input(self):
        consumed = []

        def callbacks():
            for index in range(1000):
                consumed.append(index)
                yield lambda context: None

        with self.assertRaises(ValueError):
            hooks_module._snapshot(callbacks())
        self.assertEqual(len(consumed), 257)


class HookPumpTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.native = patch.object(
            FACADE._native, "NativeHeaderHooks", Mailbox, create=True
        )
        self.native.start()
        self.addCleanup(self.native.stop)

    async def test_distinct_request_owners_inherit_context_and_release_the_loop(self):
        entered, release = asyncio.Event(), asyncio.Event()
        seen = []

        async def slow(context):
            seen.append(
                (TRACE.get(), asyncio.get_running_loop(), context.method, context.url)
            )
            entered.set()
            await release.wait()
            context.append(("X-Slow", "done"))

        token = TRACE.set("sending-task")
        first = hooks_module.Hooks((slow,), False)
        TRACE.reset(token)
        second = hooks_module.Hooks(
            (lambda context: context.append(("X-Fast", "done")),), False
        )
        pending = asyncio.create_task(first.native.invoke(0))
        await entered.wait()
        self.assertEqual(
            await second.native.invoke(0), [("append", "X-Fast", b"done", False)]
        )
        self.assertFalse(pending.done())
        self.assertEqual(
            seen,
            [("sending-task", asyncio.get_running_loop(), "GET", "https://local/")],
        )
        release.set()
        self.assertEqual(await pending, [("append", "X-Slow", b"done", False)])
        for owner in (first, second):
            owner.close()
            self.assertTrue(await owner.wait())

    async def test_original_exception_and_callback_cancel_are_header_failures(self):
        for original in (
            ValueError("private-canary"),
            asyncio.CancelledError("callback"),
        ):

            def callback(context, original=original):
                raise original

            owner = hooks_module.Hooks((callback,), False)
            try:
                with self.assertRaises(FACADE._native.NativeError) as caught:
                    await owner.native.invoke(0)
                mapped = FACADE._error(caught.exception)
                self.assertEqual(mapped.kind, "header_hook")
                self.assertIs(mapped.original, original)
                self.assertIsNotNone(original.__traceback__)
                self.assertNotIn("canary", str(mapped))
            finally:
                owner.close()
                self.assertTrue(await owner.wait())

    async def test_closed_receiver_cancels_host_task_and_retains_uncooperative_cleanup(
        self,
    ):
        entered, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        contexts = []

        async def callback(context):
            contexts.append(context)
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelled.set()
                await release.wait()
                context.append(("X-Late", "forbidden"))

        owner = hooks_module.Hooks((callback,), False)
        request = asyncio.create_task(owner.native.invoke(0))
        await entered.wait()
        owner.native.abort()
        await cancelled.wait()
        self.assertFalse(await owner.wait(0))
        with self.assertRaisesRegex(RuntimeError, "closed"):
            contexts[0].remove("X")
        release.set()
        self.assertTrue(await owner.wait())
        self.assertIsInstance(owner.cleanup_error, RuntimeError)
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request

    async def test_defaults_are_snapshotted_and_survive_fork_restore_with_no_offpath_owner(
        self,
    ):
        with patch.object(FACADE._native, "NativeClient", Native, create=True):
            calls = []
            callbacks = [lambda context: calls.append("client")]
            source = FACADE.AsyncClient(
                profile="chrome-154-windows", header_hooks=callbacks
            )
            callbacks.clear()
            child = source.fork()
            restored = await source.restore_session(b"snapshot", b"k" * 32)
            for client in (source, child, restored):
                await client.get(
                    "https://local/",
                    header_hooks=(lambda context: calls.append("request"),),
                )
                await client.close()
            self.assertEqual(calls, ["client", "request"] * 3)
            ordinary = FACADE.AsyncClient(profile="chrome-154-windows")
            await ordinary.get("https://local/")
            self.assertEqual(ordinary._native.calls, [None])
            await ordinary.close()

    async def test_timeout_and_caller_cancel_keep_precedence_over_late_callback_failure(
        self,
    ):
        for cancellation in (False, True):
            entered = asyncio.Event()
            original = ValueError("private-late-failure")

            async def callback(context, original=original, entered=entered):
                entered.set()
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    raise original from None

            class FailingNative(Native):
                async def request(
                    self,
                    *args,
                    header_hooks=None,
                    _cancellation=cancellation,
                    _entered=entered,
                    **kwargs,
                ):
                    invocation = asyncio.create_task(header_hooks.invoke(0))
                    try:
                        await _entered.wait()
                        if _cancellation:
                            await asyncio.Future()
                        raise FACADE._native.NativeError(
                            "request", "timeout", "h1", "total"
                        )
                    finally:
                        header_hooks.abort()
                        invocation.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await invocation

            client = FACADE.AsyncClient._from_native(FailingNative())
            request = asyncio.create_task(
                client.get("https://local/", header_hooks=(callback,))
            )
            await entered.wait()
            if cancellation:
                request.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await request
                with self.assertRaises(FACADE.Error) as caught:
                    await client.close()
                self.assertEqual(caught.exception.kind, "header_hook_cleanup")
                self.assertIs(caught.exception.original, original)
            else:
                with self.assertRaises(FACADE.TimeoutError) as caught:
                    await request
                self.assertEqual(caught.exception.timeout_phase, "total")
                self.assertIs(caught.exception.cleanup_error, original)
            await client.close()

    async def test_late_cleanup_failure_stays_owned_until_client_close_reports_it(self):
        entered, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original = OSError("private-cleanup-canary")

        async def callback(context):
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelled.set()
                await release.wait()
                raise original from None

        client = FACADE.AsyncClient._from_native(Native())
        owner = hooks_module.Hooks((callback,), False)
        client._header_pumps.add(owner)
        owner.settled.add_done_callback(lambda _: client._settle_header_hooks(owner))
        request = asyncio.create_task(owner.native.invoke(0))
        await entered.wait()
        owner.close()
        await cancelled.wait()
        self.assertFalse(await owner.wait(0))
        release.set()
        self.assertTrue(await owner.wait())
        self.assertIn(owner, client._header_pumps)
        with self.assertRaises(FACADE.Error) as caught:
            await client.close()
        self.assertEqual(caught.exception.kind, "header_hook_cleanup")
        self.assertIs(caught.exception.original, original)
        self.assertNotIn("canary", str(caught.exception))
        self.assertNotIn(owner, client._header_pumps)
        await client.close()
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request


class SyncHookTests(unittest.TestCase):
    def test_sync_callbacks_use_private_loop_and_reject_awaitables_and_reentry(self):
        with (
            patch.object(FACADE._native, "NativeHeaderHooks", Mailbox, create=True),
            patch.object(FACADE._native, "NativeClient", Native, create=True),
            FACADE.Client(profile="chrome-154-windows") as client,
        ):
            loops = []
            client.get(
                "https://local/",
                header_hooks=(
                    lambda context: loops.append(asyncio.get_running_loop()),
                ),
            )
            self.assertEqual(loops, [client._loop])

            async def asynchronous(context):
                pass

            with self.assertRaises(FACADE.Error) as caught:
                client.get("https://local/", header_hooks=(asynchronous,))
            self.assertIsInstance(caught.exception.original, TypeError)
            with self.assertRaises(FACADE.Error) as caught:
                client.get(
                    "https://local/",
                    header_hooks=(lambda context: client.get("https://local/"),),
                )
            self.assertIsInstance(caught.exception.original, RuntimeError)


if __name__ == "__main__":
    unittest.main()
