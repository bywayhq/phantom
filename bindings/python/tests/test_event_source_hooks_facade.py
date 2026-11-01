"""Source-owned callback cancellation and reconnects without native code."""

import asyncio
import types
import unittest
from unittest.mock import patch

from test_event_source_facade import Source
from test_header_hooks_facade import hooks_module
from test_upload_errors import FACADE


class SourceMailbox:
    def __init__(self, count, redirects=False, source=False):
        if redirects or not source:
            raise AssertionError("expected a source-owned header mailbox")
        self.count = count
        self.queue = asyncio.Queue()
        self.changed = asyncio.Event()
        self.queued = asyncio.Event()
        self.closed = False
        self.cancelled = 0
        self.serial = 0
        self.active = None
        self.reply = None

    def begin(self, index=0, fields=()):
        if self.active is not None:
            raise AssertionError("overlapping native invocations")
        self.serial += 1
        self.active = self.serial
        self.reply = asyncio.get_running_loop().create_future()
        self.queue.put_nowait(
            (self.serial, index, "GET", "https://local/events", list(fields))
        )
        self.queued.set()
        return self.reply

    async def invoke(self, index=0, fields=()):
        return await self.begin(index, fields)

    async def next(self):
        return await self.queue.get()

    async def next_cancelled(self, after):
        while not self.closed and self.cancelled <= after:
            self.changed.clear()
            await self.changed.wait()
        return None if self.closed else self.cancelled

    def is_active(self, serial):
        return not self.closed and self.active == serial

    def cancel_current(self):
        self.cancel_get(self.active)

    def cancel_get(self, serial):
        # Match the native invocation guard: a reply already delivered no longer
        # owns the slot, so its subsequent drop cannot cancel a later invocation.
        if self.active != serial or serial is None:
            return
        self.cancelled = serial
        self.active = None
        self.reply.cancel()
        self.changed.set()

    def complete(self, serial, edits):
        if not self.is_active(serial):
            raise FACADE._native.NativeError("input", "header_hook_closed", None, None)
        self.active = None
        self.reply.set_result(edits)

    def fail(self, serial, original):
        if not self.is_active(serial):
            raise FACADE._native.NativeError("input", "header_hook_closed", None, None)
        self.active = None
        failure = FACADE._native.NativeError("request", "header_hook", "h1", None)
        failure.original = original
        self.reply.set_exception(failure)

    def abort(self):
        self.closed = True
        self.active = None
        if self.reply is not None and not self.reply.done():
            self.reply.cancel()
        self.changed.set()


class SourceHookTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        native = patch.object(
            FACADE._native, "NativeHeaderHooks", SourceMailbox, create=True
        )
        native.start()
        self.addCleanup(native.stop)

    async def test_close_does_not_cancel_callback_cleanup_again_for_queued_notice(self):
        entered, cleaning, release, exited = (asyncio.Event() for _ in range(4))
        notification, queued, deliver = (asyncio.Event() for _ in range(3))
        original = RuntimeError("late callback cleanup")

        async def callback(_):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                await release.wait()
                exited.set()
                raise original

        hooks = hooks_module.Hooks((callback,), False, source=True)

        async def next_cancelled(after):
            if after:
                return None
            await notification.wait()
            queued.set()
            await deliver.wait()
            return 1

        hooks.native.next_cancelled = next_cancelled
        first = hooks.native.begin()
        try:
            await asyncio.wait_for(entered.wait(), 1)
            notification.set()
            await asyncio.wait_for(queued.wait(), 1)
            hooks.close()
            await asyncio.wait_for(cleaning.wait(), 1)
            deliver.set()
            self.assertFalse(await hooks.wait(timeout_ms=20))
            self.assertFalse(exited.is_set())
            hooks.close()
            self.assertFalse(await hooks.wait(timeout_ms=20))
            release.set()
            self.assertTrue(await hooks.wait())
            self.assertTrue(exited.is_set())
            self.assertIs(hooks.cleanup_error, original)
        finally:
            release.set()
            deliver.set()
            hooks.close()
            self.assertTrue(await hooks.wait())
            with self.assertRaises(asyncio.CancelledError):
                await first

    async def test_timed_out_get_waits_for_cleanup_then_reuses_the_same_owner(self):
        entered, cleaning, release = (asyncio.Event() for _ in range(3))
        calls = []
        original = RuntimeError("late cleanup")

        async def callback(context):
            calls.append(context)
            if len(calls) == 1:
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cleaning.set()
                    await release.wait()
                    raise original
            context.append(("x-next", "ready"))

        hooks = hooks_module.Hooks((callback,), False, source=True)
        first = asyncio.create_task(hooks.native.invoke())
        second = None
        try:
            await entered.wait()
            hooks.native.cancel_current()
            with self.assertRaises(asyncio.CancelledError):
                await first
            await cleaning.wait()
            hooks.native.queued.clear()
            second = asyncio.create_task(hooks.native.invoke())
            await hooks.native.queued.wait()
            self.assertEqual(len(calls), 1)
            self.assertFalse(second.done())
            release.set()
            self.assertEqual(
                await asyncio.wait_for(second, 1),
                [("append", "x-next", b"ready", False)],
            )
            self.assertIs(hooks.cleanup_error, original)
            self.assertFalse(hooks.closing)
        finally:
            release.set()
            hooks.close()
            self.assertTrue(await hooks.wait())
            if second is not None:
                await asyncio.gather(second, return_exceptions=True)

    async def test_cancelled_undelivered_invocation_and_stale_reply_cannot_reach_next_get(
        self,
    ):
        seen = []
        hooks = hooks_module.Hooks(
            (lambda context: seen.append(context),), False, source=True
        )
        try:
            first = hooks.native.begin()
            hooks.native.cancel_current()
            with self.assertRaises(asyncio.CancelledError):
                await first
            second = hooks.native.begin()
            with self.assertRaises(FACADE._native.NativeError):
                hooks.native.complete(1, [("append", "x-stale", b"bad", False)])
            self.assertEqual(await asyncio.wait_for(second, 1), [])
            self.assertEqual(len(seen), 1)
        finally:
            hooks.close()
            self.assertTrue(await hooks.wait())

    async def test_terminal_close_does_not_cancel_a_callback_finalizer_twice(self):
        entered, cleaning, release, finished = (asyncio.Event() for _ in range(4))

        async def callback(context):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await release.wait()
                finished.set()

        hooks = hooks_module.Hooks((callback,), False, source=True)
        pending = asyncio.create_task(hooks.native.invoke())
        try:
            await entered.wait()
            hooks.native.cancel_current()
            with self.assertRaises(asyncio.CancelledError):
                await pending
            await cleaning.wait()
            hooks.close()
            self.assertFalse(await hooks.wait(0))
            self.assertFalse(finished.is_set())
            release.set()
            self.assertTrue(await hooks.wait())
            self.assertTrue(finished.is_set())
        finally:
            release.set()
            hooks.close()
            await hooks.wait()

    async def test_delivered_error_remains_owned_if_core_deadline_wins_the_result(self):
        original = ValueError("callback raced deadline")
        calls = []

        def callback(context):
            calls.append(context)
            if len(calls) == 1:
                raise original
            context.append(("x-next", "ready"))

        hooks = hooks_module.Hooks((callback,), False, source=True)
        try:
            # Delivery succeeded, but the core may select its deadline instead of
            # consuming this result. It then admits another GET on the same owner.
            with self.assertRaises(FACADE._native.NativeError) as caught:
                await hooks.native.invoke()
            self.assertIs(caught.exception.original, original)
            hooks.native.cancel_get(1)
            self.assertEqual(
                await hooks.native.invoke(), [("append", "x-next", b"ready", False)]
            )
            self.assertIs(hooks.cleanup_error, original)
        finally:
            hooks.close()
            self.assertTrue(await hooks.wait())

    async def test_field_allowance_resets_at_each_fresh_get_but_not_between_callbacks(
        self,
    ):
        def first(context):
            if len(context.headers) == 257:
                context.remove("x-256")

        def second(context):
            context.append(("x-256", "restored"))

        hooks = hooks_module.Hooks((first, second), False, source=True)
        try:
            fields = [(f"x-{index}", b"a", False) for index in range(257)]
            await hooks.native.invoke(0, fields)
            await hooks.native.invoke(1, fields[:-1])
            fields.pop()
            await hooks.native.invoke(0, fields)
            with self.assertRaises(FACADE._native.NativeError) as caught:
                await hooks.native.invoke(1, fields)
            self.assertIsInstance(caught.exception.original, ValueError)
        finally:
            hooks.close()
            self.assertTrue(await hooks.wait())

    async def test_opening_and_reconnect_share_client_and_source_hooks_until_close(
        self,
    ):
        calls = []
        native_source = Source()
        mailbox = None

        async def connect(*args, header_hooks=None, **kwargs):
            nonlocal mailbox
            mailbox = header_hooks
            for index in range(mailbox.count):
                await mailbox.invoke(index)
            return native_source

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(event_source=connect, cookies=object()),
            (lambda context: calls.append("client"),),
        )
        source = await client.event_source(
            "https://local/events",
            protocol="h2",
            header_hooks=(lambda context: calls.append("source"),),
        )
        try:
            self.assertEqual(calls, ["client", "source"])
            self.assertEqual(len(client._header_pumps), 1)
            for index in range(mailbox.count):
                await mailbox.invoke(index)
            self.assertEqual(calls, ["client", "source", "client", "source"])
        finally:
            await source.aclose()
        self.assertEqual(len(client._header_pumps), 0)

    async def test_without_client_hooks_and_original_failure_identity(self):
        original = LookupError("callback")
        called = []

        def callback(context):
            called.append("source")
            raise original

        async def connect(*args, header_hooks=None, **kwargs):
            try:
                await header_hooks.invoke()
            finally:
                header_hooks.abort()

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(event_source=connect, cookies=object()),
            (lambda context: called.append("client"),),
        )
        with self.assertRaises(FACADE.Error) as caught:
            await client.event_source(
                "https://local/events",
                protocol="h1",
                header_hooks=(callback,),
                without_client_hooks=True,
            )
        self.assertIs(caught.exception.original, original)
        self.assertEqual(called, ["source"])
        self.assertEqual(len(client._header_pumps), 0)

    async def test_late_cleanup_failure_is_observed_once_by_source_close(self):
        original = RuntimeError("late cleanup")
        native_source = Source()

        async def connect(*args, **kwargs):
            return native_source

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(event_source=connect, cookies=object())
        )
        source = await client.event_source(
            "https://local/events", protocol="h1", header_hooks=(lambda context: None,)
        )
        source._hooks.cleanup_error = original
        with self.assertRaises(FACADE.Error) as caught:
            await source.aclose()
        self.assertEqual(caught.exception.kind, "header_hook_cleanup")
        self.assertIs(caught.exception.original, original)
        self.assertEqual(len(client._header_pumps), 0)
        await source.aclose()
