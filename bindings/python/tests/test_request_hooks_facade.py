"""Logical callback phases and ownership without loading native transport."""

import asyncio
import contextvars
import dataclasses
import unittest
from unittest.mock import patch

from test_event_source_hooks_facade import SourceMailbox
from test_header_hooks_facade import Native, hooks_module
from test_upload_errors import FACADE

TRACE = contextvars.ContextVar("logical-hook-trace", default=None)


class LogicalMailbox(SourceMailbox):
    def __init__(self, count, redirects=False, source=False, logical=False):
        if not logical or source:
            raise AssertionError("expected a request-owned logical mailbox")
        super().__init__(count, source=True)

    def begin_logical(self, phase, *metadata):
        if self.active is not None:
            raise AssertionError("overlapping native invocations")
        self.serial += 1
        self.active = self.serial
        self.reply = asyncio.get_running_loop().create_future()
        self.queue.put_nowait(
            (self.serial, phase, "GET", "https://local/private?secret", *metadata)
        )
        return self.reply

    def complete_logical(self, serial):
        self.complete(serial, None)

    def fail(self, serial, original):
        if not self.is_active(serial):
            return super().fail(serial, original)
        self.active = None
        failure = FACADE._native.NativeError("request", "request_hook", None, None)
        failure.original = original
        self.reply.set_exception(failure)


class LogicalHookTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        native = patch.object(
            FACADE._native, "NativeHeaderHooks", LogicalMailbox, create=True
        )
        native.start()
        self.addCleanup(native.stop)

    def owner(self, *observers, synchronous=False):
        owner = hooks_module.Hooks((), synchronous, observers=observers)
        self.addAsyncCleanup(self.close_owner, owner)
        return owner

    async def close_owner(self, owner):
        owner.close()
        await owner.settled

    async def test_client_first_metadata_is_immutable_and_context_is_preserved(self):
        seen = []
        token = TRACE.set("owner")
        try:

            def request(context):
                seen.append(("client:request", TRACE.get()))
                self.assertNotIn("secret", repr(context))
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    context.url = "replacement"

            async def response(context):
                await asyncio.sleep(0)
                seen.append(("client:response", TRACE.get()))
                self.assertEqual(context.status, 404)
                self.assertEqual(
                    context.headers.get_list("x-duplicate"), [b"one", b"two"]
                )
                self.assertEqual(
                    (context.redirects_followed, context.retries_performed), (2, 3)
                )
                self.assertEqual(context.decoded_content_codings, ("gzip",))
                self.assertNotIn("secret", repr(context))
                self.assertFalse(hasattr(context, "body"))

            owner = self.owner(
                FACADE.AsyncRequestHooks(on_request=request, on_response=response),
                FACADE.RequestHooks(
                    on_request=lambda _: seen.append(("request:request", TRACE.get())),
                    on_response=lambda _: seen.append(
                        ("request:response", TRACE.get())
                    ),
                ),
            )
        finally:
            TRACE.reset(token)
        await owner.native.begin_logical("request")
        await owner.native.begin_logical(
            "response",
            404,
            "h2",
            [("x-duplicate", b"one", False), ("x-duplicate", b"two", False)],
            "https://local/final?secret",
            2,
            3,
            ["gzip"],
        )
        self.assertEqual(
            seen,
            [
                ("client:request", "owner"),
                ("request:request", "owner"),
                ("client:response", "owner"),
                ("request:response", "owner"),
            ],
        )

    async def test_delivered_failure_keeps_owner_for_error_phase_and_secondary_cause(
        self,
    ):
        original, secondary = (
            ValueError("secret original"),
            RuntimeError("secret secondary"),
        )
        seen = []

        def request(_):
            raise original

        def error(context):
            self.assertIs(context.error.original, original)
            seen.append(context.error)
            raise secondary

        owner = self.owner(FACADE.RequestHooks(on_request=request, on_error=error))
        with self.assertRaises(FACADE._native.NativeError) as first:
            await owner.native.begin_logical("request")
        self.assertFalse(owner.native.closed)
        with self.assertRaises(FACADE._native.NativeError) as second:
            await owner.native.begin_logical("error", first.exception)
        first.exception.hook_error = second.exception
        first.exception.origin = ("https", "local", 443)
        mapped = FACADE._error(first.exception)
        self.assertIs(mapped.original, original)
        self.assertIs(mapped.hook_error.original, secondary)
        self.assertEqual(mapped.origin, ("https", "local", 443))
        self.assertNotIn("secret", repr(mapped))
        self.assertIs(owner.error, original)
        self.assertEqual(len(seen), 1)
        owner.reported(mapped)
        self.assertIsNone(owner.cleanup_error)
        self.assertIsNone(owner.error_hook_failure)

    async def test_header_failure_can_be_followed_by_logical_error(self):
        original = LookupError("header")
        seen = []

        def header(_):
            raise original

        with patch.object(hooks_module, "_snapshot", wraps=hooks_module._snapshot):
            owner = hooks_module.Hooks(
                (header,),
                False,
                observers=(
                    FACADE.RequestHooks(
                        on_error=lambda context: seen.append(context.error.original)
                    ),
                ),
            )
        self.addAsyncCleanup(self.close_owner, owner)
        with self.assertRaises(FACADE._native.NativeError) as first:
            await owner.native.invoke()
        await owner.native.begin_logical("error", first.exception)
        self.assertEqual(seen, [original])

    async def test_cancelled_invocation_waits_for_real_cleanup_before_error_dispatch(
        self,
    ):
        entered, cleaning, release = (asyncio.Event() for _ in range(3))
        seen = []

        async def request(_):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                await release.wait()
                seen.append("cleaned")

        owner = self.owner(
            FACADE.AsyncRequestHooks(
                on_request=request, on_error=lambda _: seen.append("error")
            )
        )
        first = owner.native.begin_logical("request")
        await entered.wait()
        owner.native.cancel_current()
        await cleaning.wait()
        failure = FACADE._native.NativeError("request", "timeout", None, "total")
        following = owner.native.begin_logical("error", failure)
        self.assertFalse(following.done())
        release.set()
        await following
        self.assertTrue(first.cancelled())
        self.assertEqual(seen, ["cleaned", "error"])

    async def test_stale_queued_phase_is_not_dispatched(self):
        seen = []
        owner = self.owner(
            FACADE.RequestHooks(
                on_request=lambda _: seen.append("stale"),
                on_error=lambda _: seen.append("error"),
            )
        )
        first = owner.native.begin_logical("request")
        owner.native.cancel_current()
        failure = FACADE._native.NativeError("request", "timeout", None, "total")
        await owner.native.begin_logical("error", failure)
        self.assertTrue(first.cancelled())
        self.assertEqual(seen, ["error"])

    async def test_sync_rejects_awaitables_and_observes_the_error_phase(self):
        async def request(_):
            return None

        seen = []
        owner = self.owner(
            FACADE.RequestHooks(
                on_request=request,
                on_error=lambda context: seen.append(context.error.original),
            ),
            synchronous=True,
        )
        with self.assertRaises(FACADE._native.NativeError) as caught:
            await owner.native.begin_logical("request")
        await owner.native.begin_logical("error", caught.exception)
        self.assertIsInstance(seen[0], TypeError)

    async def test_exception_after_terminal_close_is_owned_until_cleanup_finishes(self):
        entered, cleaning, release = (asyncio.Event() for _ in range(3))
        late = RuntimeError("late cleanup")

        async def request(_):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                await release.wait()
                raise late

        owner = self.owner(FACADE.AsyncRequestHooks(on_request=request))
        owner.native.begin_logical("request")
        await entered.wait()
        owner.close()
        await cleaning.wait()
        self.assertFalse(owner.settled.done())
        release.set()
        await owner.settled
        self.assertIs(owner.cleanup_error, late)

    async def test_upload_cleanup_cannot_overwrite_a_native_callback_cause(self):
        original, producer = ValueError("callback"), RuntimeError("producer")
        failure = FACADE._native.NativeError("request", "request_hook", None, None)
        failure.original = original
        upload = type("Upload", (), {"error": producer, "cleanup_error": None})()
        self.assertIs(FACADE._primary_error(failure, upload).original, original)

    async def test_cancel_after_delivered_failures_retains_two_causes_without_completed_owners(
        self,
    ):
        first, second = ValueError("first"), LookupError("second")

        def request(_):
            raise first

        def error(_):
            raise second

        owner = self.owner(FACADE.RequestHooks(on_request=request, on_error=error))
        with self.assertRaises(FACADE._native.NativeError) as initial:
            await owner.native.begin_logical("request")
        with self.assertRaises(FACADE._native.NativeError):
            await owner.native.begin_logical("error", initial.exception)
        # Both replies were delivered. Native cancellation now wins before the
        # public boundary exposes either error; their owner must still be released.
        owner.close()
        await owner.settled
        client = FACADE.AsyncClient._from_native(Native())
        client._header_pumps.add(owner)
        cancellation = asyncio.CancelledError()
        self.assertIs(client._finish_logical_hooks(owner, cancellation), cancellation)
        self.assertFalse(client._header_pumps)
        with self.assertRaises(FACADE.Error) as caught:
            await client.close()
        self.assertIs(caught.exception.original, first)
        self.assertIs(caught.exception.hook_error.original, second)
        client._settle_header_hooks(owner)
        await client.close()

    async def test_empty_observers_use_the_same_path_as_no_hooks(self):
        with (
            patch.object(FACADE._native, "NativeClient", Native, create=True),
            patch.object(
                FACADE._native,
                "NativeHeaderHooks",
                side_effect=AssertionError("empty hooks must not cross the bridge"),
            ) as constructor,
        ):
            client = FACADE.AsyncClient(
                profile="exact-profile", request_hooks=FACADE.RequestHooks()
            )
            response = await client.get(
                "https://local", request_hooks=FACADE.AsyncRequestHooks()
            )
            self.assertEqual(response.status, 200)
            constructor.assert_not_called()
            await client.close()
