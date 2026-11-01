"""Source observer ownership and forwarding without native execution."""

import asyncio
import types
import unittest
from unittest.mock import patch

from test_event_source_facade import Source
from test_event_source_hooks_facade import SourceMailbox
from test_header_hooks_facade import hooks_module
from test_request_hooks_facade import LogicalMailbox
from test_upload_errors import FACADE


class SourceLogicalMailbox(LogicalMailbox):
    def __init__(self, count, redirects=False, source=False, logical=0):
        if not source or redirects or not logical:
            raise AssertionError("expected one source-owned logical mailbox")
        SourceMailbox.__init__(self, count, source=True)
        self.phases = logical


class SourceLogicalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        native = patch.object(
            FACADE._native, "NativeHeaderHooks", SourceLogicalMailbox, create=True
        )
        native.start()
        self.addCleanup(native.stop)

    async def test_client_first_observers_share_the_source_owner_on_each_get(self):
        seen, mailboxes = [], []

        async def connect(*args, header_hooks, **options):
            mailboxes.append(header_hooks)
            await header_hooks.begin_logical("request")
            return Source()

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(event_source=connect, cookies=object()),
            header_hooks=(lambda _: self.fail("inherited header hook was skipped"),),
            request_hooks=FACADE.RequestHooks(
                on_request=lambda _: seen.append("client")
            ),
        )
        async with client.event_source(
            "https://local/events",
            protocol="h2",
            without_client_hooks=True,
            request_hooks=FACADE.AsyncRequestHooks(
                on_request=lambda _: seen.append("source")
            ),
        ) as source:
            owner = source._hooks
            self.assertTrue(owner.source)
            self.assertEqual(mailboxes[0].phases, 1)
            self.assertEqual(mailboxes[0].count, 0)
            await owner.native.begin_logical("request")
            self.assertEqual(seen, ["client", "source", "client", "source"])
            self.assertEqual(len(client._header_pumps), 1)
        self.assertFalse(client._header_pumps)

    async def test_timed_out_get_retains_cleanup_before_next_logical_invocation(self):
        entered, cleaning, release = (asyncio.Event() for _ in range(3))
        calls = []
        late = RuntimeError("late source callback")

        async def callback(_):
            calls.append("request")
            if len(calls) == 1:
                entered.set()
                try:
                    await asyncio.Future()
                finally:
                    cleaning.set()
                    await release.wait()
                    raise late

        owner = hooks_module.Hooks(
            (),
            False,
            source=True,
            observers=(FACADE.AsyncRequestHooks(on_request=callback),),
        )
        try:
            first = owner.native.begin_logical("request")
            await asyncio.wait_for(entered.wait(), 1)
            owner.native.cancel_current()
            with self.assertRaises(asyncio.CancelledError):
                await first
            await asyncio.wait_for(cleaning.wait(), 1)
            second = owner.native.begin_logical("request")
            self.assertEqual(calls, ["request"])
            release.set()
            await asyncio.wait_for(second, 1)
            self.assertEqual(calls, ["request", "request"])
            self.assertIs(owner.cleanup_error, late)
        finally:
            release.set()
            owner.close()
            self.assertTrue(await owner.wait())

    async def test_two_delivered_failures_are_observed_once_on_source_close(self):
        original, secondary = ValueError("request"), RuntimeError("error phase")

        def fail(_):
            raise original

        def error(_):
            raise secondary

        owner = hooks_module.Hooks(
            (),
            False,
            source=True,
            observers=(FACADE.RequestHooks(on_request=fail, on_error=error),),
        )
        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(cookies=object())
        )
        client._header_pumps.add(owner)
        for phase, metadata in (
            ("request", ()),
            (
                "error",
                (FACADE._native.NativeError("request", "request_hook", None, None),),
            ),
        ):
            with self.assertRaises(FACADE._native.NativeError):
                await owner.native.begin_logical(phase, *metadata)
        source_module = __import__(
            FACADE.__name__ + "._event_source", fromlist=["AsyncEventSource"]
        )
        source = source_module.AsyncEventSource(Source(), owner, client)
        with self.assertRaises(FACADE.Error) as caught:
            await source.aclose()
        self.assertIs(caught.exception.original, original)
        self.assertIs(caught.exception.hook_error.original, secondary)
        self.assertFalse(client._header_pumps)
        await source.aclose()

    async def test_nested_public_failure_acknowledges_both_original_causes(self):
        owner = hooks_module.Hooks(
            (),
            False,
            source=True,
            observers=(FACADE.RequestHooks(on_request=lambda _: None),),
        )
        original, secondary = ValueError("request"), RuntimeError("error phase")
        owner.cleanup_error, owner.error_hook_failure = original, secondary
        request = FACADE.Error("request", "request_hook")
        request.original = original
        request.hook_error = FACADE.Error("request", "request_hook")
        request.hook_error.original = secondary
        outer = FACADE.SseError("sse", "request")
        outer.original = request
        source_module = __import__(
            FACADE.__name__ + "._event_source", fromlist=["_observe_hook_error"]
        )
        source_module._observe_hook_error(outer, owner)
        self.assertIsNone(owner.cleanup_error)
        self.assertIsNone(owner.error_hook_failure)
        owner.close()
        self.assertTrue(await owner.wait())

    async def test_sync_source_rejects_async_bundle_before_native_opening(self):
        calls = []

        async def connect(*args, **options):
            calls.append(args)
            return Source()

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(event_source=connect, cookies=object())
        )
        opening = client.event_source(
            "https://local/events",
            protocol="h2",
            request_hooks=FACADE.AsyncRequestHooks(on_request=lambda _: None),
        )
        with self.assertRaisesRegex(TypeError, "RequestHooks"):
            await opening._connect(synchronous=True)
        self.assertEqual(calls, [])

    async def test_cancelled_queued_invocation_cannot_reach_a_later_get(self):
        seen = []
        owner = hooks_module.Hooks(
            (),
            False,
            source=True,
            observers=(
                FACADE.RequestHooks(on_request=lambda _: seen.append("request")),
            ),
        )
        try:
            first = owner.native.begin_logical("request")
            owner.native.cancel_current()
            with self.assertRaises(asyncio.CancelledError):
                await first
            second = owner.native.begin_logical("request")
            with self.assertRaises(FACADE._native.NativeError):
                owner.native.complete_logical(1)
            await asyncio.wait_for(second, 1)
            self.assertEqual(seen, ["request"])
        finally:
            owner.close()
            self.assertTrue(await owner.wait())

    async def test_client_shutdown_reports_both_unobserved_source_causes(self):
        async def shutdown(timeout_ms):
            pass

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(cookies=object(), shutdown=shutdown)
        )
        owner = hooks_module.Hooks(
            (),
            False,
            source=True,
            observers=(FACADE.RequestHooks(on_request=lambda _: None),),
        )
        original, secondary = ValueError("request"), RuntimeError("error phase")
        owner.cleanup_error, owner.error_hook_failure = original, secondary
        client._header_pumps.add(owner)
        owner.close()
        self.assertTrue(await owner.wait())
        client._settle_header_hooks(owner)
        self.assertIn(owner, client._header_pumps)
        with self.assertRaises(FACADE.Error) as caught:
            await client.close()
        self.assertIs(caught.exception.original, original)
        self.assertIs(caught.exception.hook_error.original, secondary)
        await client.close()

    async def test_empty_source_observers_create_no_callback_owner(self):
        async def connect(*args, **options):
            self.assertNotIn("header_hooks", options)
            return Source()

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(event_source=connect, cookies=object()),
        )
        async with client.event_source(
            "https://local/events",
            protocol="h2",
            request_hooks=FACADE.AsyncRequestHooks(),
        ) as source:
            self.assertIsNone(source._hooks)
