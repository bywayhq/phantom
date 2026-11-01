"""Dedicated EventSource hook ordering and ownership against local peers."""

import asyncio
import unittest

from phantom_http import (
    AsyncClient,
    Client,
    Error,
    LastEventId,
    RedirectPolicy,
    SseError,
    TimeoutError,
    TimeoutOverrides,
)
from test_event_source import PROFILE, EventSourceHandler, configure
from test_http2 import H2Peer
from test_uploads import server


class SyncSourceHookTests(unittest.TestCase):
    def test_forked_and_restored_clients_keep_inherited_source_hooks(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: inherited\n\n")

            def callback(context):
                context.append(("x-inherited", "ready"))

            with Client(
                profile=PROFILE, context="raw", header_hooks=(callback,)
            ) as client:
                key = b"s" * 32
                with (
                    client.fork() as fork,
                    client.restore_session(client.export_session(key), key) as restored,
                ):
                    for owner in (client, fork, restored):
                        with owner.event_source(url, protocol="h1") as source:
                            self.assertEqual(next(source).data, "inherited")
            self.assertEqual(len(peer.records), 3)
            for _, fields in peer.records:
                self.assertIn(("x-inherited", "ready"), fields)

    def test_client_and_source_hooks_run_on_each_get_with_the_current_managed_id(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"id: seven\ndata: first\n\n", b"data: second\n\n")
            seen = []

            def inherited(context):
                seen.append(("client", context.method, context.url))
                context.append(("x-client", "before"))

            def opening(context):
                self.assertEqual(context.headers[-1].name, "x-client")
                ids = [h.value for h in context.headers if h.name == "last-event-id"]
                seen.append(("source", ids))
                context.append(("x-source", "after"))

            with (
                Client(
                    profile=PROFILE, context="raw", header_hooks=(inherited,)
                ) as client,
                client.event_source(
                    url + "/events",
                    protocol="h1",
                    headers=[
                        ("accept", "text/event-stream"),
                        LastEventId("last-event-id"),
                    ],
                    header_hooks=(opening,),
                    initial_retry=0,
                    max_reconnects=1,
                ) as source,
            ):
                self.assertEqual(next(source).data, "first")
                self.assertEqual(next(source).data, "second")
            self.assertEqual(
                seen,
                [
                    ("client", "GET", url + "/events"),
                    ("source", []),
                    ("client", "GET", url + "/events"),
                    ("source", [b"seven"]),
                ],
            )
            self.assertEqual(len(peer.records), 2)
            for _, fields in peer.records:
                ordered = [(name.lower(), value) for name, value in fields]
                self.assertLess(
                    ordered.index(("x-client", "before")),
                    ordered.index(("x-source", "after")),
                )

    def test_source_can_skip_inherited_hooks_and_reject_awaitable_callbacks(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: ready\n\n")
            seen = []

            async def asynchronous(context):
                seen.append("async body must not run")

            with Client(
                profile=PROFILE,
                context="raw",
                header_hooks=(lambda context: seen.append("client"),),
            ) as client:
                with client.event_source(
                    url,
                    protocol="h1",
                    without_client_hooks=True,
                    header_hooks=(lambda context: seen.append("source"),),
                ) as source:
                    self.assertEqual(next(source).data, "ready")
                with self.assertRaises(SseError) as caught:
                    client.event_source(
                        url,
                        protocol="h1",
                        without_client_hooks=True,
                        header_hooks=(asynchronous,),
                    )
                self.assertIsInstance(caught.exception.original.original, TypeError)
            self.assertEqual(seen, ["source"])
            self.assertEqual(len(peer.records), 1)


class AsyncSourceHookTests(unittest.IsolatedAsyncioTestCase):
    async def test_source_hook_runs_once_across_http2_redirect_and_keeps_pool_usable(
        self,
    ):
        calls = []

        async def callback(context):
            calls.append(context.url)
            context.append(("x-source", "once"))

        with H2Peer(event_stream=True, redirects={b"/redirect": "/events"}) as peer:
            async with AsyncClient(
                profile=PROFILE,
                protocol="h2",
                context="raw",
                redirect_policy=RedirectPolicy.limited(1),
            ) as client:
                async with client.event_source(
                    peer.url + "/redirect",
                    protocol="h2",
                    header_hooks=(callback,),
                ) as source:
                    self.assertEqual((await anext(source)).data, "hello")
                    self.assertEqual(source.url, peer.url + "/events")
                async with await client.get(peer.url + "/reuse") as response:
                    self.assertEqual(await response.read(max_bytes=5), b"hello")
            self.assertEqual(calls, [peer.url + "/redirect"])
            self.assertEqual(
                [path for _, path in peer.requests],
                [b"/redirect", b"/events", b"/reuse"],
            )
            for fields in peer.headers[:2]:
                self.assertIn((b"x-source", b"once"), fields)

    async def test_callback_failure_is_terminal_and_preserves_original_base_exception(
        self,
    ):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: unused\n\n")
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                for original in (
                    LookupError("callback"),
                    BaseException("callback"),
                    asyncio.CancelledError(),
                ):
                    with self.subTest(original=type(original)):

                        async def fail(context, original=original):
                            raise original

                        with self.assertRaises(SseError) as caught:
                            await client.event_source(
                                url,
                                protocol="h1",
                                header_hooks=(fail,),
                                initial_retry=0,
                                max_reconnects=3,
                            )
                        self.assertEqual(caught.exception.kind, "request")
                        self.assertEqual(caught.exception.original.kind, "header_hook")
                        self.assertIs(caught.exception.original.original, original)
                        self.assertIsNotNone(original.__traceback__)
            self.assertEqual(peer.records, [])

    async def test_managed_id_cannot_be_set_appended_or_removed(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: unused\n\n")
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                for operation in ("set", "append", "remove"):
                    with self.subTest(operation=operation):

                        def alter(context, operation=operation):
                            if operation == "remove":
                                context.remove("Last-Event-ID")
                            else:
                                getattr(context, operation)(("last-event-id", "forged"))

                        with self.assertRaises(SseError) as caught:
                            await client.event_source(
                                url,
                                protocol="h1",
                                header_hooks=(alter,),
                                headers=[LastEventId("last-event-id")],
                            )
                        self.assertEqual(caught.exception.original.kind, "header_hook")
            self.assertEqual(peer.records, [])

    async def test_timed_out_initial_hook_is_cleaned_before_a_reconnect_uses_it_again(
        self,
    ):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: recovered\n\n")
            cleaned = asyncio.Event()
            calls = []

            async def callback(context):
                calls.append(asyncio.get_running_loop())
                if len(calls) == 1:
                    try:
                        await asyncio.Event().wait()
                    finally:
                        cleaned.set()
                else:
                    self.assertTrue(cleaned.is_set())
                    context.append(("x-reconnected", "ready"))

            async with AsyncClient(profile=PROFILE, context="raw") as client:
                async with await asyncio.wait_for(
                    client.event_source(
                        url,
                        protocol="h1",
                        header_hooks=(callback,),
                        timeouts=TimeoutOverrides(total=0.5),
                        initial_retry=0,
                        max_reconnects=1,
                    ),
                    5,
                ) as source:
                    self.assertEqual((await anext(source)).data, "recovered")
                    self.assertEqual(source.reconnects, 1)
                self.assertEqual(calls, [asyncio.get_running_loop()] * 2)
            self.assertEqual(len(peer.records), 1)
            self.assertIn(("x-reconnected", "ready"), peer.records[0][1])

    async def test_cancelled_read_retains_reconnect_callback_and_http2_sibling_body(
        self,
    ):
        entered, release, finished = (asyncio.Event() for _ in range(3))
        calls = []

        async def callback(context):
            calls.append(context)
            if len(calls) == 2:
                entered.set()
                try:
                    await release.wait()
                finally:
                    finished.set()

        with H2Peer(event_stream=True, release_stall_on=b"/second") as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", context="raw"
            ) as client:
                sibling = await client.get(
                    peer.url + "/stall", timeouts=TimeoutOverrides(total=None)
                )
                try:
                    self.assertEqual(await sibling.read_chunk(), b"data: first\n\n")
                    async with client.event_source(
                        peer.url + "/events",
                        protocol="h2",
                        header_hooks=(callback,),
                        initial_retry=0,
                        max_reconnects=1,
                    ) as source:
                        self.assertEqual((await anext(source)).data, "hello")
                        reading = asyncio.create_task(anext(source))
                        try:
                            await asyncio.wait_for(entered.wait(), 5)
                            reading.cancel()
                            with self.assertRaises(asyncio.CancelledError):
                                await reading
                            self.assertFalse(finished.is_set())
                            self.assertFalse(source.closed)
                            release.set()
                            self.assertEqual(
                                (await asyncio.wait_for(anext(source), 5)).data, "hello"
                            )
                            self.assertTrue(finished.is_set())
                            self.assertEqual(len(calls), 2)
                        finally:
                            release.set()
                            if not reading.done():
                                reading.cancel()
                            await asyncio.gather(reading, return_exceptions=True)
                    async with await client.get(peer.url + "/second") as response:
                        self.assertEqual(await response.read(max_bytes=5), b"hello")
                    self.assertEqual(await sibling.read(max_bytes=16), b"tail")
                    self.assertIsNone(await sibling.read_chunk())
                finally:
                    release.set()
                    await sibling.aclose()
            self.assertEqual(
                [path for _, path in peer.requests],
                [b"/stall", b"/events", b"/events", b"/second"],
            )

    async def test_source_close_waits_for_actual_hook_cleanup_and_can_be_retried(self):
        entered, cleaning, release, finished = (asyncio.Event() for _ in range(4))
        calls = []

        async def callback(context):
            calls.append(context)
            if len(calls) == 2:
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cleaning.set()
                    await release.wait()
                    finished.set()

        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: first\n\n")
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                source = await client.event_source(
                    url, protocol="h1", header_hooks=(callback,), initial_retry=0
                )
                reading = None
                try:
                    self.assertEqual((await anext(source)).data, "first")
                    reading = asyncio.create_task(anext(source))
                    await asyncio.wait_for(entered.wait(), 5)
                    closing = asyncio.create_task(source.aclose(timeout_ms=20))
                    await asyncio.wait_for(cleaning.wait(), 5)
                    with self.assertRaises(TimeoutError):
                        await closing
                    self.assertFalse(finished.is_set())
                    with self.assertRaises(SseError) as caught:
                        await reading
                    self.assertEqual(caught.exception.kind, "closed")
                    with self.assertRaises(TimeoutError):
                        await client.close(timeout_ms=0)
                    self.assertEqual(len(client._header_pumps), 1)
                    self.assertFalse(finished.is_set())
                    release.set()
                    await source.aclose()
                    await client.close()
                    self.assertTrue(finished.is_set())
                finally:
                    release.set()
                    await source.aclose()
                    if reading is not None:
                        await asyncio.gather(reading, return_exceptions=True)
            self.assertEqual(len(peer.records), 1)

    async def test_late_callback_failure_remains_observable_on_source_close(self):
        entered, cleaning, release = (asyncio.Event() for _ in range(3))
        original = RuntimeError("cleanup")
        calls = []

        async def callback(context):
            calls.append(context)
            if len(calls) == 2:
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cleaning.set()
                    await release.wait()
                    raise original

        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: first\n\n")
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                source = await client.event_source(
                    url, protocol="h1", header_hooks=(callback,), initial_retry=0
                )
                reading = None
                try:
                    await anext(source)
                    reading = asyncio.create_task(anext(source))
                    await asyncio.wait_for(entered.wait(), 5)
                    closing = asyncio.create_task(source.aclose())
                    await asyncio.wait_for(cleaning.wait(), 5)
                    release.set()
                    with self.assertRaises(Error) as caught:
                        await closing
                    self.assertEqual(caught.exception.kind, "header_hook_cleanup")
                    self.assertIs(caught.exception.original, original)
                    with self.assertRaises(SseError):
                        await reading
                    await source.aclose()
                finally:
                    release.set()
                    await source.aclose()
                    if reading is not None:
                        await asyncio.gather(reading, return_exceptions=True)
