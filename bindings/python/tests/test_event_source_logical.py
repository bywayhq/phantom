"""Dedicated source observers against independent HTTP peers."""

import asyncio
import unittest

from phantom_http import (
    AsyncClient,
    AsyncRequestHooks,
    Client,
    Error,
    LastEventId,
    RedirectPolicy,
    RequestHooks,
    RetryPolicy,
    SseError,
    StatusRetry,
    TimeoutError,
    TimeoutOverrides,
)
from test_event_source import PROFILE, EventSourceHandler, configure
from test_http2 import H2Peer
from test_uploads import server


class SyncLogicalSourceTests(unittest.TestCase):
    def test_client_first_observers_run_per_get_without_suppressing_managed_id(self):
        phases, ids = [], []

        def headers(context):
            ids.append([h.value for h in context.headers if h.name == "Last-Event-ID"])

        def response(context):
            phases.append("source:response")
            self.assertEqual(context.status, 200)
            self.assertEqual(context.protocol, "h1")

        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"id: seven\ndata: first\n\n", b"data: second\n\n")
            with (
                Client(
                    profile=PROFILE,
                    context="raw",
                    header_hooks=(lambda _: self.fail("header default was skipped"),),
                    request_hooks=RequestHooks(
                        on_request=lambda _: phases.append("client:request"),
                        on_response=lambda _: phases.append("client:response"),
                    ),
                ) as client,
                client.event_source(
                    url,
                    protocol="h1",
                    headers=[
                        ("Accept", "text/event-stream"),
                        LastEventId("Last-Event-ID"),
                    ],
                    without_client_hooks=True,
                    header_hooks=(headers,),
                    request_hooks=RequestHooks(
                        on_request=lambda _: phases.append("source:request"),
                        on_response=response,
                    ),
                    initial_retry=0,
                    max_reconnects=1,
                ) as source,
            ):
                self.assertEqual(next(source).data, "first")
                self.assertEqual(next(source).data, "second")
            self.assertEqual(ids, [[], [b"seven"]])
            self.assertEqual(
                phases,
                [
                    "client:request",
                    "source:request",
                    "client:response",
                    "source:response",
                ]
                * 2,
            )
            self.assertEqual(len(peer.records), 2)

    def test_forks_and_restored_clients_keep_source_observers(self):
        seen = []
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: ready\n\n")
            with Client(
                profile=PROFILE,
                context="raw",
                request_hooks=RequestHooks(
                    on_request=lambda context: seen.append(context.url)
                ),
            ) as client:
                key = b"s" * 32
                with (
                    client.fork() as fork,
                    client.restore_session(client.export_session(key), key) as restored,
                ):
                    for owner in (fork, restored):
                        with owner.event_source(url, protocol="h1") as source:
                            self.assertEqual(next(source).data, "ready")
            self.assertEqual(seen, [url + "/", url + "/"])
            self.assertEqual(len(peer.records), 2)


class AsyncLogicalSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_logical_observers_run_once_across_redirect_without_losing_pool(self):
        phases = []

        async def request(context):
            phases.append(("request", context.url))

        async def response(context):
            phases.append(("response", context.url))
            self.assertEqual(context.redirects_followed, 1)

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
                    request_hooks=AsyncRequestHooks(
                        on_request=request, on_response=response
                    ),
                ) as source:
                    self.assertEqual((await anext(source)).data, "hello")
                self.assertEqual(
                    await (await client.get(peer.url + "/reuse")).read(max_bytes=5),
                    b"hello",
                )
            self.assertEqual(
                phases,
                [
                    ("request", peer.url + "/redirect"),
                    ("response", peer.url + "/events"),
                ],
            )
            self.assertEqual(
                [path for _, path in peer.requests],
                [b"/redirect", b"/events", b"/reuse"],
            )
        self.assertFalse(peer.premature_close)

    async def test_status_retry_does_not_repeat_logical_source_phases(self):
        phases = []
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"", b"data: recovered\n\n")
            peer.responses[0] = (503, "text/event-stream", None, b"")
            async with (
                AsyncClient(
                    profile=PROFILE,
                    context="raw",
                    retry_policy=RetryPolicy(
                        status_retry=StatusRetry(statuses=(503,), maximum=1, delay=0)
                    ),
                ) as client,
                client.event_source(
                    url,
                    protocol="h1",
                    request_hooks=RequestHooks(
                        on_request=lambda _: phases.append("request"),
                        on_response=lambda _: phases.append("response"),
                    ),
                ) as source,
            ):
                self.assertEqual((await anext(source)).data, "recovered")
                self.assertEqual(source.reconnects, 0)
            self.assertEqual(phases, ["request", "response"])
            self.assertEqual(len(peer.records), 2)

    async def test_response_failure_is_terminal_without_running_error_observers(self):
        original = ValueError("response callback")
        phases = []

        async def response(_):
            phases.append("response")
            raise original

        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: unread\n\n")
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                with self.assertRaises(SseError) as caught:
                    await client.event_source(
                        url,
                        protocol="h1",
                        initial_retry=0,
                        max_reconnects=2,
                        request_hooks=AsyncRequestHooks(
                            on_response=response,
                            on_error=lambda _: phases.append("error"),
                        ),
                    )
                self.assertIs(caught.exception.original.original, original)
                self.assertEqual(phases, ["response"])
            self.assertEqual(len(peer.records), 1)

    async def test_callback_and_error_callback_failures_keep_both_original_causes(self):
        for original in (
            ValueError("request callback"),
            asyncio.CancelledError("callback cancellation"),
        ):
            with (
                self.subTest(cause=type(original).__name__),
                server(EventSourceHandler) as (peer, url),
            ):
                configure(peer, b"data: forbidden\n\n")
                secondary = RuntimeError("error callback")
                seen = []

                async def request(_, seen=seen, original=original):
                    seen.append("request")
                    raise original

                async def failure(
                    context, seen=seen, original=original, secondary=secondary
                ):
                    seen.append("error")
                    self.assertIs(context.error.original, original)
                    raise secondary

                async with AsyncClient(profile=PROFILE, context="raw") as client:
                    with self.assertRaises(SseError) as caught:
                        await client.event_source(
                            url,
                            protocol="h1",
                            initial_retry=0,
                            max_reconnects=2,
                            request_hooks=AsyncRequestHooks(
                                on_request=request, on_error=failure
                            ),
                        )
                    cause = caught.exception.original
                    self.assertIsInstance(cause, Error)
                    self.assertIs(cause.original, original)
                    self.assertIs(cause.hook_error.original, secondary)
                    self.assertIsNotNone(original.__traceback__)
                    self.assertIsNotNone(secondary.__traceback__)
                    self.assertEqual(seen, ["request", "error"])
                self.assertEqual(peer.records, [])

    async def test_timed_out_request_callback_finishes_before_reconnect(self):
        cleaned = asyncio.Event()
        calls = []

        async def request(_):
            calls.append(asyncio.get_running_loop())
            if len(calls) == 1:
                try:
                    await asyncio.Future()
                finally:
                    cleaned.set()
            else:
                self.assertTrue(cleaned.is_set())

        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: recovered\n\n")
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                async with client.event_source(
                    url,
                    protocol="h1",
                    initial_retry=0,
                    max_reconnects=1,
                    timeouts=TimeoutOverrides(total=0.5),
                    request_hooks=AsyncRequestHooks(on_request=request),
                ) as source:
                    self.assertEqual((await anext(source)).data, "recovered")
                    self.assertEqual(source.reconnects, 1)
                self.assertEqual(calls, [asyncio.get_running_loop()] * 2)
            self.assertEqual(len(peer.records), 1)

    async def test_cancelled_read_keeps_reconnect_observer_and_http2_sibling(self):
        entered, release, finished = (asyncio.Event() for _ in range(3))
        calls = []

        async def request(_):
            calls.append("request")
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
                        initial_retry=0,
                        max_reconnects=1,
                        request_hooks=AsyncRequestHooks(on_request=request),
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
                            self.assertEqual((await anext(source)).data, "hello")
                            self.assertTrue(finished.is_set())
                            self.assertEqual(calls, ["request", "request"])
                            self.assertEqual(
                                await (await client.get(peer.url + "/second")).read(
                                    max_bytes=16
                                ),
                                b"hello",
                            )
                            self.assertEqual(await sibling.read(max_bytes=16), b"tail")
                            self.assertIsNone(await sibling.read_chunk())
                        finally:
                            release.set()
                            await asyncio.gather(reading, return_exceptions=True)
                finally:
                    release.set()
                    await sibling.aclose()
        self.assertEqual(
            [path for _, path in peer.requests],
            [b"/stall", b"/events", b"/events", b"/second"],
        )

    async def test_close_waits_for_response_callback_cleanup_and_retains_late_failure(
        self,
    ):
        entered, cleaning, release, exited = (asyncio.Event() for _ in range(4))
        late = RuntimeError("late response callback cleanup")
        calls = []

        async def response(_):
            calls.append("response")
            if len(calls) == 2:
                entered.set()
                try:
                    await asyncio.Future()
                finally:
                    cleaning.set()
                    await release.wait()
                    exited.set()
                    raise late

        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: first\n\n", b"data: second\n\n")
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                source = await client.event_source(
                    url,
                    protocol="h1",
                    initial_retry=0,
                    max_reconnects=1,
                    request_hooks=AsyncRequestHooks(on_response=response),
                )
                reading = None
                try:
                    self.assertEqual((await anext(source)).data, "first")
                    reading = asyncio.create_task(anext(source))
                    await asyncio.wait_for(entered.wait(), 5)
                    reading.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await reading
                    with self.assertRaises(TimeoutError):
                        await source.aclose(timeout_ms=20)
                    await asyncio.wait_for(cleaning.wait(), 2)
                    self.assertFalse(exited.is_set())
                    release.set()
                    with self.assertRaises(Error) as caught:
                        await source.aclose()
                    self.assertIs(caught.exception.original, late)
                    self.assertTrue(exited.is_set())
                    await source.aclose()
                finally:
                    release.set()
                    if reading is not None:
                        await asyncio.gather(reading, return_exceptions=True)
                    await source.aclose()

    async def test_client_abort_waits_for_actual_reconnect_callback_exit(self):
        entered, cleaning, release, exited = (asyncio.Event() for _ in range(4))
        calls = []

        async def request(_):
            calls.append("request")
            if len(calls) == 2:
                entered.set()
                try:
                    await asyncio.Future()
                finally:
                    cleaning.set()
                    await release.wait()
                    exited.set()

        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: first\n\n")
            client = AsyncClient(profile=PROFILE, context="raw")
            source = await client.event_source(
                url,
                protocol="h1",
                initial_retry=0,
                max_reconnects=1,
                request_hooks=AsyncRequestHooks(on_request=request),
            )
            reading = None
            try:
                self.assertEqual((await anext(source)).data, "first")
                reading = asyncio.create_task(anext(source))
                await asyncio.wait_for(entered.wait(), 5)
                reading.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await reading
                with self.assertRaises(TimeoutError):
                    await client.abort(timeout_ms=20)
                await asyncio.wait_for(cleaning.wait(), 2)
                self.assertFalse(exited.is_set())
                release.set()
                await client.abort()
                self.assertTrue(exited.is_set())
                self.assertTrue(source.closed)
            finally:
                release.set()
                if reading is not None:
                    await asyncio.gather(reading, return_exceptions=True)
                await source.aclose()
                await client.abort()
