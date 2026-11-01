"""Logical observers against independent peers (native required)."""

import asyncio
import contextvars
import dataclasses
import threading
import traceback
import unittest

from phantom_http import (
    AsyncClient,
    AsyncRequestHooks,
    AttemptBudget,
    Client,
    Error,
    RedirectPolicy,
    RequestHooks,
    RetryPolicy,
    StatusRetry,
    TimeoutError,
)
from test_header_hooks import Handler
from test_http2 import H2Peer
from test_uploads import PROFILE, server

TRACE = contextvars.ContextVar("logical-hook-context", default=None)


class LogicalRequestHookTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_then_request_once_across_redirect_and_status_retry(self):
        seen = []
        loop, thread = asyncio.get_running_loop(), threading.get_ident()

        async def request(context):
            self.assertIs(asyncio.get_running_loop(), loop)
            self.assertEqual(threading.get_ident(), thread)
            self.assertEqual(TRACE.get(), "request-context")
            self.assertTrue(context.url.endswith("/start"))
            self.assertNotIn("/start", repr(context))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                context.method = "POST"
            seen.append("client:request")

        async def response(context):
            self.assertEqual(context.status, 200)
            self.assertEqual(context.protocol, "h1")
            self.assertTrue(context.url.endswith("/retry"))
            self.assertEqual(context.redirects_followed, 1)
            self.assertEqual(context.retries_performed, 0)
            self.assertEqual(context.decoded_content_codings, ())
            self.assertEqual(context.headers.get("content-length"), b"0")
            self.assertFalse(hasattr(context, "body"))
            seen.append("client:response")

        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                timeout_ms=5000,
                redirect_policy=RedirectPolicy.limited(2),
                retry_policy=RetryPolicy(
                    status_retry=StatusRetry(statuses=(503,), maximum=1, delay=0)
                ),
                request_hooks=AsyncRequestHooks(
                    on_request=request, on_response=response
                ),
            ) as client:
                budget = AttemptBudget(3)
                token = TRACE.set("request-context")
                try:
                    response_value = await client.get(
                        url + "/start",
                        budget=budget,
                        request_hooks=RequestHooks(
                            on_request=lambda _: seen.append("request:request"),
                            on_response=lambda _: seen.append("request:response"),
                        ),
                    )
                finally:
                    TRACE.reset(token)
                await response_value.read(max_bytes=0)
                self.assertEqual(
                    [record[0] for record in peer.records],
                    ["/start", "/retry", "/retry"],
                )
                self.assertEqual(budget.remaining, 0)
                self.assertEqual(
                    seen,
                    [
                        "client:request",
                        "request:request",
                        "client:response",
                        "request:response",
                    ],
                )

    async def test_request_and_header_failures_preserve_both_python_causes(self):
        for phase in ("request", "header"):
            for exception_type in (ValueError, asyncio.CancelledError):
                with self.subTest(phase=phase, exception_type=exception_type):
                    first, second = (
                        exception_type("secret original"),
                        LookupError("secret observer"),
                    )
                    seen = []

                    def fail(_, first=first):
                        raise first

                    def observe(context, first=first, second=second, seen=seen):
                        self.assertIs(context.error.original, first)
                        self.assertEqual(context.error.origin[0], "http")
                        seen.append(context.error.kind)
                        raise second

                    with server(Handler) as (peer, url):
                        async with AsyncClient(
                            profile=PROFILE,
                            protocol="h1",
                            context="raw",
                            request_hooks=RequestHooks(
                                on_request=fail if phase == "request" else None,
                                on_error=observe,
                            ),
                        ) as client:
                            budget = AttemptBudget(1)
                            with self.assertRaises(Error) as caught:
                                await client.get(
                                    url,
                                    budget=budget,
                                    header_hooks=(fail,) if phase == "header" else (),
                                )
                            error = caught.exception
                            self.assertEqual(
                                error.kind,
                                "request_hook" if phase == "request" else "header_hook",
                            )
                            self.assertEqual(error.protocol, None)
                            self.assertEqual(error.timeout_phase, None)
                            self.assertIs(error.original, first)
                            self.assertIs(error.hook_error.original, second)
                            self.assertEqual(error.hook_error.kind, "request_hook")
                            self.assertEqual(error.origin, error.hook_error.origin)
                            self.assertNotIn("secret", repr(error))
                            self.assertIn(
                                "fail",
                                [
                                    frame.name
                                    for frame in traceback.extract_tb(
                                        first.__traceback__
                                    )
                                ],
                            )
                            self.assertEqual(seen, [error.kind])
                            self.assertEqual(budget.remaining, 1)
                            self.assertEqual(peer.records, [])

    async def test_pending_request_deadline_keeps_timeout_primary_and_spends_no_attempt(
        self,
    ):
        entered, cleaning = asyncio.Event(), asyncio.Event()

        async def request(_):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()

        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                request_hooks=AsyncRequestHooks(on_request=request),
            ) as client:
                budget = AttemptBudget(1)
                sending = asyncio.create_task(
                    client.get(url, budget=budget, timeout_ms=500)
                )
                await asyncio.wait_for(entered.wait(), 2)
                with self.assertRaises(TimeoutError) as caught:
                    await asyncio.wait_for(sending, 3)
                self.assertEqual(caught.exception.timeout_phase, "total")
                self.assertIsNone(caught.exception.hook_error)
                await asyncio.wait_for(cleaning.wait(), 1)
                self.assertEqual(budget.remaining, 1)
                self.assertEqual(peer.records, [])

    async def test_shutdown_waits_for_error_callback_and_caller_cancel_retains_cleanup(
        self,
    ):
        entered, cleaning, release = (asyncio.Event() for _ in range(3))
        terminal = []

        def fail(_):
            raise ValueError("request")

        async def error(_):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                await release.wait()
                terminal.append("cleaned")

        with server(Handler) as (peer, url):
            client = AsyncClient(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                request_hooks=AsyncRequestHooks(on_request=fail, on_error=error),
            )
            sending = asyncio.create_task(client.get(url))
            try:
                await asyncio.wait_for(entered.wait(), 2)
                with self.assertRaises(TimeoutError):
                    await client.close(timeout_ms=0)
                self.assertFalse(sending.done())
                sending.cancel()
                await asyncio.wait_for(cleaning.wait(), 2)
                self.assertFalse(sending.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await sending
                self.assertEqual(terminal, ["cleaned"])
                self.assertEqual(peer.records, [])
                await client.close()
            finally:
                release.set()
                await client.abort()

    async def test_response_failure_discards_body_without_error_phase(self):
        original = RuntimeError("secret response")
        phases = []

        def response(context):
            phases.append(context.status)
            raise original

        class BodyHandler(Handler):
            def respond(self):
                self.send_response(200)
                self.send_header("Content-Length", "5")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"hello")
                self.close_connection = True

        with server(BodyHandler) as (_, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                with self.assertRaises(Error) as caught:
                    await client.get(
                        url,
                        request_hooks=RequestHooks(
                            on_response=response,
                            on_error=lambda _: phases.append("error"),
                        ),
                    )
                self.assertEqual(caught.exception.kind, "request_hook")
                self.assertEqual(caught.exception.protocol, "h1")
                self.assertIs(caught.exception.original, original)
                self.assertEqual(phases, [200])
                reused = await client.get(url + "/reuse")
                self.assertEqual(await reused.read(max_bytes=5), b"hello")

    async def test_cancelled_response_callback_preserves_http2_sibling_tail_and_reuse(
        self,
    ):
        entered, cancelled = asyncio.Event(), asyncio.Event()
        seen = []

        async def pending(_):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        with H2Peer(release_stall_on=b"/second") as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", context="raw", timeout_ms=5000
            ) as client:
                sibling = await client.get(peer.url + "/stall")
                self.assertEqual(await sibling.read_chunk(1024), b"a")
                sending = asyncio.create_task(
                    client.get(
                        peer.url + "/healthy",
                        request_hooks=AsyncRequestHooks(
                            on_response=pending, on_error=lambda _: seen.append("error")
                        ),
                    )
                )
                await asyncio.wait_for(entered.wait(), 2)
                sending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await sending
                await asyncio.wait_for(cancelled.wait(), 1)
                self.assertEqual(
                    await (await client.get(peer.url + "/second")).read(max_bytes=16),
                    b"hello",
                )
                self.assertEqual(await sibling.read(max_bytes=16), b"tail")
                self.assertIsNone(await sibling.read_chunk())
                self.assertEqual(seen, [])
                self.assertEqual(
                    [path for _, path in peer.requests],
                    [b"/stall", b"/healthy", b"/second"],
                )

    async def test_fork_restore_inherit_observers_and_eventsource_is_explicitly_rejected(
        self,
    ):
        seen = []
        with server(Handler) as (_, url):
            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                request_hooks=RequestHooks(
                    on_request=lambda context: seen.append(context.url)
                ),
            ) as client:
                fork = client.fork()
                restored = await client.restore_session(
                    await client.export_session(b"k" * 32), b"k" * 32
                )
                for child in (fork, restored):
                    async with child:
                        await (await child.get(url + "/kept")).aclose()
                        with self.assertRaisesRegex(
                            ValueError, "logical request hooks"
                        ):
                            child.event_source(url, protocol="h1")
                self.assertEqual(seen, [url + "/kept", url + "/kept"])

    async def test_response_deadline_drops_body_without_entering_error_phase(self):
        entered, cleaned = asyncio.Event(), asyncio.Event()
        phases = []

        async def pending(_):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaned.set()

        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                task = asyncio.create_task(
                    client.get(
                        url,
                        timeout_ms=500,
                        request_hooks=AsyncRequestHooks(
                            on_response=pending,
                            on_error=lambda _: phases.append("error"),
                        ),
                    )
                )
                await asyncio.wait_for(entered.wait(), 2)
                with self.assertRaises(TimeoutError) as caught:
                    await asyncio.wait_for(task, 3)
                self.assertEqual(caught.exception.protocol, "h1")
                self.assertEqual(caught.exception.timeout_phase, "total")
                await asyncio.wait_for(cleaned.wait(), 1)
                self.assertEqual(phases, [])
                await (await client.get(url + "/second")).aclose()
                self.assertEqual(
                    [record[0] for record in peer.records], ["/", "/second"]
                )


class SynchronousRequestHookTests(unittest.TestCase):
    def test_sync_callbacks_use_creating_thread_and_reject_awaitables(self):
        seen = []
        thread = threading.get_ident()

        async def unsupported(_):
            return None

        with (
            server(Handler) as (peer, url),
            Client(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                request_hooks=RequestHooks(
                    on_request=lambda _: seen.append(threading.get_ident())
                ),
            ) as client,
        ):
            with client.get(url) as response:
                self.assertEqual(response.status, 200)
            with self.assertRaises(Error) as caught:
                client.get(url, request_hooks=RequestHooks(on_request=unsupported))
            self.assertIsInstance(caught.exception.original, TypeError)
            self.assertEqual(seen, [thread, thread])
            self.assertEqual(len(peer.records), 1)
