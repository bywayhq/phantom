"""Awaited core header hooks against independent HTTP peers (native required)."""

import asyncio
import contextvars
import http.server
import threading
import traceback
import unittest

from phantom_http import (
    AsyncClient,
    AttemptBudget,
    Client,
    Error,
    Header,
    PreparedBody,
    RedirectPolicy,
    RetryPolicy,
    StatusRetry,
    TimeoutError,
)
from test_http2 import H2Peer
from test_uploads import PROFILE, server

TRACE = contextvars.ContextVar("native-hook-trace", default=None)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        self.connection.settimeout(5)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.records.append((self.path, list(self.headers.raw_items()), body))
        status = 200
        if self.path == "/start":
            status = 302
        elif (
            self.path == "/retry"
            and len([r for r in self.server.records if r[0] == "/retry"]) == 1
        ):
            status = 503
        elif self.path == "/external":
            status = 302
        self.send_response(status)
        if status == 302:
            self.send_header("Location", getattr(self.server, "destination", "/retry"))
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True


class HeaderHookTests(unittest.IsolatedAsyncioTestCase):
    async def test_ordered_hooks_run_once_across_redirect_and_retry(self):
        seen = []

        async def client_hook(context):
            self.assertEqual(context.method, "GET")
            self.assertTrue(context.url.endswith("/start"))
            self.assertEqual(
                [h.value for h in context.headers if h.name.lower() == "x-repeat"],
                [b"one", b"two"],
            )
            await asyncio.sleep(0)
            context.set(Header("X-Repeat", b"\xff", sensitive=True))
            context.append(("x-repeat", "last"))
            seen.append("client")

        def request_hook(context):
            self.assertEqual(
                [h.value for h in context.headers if h.name.lower() == "x-repeat"],
                [b"\xff", b"last"],
            )
            self.assertTrue(
                next(h for h in context.headers if h.name == "X-Repeat").sensitive
            )
            context.remove("X-REMOVE")
            context.append(("X-End", "end"))
            seen.append("request")

        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                timeout_ms=5000,
                header_hooks=(client_hook,),
            ) as client:
                budget = AttemptBudget(3)
                response = await client.get(
                    url + "/start",
                    headers=(
                        ("X-First", "first"),
                        ("X-Repeat", "one"),
                        ("X-REMOVE", "gone"),
                        ("x-repeat", "two"),
                    ),
                    header_hooks=(request_hook,),
                    budget=budget,
                    redirect_policy=RedirectPolicy.limited(1),
                    retry_policy=RetryPolicy(
                        status_retry=StatusRetry(statuses=(503,), maximum=1, delay=0)
                    ),
                )
                await response.read(max_bytes=0)
                self.assertEqual(budget.remaining, 0)
            self.assertEqual(seen, ["client", "request"])
            self.assertEqual(
                [record[0] for record in peer.records], ["/start", "/retry", "/retry"]
            )
            for _, headers, _ in peer.records:
                self.assertEqual(
                    [(n, v) for n, v in headers if n.lower().startswith("x-")],
                    [
                        ("X-First", "first"),
                        ("X-Repeat", "ÿ"),
                        ("x-repeat", "last"),
                        ("X-End", "end"),
                    ],
                )
            self.assertEqual(peer.errors, [])

    async def test_prepared_metadata_is_visible_and_still_validated_before_send(self):
        body = PreparedBody.form((("name", "value"),), maximum_bytes=100)
        contexts = []

        def inspect(context):
            contexts.append(context)
            self.assertIn(
                ("content-type", body.content_type.encode()),
                [(h.name.lower(), h.value) for h in context.headers],
            )

        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                response = await client.post(url, body=body, header_hooks=(inspect,))
                await response.read(max_bytes=0)
                self.assertEqual(peer.records[0][2], body.to_bytes())
                budget = AttemptBudget(1)
                with self.assertRaises(Error):
                    await client.post(
                        url,
                        body=body,
                        budget=budget,
                        header_hooks=(
                            lambda context: context.set(("Content-Type", "text/plain")),
                        ),
                    )
                self.assertEqual(budget.remaining, 1)
                self.assertEqual(len(peer.records), 1)
                with self.assertRaisesRegex(RuntimeError, "closed"):
                    contexts[0].append(("X-Late", "no"))

    async def test_original_exception_traceback_and_callback_cancel_have_no_send(self):
        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                for original in (
                    ValueError("private-hook-canary"),
                    asyncio.CancelledError("callback"),
                ):

                    async def callback(context, original=original):
                        await asyncio.sleep(0)
                        raise original

                    budget = AttemptBudget(1)
                    with self.assertRaises(Error) as caught:
                        await client.get(url, header_hooks=(callback,), budget=budget)
                    self.assertEqual(caught.exception.kind, "header_hook")
                    self.assertIs(caught.exception.original, original)
                    self.assertIn(
                        "callback", "".join(traceback.format_tb(original.__traceback__))
                    )
                    self.assertNotIn("canary", str(caught.exception))
                    self.assertEqual(budget.remaining, 1)
                self.assertEqual(peer.records, [])

    async def test_pending_hook_keeps_loop_and_same_client_usable_and_cancels_without_send(
        self,
    ):
        entered, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        observed = []
        loop = asyncio.get_running_loop()
        host_thread = threading.get_ident()

        async def pending(context):
            observed.append(
                (
                    loop is asyncio.get_running_loop(),
                    threading.get_ident(),
                    TRACE.get(),
                    context,
                )
            )
            entered.set()
            try:
                await release.wait()
            finally:
                cancelled.set()

        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                budget = AttemptBudget(1)
                token = TRACE.set("sender-context")
                request = asyncio.create_task(
                    client.get(url + "/pending", header_hooks=(pending,), budget=budget)
                )
                TRACE.reset(token)
                await asyncio.wait_for(entered.wait(), 2)
                heartbeat = asyncio.Event()
                loop.call_soon(heartbeat.set)
                await asyncio.wait_for(heartbeat.wait(), 1)
                response = await client.get(url + "/healthy")
                await response.read(max_bytes=0)
                self.assertFalse(request.done())
                self.assertEqual(budget.remaining, 1)
                self.assertEqual([r[0] for r in peer.records], ["/healthy"])
                request.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await request
                await asyncio.wait_for(cancelled.wait(), 2)
                self.assertEqual(observed[0][:3], (True, host_thread, "sender-context"))
                with self.assertRaisesRegex(RuntimeError, "closed"):
                    observed[0][3].remove("X")
                self.assertEqual(budget.remaining, 1)

    async def test_total_deadline_drops_pending_hook_without_send(self):
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def pending(context):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                budget = AttemptBudget(1)
                request = asyncio.create_task(
                    client.get(
                        url, header_hooks=(pending,), budget=budget, timeout_ms=500
                    )
                )
                await asyncio.wait_for(entered.wait(), 2)
                with self.assertRaises(TimeoutError) as caught:
                    await asyncio.wait_for(request, 3)
                self.assertEqual(caught.exception.timeout_phase, "total")
                await asyncio.wait_for(cancelled.wait(), 1)
                self.assertEqual(budget.remaining, 1)
                self.assertEqual(peer.records, [])

    async def test_abort_retains_noncooperative_hook_until_bounded_cleanup_finishes(
        self,
    ):
        entered, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        contexts = []

        async def pending(context):
            contexts.append(context)
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelled.set()
                await release.wait()

        with server(Handler) as (peer, url):
            client = AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            )
            request = asyncio.create_task(client.get(url, header_hooks=(pending,)))
            try:
                await asyncio.wait_for(entered.wait(), 2)
                with self.assertRaises(TimeoutError):
                    await client.abort(timeout_ms=0)
                await asyncio.wait_for(cancelled.wait(), 1)
                self.assertTrue(client._header_pumps)
                with self.assertRaisesRegex(RuntimeError, "closed"):
                    contexts[0].append(("X-Late", "no"))
                release.set()
                with self.assertRaises(Error) as caught:
                    await request
                self.assertEqual(caught.exception.kind, "client_closed")
                await client.abort()
                self.assertEqual(peer.records, [])
            finally:
                release.set()
                await client.abort()

    async def test_cross_origin_redirect_still_strips_hook_credentials(self):
        with server(Handler) as (first, url), server(Handler) as (second, destination):
            first.destination = destination

            def credentials(context):
                context.append(
                    Header("Authorization", "Bearer private", sensitive=True)
                )
                context.append(Header("X-Secret", "private", sensitive=True))

            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                timeout_ms=5000,
                header_hooks=(credentials,),
            ) as client:
                response = await client.get(
                    url + "/external",
                    redirect_policy=RedirectPolicy.limited(
                        1, credential_headers=("X-Secret",)
                    ),
                )
                await response.read(max_bytes=0)
            self.assertIn("Authorization", dict(first.records[0][1]))
            self.assertFalse(
                {n.lower() for n, _ in second.records[0][1]}
                & {"authorization", "x-secret"}
            )

    async def test_cancelling_pending_hook_preserves_unrelated_h2_stream(self):
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def pending(context):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        with H2Peer() as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", context="raw", timeout_ms=5000
            ) as client:
                sibling = await client.get(peer.url + "/stall")
                self.assertEqual(await sibling.read_chunk(), b"a")
                request = asyncio.create_task(
                    client.get(peer.url + "/pending", header_hooks=(pending,))
                )
                await asyncio.wait_for(entered.wait(), 2)
                request.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await request
                await asyncio.wait_for(cancelled.wait(), 1)
                response = await client.get(peer.url + "/second")
                self.assertEqual(await response.read(max_bytes=5), b"hello")
                await sibling.aclose()
                final = await client.get(peer.url + "/third")
                self.assertEqual(await final.read(max_bytes=5), b"hello")
            self.assertEqual(
                [path for _, path in peer.requests], [b"/stall", b"/second", b"/third"]
            )
            self.assertFalse(peer.premature_close)


class SyncHeaderHookTests(unittest.TestCase):
    def test_sync_core_hook_edits_headers_on_the_private_loop(self):
        seen = []

        def callback(context):
            seen.append((threading.get_ident(), asyncio.get_running_loop()))
            context.append(("X-Sync", "yes"))

        with server(Handler) as (peer, url):
            with Client(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                timeout_ms=5000,
                header_hooks=(callback,),
            ) as client:
                with client.get(url) as response:
                    response.read(max_bytes=0)
                self.assertEqual(seen, [(threading.get_ident(), client._loop)])
            self.assertIn(("X-Sync", "yes"), peer.records[0][1])
