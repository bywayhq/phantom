"""Redirect decisions on the host loop against independent HTTP peers."""

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
    RedirectDecision,
    RedirectPolicy,
    TimeoutError,
)
from test_http2 import H2Peer
from test_uploads import PROFILE, server

TRACE = contextvars.ContextVar("native-redirect-trace", default=None)


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
        self.server.records.append(
            (self.path, list(self.headers.raw_items()), body, self.command)
        )
        target = getattr(self.server, "redirects", {}).get(self.path)
        payload = b"unread redirect body" if target is not None else b"done"
        self.send_response(303 if self.path == "/post" else 302 if target else 200)
        if target is not None:
            self.send_header("Location", target)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


class RedirectCallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_callback_inherits_through_fork_restore_and_request_override(
        self,
    ):
        seen = []

        def stop(attempt):
            seen.append(attempt.hop)
            return RedirectDecision.STOP

        with server(Handler) as (peer, url):
            peer.redirects = {"/start": "/end"}
            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                timeout_ms=5000,
                redirect_policy=RedirectPolicy.custom(1, stop),
            ) as client:
                forked = client.fork()
                restored = await client.restore_session(
                    await client.export_session(b"k" * 32), b"k" * 32
                )
                try:
                    for owner in (client, forked, restored):
                        response = await owner.get(url + "/start")
                        self.assertEqual(
                            await response.read(max_bytes=64), b"unread redirect body"
                        )
                    response = await client.get(
                        url + "/start", redirect_policy=RedirectPolicy.none()
                    )
                    await response.read(max_bytes=64)
                    with self.assertRaisesRegex(ValueError, "EventSource"):
                        client.event_source(url + "/start", protocol="h1")
                finally:
                    await forked.close()
                    await restored.close()
            self.assertEqual(seen, [1, 1, 1])
            self.assertEqual([record[0] for record in peer.records], ["/start"] * 4)

    async def test_follow_method_rewrite_history_and_once_only_headers(self):
        seen, header_calls = [], []

        async def decide(attempt):
            await asyncio.sleep(0)
            seen.append(
                (attempt.status, attempt.method, attempt.next_method, attempt.hop)
            )
            return RedirectDecision.FOLLOW

        with server(Handler) as (peer, url):
            peer.redirects = {"/post": "/middle", "/middle": "/end"}
            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                timeout_ms=5000,
                header_hooks=(lambda context: header_calls.append(context.method),),
                redirect_policy=RedirectPolicy.custom(2, decide),
            ) as client:
                budget = AttemptBudget(3)
                response = await client.post(
                    url + "/post",
                    body=b"payload",
                    budget=budget,
                    redirect_history_limit=2,
                )
                self.assertEqual(await response.read(max_bytes=32), b"done")
                self.assertEqual(response.redirects_followed, 2)
                self.assertEqual(len(response.redirect_history.entries), 2)
                self.assertEqual(budget.remaining, 0)
            self.assertEqual(seen, [(303, "POST", "GET", 1), (302, "GET", "GET", 2)])
            self.assertEqual(header_calls, ["POST"])
            self.assertEqual(
                [record[0] for record in peer.records], ["/post", "/middle", "/end"]
            )
            self.assertEqual(
                [record[2:] for record in peer.records],
                [(b"payload", "POST"), (b"", "GET"), (b"", "GET")],
            )

    async def test_stop_returns_unread_body_and_reject_prevents_next_attempt(self):
        with server(Handler) as (peer, url):
            peer.redirects = {"/start": "/end"}
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                for decision in (RedirectDecision.STOP, RedirectDecision.REJECT):
                    with self.subTest(decision=decision):
                        budget = AttemptBudget(2)
                        policy = RedirectPolicy.custom(
                            2, lambda attempt, decision=decision: decision
                        )
                        if decision is RedirectDecision.STOP:
                            response = await client.get(
                                url + "/start", redirect_policy=policy, budget=budget
                            )
                            self.assertEqual(response.status, 302)
                            self.assertEqual(
                                await response.read(max_bytes=64),
                                b"unread redirect body",
                            )
                        else:
                            with self.assertRaises(Error) as caught:
                                await client.get(
                                    url + "/start",
                                    redirect_policy=policy,
                                    budget=budget,
                                )
                            self.assertEqual(caught.exception.kind, "redirect")
                        self.assertEqual(budget.remaining, 1)
                self.assertEqual(
                    [record[0] for record in peer.records], ["/start", "/start"]
                )

    async def test_callback_cannot_restore_credentials_after_cross_origin_return(self):
        seen = []

        async def follow(attempt):
            seen.append(attempt.hop)
            return RedirectDecision.FOLLOW

        with server(Handler) as (first, url), server(Handler) as (second, other):
            first.redirects = {"/start": other + "/middle"}
            second.redirects = {"/middle": url + "/end"}
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                response = await client.get(
                    url + "/start",
                    headers=(("Authorization", "Bearer secret"), ("X-Key", "secret")),
                    redirect_policy=RedirectPolicy.custom(
                        2, follow, credential_headers=("x-key",)
                    ),
                )
                await response.read(max_bytes=32)
            self.assertEqual(seen, [1, 2])
            self.assertTrue(
                {name.lower() for name, _ in first.records[0][1]}
                >= {"authorization", "x-key"}
            )
            for record in (second.records[0], first.records[1]):
                self.assertFalse(
                    {name.lower() for name, _ in record[1]} & {"authorization", "x-key"}
                )

    async def test_hop_limit_precedes_callback_and_follow_does_not_bypass_budget(self):
        seen = []

        def follow(attempt):
            seen.append(attempt.hop)
            return RedirectDecision.FOLLOW

        with server(Handler) as (peer, url):
            peer.redirects = {"/start": "/middle", "/middle": "/end"}
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                with self.assertRaises(Error) as caught:
                    await client.get(
                        url + "/start", redirect_policy=RedirectPolicy.custom(1, follow)
                    )
                self.assertEqual(caught.exception.kind, "redirect")
                self.assertEqual(seen, [1])
                self.assertEqual(
                    [record[0] for record in peer.records], ["/start", "/middle"]
                )
                budget = AttemptBudget(1)
                with self.assertRaises(Error) as caught:
                    await client.get(
                        url + "/start",
                        redirect_policy=RedirectPolicy.custom(2, follow),
                        budget=budget,
                    )
                self.assertEqual(caught.exception.kind, "attempt_budget_exhausted")
                self.assertEqual(budget.remaining, 0)
                self.assertEqual(
                    [record[0] for record in peer.records],
                    ["/start", "/middle", "/start"],
                )

    async def test_original_base_exception_traceback_and_invalid_result(self):
        with server(Handler) as (peer, url):
            peer.redirects = {"/start": "/end"}
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                for original in (
                    ValueError("private"),
                    asyncio.CancelledError("private"),
                ):
                    with self.subTest(original=type(original).__name__):

                        async def decide(attempt, original=original):
                            await asyncio.sleep(0)
                            raise original

                        with self.assertRaises(Error) as caught:
                            await client.get(
                                url + "/start",
                                redirect_policy=RedirectPolicy.custom(1, decide),
                            )
                        self.assertEqual(caught.exception.kind, "redirect")
                        self.assertIs(caught.exception.original, original)
                        self.assertIn(
                            "decide",
                            "".join(traceback.format_tb(original.__traceback__)),
                        )
                        self.assertNotIn("private", str(caught.exception))
                with self.assertRaises(Error) as caught:
                    await client.get(
                        url + "/start",
                        redirect_policy=RedirectPolicy.custom(
                            1, lambda attempt: "follow"
                        ),
                    )
                self.assertIsInstance(caught.exception.original, TypeError)
            self.assertEqual([record[0] for record in peer.records], ["/start"] * 3)

    async def test_total_deadline_cancels_callback_before_follow_and_keeps_late_cause(
        self,
    ):
        entered, cancelled = asyncio.Event(), asyncio.Event()
        late = ValueError("callback cleanup failed")

        async def pending(attempt):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()
                raise late

        with server(Handler) as (peer, url):
            peer.redirects = {"/start": "/end"}
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                budget = AttemptBudget(2)
                task = asyncio.create_task(
                    client.get(
                        url + "/start",
                        timeout_ms=500,
                        budget=budget,
                        redirect_policy=RedirectPolicy.custom(1, pending),
                    )
                )
                await asyncio.wait_for(entered.wait(), 2)
                with self.assertRaises(TimeoutError) as caught:
                    await asyncio.wait_for(task, 3)
                self.assertEqual(caught.exception.timeout_phase, "total")
                self.assertIs(caught.exception.cleanup_error, late)
                await asyncio.wait_for(cancelled.wait(), 1)
                self.assertEqual(budget.remaining, 1)
                self.assertEqual([record[0] for record in peer.records], ["/start"])

    async def test_caller_cancellation_preserves_h2_sibling_and_reuse(self):
        entered, cancelled = asyncio.Event(), asyncio.Event()
        loop, thread = asyncio.get_running_loop(), threading.get_ident()
        seen = []

        async def pending(attempt):
            seen.append(
                (asyncio.get_running_loop() is loop, threading.get_ident(), TRACE.get())
            )
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        with H2Peer(
            redirects={b"/start": "/never"}, release_stall_on=b"/second"
        ) as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", context="raw", timeout_ms=5000
            ) as client:
                sibling = await client.get(peer.url + "/stall")
                self.assertEqual(await sibling.read_chunk(), b"a")
                token = TRACE.set("sender")
                budget = AttemptBudget(2)
                task = asyncio.create_task(
                    client.get(
                        peer.url + "/start",
                        budget=budget,
                        redirect_policy=RedirectPolicy.custom(1, pending),
                    )
                )
                TRACE.reset(token)
                await asyncio.wait_for(entered.wait(), 2)
                heartbeat = asyncio.Event()
                loop.call_soon(heartbeat.set)
                await asyncio.wait_for(heartbeat.wait(), 1)
                self.assertEqual(budget.remaining, 1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await asyncio.wait_for(cancelled.wait(), 1)
                response = await client.get(peer.url + "/second")
                self.assertEqual(await response.read(max_bytes=16), b"hello")
                self.assertEqual(await sibling.read(max_bytes=16), b"tail")
                self.assertIsNone(await sibling.read_chunk())
                self.assertEqual(
                    [path for _, path in peer.requests],
                    [b"/stall", b"/start", b"/second"],
                )
                self.assertEqual(seen, [(True, thread, "sender")])
                sibling.close()


class SyncRedirectCallbackTests(unittest.TestCase):
    def test_sync_callback_uses_existing_private_loop_and_async_is_rejected(self):
        seen = []

        def stop(attempt):
            seen.append(
                (threading.get_ident(), asyncio.get_running_loop(), attempt.hop)
            )
            return RedirectDecision.STOP

        async def asynchronous(attempt):
            raise AssertionError("async callback body must not run in Client")

        host = threading.get_ident()
        with server(Handler) as (peer, url):
            peer.redirects = {"/start": "/end"}
            with Client(
                profile=PROFILE,
                protocol="h1",
                context="raw",
                timeout_ms=5000,
                redirect_policy=RedirectPolicy.custom(1, stop),
            ) as client:
                private_loop = client._loop
                for _ in range(2):
                    with client.get(url + "/start") as response:
                        self.assertEqual(
                            response.read(max_bytes=64), b"unread redirect body"
                        )
                with self.assertRaises(Error) as caught:
                    client.get(
                        url + "/start",
                        redirect_policy=RedirectPolicy.custom(1, asynchronous),
                    )
                self.assertIsInstance(caught.exception.original, TypeError)
                self.assertIn("synchronous", str(caught.exception.original))
            self.assertEqual(seen[0][:2], (host, private_loop))
            self.assertEqual(seen[0][:2], seen[1][:2])
            self.assertEqual([record[0] for record in peer.records], ["/start"] * 3)
