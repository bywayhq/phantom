"""Redirect callback ownership without loading native code."""

import asyncio
import contextvars
import dataclasses
import traceback
import types
import unittest
from unittest.mock import patch

from test_header_hooks_facade import Mailbox as HeaderMailbox
from test_upload_errors import FACADE

hooks_module = __import__(FACADE.__name__ + "._header_hooks", fromlist=["_"])
TRACE = contextvars.ContextVar("redirect-callback-trace", default=None)


class Mailbox(HeaderMailbox):
    def __init__(self, count, redirects=False):
        super().__init__(count)
        self.redirects = redirects

    async def redirect(self):
        self.serial += 1
        self.reply = asyncio.get_running_loop().create_future()
        self.queue.put_nowait(
            (
                self.serial,
                "redirect",
                "https://local/private?secret",
                "https://other/next?secret",
                303,
                "POST",
                "GET",
                1,
            )
        )
        return await self.reply

    def complete_redirect(self, serial, decision):
        self.complete(serial, decision)

    def fail(self, serial, original):
        if self.closed.is_set() or self.reply.done() or serial != self.serial:
            raise FACADE._native.NativeError("input", "header_hook_closed", None, None)
        failure = FACADE._native.NativeError("request", "redirect", "h1", None)
        failure.original = original
        self.reply.set_exception(failure)


class Native:
    cookies = object()
    is_closed = False

    def __init__(self, *args, **kwargs):
        self.calls = []

    async def request(self, *args, header_hooks=None, **kwargs):
        self.calls.append((args, kwargs))
        decision = None
        if header_hooks is not None:
            try:
                for index in range(header_hooks.count):
                    await header_hooks.invoke(index)
                if header_hooks.redirects:
                    decision = await header_hooks.redirect()
            finally:
                header_hooks.abort()
        return types.SimpleNamespace(
            status=302 if decision == "stop" else 200, protocol="h1", headers=[]
        )

    def fork(self, *args):
        return Native()

    def restore_session(self, *args):
        return Native()

    async def shutdown(self, timeout_ms):
        self.is_closed = True

    def abort(self):
        self.is_closed = True


class RedirectPolicyTests(unittest.TestCase):
    def test_bounded_policy_and_immutable_redacted_attempt(self):
        def callback(attempt):
            return FACADE.RedirectDecision.FOLLOW

        for maximum in (0, -1, 2**65):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                FACADE.RedirectPolicy.custom(maximum, callback)
        for maximum in (True, 1.0):
            with self.subTest(maximum=maximum), self.assertRaises(TypeError):
                FACADE.RedirectPolicy.custom(maximum, callback)
        with self.assertRaises(TypeError):
            FACADE.RedirectPolicy.custom(1, None)
        attempt = FACADE.RedirectAttempt("private", "secret", 303, "POST", "GET", 1)
        self.assertNotIn("secret", repr(attempt))
        self.assertNotIn("private", repr(attempt))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            attempt.hop = 2
        self.assertNotIn("callback", repr(FACADE.RedirectPolicy.custom(1, callback)))


class RedirectCallbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        for name, value in (("NativeHeaderHooks", Mailbox), ("NativeClient", Native)):
            replacement = patch.object(FACADE._native, name, value, create=True)
            replacement.start()
            self.addCleanup(replacement.stop)

    async def test_owning_loop_context_order_and_default_fork_restore_override(self):
        seen = []
        loop = asyncio.get_running_loop()

        async def decide(attempt):
            await asyncio.sleep(0)
            self.assertIs(asyncio.get_running_loop(), loop)
            self.assertEqual(TRACE.get(), "caller")
            self.assertEqual(
                (attempt.status, attempt.method, attempt.next_method, attempt.hop),
                (303, "POST", "GET", 1),
            )
            self.assertTrue(attempt.to_url.endswith("/next?secret"))
            seen.append("redirect")
            return FACADE.RedirectDecision.STOP

        policy = FACADE.RedirectPolicy.custom(
            3, decide, credential_headers=("x-api-key",)
        )
        TRACE.set("caller")
        client = FACADE.AsyncClient(
            profile="chrome-154-windows",
            redirect_policy=policy,
            header_hooks=(lambda context: seen.append("headers"),),
        )
        children = (client.fork(), await client.restore_session(b"snapshot", b"k" * 32))
        try:
            for owner in (client, *children):
                self.assertIs(owner._redirect_policy, policy)
                response = await owner.post("https://local", body=b"body")
                self.assertEqual(response.status, 302)
                args, fields = owner._native.calls[-1]
                self.assertEqual(args[9], 3)
                self.assertEqual(fields["redirect_credential_headers"], ("x-api-key",))
                await owner.get(
                    "https://local", redirect_policy=FACADE.RedirectPolicy.none()
                )
                self.assertEqual(owner._native.calls[-1][0][9], 0)
            self.assertEqual(seen, ["headers", "redirect", "headers"] * 3)
            with self.assertRaisesRegex(ValueError, "EventSource"):
                client.event_source("https://local", protocol="h1")
        finally:
            for owner in (*children, client):
                await owner.close()

    async def test_original_base_exception_identity_traceback_and_invalid_decision(
        self,
    ):
        for original in (ValueError("private"), asyncio.CancelledError("private")):
            with self.subTest(original=type(original).__name__):

                async def callback(attempt, original=original):
                    await asyncio.sleep(0)
                    raise original

                async with FACADE.AsyncClient(profile="chrome-154-windows") as client:
                    with self.assertRaises(FACADE.Error) as caught:
                        await client.get(
                            "https://local",
                            redirect_policy=FACADE.RedirectPolicy.custom(2, callback),
                        )
                    self.assertEqual(caught.exception.kind, "redirect")
                    self.assertIs(caught.exception.original, original)
                    self.assertIn(
                        "callback", "".join(traceback.format_tb(original.__traceback__))
                    )
        async with FACADE.AsyncClient(profile="chrome-154-windows") as client:
            with self.assertRaises(FACADE.Error) as caught:
                await client.get(
                    "https://local",
                    redirect_policy=FACADE.RedirectPolicy.custom(
                        2, lambda attempt: "follow"
                    ),
                )
            self.assertIsInstance(caught.exception.original, TypeError)

    async def test_sync_host_rejects_awaitable_without_running_callback_body(self):
        ran = False

        async def callback(attempt):
            nonlocal ran
            ran = True
            return FACADE.RedirectDecision.FOLLOW

        async with FACADE.AsyncClient(profile="chrome-154-windows") as client:
            with self.assertRaises(FACADE.Error) as caught:
                await client._request(
                    "GET",
                    "https://local",
                    _synchronous=True,
                    redirect_policy=FACADE.RedirectPolicy.custom(1, callback),
                )
            self.assertIsInstance(caught.exception.original, TypeError)
            self.assertIn("synchronous", str(caught.exception.original))
        self.assertFalse(ran)

    async def test_caller_cancellation_waits_for_callback_cleanup_and_retains_late_error(
        self,
    ):
        entered, release, exiting = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original = ValueError("late callback failure")

        async def callback(attempt):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                exiting.set()
                await release.wait()
                raise original

        async with FACADE.AsyncClient(profile="chrome-154-windows") as client:
            task = asyncio.create_task(
                client.get(
                    "https://local",
                    redirect_policy=FACADE.RedirectPolicy.custom(1, callback),
                )
            )
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            await asyncio.wait_for(exiting.wait(), 1)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            pumps = tuple(client._header_pumps)
            self.assertEqual(len(pumps), 1)
            self.assertIs(pumps[0].cleanup_error, original)
            with self.assertRaises(FACADE.Error) as caught:
                await client.close()
            self.assertIs(caught.exception.original, original)

    async def test_native_deadline_stays_primary_and_waits_for_late_callback_failure(
        self,
    ):
        entered, cleanup, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original = ValueError("late redirect failure")

        async def callback(attempt):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleanup.set()
                await release.wait()
                raise original

        async def timeout(native, *args, header_hooks, **kwargs):
            invocation = asyncio.create_task(header_hooks.redirect())
            try:
                await entered.wait()
                raise FACADE._native.NativeError("request", "timeout", "h1", "total")
            finally:
                header_hooks.abort()
                invocation.cancel()
                await asyncio.gather(invocation, return_exceptions=True)

        async with FACADE.AsyncClient(profile="chrome-154-windows") as client:
            with patch.object(Native, "request", timeout):
                task = asyncio.create_task(
                    client.get(
                        "https://local",
                        redirect_policy=FACADE.RedirectPolicy.custom(1, callback),
                    )
                )
                await asyncio.wait_for(cleanup.wait(), 1)
                self.assertFalse(task.done())
                release.set()
                with self.assertRaises(FACADE.TimeoutError) as caught:
                    await task
                self.assertEqual(caught.exception.timeout_phase, "total")
                self.assertIs(caught.exception.cleanup_error, original)
