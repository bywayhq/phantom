"""Encrypted checkpoints retain state while restoring privately owned clients."""

import asyncio
import gc
import threading
import unittest
import weakref
from unittest.mock import patch

import phantom_http
from phantom_http import AsyncClient, Client, Proxy, SessionSnapshotError
from test_client import OPTIONS, server

KEY = b"checkpoint-test-key-not-a-secret"


class SnapshotFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_checkpoint_error_keeps_its_typed_redacted_identity(self):
        class Native:
            cookies = object()

            def export_session(self, _):
                raise phantom_http._native.NativeError(
                    "session_snapshot", "unsupported", None, None
                )

        source = AsyncClient._from_native(Native())
        with self.assertRaises(SessionSnapshotError) as caught:
            await source.export_session(KEY)
        self.assertEqual(caught.exception.kind, "unsupported")
        self.assertEqual(str(caught.exception), "session_snapshot: unsupported")
        self.assertIsNone(caught.exception.__cause__)

    async def test_cpu_work_is_off_loop_and_routes_are_owned_before_submission(self):
        loop_thread = threading.get_ident()
        calls = []

        class Native:
            cookies = object()

            def export_session(self, key):
                calls.append(("export", threading.get_ident(), key))
                return b"encrypted"

            def restore_session(self, snapshot, key, routes):
                calls.append(("restore", threading.get_ident(), snapshot, key, routes))
                return Native()

        source = AsyncClient._from_native(Native())
        self.assertEqual(await source.export_session(KEY), b"encrypted")
        child = await source.restore_session(
            b"encrypted",
            KEY,
            receiving_routes=(
                None,
                "http://127.0.0.1:80",
                Proxy("socks5h://127.0.0.1:81", "user", "password"),
            ),
        )
        self.assertIsNot(child._native, source._native)
        self.assertTrue(all(call[1] != loop_thread for call in calls))
        self.assertEqual(
            calls[1][4],
            [
                (None, None, None),
                ("http://127.0.0.1:80", None, None),
                ("socks5h://127.0.0.1:81", "user", "password"),
            ],
        )
        for operation in (
            source.export_session(bytearray(KEY)),
            source.restore_session(b"encrypted", KEY, receiving_routes=[object()]),
        ):
            with self.assertRaises(TypeError):
                await operation
        self.assertEqual(len(calls), 2)

    async def test_cancelled_restore_drops_its_unpublished_private_owner(self):
        entered, release, finished = (threading.Event() for _ in range(3))
        references = []

        class Native:
            cookies = object()

            def restore_session(self, *_):
                entered.set()
                if not release.wait(5):
                    raise AssertionError("test did not release CPU work")
                child = Native()
                references.append(weakref.ref(child))
                finished.set()
                return child

        source = AsyncClient._from_native(Native())
        pending = asyncio.create_task(source.restore_session(b"encrypted", KEY))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            pending.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await pending
        finally:
            release.set()
            self.assertTrue(await asyncio.to_thread(finished.wait, 5))
        # Join all executor work so no late callback/owner remains at inspection.
        await asyncio.get_running_loop().shutdown_default_executor()
        gc.collect()
        self.assertEqual(len(references), 1)
        self.assertIsNone(references[0]())


class SnapshotSyncFacadeTests(unittest.TestCase):
    def test_restore_uses_an_independent_loop_even_after_source_close(self):
        constructions = []

        class Native:
            cookies = object()

            def __init__(self, *_):
                constructions.append(self)
                self.is_closed = False

            def export_session(self, _):
                return b"encrypted"

            def restore_session(self, *_):
                child = object.__new__(Native)
                child.is_closed = False
                return child

            async def shutdown(self, _):
                self.is_closed = True

        with patch.object(phantom_http._native, "NativeClient", Native):
            with Client(**OPTIONS) as source:
                snapshot = source.export_session(KEY)
            with source.restore_session(snapshot, KEY) as child:
                self.assertEqual(len(constructions), 1)
                self.assertIsNot(source._loop, child._loop)
                self.assertFalse(child.is_closed)
                self.assertTrue(source.is_closed)
            self.assertTrue(child._loop.is_closed())


class SnapshotTests(unittest.TestCase):
    def test_cookie_checkpoint_private_pools_source_retention_and_close(self):
        with (
            server() as (origin, url),
            Client(**OPTIONS, base_url=url + "/", context="fetch") as source,
        ):
            source.cookies.set(url, "checkpoint=original; Path=/")
            snapshot = source.export_session(KEY)
            self.assertIsInstance(snapshot, bytes)
            self.assertNotIn(b"checkpoint=original", snapshot)
            source.cookies.set(url, "checkpoint=changed; Path=/")
            with source.restore_session(
                snapshot, KEY, receiving_routes=[None, Proxy("http://127.0.0.1:80")]
            ) as child:
                self.assertEqual(child.cookies.for_url(url), "checkpoint=original")
                self.assertEqual(source.cookies.for_url(url), "checkpoint=changed")
                for client, path in (
                    (source, "source"),
                    (child, "child"),
                    (child, "reuse"),
                ):
                    with client.request("GET", path) as response:
                        self.assertEqual(response.url, url + "/" + path)
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                source.close()
                with child.request("GET", "after-close") as response:
                    self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertNotEqual(origin.requests[0][1], origin.requests[1][1])
            self.assertEqual(origin.requests[1][1], origin.requests[2][1])
            self.assertEqual(origin.requests[1][1], origin.requests[3][1])
            for _, _, headers in origin.requests:
                self.assertEqual(dict(headers).get("Sec-Fetch-Mode"), "cors")

    def test_precise_redacted_failures_and_receiving_state_unchanged(self):
        with Client(**OPTIONS) as source, Client(**OPTIONS) as receiving:
            url = "https://origin.example/"
            source.cookies.set(url, "source=secret; Path=/; Secure")
            receiving.cookies.set(url, "receiving=untouched; Path=/; Secure")
            snapshot = source.export_session(KEY)
            version = snapshot[:8] + b"\0\xff" + snapshot[10:]
            corrupt = snapshot[:-1] + bytes([snapshot[-1] ^ 1])
            for data, key, kind in (
                (snapshot, b"x" * 32, "authentication"),
                (corrupt, KEY, "authentication"),
                (b"short", KEY, "invalid_snapshot"),
                (version, KEY, "incompatible"),
                (bytes(32 * 1024 * 1024), KEY, "invalid_snapshot"),
                (bytes(32 * 1024 * 1024 + 1), KEY, "too_large"),
                (snapshot, b"", "invalid_key_length"),
                (snapshot, bytes(31), "invalid_key_length"),
                (snapshot, bytes(33), "invalid_key_length"),
            ):
                with (
                    self.subTest(kind=kind),
                    self.assertRaises(SessionSnapshotError) as caught,
                ):
                    receiving.restore_session(data, key)
                self.assertEqual(caught.exception.category, "session_snapshot")
                self.assertEqual(caught.exception.kind, kind)
                self.assertNotIn("secret", repr(caught.exception))
            self.assertEqual(source.cookies.for_url(url), "source=secret")
            self.assertEqual(receiving.cookies.for_url(url), "receiving=untouched")
            with Client(**{**OPTIONS, "cookies": False}) as disabled:
                with self.assertRaises(SessionSnapshotError) as caught:
                    disabled.restore_session(snapshot, KEY)
                self.assertEqual(caught.exception.kind, "disabled")

    def test_core_rejects_unsupported_default_credentials_and_incompatible_route(self):
        with Client(**OPTIONS) as direct:
            snapshot = direct.export_session(KEY)
            with Client(**OPTIONS, proxy="http://127.0.0.1:80") as proxy:
                with self.assertRaises(SessionSnapshotError) as caught:
                    proxy.restore_session(snapshot, KEY)
                self.assertEqual(caught.exception.kind, "incompatible")
        with Client(
            **OPTIONS, proxy=Proxy("http://127.0.0.1:80", "secret", "password")
        ) as authenticated:
            with self.assertRaises(SessionSnapshotError) as caught:
                authenticated.export_session(KEY)
            self.assertEqual(caught.exception.kind, "unsupported")
            self.assertNotIn("secret", str(caught.exception))


class AsyncSnapshotTests(unittest.IsolatedAsyncioTestCase):
    async def test_restore_is_independent_and_uses_compatible_receiver_configuration(
        self,
    ):
        with server() as (_, url):
            async with AsyncClient(**OPTIONS) as source:
                source.cookies.set(url, "checkpoint=async; Path=/")
                snapshot = await source.export_session(KEY)
                async with await source.restore_session(snapshot, KEY) as child:
                    self.assertEqual(child.cookies.for_url(url), "checkpoint=async")
                    child.cookies.clear()
                    self.assertEqual(source.cookies.for_url(url), "checkpoint=async")
                    await child.close()
                    async with await source.request("GET", url) as response:
                        self.assertEqual(await response.read(max_bytes=5), b"hello")
