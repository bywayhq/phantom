"""Facade lifecycle controls use owned fake native operations, without transport."""

import asyncio
import types
import unittest
from unittest.mock import patch

import phantom_http
from phantom_http import (
    AsyncClient,
    AsyncResponse,
    Client,
    Response,
    TimeoutError,
    UploadError,
    _upload,
)
from test_upload_pump import Native


class NativeClient:
    cookies = object()
    is_closed = False

    def __init__(self, *_):
        pass

    async def shutdown(self, _):
        self.is_closed = True

    def abort(self):
        self.is_closed = True


class SyncLifecycleTests(unittest.TestCase):
    def test_response_close_after_client_shutdown_is_idempotent(self):
        calls = []
        native = types.SimpleNamespace(
            status=200, protocol="h1", headers=[], close=lambda: calls.append("close")
        )
        with patch.object(phantom_http._native, "NativeClient", NativeClient):
            client = Client(profile="exact", protocol="h1")
            response = Response(client, AsyncResponse(native))
            client.close()
            response.close()
            response.close()
            self.assertEqual(calls, ["close", "close"])

    def test_unfinished_sync_cleanup_retains_loop_and_can_be_closed_again(self):
        with (
            patch.object(phantom_http._native, "NativeClient", NativeClient),
            patch.object(_upload._native, "NativeUpload", Native),
        ):
            client = Client(profile="exact", protocol="h1")
            release = None
            pump = None

            async def setup():
                nonlocal release, pump
                release = asyncio.Event()
                entered = asyncio.Event()

                class Source:
                    def __aiter__(self):
                        return self

                    async def __anext__(self):
                        entered.set()
                        await asyncio.Future()

                    async def aclose(self):
                        await release.wait()

                pump = _upload.Upload(Source(), None)
                client._async._uploads.add(pump)
                pump.settled.add_done_callback(
                    lambda _: client._async._uploads.discard(pump)
                )
                pump.native.credits.put_nowait(True)
                await entered.wait()

            client._run(setup)
            try:
                with self.assertRaises(TimeoutError):
                    client.abort(timeout_ms=0)
                self.assertFalse(client._loop.is_closed())
                self.assertFalse(pump.settled.done())
                release.set()
                client.abort()
                self.assertTrue(client._loop.is_closed())
                self.assertTrue(pump.settled.done())
            finally:
                if not client._loop.is_closed():
                    release.set()
                    client.abort()


class AsyncLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_self_cleanup_wait_is_rejected_without_deadlock(self):
        with patch.object(_upload._native, "NativeUpload", Native):
            client = AsyncClient._from_native(NativeClient())
            original = RuntimeError("private-original")

            class Source:
                def __aiter__(self):
                    return self

                async def __anext__(self):
                    raise original

                async def aclose(self):
                    await client.close()

            pump = _upload.Upload(Source(), None)
            client._uploads.add(pump)
            pump.settled.add_done_callback(lambda _: client._uploads.discard(pump))
            pump.native.credits.put_nowait(True)
            self.assertTrue(await pump.wait())
            self.assertIs(pump.error, original)
            self.assertIsInstance(pump.cleanup_error, RuntimeError)
            self.assertIn("own cleanup", str(pump.cleanup_error))
            self.assertFalse(client.is_closed)
            await client.close()

    async def test_response_self_settlement_is_rejected_and_error_is_redacted(self):
        with patch.object(_upload._native, "NativeUpload", Native):
            response = None

            class Source:
                def __aiter__(self):
                    return self

                async def __anext__(self):
                    raise StopAsyncIteration

                async def aclose(self):
                    await response.aclose()

            pump = _upload.Upload(Source(), None)
            response = AsyncResponse(
                types.SimpleNamespace(
                    status=200, protocol="h2", headers=[], close=lambda: None
                ),
                pump,
            )
            pump.native.credits.put_nowait(True)
            self.assertTrue(await pump.wait())
            with self.assertRaises(UploadError) as caught:
                await response.aclose()
            self.assertIs(caught.exception.cleanup_error, pump.cleanup_error)
            self.assertNotIn("own cleanup", str(caught.exception))
