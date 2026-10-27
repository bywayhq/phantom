"""Request contexts cross the native seam without changing client defaults."""

import asyncio
import unittest
from unittest.mock import patch

from test_convenience_facade import NativeClient
from test_upload_errors import FACADE
from test_upload_pump import Native as NativeUpload


class ContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_methods_and_stream_forward_only_explicit_request_contexts(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        for method in ("get", "head", "post", "put", "patch", "delete", "options"):
            response = await getattr(client, method)("/", context="fetch")
            await response.aclose()
            self.assertEqual(native.calls[-1][1]["context"], "fetch")

        async with client.stream("GET", "/", context="raw"):
            self.assertEqual(native.calls[-1][1]["context"], "raw")

        await client.get("/")
        self.assertNotIn("context", native.calls[-1][1])
        await client.get("/", context=None)
        self.assertNotIn("context", native.calls[-1][1])

    async def test_concurrent_overrides_remain_local_to_each_call(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        contexts = ["navigation", "fetch", "raw", "script", "font"]
        await asyncio.gather(
            *(client.get("/" + context, context=context) for context in contexts)
        )
        self.assertEqual(
            {args[1]: options["context"] for args, options in native.calls},
            {"/" + context: context for context in contexts},
        )

    async def test_native_context_rejection_settles_unrequested_upload(self):
        class RejectingClient(NativeClient):
            def request(self, *arguments, **options):
                self.calls.append((arguments, options))
                raise FACADE._native.NativeError(
                    "request", "request_template", None, None
                )

        pulls = []

        async def source():
            pulls.append(True)
            yield b"not requested"

        native = RejectingClient()
        client = FACADE.AsyncClient._from_native(native)
        uploads = []

        def upload(length):
            owner = NativeUpload(length)
            uploads.append(owner)
            return owner

        with (
            patch.object(FACADE._native, "NativeUpload", upload, create=True),
            self.assertRaises(FACADE.Error) as caught,
        ):
            await client.post("/", context="font", body=source())

        self.assertEqual(caught.exception.kind, "request_template")
        self.assertEqual(pulls, [])
        self.assertTrue(uploads[0].aborted)
        self.assertEqual(client._uploads, set())


class SyncContextTests(unittest.TestCase):
    def test_sync_methods_and_stream_forward_contexts(self):
        native = NativeClient()
        with (
            patch.object(
                FACADE._native, "NativeClient", lambda *args: native, create=True
            ),
            FACADE.Client(profile="exact", context="navigation") as client,
        ):
            with client.get("/", context="fetch"):
                self.assertEqual(native.calls[-1][1]["context"], "fetch")
            with client.stream("GET", "/", context="raw"):
                self.assertEqual(native.calls[-1][1]["context"], "raw")
            with client.request("GET", "/"):
                self.assertNotIn("context", native.calls[-1][1])
