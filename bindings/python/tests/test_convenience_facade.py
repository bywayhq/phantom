"""Everyday request preparation without loading a native extension."""

import asyncio
import inspect
import unittest
from types import SimpleNamespace
from typing import get_type_hints
from unittest.mock import patch

from test_upload_errors import FACADE, NativeResponse


class NativeClient:
    cookies = object()
    is_closed = False

    def __init__(self):
        self.calls = []
        self.responses = []

    async def request(self, *arguments, **options):
        self.calls.append((arguments, options))
        response = NativeResponse()
        self.responses.append(response)
        return response

    async def shutdown(self, _):
        self.is_closed = True


class EncodedBody:
    def __init__(self, data, content_type, _):
        self.data = data
        self.content_type = content_type
        self.length = len(data)


class ConvenienceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        factory = SimpleNamespace(encoded=EncodedBody)
        stub = patch.object(FACADE._native, "NativePreparedBody", factory, create=True)
        stub.start()
        self.addCleanup(stub.stop)

    async def test_query_appends_ordered_fields_without_reencoding_existing_url(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        await client.get(
            "/resource?raw=%2f#fragment",
            params=[
                ("tag", "one"),
                ("tag", "two"),
                ("space", "a b"),
                ("enabled", True),
                ("absent", None),
                ("empty", ""),
                ("utf8", "é"),
            ],
        )
        self.assertEqual(
            native.calls[0][0][:2],
            (
                "GET",
                "/resource?raw=%2f&tag=one&tag=two&space=a+b&enabled=true&empty=&utf8=%C3%A9#fragment",
            ),
        )
        await client.get("/untouched?", params={"skip": None})
        self.assertEqual(native.calls[-1][0][1], "/untouched?")
        await client.get("/empty?", params={"page": 1})
        self.assertEqual(native.calls[-1][0][1], "/empty?page=1")

    async def test_json_null_utf8_and_explicit_header_position(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        await client.post("/", json=None)
        self.assertEqual(native.calls[-1][1]["prepared_body"].data, b"null")
        self.assertEqual(
            native.calls[-1][0][2], [("content-type", b"application/json", False)]
        )
        await client.put(
            "/",
            json={"city": "Zürich"},
            headers=[
                ("X-Before", "a"),
                FACADE.Header("Content-Type", b"application/json", sensitive=True),
                ("X-After", "b"),
            ],
        )
        self.assertEqual(
            native.calls[-1][1]["prepared_body"].data, '{"city":"Zürich"}'.encode()
        )
        self.assertEqual(
            native.calls[-1][0][2],
            [
                ("X-Before", b"a", False),
                ("Content-Type", b"application/json", True),
                ("X-After", b"b", False),
            ],
        )

    async def test_form_reuses_native_preparation_without_exporting_bytes(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        body = SimpleNamespace(
            content_type="application/x-www-form-urlencoded;charset=UTF-8", length=15
        )
        constructor = SimpleNamespace(form=lambda pairs, cap: body)
        with patch.object(
            FACADE._native, "NativePreparedBody", constructor, create=True
        ):
            await client.post("/", form=[("tag", "one"), ("tag", "two")])
        arguments, options = native.calls[-1]
        self.assertIsNone(arguments[3])
        self.assertIs(options["prepared_body"], body)
        self.assertEqual(
            arguments[2],
            [("content-type", body.content_type.encode(), False)],
        )

    async def test_invalid_combinations_and_bounds_never_submit(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        for options in (
            {"body": b"", "json": None},
            {"upload": "unused", "json": {}},
            {"form": [], "json": {}},
            {"json": {"x": float("nan")}},
            {"json": "é", "maximum_body_bytes": 3},
            {"json": None, "maximum_body_bytes": -1},
            {"json": {}, "headers": [("Content-Type", "text/plain")]},
            {
                "json": {},
                "headers": [("Content-Type", "application/json")] * 2,
            },
            {"params": [("large", "a" * 65536)]},
        ):
            with self.subTest(options=tuple(options)), self.assertRaises(ValueError):
                await client.post("/", **options)
        await client.post("/", json="é", maximum_body_bytes=4)
        self.assertEqual(len(native.calls), 1)
        self.assertEqual(native.calls[0][1]["prepared_body"].data, b'"\xc3\xa9"')

    async def test_stream_context_closes_on_early_exit_exception_and_cancellation(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        async with client.stream("GET", "/"):
            self.assertFalse(native.responses[-1].closed)
        self.assertTrue(native.responses[-1].closed)

        failure = ValueError("consumer failed")
        with self.assertRaises(ValueError) as caught:
            async with client.stream("GET", "/"):
                raise failure
        self.assertIs(caught.exception, failure)
        self.assertTrue(native.responses[-1].closed)

        with self.assertRaises(asyncio.CancelledError):
            async with client.stream("GET", "/"):
                raise asyncio.CancelledError
        self.assertTrue(native.responses[-1].closed)

    async def test_helpers_retain_controls_and_async_shutdown_alias(self):
        native = NativeClient()
        client = FACADE.AsyncClient._from_native(native)
        budget = SimpleNamespace(_native=object())
        for verb in ("get", "head", "post", "put", "patch", "delete", "options"):
            await getattr(client, verb)("/", budget=budget, timeout_ms=99)
            arguments, _ = native.calls[-1]
            self.assertEqual(arguments[0], verb.upper())
            self.assertIs(arguments[5], budget._native)
            self.assertEqual(arguments[6], 99)
        await client.aclose()
        self.assertTrue(native.is_closed)


class SyncAndHeaderTests(unittest.TestCase):
    def setUp(self):
        factory = SimpleNamespace(encoded=EncodedBody)
        stub = patch.object(FACADE._native, "NativePreparedBody", factory, create=True)
        stub.start()
        self.addCleanup(stub.stop)

    def test_sync_helpers_and_stream_share_async_preparation(self):
        native = NativeClient()
        asynchronous = FACADE.AsyncClient._from_native(native)
        with (
            patch.object(FACADE, "AsyncClient", return_value=asynchronous),
            FACADE.Client(profile="test") as client,
        ):
            with client.stream("POST", "/", json={"ok": True}) as response:
                self.assertEqual(response.status_code, 200)
            self.assertTrue(native.responses[-1].closed)
            client.get("/", params={"page": 2})
            self.assertEqual(native.calls[-1][0][:2], ("GET", "/?page=2"))
            self.assertEqual(native.calls[0][1]["prepared_body"].data, b'{"ok":true}')

    def test_headers_preserve_order_markers_bytes_and_tuple_compatibility(self):
        native = NativeResponse()
        native.headers = [
            ("Set-Cookie", b"a=1", True),
            ("X-Raw", b"\xff", False),
            ("set-cookie", b"b=2", False),
        ]
        response = FACADE.AsyncResponse(native)
        fields = response.headers
        self.assertIsInstance(fields, tuple)
        self.assertEqual(fields[0], FACADE.ResponseHeader("Set-Cookie", b"a=1", True))
        self.assertEqual(fields.get("SET-cookie"), b"a=1")
        self.assertEqual(fields.get_list("set-cookie"), [b"a=1", b"b=2"])
        self.assertEqual(fields.get("x-raw"), b"\xff")
        self.assertIsNone(fields.get("absent"))
        self.assertEqual(fields.get("absent", "fallback"), "fallback")
        self.assertEqual(fields.get_list("absent"), [])
        self.assertIs(FACADE.Response(None, response).headers, fields)

    def test_helpers_have_resolvable_typed_options_and_negotiated_default(self):
        for owner in (FACADE.Client, FACADE.AsyncClient):
            self.assertEqual(
                inspect.signature(owner).parameters["protocol"].default, "negotiated"
            )
            for name in ("get", "post", "stream"):
                self.assertIn("options", get_type_hints(getattr(owner, name)))
