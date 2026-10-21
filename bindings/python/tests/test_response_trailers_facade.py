"""Non-draining immutable trailer projections without loading the extension."""

import asyncio
import dataclasses
import unittest

from test_upload_errors import FACADE


class Native:
    status = 200
    protocol = "h1"
    headers = []

    def __init__(self, payload=b"!"):
        self.state = "pending"
        self.payload = payload
        self.reads = 0
        self.snapshots = 0

    @property
    def trailers(self):
        self.snapshots += 1
        return self.state, (
            [("X-A", b"first", False), ("x-b", b"\x80", True), ("x-a", b"last", False)]
            if self.state == "complete"
            else None
        )

    async def read(self, _):
        self.reads += 1
        self.state = "complete"
        return self.payload

    def close(self):
        if self.state == "pending":
            self.state = "unavailable"


class TrailerFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_head_records_share_the_trailer_type_without_reading(self):
        native = Native()
        native.headers = [
            ("X-A", b"first", False),
            ("x-b", b"\x80", True),
            ("x-a", b"last", False),
        ]
        response = FACADE.AsyncResponse(native)
        sync = FACADE.Response(None, response)
        expected = tuple(FACADE.ResponseHeader(*field) for field in native.headers)
        for owner in (response, sync):
            self.assertEqual(owner.headers, expected)
            self.assertTrue(owner.headers[1].sensitive)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                owner.headers[1].sensitive = False
        self.assertNotIn("first", repr(response.headers))
        native.headers.clear()
        self.assertEqual(response.headers, expected)
        self.assertEqual(native.reads, 0)
        await response.read(max_bytes=1)
        self.assertEqual(type(response.trailers.headers[0]), type(response.headers[0]))
        response.close()
        self.assertEqual(sync.headers, expected)

    async def test_properties_do_not_poll_and_preserve_owned_order_bytes_and_marker(
        self,
    ):
        native = Native()
        response = FACADE.AsyncResponse(native)
        sync = FACADE.Response(None, response)
        for owner in (response, sync):
            self.assertEqual(owner.trailers, FACADE.ResponseTrailers("pending", None))
        self.assertEqual(native.reads, 0)
        self.assertEqual(native.snapshots, 2)
        await response.read(max_bytes=1)
        retained = response.trailers
        self.assertEqual(
            [field.name for field in retained.headers], ["X-A", "x-b", "x-a"]
        )
        self.assertEqual(retained.headers[1].value, b"\x80")
        self.assertTrue(retained.headers[1].sensitive)
        self.assertNotIn("first", repr(retained))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            retained.state = "unavailable"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            retained.headers[0].value = b"other"
        for owner in (response, sync):
            with self.assertRaises(AttributeError):
                owner.trailers = retained
            self.assertEqual(owner.trailers, retained)
        response.close()
        self.assertEqual(response.trailers, retained)
        self.assertIsNot(response.trailers, retained)
        self.assertEqual(native.reads, 1)

    async def test_post_eof_parse_errors_retain_completion_but_abandonment_does_not(
        self,
    ):
        for method, payload in (("text", b"\xff"), ("json", b"!")):
            response = FACADE.AsyncResponse(Native(payload))
            with self.assertRaises(FACADE.DecodeError):
                await getattr(response, method)(max_bytes=1)
            self.assertEqual(response.trailers.state, "complete")
        native = Native()
        response = FACADE.AsyncResponse(native)
        response.close()
        self.assertEqual(
            response.trailers, FACADE.ResponseTrailers("unavailable", None)
        )
        self.assertEqual(native.reads, 0)

    async def test_cancelled_collection_and_future_state_are_explicit_without_polling(
        self,
    ):
        entered = asyncio.Event()

        class Pending(Native):
            async def read(self, _):
                entered.set()
                await asyncio.Future()

        native = Pending()
        response = FACADE.AsyncResponse(native)
        reading = asyncio.create_task(response.read(max_bytes=1))
        await entered.wait()
        reading.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await reading
        self.assertEqual(response.trailers.state, "unavailable")
        native.state = "private-future-state"
        with self.assertRaises(FACADE.Error) as caught:
            _ = response.trailers
        self.assertEqual(caught.exception.kind, "unsupported_response_trailers")
        self.assertNotIn("private", str(caught.exception))
