"""Bounded response helpers keep the existing body ownership rules."""

import asyncio
import types
import unittest

from phantom_http import (
    AsyncClient,
    AsyncResponse,
    BodyLimitExceeded,
    Client,
    DecodeError,
    HTTPStatusError,
    Response,
)
from test_client import OPTIONS, server
from test_http2 import PROFILE, H2Peer


class ReaderFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_checks_do_not_consume_or_close_a_response(self):
        for status in (399, 400, 599, 600):
            with self.subTest(status=status):
                native = types.SimpleNamespace(status=status, protocol="h2", headers=[])
                response = AsyncResponse(native)
                synchronous = Response(None, response)
                for owner in (response, synchronous):
                    self.assertEqual(owner.status_code, status)
                    if 400 <= status < 600:
                        with self.assertRaises(HTTPStatusError) as caught:
                            owner.raise_for_status()
                        self.assertIs(caught.exception.response, owner)
                        self.assertEqual(caught.exception.status_code, status)
                        self.assertEqual(caught.exception.protocol, "h2")
                        self.assertEqual(caught.exception.kind, "http_status")
                        self.assertEqual(
                            str(caught.exception), f"response: HTTP status {status}"
                        )
                    else:
                        self.assertIsNone(owner.raise_for_status())

    async def test_helpers_use_one_native_read_and_redact_decode_failures(self):
        class Native:
            status = 200
            protocol = "h1"
            headers = []

            def __init__(self, body):
                self.body = body
                self.calls = []
                self.closed = False

            async def read(self, maximum):
                self.calls.append(maximum)
                return self.body

            def close(self):
                self.closed = True

        for method, body, kind in (
            ("text", b"private-response\xff", "text_decode"),
            ("json", b'{"private-response":', "json_decode"),
            ("json", b"\xffprivate-response", "json_decode"),
        ):
            with self.subTest(method=method, kind=kind):
                native = Native(body)
                response = AsyncResponse(native)
                with self.assertRaises(DecodeError) as caught:
                    await getattr(response, method)(max_bytes=100)
                self.assertEqual(caught.exception.kind, kind)
                self.assertEqual(caught.exception.protocol, "h1")
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertNotIn("private-response", str(caught.exception))
                self.assertEqual(native.calls, [100])
                self.assertTrue(native.closed)

    async def test_cancelling_text_or_json_closes_the_pending_collection(self):
        for method in ("text", "json"):
            with self.subTest(method=method):
                started = asyncio.Event()

                class Native:
                    status = 200
                    protocol = "h2"
                    headers = []
                    closed = False

                    def __init__(self, entered):
                        self.entered = entered

                    async def read(self, _):
                        self.entered.set()
                        await asyncio.Future()

                    def close(self):
                        self.closed = True

                native = Native(started)
                response = AsyncResponse(native)
                pending = asyncio.create_task(getattr(response, method)(max_bytes=10))
                await started.wait()
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await pending
                self.assertTrue(native.closed)


class SyncReaderTests(unittest.TestCase):
    def test_text_encoding_and_json_use_bounded_remaining_bytes(self):
        with server() as (_, url), Client(**OPTIONS) as client:
            response = client.request("GET", url)
            self.assertEqual(response.text(max_bytes=5), "hello")
            self.assertEqual(response.text(max_bytes=0), "")
            response = client.request("GET", url + "/latin1")
            self.assertEqual(
                response.text(max_bytes=4, encoding="latin-1"), "caf\u00e9"
            )
            response = client.request("GET", url + "/latin1")
            self.assertEqual(response.text(max_bytes=4, errors="replace"), "caf\ufffd")
            response = client.request("GET", url)
            with self.assertRaises(DecodeError) as caught:
                response.text(max_bytes=5, encoding="unknown-private-encoding")
            self.assertEqual(caught.exception.kind, "encoding")
            self.assertNotIn("unknown-private-encoding", str(caught.exception))
            self.assertEqual(response.read(max_bytes=5), b"hello")
            response = client.request("GET", url + "/json")
            self.assertEqual(response.json(max_bytes=23), {"value": [True, None]})
            response = client.request("GET", url + "/json-utf16")
            self.assertEqual(response.json(max_bytes=100), {"value": "caf\u00e9"})
            response = client.request("GET", url + "/json-null")
            self.assertIsNone(response.json(max_bytes=4))
            response = client.request("GET", url + "/invalid-json")
            with self.assertRaises(DecodeError):
                response.json(max_bytes=100)

    def test_status_error_keeps_the_original_response_and_body(self):
        with server() as (_, url), Client(**OPTIONS) as client:
            response = client.request("GET", url + "/status")
            with self.assertRaises(HTTPStatusError) as caught:
                response.raise_for_status()
            self.assertIs(caught.exception.response, response)
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.text(max_bytes=11), "status body")


class AsyncReaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_reader_cancel_and_overflow_keep_a_healthy_http2_sibling(self):
        for method in ("text", "json"):
            for overflow in (False, True):
                with self.subTest(method=method, overflow=overflow), H2Peer() as peer:
                    async with AsyncClient(
                        profile=PROFILE, protocol="h2", timeout_ms=5000
                    ) as client:
                        path = "/overflow" if overflow else "/stall"
                        selected = await client.request("GET", peer.url + path)
                        if not overflow:
                            self.assertEqual(await selected.read_chunk(), b"a")
                        healthy = await client.request("GET", peer.url + "/healthy")
                        other = asyncio.create_task(healthy.text(max_bytes=5))
                        if overflow:
                            with self.assertRaises(BodyLimitExceeded):
                                await getattr(selected, method)(max_bytes=0)
                        else:
                            pending = asyncio.create_task(
                                getattr(selected, method)(max_bytes=20)
                            )
                            done, _ = await asyncio.wait({pending, other}, timeout=0.05)
                            self.assertFalse(done)
                            pending.cancel()
                            with self.assertRaises(asyncio.CancelledError):
                                await pending
                        self.assertTrue(await asyncio.to_thread(peer.reset.wait, 5))
                        self.assertEqual(peer.reset_code, 8)
                        self.assertEqual(peer.reset_stream, peer.requests[0][0])
                        self.assertEqual(await other, "hello")
                        reused = await client.request("GET", peer.url + "/reuse")
                        self.assertEqual(await reused.text(max_bytes=5), "hello")
                        self.assertEqual(len(peer.requests), 3)
                        self.assertEqual(
                            len({stream for stream, _ in peer.requests}), 3
                        )
                self.assertFalse(peer.premature_close)

    async def test_text_and_json_caps_partial_cursor_and_typed_errors(self):
        with server() as (_, url):
            async with AsyncClient(**OPTIONS) as client:
                response = await client.request("GET", url)
                self.assertEqual(await response.read_chunk(1), b"h")
                self.assertEqual(await response.text(max_bytes=4), "ello")
                response = await client.request("GET", url + "/json-null")
                self.assertIsNone(await response.json(max_bytes=4))
                for method, path in (("text", ""), ("json", "/json-null")):
                    response = await client.request("GET", url + path)
                    with self.assertRaises(BodyLimitExceeded):
                        await getattr(response, method)(max_bytes=0)
                    self.assertIsNone(await response.read_chunk())
                response = await client.request("GET", url + "/latin1")
                with self.assertRaises(DecodeError) as caught:
                    await response.text(max_bytes=4)
                self.assertEqual(caught.exception.kind, "text_decode")
                response = await client.request("GET", url + "/status")
                with self.assertRaises(HTTPStatusError) as caught:
                    response.raise_for_status()
                self.assertIs(caught.exception.response, response)
                self.assertEqual(await response.read(max_bytes=11), b"status body")
