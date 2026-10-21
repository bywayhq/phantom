"""Opt-in core decoding keeps the ordered wire headers and body cursor."""

import dataclasses
import gzip
import http.server
import types
import unittest
import zlib
from unittest.mock import patch

import phantom_http
from phantom_http import (
    AsyncClient,
    BodyLimitExceeded,
    Client,
    ContentDecoding,
    Error,
    Response,
)
from test_client import OPTIONS
from test_settings_transport import peer

PAYLOAD = b"hello"
GZIP = gzip.compress(PAYLOAD, mtime=0)


class DecodingHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests.append(list(self.headers.raw_items()))
        coding = "gzip"
        body = GZIP
        if self.path == "/empty":
            body = gzip.compress(b"", mtime=0)
        elif self.path == "/bad":
            body = b"private-invalid-gzip"
        elif self.path == "/stacked":
            coding = "gzip, deflate"
            body = zlib.compress(GZIP)
        elif self.path == "/unknown":
            coding = "private-unknown-coding"
        self.send_response(200)
        self.send_header("Content-Encoding", coding)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()


class DecodingFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_unsigned_limit_and_immutable_metadata(self):
        for maximum in (0, 2**64 - 1):
            self.assertEqual(
                ContentDecoding.advertised(maximum).maximum_decoded_bytes, maximum
            )
        self.assertIsNone(ContentDecoding.none().maximum_decoded_bytes)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ContentDecoding.advertised(0).maximum_decoded_bytes = 1
        for value in (True, 0.5, "private", None):
            with self.assertRaises(TypeError):
                ContentDecoding.advertised(value)
        for value in (-1, 2**64):
            with self.assertRaises(ValueError):
                ContentDecoding.advertised(value)
        received = []

        class Native:
            cookies = object()

            def __init__(self, *_):
                pass

            async def request(self, *arguments):
                received.append(arguments)
                return types.SimpleNamespace(
                    status=200,
                    protocol="h1",
                    headers=[],
                    decoded_content_codings=["gzip", "deflate"],
                )

        with patch.object(phantom_http._native, "NativeClient", Native):
            client = AsyncClient(**OPTIONS)
            for maximum in (0, 2**64 - 1):
                response = await client.request(
                    "GET",
                    "http://origin.invalid/",
                    content_decoding=ContentDecoding.advertised(maximum),
                )
                self.assertEqual(received[-1][-4], maximum)
                for owner in (response, Response(None, response)):
                    self.assertEqual(owner.decoded_content_codings, ("gzip", "deflate"))
                    with self.assertRaises(AttributeError):
                        owner.decoded_content_codings = ()
                response._native.decoded_content_codings.append("br")
                self.assertEqual(
                    response.decoded_content_codings, ("gzip", "deflate", "br")
                )
            with self.assertRaises(TypeError):
                await client.request(
                    "GET", "http://origin.invalid/", content_decoding={}
                )
            self.assertEqual(len(received), 2)


class SyncDecodingTests(unittest.TestCase):
    def test_default_encoded_and_opt_in_decoded_bytes_have_identical_request_order(
        self,
    ):
        fields = [
            ("X-Before", b"one"),
            ("Accept-Encoding", b"gzip"),
            ("X-After", b"two"),
        ]
        with peer() as server:
            server.RequestHandlerClass = DecodingHandler
            with Client(**OPTIONS) as client:
                for policy, expected, codings in (
                    (None, GZIP, ()),
                    (ContentDecoding.none(), GZIP, ()),
                    (ContentDecoding.advertised(5), PAYLOAD, ("gzip",)),
                ):
                    with client.request(
                        "GET", server.url, headers=fields, content_decoding=policy
                    ) as response:
                        self.assertEqual(response.status, 200)
                        wire = {
                            field.name.lower(): field.value
                            for field in response.headers
                        }
                        self.assertEqual(wire["content-encoding"], b"gzip")
                        self.assertEqual(
                            wire["content-length"],
                            str(len(GZIP)).encode(),
                        )
                        self.assertEqual(response.read(max_bytes=100), expected)
                        self.assertEqual(response.decoded_content_codings, codings)
            self.assertEqual(server.requests[0], server.requests[1])
            self.assertEqual(server.requests[1], server.requests[2])
            self.assertEqual(
                [field for field in server.requests[0] if field[0] in dict(fields)],
                [(name, value.decode()) for name, value in fields],
            )


class AsyncDecodingTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_exact_overflow_and_remaining_cursor(self):
        with peer() as server:
            server.RequestHandlerClass = DecodingHandler
            async with AsyncClient(**OPTIONS) as client:
                for path, maximum, expected in (("/empty", 0, b""), ("/", 5, PAYLOAD)):
                    async with await client.request(
                        "GET",
                        server.url + path,
                        headers=[("Accept-Encoding", "gzip")],
                        content_decoding=ContentDecoding.advertised(maximum),
                    ) as response:
                        self.assertEqual(await response.read(max_bytes=5), expected)
                for maximum in (0, 4):
                    async with await client.request(
                        "GET",
                        server.url,
                        headers=[("Accept-Encoding", "gzip")],
                        content_decoding=ContentDecoding.advertised(maximum),
                    ) as response:
                        with self.assertRaises(BodyLimitExceeded):
                            await response.read(max_bytes=100)
                        self.assertEqual(await response.read(max_bytes=0), b"")
                async with await client.request(
                    "GET",
                    server.url + "/stacked",
                    headers=[("Accept-Encoding", "gzip, deflate")],
                    content_decoding=ContentDecoding.advertised(5),
                ) as response:
                    self.assertEqual(
                        response.decoded_content_codings, ("gzip", "deflate")
                    )
                    self.assertEqual(await response.read_chunk(2), b"he")
                    self.assertEqual(await response.read(max_bytes=3), b"llo")

    async def test_malformed_unadvertised_and_unknown_codings_fail_on_body_read(self):
        with peer() as server:
            server.RequestHandlerClass = DecodingHandler
            async with AsyncClient(**OPTIONS) as client:
                for path, fields in (
                    ("/bad", [("Accept-Encoding", "gzip")]),
                    ("/", []),
                    ("/unknown", [("Accept-Encoding", "gzip")]),
                ):
                    async with await client.request(
                        "GET",
                        server.url + path,
                        headers=fields,
                        content_decoding=ContentDecoding.advertised(100),
                    ) as response:
                        self.assertEqual(response.status, 200)
                        with self.assertRaises(Error) as caught:
                            await response.read(max_bytes=100)
                        self.assertEqual(caught.exception.kind, "content_decoding")
                        self.assertNotIn("private", str(caught.exception))
                        self.assertEqual(await response.read(max_bytes=0), b"")
