"""Raw HTTP/1 fields are retained only after validated body completion."""

import gzip
import threading
import unittest

from phantom_http import (
    AsyncClient,
    Client,
    ContentDecoding,
    DecodeError,
    Error,
    ResponseHeader,
    ResponseTrailers,
)
from test_client import OPTIONS
from test_uploads import Handler as UploadHandler
from test_uploads import server

FIELDS = b"X-A: first\r\nx-b: \x80middle\r\nx-a: last\r\n\r\n"
EXPECTED = (
    ResponseHeader("X-A", b"first", False),
    ResponseHeader("x-b", b"\x80middle", False),
    ResponseHeader("x-a", b"last", False),
)
HEAD = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"


def chunk(data):
    return f"{len(data):x}\r\n".encode() + data + b"\r\n"


class Handler(UploadHandler):
    def do_GET(self):
        self.connection.settimeout(5)
        self.server.records.append((self.path, self.client_address))
        if self.path == "/empty":
            self.wfile.write(HEAD + b"0\r\n\r\n")
            return
        if self.path == "/held":
            self.wfile.write(HEAD + chunk(b"a"))
            if not self.server.release_trailers.wait(5):
                raise AssertionError("caller did not consume the first body chunk")
            self.wfile.write(chunk(b"bc") + b"0\r\n" + FIELDS)
            return
        if self.path in ("/truncated", "/malformed"):
            suffix = (
                b"X-A: unfinished"
                if self.path == "/truncated"
                else b"Bad Name: x\r\n\r\n"
            )
            self.wfile.write(HEAD + chunk(b"a") + b"0\r\n" + suffix)
            self.close_connection = True
            return
        if self.path.startswith("/gzip"):
            data = bytearray(gzip.compress(b"abc", mtime=0))
            if self.path == "/gzip-bad":
                data[-8] ^= 1  # Invalid CRC after all decoded body bytes.
            self.wfile.write(
                HEAD.replace(b"\r\n\r\n", b"\r\nContent-Encoding: gzip\r\n\r\n")
                + chunk(data)
                + b"0\r\n"
                + FIELDS
            )
            return
        self.wfile.write(
            HEAD + chunk(b"\xff" if self.path == "/utf8" else b"!") + b"0\r\n" + FIELDS
        )


class SyncTrailerTests(unittest.TestCase):
    def test_pending_partial_and_complete_keep_wire_fields_after_close_and_reuse(self):
        with server(Handler) as (peer, origin), Client(**OPTIONS) as client:
            peer.release_trailers = threading.Event()
            response = client.request("GET", origin + "/held")
            self.assertEqual(response.trailers, ResponseTrailers("pending", None))
            chunks = response.iter_bytes(1)
            try:
                self.assertEqual(next(chunks), b"a")
                self.assertEqual(response.trailers.state, "pending")
                peer.release_trailers.set()
                self.assertEqual(list(chunks), [b"b", b"c"])
            finally:
                peer.release_trailers.set()
                chunks.close()
                response.close()
            self.assertEqual(response.trailers, ResponseTrailers("complete", EXPECTED))
            empty = client.request("GET", origin + "/empty")
            self.assertEqual(empty.read(max_bytes=0), b"")
            self.assertEqual(empty.trailers, ResponseTrailers("complete", ()))
            client.close()
            self.assertEqual(response.trailers.headers, EXPECTED)
        self.assertEqual(len({address for _, address in peer.records}), 1)

    def test_parse_errors_after_eof_keep_trailers_while_native_failures_do_not(self):
        with server(Handler) as (_, origin), Client(**OPTIONS) as client:
            for path, method in (("/utf8", "text"), ("/json", "json")):
                response = client.request("GET", origin + path)
                with self.assertRaises(DecodeError):
                    getattr(response, method)(max_bytes=1)
                self.assertEqual(
                    response.trailers, ResponseTrailers("complete", EXPECTED)
                )
            decoded = client.request(
                "GET",
                origin + "/gzip-ok",
                headers=(("accept-encoding", "gzip"),),
                content_decoding=ContentDecoding.advertised(3),
            )
            self.assertEqual(decoded.read(max_bytes=3), b"abc")
            self.assertEqual(decoded.trailers.headers, EXPECTED)
            for path, maximum in (
                ("/limit", 0),
                ("/truncated", 10),
                ("/malformed", 10),
                ("/gzip-bad", 10),
            ):
                response = client.request(
                    "GET",
                    origin + path,
                    headers=(("accept-encoding", "gzip"),),
                    content_decoding=ContentDecoding.advertised(3)
                    if path == "/gzip-bad"
                    else None,
                )
                with self.assertRaises(Error):
                    response.read(max_bytes=maximum)
                self.assertEqual(
                    response.trailers, ResponseTrailers("unavailable", None)
                )


class AsyncTrailerTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_collection_retains_trailers_and_unread_close_is_unavailable(
        self,
    ):
        with server(Handler) as (_, origin):
            async with AsyncClient(**OPTIONS) as client:
                response = await client.request("GET", origin + "/coalesced")
                self.assertEqual(response.trailers.state, "pending")
                self.assertEqual(await response.read(max_bytes=1), b"!")
                self.assertEqual(
                    response.trailers, ResponseTrailers("complete", EXPECTED)
                )
                await response.aclose()
                self.assertEqual(response.trailers.state, "complete")
                abandoned = await client.request("GET", origin + "/coalesced")
                await abandoned.aclose()
                self.assertEqual(
                    abandoned.trailers, ResponseTrailers("unavailable", None)
                )
