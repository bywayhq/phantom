"""Ordered trailers and 100-continue against the existing owned HTTP/1 peer."""

import socket
import unittest

from phantom_http import (
    AsyncClient,
    AttemptBudget,
    Client,
    Error,
    Header,
    RedirectPolicy,
)
from test_uploads import PROFILE, server
from test_uploads import Handler as UploadHandler


class Handler(UploadHandler):
    rbufsize = 0

    def handle_expect_100(self):
        self.connection.settimeout(5)
        # No buffered reader can hide body bytes from this independent head oracle.
        self.connection.setblocking(False)
        try:
            try:
                pending = self.connection.recv(1, socket.MSG_PEEK)
            except BlockingIOError:
                pending = b""
            if pending and self.path != "/zero":
                raise AssertionError("body arrived before 100 Continue")
        finally:
            self.connection.settimeout(5)
        self.server.records.append(("head", self.path, list(self.headers.raw_items())))
        if self.path == "/early":
            self.send_response(417)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.flush()
            if self.rfile.read(1):
                raise AssertionError("body sent after final response")
            self.server.records.append(("early-eof",))
            self.close_connection = True
            return False
        self.send_response_only(100)
        self.end_headers()
        self.server.records.append(("continue", self.path))
        return True

    def read_exact(self, length):
        chunks = bytearray()
        while len(chunks) < length:
            data = self.rfile.read(length - len(chunks))
            if not data:
                raise AssertionError("incomplete body")
            chunks.extend(data)
        return bytes(chunks)

    def do_POST(self):
        self.connection.settimeout(5)
        payload = bytearray()
        trailers = []
        if self.headers.get("Transfer-Encoding") == "chunked":
            while True:
                length = int(self.rfile.readline().split(b";", 1)[0], 16)
                if not length:
                    while (line := self.rfile.readline()) != b"\r\n":
                        if not line:
                            raise AssertionError("incomplete trailers")
                        trailers.append(line)
                    break
                chunk = self.read_exact(length)
                if len(chunk) != length or self.read_exact(2) != b"\r\n":
                    raise AssertionError("incomplete body")
                payload.extend(chunk)
        else:
            length = int(self.headers.get("Content-Length", "0"))
            chunk = self.read_exact(length)
            if len(chunk) != length:
                raise AssertionError("incomplete body")
            payload.extend(chunk)
        self.server.records.append(
            (
                "body",
                self.path,
                list(self.headers.raw_items()),
                bytes(payload),
                trailers,
            )
        )
        self.send_response(307 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "/final")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True


class RequestBodyTests(unittest.IsolatedAsyncioTestCase):
    async def test_static_trailers_preserve_exact_wire_order_and_spelling(self):
        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                response = await client.request(
                    "POST",
                    url,
                    body=b"payload",
                    trailers=(
                        Header("X-Repeat", b"one", sensitive=True),
                        ("X-Middle", "between"),
                        ("x-repeat", b"two"),
                    ),
                )
                self.assertEqual(await response.read(max_bytes=0), b"")
            record = peer.records[0]
            self.assertEqual(record[3], b"payload")
            self.assertEqual(
                record[4],
                [b"X-Repeat: one\r\n", b"X-Middle: between\r\n", b"x-repeat: two\r\n"],
            )
            fields = [(name.lower(), value) for name, value in record[2]]
            self.assertIn(("transfer-encoding", "chunked"), fields)
            self.assertFalse(any(name == "content-length" for name, _ in fields))

    async def test_continue_wait_and_replay_are_core_owned_per_attempt(self):
        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                budget = AttemptBudget(2)
                response = await client.request(
                    "POST",
                    url + "/redirect",
                    body=b"payload",
                    expect_continue_ms=5000,
                    redirect_policy=RedirectPolicy.limited(1),
                    budget=budget,
                )
                self.assertEqual(response.status, 200)
                await response.read(max_bytes=0)
                self.assertEqual(budget.remaining, 0)
            self.assertEqual(
                [record[0] for record in peer.records], ["head", "continue", "body"] * 2
            )
            self.assertEqual(
                [record[3] for record in peer.records if record[0] == "body"],
                [b"payload"] * 2,
            )

    async def test_early_final_sends_no_body_and_closes_the_producer(self):
        class Source:
            pulls = 0
            closes = 0

            def __aiter__(self):
                return self

            async def __anext__(self):
                self.pulls += 1
                return b"payload"

            async def aclose(self):
                self.closes += 1

        with server(Handler) as (peer, url):
            source = Source()
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                response = await client.request(
                    "POST",
                    url + "/early",
                    body=source,
                    body_length=7,
                    expect_continue_ms=5000,
                )
                self.assertEqual(response.status, 417)
                await response.read(max_bytes=0)
                await response.aclose()
                self.assertLessEqual(source.pulls, 1)
                self.assertEqual(source.closes, int(source.pulls > 0))
        self.assertEqual([record[0] for record in peer.records], ["head", "early-eof"])

    async def test_invalid_fields_and_framing_leave_budget_unspent(self):
        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                cases = (
                    ({"trailers": [("Bad Name", b"value")]}, "http1"),
                    ({"trailers": [("Content-Length", b"3")]}, "http1"),
                    (
                        {
                            "headers": [("Content-Length", b"3")],
                            "trailers": [("X", b"a")],
                        },
                        "http1",
                    ),
                    (
                        {"headers": [("Expect", b"other")], "expect_continue_ms": 1},
                        "invalid_header",
                    ),
                )
                for options, kind in cases:
                    with self.subTest(options=tuple(options)):
                        budget = AttemptBudget(1)
                        with self.assertRaises(Error) as failed:
                            await client.request(
                                "POST", url, body=b"abc", budget=budget, **options
                            )
                        self.assertEqual(failed.exception.kind, kind)
                        self.assertEqual(budget.remaining, 1)
            self.assertEqual(peer.records, [])


class SyncRequestBodyTests(unittest.TestCase):
    def test_sync_zero_wait_and_trailers_use_the_same_native_controls(self):
        with server(Handler) as (peer, url):
            with (
                Client(profile=PROFILE, protocol="h1", context="raw") as client,
                client.request(
                    "POST",
                    url + "/zero",
                    body=b"payload",
                    trailers=(("X-End", "done"),),
                    expect_continue_ms=0,
                ) as response,
            ):
                self.assertEqual(response.read(max_bytes=0), b"")
            self.assertEqual(peer.records[-1][4], [b"X-End: done\r\n"])
