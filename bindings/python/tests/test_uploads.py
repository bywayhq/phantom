"""Actual public producer uploads against independent HTTP/1 peers."""

import contextlib
import http.server
import threading
import time
import unittest

from phantom_http import (
    AsyncClient,
    AttemptBudget,
    Client,
    Error,
    RedirectPolicy,
    TimeoutError,
    TimeoutOverrides,
    Timeouts,
    UploadError,
)

PROFILE = "chrome/154.0.8037.97/windows-11-26200/r1"


class Peer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.records = []
        self.errors = []
        self.changed = threading.Condition()
        self.active = 0

    def process_request(self, request, address):
        with self.changed:
            self.active += 1
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            with self.changed:
                self.active -= 1
                self.changed.notify_all()

    def handle_error(self, *_):
        import sys

        self.errors.append(
            sys.exception() if hasattr(sys, "exception") else sys.exc_info()[1]
        )


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        self.connection.settimeout(5)
        payload = bytearray()
        if self.headers.get("Transfer-Encoding") == "chunked":
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                length = int(line.split(b";", 1)[0], 16)
                if length == 0:
                    if self.rfile.readline() != b"\r\n":
                        raise AssertionError("unexpected trailers")
                    break
                data = self.rfile.read(length)
                if len(data) != length or self.rfile.read(2) != b"\r\n":
                    return
                payload.extend(data)
        else:
            length = int(self.headers.get("Content-Length", "0"))
            payload.extend(self.rfile.read(length))
            if len(payload) != length:
                return
        self.server.records.append(
            (self.path, list(self.headers.raw_items()), bytes(payload))
        )
        status = 307 if self.path == "/redirect" else 200
        self.send_response(status)
        if status == 307:
            self.send_header("Location", "/must-not-replay")
        self.send_header("Content-Length", "0" if status == 307 else str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        if status == 200:
            self.wfile.write(payload)
        self.wfile.flush()
        self.close_connection = True


@contextlib.contextmanager
def server():
    peer = Peer()
    thread = threading.Thread(target=peer.serve_forever, daemon=True)
    thread.start()
    try:
        yield peer, f"http://127.0.0.1:{peer.server_port}"
    finally:
        peer.shutdown()
        peer.server_close()
        thread.join(5)
        deadline = time.monotonic() + 5
        with peer.changed:
            while peer.active:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError("upload peer handler did not settle")
                peer.changed.wait(remaining)
        if thread.is_alive():
            raise AssertionError("upload peer did not stop")
        unexpected = [
            error
            for error in peer.errors
            if not isinstance(
                error, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)
            )
        ]
        if unexpected:
            raise unexpected[0]


class UploadTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_total_rejects_before_attempt_and_producer_demand(self):
        with server() as (peer, url):
            async with (
                AsyncClient(
                    profile=PROFILE, protocol="h1", timeouts=Timeouts(total=0)
                ) as zero,
                zero.fork() as fork,
                AsyncClient(
                    profile=PROFILE, protocol="h1", timeouts=Timeouts(total=5)
                ) as positive,
            ):
                for name, client, overrides in (
                    ("client default", zero, None),
                    ("fork inherits", fork, None),
                    ("request override", positive, TimeoutOverrides(total=0)),
                ):
                    with self.subTest(name=name):
                        pulls = []

                        async def chunks(pulls=pulls):
                            pulls.append(True)
                            yield b"must not be pulled"

                        budget = AttemptBudget(1)
                        with self.assertRaises(TimeoutError) as caught:
                            await client.request(
                                "POST",
                                url,
                                body=chunks(),
                                budget=budget,
                                timeouts=overrides,
                            )
                        self.assertEqual(caught.exception.kind, "timeout")
                        self.assertEqual(caught.exception.timeout_phase, "total")
                        self.assertEqual(pulls, [])
                        self.assertEqual(budget.remaining, 1)
                        for limit in (None, 5):
                            async with await client.request(
                                "POST",
                                url,
                                body=b"ok",
                                timeouts=TimeoutOverrides(total=limit),
                            ) as response:
                                self.assertEqual(
                                    await response.read(max_bytes=2), b"ok"
                                )
                self.assertEqual(len(peer.records), 6)

    async def test_unknown_and_exact_length_preserve_payload_and_wire_headers(self):
        for length in (None, 131075):
            with self.subTest(length=length), server() as (peer, url):
                pulls = []
                closed = []

                async def chunks(pulls=pulls, closed=closed):
                    try:
                        pulls.append(1)
                        yield b"x" * 131072
                        yield b""
                        pulls.append(2)
                        yield b"end"
                    finally:
                        closed.append(True)

                async with (
                    AsyncClient(
                        profile=PROFILE, protocol="h1", timeout_ms=5000
                    ) as client,
                    await client.request(
                        "POST", url, body=chunks(), body_length=length
                    ) as response,
                ):
                    self.assertEqual(
                        await response.read(max_bytes=131075),
                        b"x" * 131072 + b"end",
                    )
                self.assertEqual(pulls, [1, 2])
                self.assertEqual(closed, [True])
                self.assertEqual(len(peer.records), 1)
                fields = {name.lower(): value for name, value in peer.records[0][1]}
                if length is None:
                    self.assertEqual(fields["transfer-encoding"], "chunked")
                    self.assertNotIn("content-length", fields)
                else:
                    self.assertEqual(fields["content-length"], str(length))
                    self.assertNotIn("transfer-encoding", fields)

    async def test_declared_length_checks_observed_frames_without_pulling_zero_body(
        self,
    ):
        for declared, payload, succeeds in [
            (0, b"", True),
            (0, b"x", True),
            (2, b"x", False),
            (1, b"xx", False),
        ]:
            with (
                self.subTest(declared=declared, payload=payload),
                server() as (peer, url),
            ):
                pulled = []

                async def chunks(payload=payload, pulled=pulled):
                    pulled.append(True)
                    if payload:
                        yield payload

                async with AsyncClient(
                    profile=PROFILE, protocol="h1", timeout_ms=5000
                ) as client:
                    if succeeds:
                        async with await client.request(
                            "POST", url, body=chunks(), body_length=declared
                        ) as response:
                            self.assertEqual(await response.read(max_bytes=0), b"")
                        self.assertEqual(len(peer.records), 1)
                        if declared == 0:
                            self.assertEqual(pulled, [])
                    else:
                        with self.assertRaises(Error) as caught:
                            response = await client.request(
                                "POST", url, body=chunks(), body_length=declared
                            )
                            await response.aclose()
                        self.assertEqual(caught.exception.kind, "request_body")

    async def test_source_failure_is_redacted_inspectable_and_client_reusable(self):
        original = ValueError("private-producer-value")

        async def chunks():
            yield b"first"
            raise original

        with server() as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", timeout_ms=5000
            ) as client:
                with self.assertRaises(UploadError) as caught:
                    await client.request("POST", url, body=chunks())
                self.assertIs(caught.exception.original, original)
                self.assertNotIn("private-producer-value", str(caught.exception))
                async with await client.request("POST", url, body=b"after") as response:
                    self.assertEqual(await response.read(max_bytes=5), b"after")
            self.assertEqual(len(peer.records), 1)

    async def test_one_shot_redirect_never_reiterates_or_sends_second_post(self):
        async def chunks():
            yield b"single-use"

        with server() as (peer, url):
            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                timeout_ms=5000,
                redirect_policy=RedirectPolicy.limited(1),
            ) as client:
                with self.assertRaises(Error) as caught:
                    await client.request("POST", url + "/redirect", body=chunks())
                self.assertEqual(caught.exception.kind, "request_body")
            self.assertEqual([record[0] for record in peer.records], ["/redirect"])

    async def test_invalid_body_kinds_and_length_fail_before_pulling(self):
        async with AsyncClient(profile=PROFILE, protocol="h1") as client:
            for body, length, exception in [
                (iter([b"x"]), None, TypeError),
                (b"x", 1, ValueError),
                (None, 0, ValueError),
            ]:
                with self.assertRaises(exception):
                    await client.request(
                        "POST", "http://127.0.0.1:1", body=body, body_length=length
                    )


class SyncUploadTests(unittest.TestCase):
    def test_sync_producer_is_consumed_and_closed_on_caller_thread(self):
        owner = threading.get_ident()
        operations = []

        def chunks():
            try:
                operations.append(threading.get_ident())
                yield b"hello"
            finally:
                operations.append(threading.get_ident())

        with server() as (peer, url):
            with (
                Client(profile=PROFILE, protocol="h1", timeout_ms=5000) as client,
                client.request("POST", url, body=chunks(), body_length=5) as response,
            ):
                self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(operations, [owner, owner])
            self.assertEqual(len(peer.records), 1)
