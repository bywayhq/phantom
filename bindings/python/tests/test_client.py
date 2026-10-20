"""Real CPython calls against controlled loopback HTTP peers."""

import asyncio
import contextlib
import http.server
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from phantom_http import (
    AsyncClient,
    AsyncResponse,
    AttemptBudget,
    AttemptBudgetExhausted,
    BodyLimitExceeded,
    Client,
    ClientClosed,
    Error,
    TimeoutError,
)

PROFILE = "chrome/154.0.8037.97/windows-11-26200/r1"
OPTIONS = {"profile": PROFILE, "protocol": "h1", "timeout_ms": 5000}


class CollectionFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_one_native_collection_call_and_unbounded_python_integer(self):
        class Native:
            status = 200
            protocol = "h1"
            headers = []
            calls = []
            closed = False

            async def read(self, maximum):
                self.calls.append(maximum)
                return b"hello"

            def close(self):
                self.closed = True

        native = Native()
        response = AsyncResponse(native)
        for invalid in (-1, None, 1.5):
            with self.assertRaises(ValueError):
                await response.read(max_bytes=invalid)
        self.assertFalse(native.closed)
        self.assertEqual(native.calls, [])
        self.assertEqual(await response.read(max_bytes=10**100), b"hello")
        self.assertEqual(native.calls, [sys.maxsize])
        self.assertTrue(native.closed)

    async def test_cancelled_native_collection_closes_response(self):
        started = asyncio.Event()

        class Native:
            status = 200
            protocol = "h2"
            headers = []
            closed = False

            async def read(self, _):
                started.set()
                await asyncio.Future()

            def close(self):
                self.closed = True

        native = Native()
        pending = asyncio.create_task(AsyncResponse(native).read(max_bytes=5))
        await started.wait()
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertTrue(native.closed)


class Peer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.requests = []
        self.entered = threading.Event()
        self.disconnected = threading.Event()
        self.upload_release = threading.Event()
        self.upload_received = 0

    def handle_error(self, *_):
        self.disconnected.set()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_PUT(self):
        size = int(self.headers.get("Content-Length", "0"))
        received = bytearray()
        self.server.entered.set()
        if self.path == "/upload-stall":
            # Leave the caller blocked on upload, then observe its disconnect.
            self.connection.settimeout(8)
            self.server.upload_release.wait(5)
            try:
                while chunk := self.rfile.read1(8192):
                    self.server.upload_received += len(chunk)
            except (ConnectionAbortedError, ConnectionResetError):
                pass
            finally:
                self.server.disconnected.set()
                self.close_connection = True
            return
        while len(received) < size:
            chunk = self.rfile.read(min(8192, size - len(received)))
            if not chunk:
                return
            received.extend(chunk)
        self.reply(bytes(received))

    def do_GET(self):
        self.server.requests.append(
            (self.path, self.client_address, list(self.headers.raw_items()))
        )
        if self.path == "/stall":
            self.send_response(200)
            self.send_header("Content-Length", "999999")
            self.end_headers()
            self.wfile.write(b"a")
            self.wfile.flush()
            self.server.entered.set()
            self.connection.settimeout(8)
            if not self.connection.recv(1):
                self.server.disconnected.set()
            return
        body = b"" if self.path == "/empty" else b"hello"
        if self.path == "/large":
            body = b"x" * 200000
        elif self.path == "/latin1":
            body = b"caf\xe9"
        elif self.path == "/json":
            body = b'{"value": [true, null]}'
        elif self.path == "/json-utf16":
            body = '{"value": "caf\u00e9"}'.encode("utf-16")
        elif self.path == "/json-null":
            body = b"null"
        elif self.path == "/invalid-json":
            body = b'{"private-response":'
        elif self.path == "/status":
            self.reply(b"status body", status=404)
            return
        elif self.path.startswith("/redirect?"):
            self.send_response(302)
            self.send_header("Location", "/must-not-be-followed")
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"hello")
            self.wfile.flush()
            return
        self.reply(body)

    def reply(self, body, *, status=200):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "seen=yes; Path=/")
        self.send_header("X-Duplicate", "one")
        self.send_header("X-Duplicate", "two")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()


@contextlib.contextmanager
def server():
    peer = Peer()
    worker = threading.Thread(
        target=lambda: peer.serve_forever(poll_interval=0.01), daemon=True
    )
    worker.start()
    try:
        yield peer, f"http://127.0.0.1:{peer.server_port}"
    finally:
        peer.shutdown()
        peer.server_close()
        worker.join(5)


class SyncTests(unittest.TestCase):
    def test_collection_limits_and_python_integer_validation(self):
        with server() as (_, url), Client(**OPTIONS) as client:
            for maximum in (5, 10**100):
                with self.subTest(maximum=maximum):
                    response = client.request("GET", url)
                    self.assertEqual(response.read(max_bytes=maximum), b"hello")
                    self.assertEqual(response.read(max_bytes=0), b"")
            for maximum in (0, False):
                response = client.request("GET", url + "/empty")
                self.assertEqual(response.read(max_bytes=maximum), b"")
            for maximum in (0, 4, True):
                with self.subTest(maximum=maximum):
                    response = client.request("GET", url)
                    with self.assertRaises(BodyLimitExceeded) as caught:
                        response.read(max_bytes=maximum)
                    self.assertEqual(caught.exception.category, "request")
                    self.assertEqual(caught.exception.kind, "response_body_limit")
                    self.assertEqual(response.read(max_bytes=0), b"")
            response = client.request("GET", url)
            for maximum in (-1, 1.5, "5", None):
                with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                    response.read(max_bytes=maximum)
            self.assertEqual(response.read(max_bytes=5), b"hello")

    def test_reuse_headers_cookies_budget_and_shutdown(self):
        with server() as (peer, url):
            client = Client(**OPTIONS)
            budget = AttemptBudget(2)
            with client.request(
                "GET",
                url + "/ok",
                headers=[("X-B", b"1"), ("X-A", "2")],
                budget=budget,
            ) as response:
                self.assertEqual(response.read(max_bytes=5), b"hello")
                self.assertEqual(
                    [
                        value
                        for name, value in response.headers
                        if name.lower() == "x-duplicate"
                    ],
                    [b"one", b"two"],
                )
            self.assertEqual(client.cookies.for_url(url), "seen=yes")
            with client.request("GET", url + "/again", budget=budget) as response:
                self.assertEqual(b"".join(response.iter_bytes(2)), b"hello")
            self.assertEqual(peer.requests[0][1], peer.requests[1][1])
            fields = peer.requests[0][2]
            self.assertLess(fields.index(("X-B", "1")), fields.index(("X-A", "2")))
            with self.assertRaises(AttemptBudgetExhausted):
                client.request("GET", url, budget=budget)
            self.assertEqual(len(peer.requests), 2)
            client.cookies.clear()
            self.assertEqual(len(client.cookies), 0)
            client.close()
            with self.assertRaises(ClientClosed):
                client.request("GET", url)

    def test_file_upload_chunks_collection_limit_and_redaction(self):
        with server() as (_, url), tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upload"
            data = bytes(range(256)) * 512
            path.write_bytes(data)
            with Client(**OPTIONS) as client:
                with client.request("PUT", url + "/upload", upload=path) as response:
                    self.assertEqual(response.read(max_bytes=len(data)), data)
                with client.request("PUT", url + "/bytes", body=b"bytes") as response:
                    self.assertEqual(response.read(max_bytes=5), b"bytes")
                with (
                    client.request("GET", url + "/large") as response,
                    self.assertRaises(BodyLimitExceeded),
                ):
                    response.read(max_bytes=9)
            with self.assertRaises(Error) as caught:
                Client(
                    profile=PROFILE, protocol="h1", proxy="http://user:secret@127.0.0.1"
                )
            self.assertNotIn("secret", str(caught.exception))

    def test_explicit_http_proxy_forwards_without_origin_dns(self):
        with server() as (peer, url), Client(**OPTIONS, proxy=url) as client:
            with client.request("GET", "http://origin.invalid/resource") as response:
                self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(peer.requests[0][0], "http://origin.invalid/resource")

    def test_sync_rejects_an_active_event_loop(self):
        async def check():
            with self.assertRaises(RuntimeError):
                Client(**OPTIONS)

        asyncio.run(check())

    def test_racing_settlement_preserves_keyboard_interrupt(self):
        class Task:
            cancelled = False

            def cancel(self):
                self.cancelled = True

        task = Task()

        class Loop:
            calls = 0

            def is_closed(self):
                return False

            def create_task(self, _):
                return task

            def run_until_complete(self, _):
                self.calls += 1
                if self.calls == 1:
                    raise KeyboardInterrupt
                raise Error("request", "connect")

        client = Client.__new__(Client)
        client._thread = threading.get_ident()
        client._loop = Loop()
        with self.assertRaises(KeyboardInterrupt):
            client._run(lambda: None)
        self.assertTrue(task.cancelled)


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_explicit_close_wakes_pending_collection(self):
        with server() as (peer, url):
            async with AsyncClient(**OPTIONS) as client:
                response = await client.request("GET", url + "/stall")
                self.assertEqual(await response.read_chunk(), b"a")
                pending = asyncio.create_task(response.read(max_bytes=20))
                done, _ = await asyncio.wait({pending}, timeout=0.05)
                self.assertFalse(done)
                response.close()
                with self.assertRaises(Error) as caught:
                    await pending
                self.assertEqual(caught.exception.kind, "body_closed")
                self.assertTrue(await asyncio.to_thread(peer.disconnected.wait, 5))
                self.assertIsNone(await response.read_chunk())

    async def test_collection_after_partial_chunk_and_multiple_frames(self):
        with server() as (_, url):
            async with AsyncClient(**OPTIONS) as client:
                response = await client.request("GET", url)
                self.assertEqual(await response.read_chunk(1), b"h")
                self.assertEqual(await response.read(max_bytes=4), b"ello")
                response = await client.request("GET", url)
                self.assertEqual(await response.read_chunk(1), b"h")
                with self.assertRaises(BodyLimitExceeded):
                    await response.read(max_bytes=3)
                response = await client.request("GET", url + "/large")
                self.assertEqual(await response.read(max_bytes=200000), b"x" * 200000)

    async def test_collection_overflow_closes_an_incomplete_body(self):
        with server() as (peer, url):
            async with AsyncClient(**OPTIONS) as client:
                response = await client.request("GET", url + "/stall")
                with self.assertRaises(BodyLimitExceeded):
                    await response.read(max_bytes=0)
                self.assertTrue(await asyncio.to_thread(peer.disconnected.wait, 5))
                self.assertIsNone(await response.read_chunk())

    async def test_close_wakes_collection_and_concurrent_collection_is_rejected(self):
        with server() as (peer, url):
            async with AsyncClient(**OPTIONS) as client:
                response = await client.request("GET", url + "/stall")
                readers = {
                    asyncio.create_task(response.read(max_bytes=20)),
                    asyncio.create_task(response.read(max_bytes=20)),
                }
                done, waiting = await asyncio.wait(
                    readers, timeout=2, return_when=asyncio.FIRST_COMPLETED
                )
                self.assertEqual(len(done), 1)
                self.assertEqual(len(waiting), 1)
                with self.assertRaises(Error) as caught:
                    await done.pop()
                self.assertEqual(caught.exception.kind, "concurrent_body_read")
                response.close()
                with self.assertRaises(Error) as caught:
                    await waiting.pop()
                self.assertEqual(caught.exception.kind, "body_closed")
                self.assertTrue(await asyncio.to_thread(peer.disconnected.wait, 5))
                self.assertEqual(await response.read(max_bytes=20), b"")

    async def test_explicit_close_wakes_a_pending_body_read(self):
        with server() as (peer, url):
            async with AsyncClient(**OPTIONS) as client:
                response = await client.request("GET", url + "/stall")
                self.assertEqual(await response.read_chunk(), b"a")
                readers = {
                    asyncio.create_task(response.read_chunk()),
                    asyncio.create_task(response.read_chunk()),
                }
                done, waiting = await asyncio.wait(
                    readers, timeout=2, return_when=asyncio.FIRST_COMPLETED
                )
                self.assertEqual(len(done), 1)
                self.assertEqual(len(waiting), 1)
                with self.assertRaises(Error) as caught:
                    await done.pop()
                self.assertEqual(caught.exception.kind, "concurrent_body_read")
                response.close()
                with self.assertRaises(Error) as caught:
                    await waiting.pop()
                self.assertEqual(caught.exception.kind, "body_closed")
                self.assertTrue(await asyncio.to_thread(peer.disconnected.wait, 5))
                self.assertIsNone(await response.read_chunk())

    async def test_cancel_streaming_file_upload(self):
        with server() as (peer, url), tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upload"
            with path.open("wb") as output:
                output.truncate(32 * 1024 * 1024)
            async with AsyncClient(**OPTIONS) as client:
                pending = asyncio.create_task(
                    client.request("PUT", url + "/upload-stall", upload=path)
                )
                self.assertTrue(await asyncio.to_thread(peer.entered.wait, 5))
                self.assertFalse(pending.done())
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await pending
                peer.upload_release.set()
                self.assertTrue(await asyncio.to_thread(peer.disconnected.wait, 5))
                self.assertLess(peer.upload_received, path.stat().st_size)

    async def test_shared_budget_concurrent_requests(self):
        with server() as (peer, url):
            async with (
                AsyncClient(**OPTIONS) as first,
                AsyncClient(**OPTIONS) as second,
            ):
                budget = AttemptBudget(3)

                async def fetch(client):
                    try:
                        response = await client.request("GET", url, budget=budget)
                        async with response:
                            return await response.read(max_bytes=5)
                    except AttemptBudgetExhausted:
                        return None

                results = await asyncio.gather(
                    *(fetch(first if index % 2 else second) for index in range(10))
                )
                self.assertEqual(results.count(b"hello"), 3)
                self.assertEqual(len(peer.requests), 3)
                self.assertEqual(budget.remaining, 0)

    async def test_read_cancel_concurrent_read_and_other_request_survives(self):
        with server() as (peer, url):
            async with AsyncClient(**OPTIONS) as client:
                response = await client.request("GET", url + "/stall")
                self.assertEqual(await response.read_chunk(), b"a")
                readers = {
                    asyncio.create_task(response.read_chunk()),
                    asyncio.create_task(response.read_chunk()),
                }
                done, waiting = await asyncio.wait(
                    readers, timeout=2, return_when=asyncio.FIRST_COMPLETED
                )
                self.assertEqual(len(done), 1)
                self.assertEqual(len(waiting), 1)
                with self.assertRaises(Error) as caught:
                    await done.pop()
                self.assertEqual(caught.exception.kind, "concurrent_body_read")
                pending = waiting.pop()
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await pending
                self.assertTrue(await asyncio.to_thread(peer.disconnected.wait, 5))
                self.assertIsNone(await response.read_chunk())
                healthy = await client.request("GET", url)
                async with healthy:
                    self.assertEqual(await healthy.read(max_bytes=5), b"hello")

    async def test_deadline_and_shutdown_are_bounded(self):
        with server() as (_, url):
            client = AsyncClient(**OPTIONS)
            response = await client.request("GET", url + "/stall", timeout_ms=500)
            with self.assertRaises(TimeoutError) as caught:
                await response.read(max_bytes=20)
            self.assertEqual(caught.exception.timeout_phase, "total")
            await client.close()
            with self.assertRaises(ClientClosed):
                await client.request("GET", url)
        with server() as (_, url):
            client = AsyncClient(**OPTIONS)
            response = await client.request("GET", url + "/stall")
            with self.assertRaises(TimeoutError):
                await client.close(timeout_ms=50)
            self.assertTrue(client.is_closed)
            response.close()
            await client.close()

    async def test_cancel_proxy_setup(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        entered = threading.Event()
        disconnected = threading.Event()

        def proxy():
            with listener:
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(8)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        data += stream.recv(4096)
                    entered.set()
                    if not stream.recv(1):
                        disconnected.set()

        worker = threading.Thread(target=proxy, daemon=True)
        worker.start()
        async with AsyncClient(
            **OPTIONS, proxy=f"http://127.0.0.1:{listener.getsockname()[1]}"
        ) as client:
            request = asyncio.create_task(
                client.request("GET", "https://origin.example/")
            )
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            request.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request
            self.assertTrue(await asyncio.to_thread(disconnected.wait, 5))
        worker.join(5)


if __name__ == "__main__":
    unittest.main()
