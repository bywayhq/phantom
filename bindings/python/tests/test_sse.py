"""Native SSE decoding against independent HTTP/1 and HTTP/2 peers."""

import asyncio
import threading
import unittest

from phantom_http import (
    AsyncClient,
    AttemptBudget,
    Client,
    Error,
    Event,
    RedirectPolicy,
    SseError,
    SseLimits,
    TimeoutError,
)
from test_http2 import H2Peer
from test_uploads import Handler, server

PROFILE = "chrome-154-windows"
PAYLOAD = (
    b"\xef\xbb\xbf: comment\r\nid: 7\rretry: 18446744073709551615\r\n"
    b"data: one\ndata: two\n\nevent: custom\ndata: \xff\n\n"
    b"id: final\nretry: 0\n\ndata: unfinished"
)


class EventHandler(Handler):
    def do_GET(self):
        self.server.records.append((self.path, list(self.headers.raw_items())))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/events")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = {
            "/large": b"data: " + b"x" * 100000 + b"\n\n",
            "/block": b"data:a\ndata:b\n\n",
            "/status": b"not events",
            "/type": b"not events",
            "/encoding": b"not encoded",
            "/broken": b"data: before\n\n",
        }.get(self.path, PAYLOAD)
        self.send_response(201 if self.path == "/status" else 200)
        self.send_header(
            "Content-Type",
            "text/plain"
            if self.path == "/type"
            else "text/event-stream; charset=utf-8",
        )
        if self.path == "/encoding":
            self.send_header("Content-Encoding", "unsupported")
        self.send_header(
            "Content-Length", str(len(data) + (1 if self.path == "/broken" else 0))
        )
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()
        self.close_connection = True

    def do_POST(self):
        if self.headers.get("Transfer-Encoding") == "chunked":
            body = bytearray()
            while length := int(self.rfile.readline().split(b";", 1)[0], 16):
                body.extend(self.rfile.read(length))
                if self.rfile.read(2) != b"\r\n":
                    raise AssertionError("invalid upload chunk")
            if self.rfile.readline() != b"\r\n":
                raise AssertionError("unexpected upload trailers")
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.records.append(
            (self.path, list(self.headers.raw_items()), bytes(body))
        )
        data = b"data: " + body + b"\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()


class SyncEventTests(unittest.TestCase):
    def test_rejected_cross_thread_close_keeps_native_events_readable(self):
        with (
            server(EventHandler) as (_, url),
            Client(profile=PROFILE, protocol="h1", timeout_ms=5000) as client,
            client.events("GET", url + "/events") as events,
        ):
            failures = []

            def close_from_other_thread():
                try:
                    events.close()
                except RuntimeError as error:
                    failures.append(error)

            worker = threading.Thread(target=close_from_other_thread)
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(failures), 1)
            self.assertEqual(next(events).data, "one\ntwo")
            events.close()
            events.close()

    def test_iteration_utf8_defaults_and_complete_retry_state(self):
        with (
            server(EventHandler) as (_, url),
            Client(profile=PROFILE, protocol="h1", timeout_ms=5000) as client,
            client.events("GET", url + "/events") as events,
        ):
            self.assertIsNone(events.retry_ms)
            self.assertEqual(next(events), Event("one\ntwo", "message", "7"))
            self.assertEqual(events.retry_ms, 2**64 - 1)
            self.assertEqual(next(events), Event("\ufffd", "custom", "7"))
            self.assertEqual(list(events), [])
            self.assertEqual(events.last_event_id, "final")
            self.assertEqual(events.retry_ms, 0)
            self.assertEqual(list(events), [])

    def test_large_events_and_distinct_line_and_event_limits(self):
        with (
            server(EventHandler) as (_, url),
            Client(profile=PROFILE, protocol="h1", timeout_ms=5000) as client,
        ):
            with client.events(
                "GET", url + "/large", limits=SseLimits(200000, 200000)
            ) as events:
                self.assertEqual(len(next(events).data), 100000)
                self.assertEqual(list(events), [])
            for path, limits, kind in (
                ("/large", SseLimits(), "line_too_long"),
                ("/block", SseLimits(100, 8), "event_too_large"),
                ("/events", SseLimits(0, 0), "line_too_long"),
            ):
                with client.events("GET", url + path, limits=limits) as events:
                    with self.assertRaises(SseError) as failure:
                        next(events)
                    self.assertEqual(failure.exception.kind, kind)
                    self.assertEqual(list(events), [])

    def test_invalid_metadata_preserves_unread_body_and_conversion_is_one_way(self):
        with (
            server(EventHandler) as (_, url),
            Client(profile=PROFILE, protocol="h1", timeout_ms=5000) as client,
        ):
            for path, kind in (
                ("/status", "unexpected_status"),
                ("/type", "invalid_content_type"),
                ("/encoding", "unsupported_content_encoding"),
            ):
                with client.get(url + path) as response:
                    with self.assertRaises(SseError) as failure:
                        response.events()
                    self.assertEqual(failure.exception.kind, kind)
                    self.assertTrue(response.read(max_bytes=20))
            with client.get(url + "/events") as response, response.events() as events:
                with self.assertRaises(Error) as failure:
                    response.read(max_bytes=200)
                self.assertEqual(failure.exception.kind, "body_consumed")
                with self.assertRaises(Error):
                    response.events()
                self.assertEqual(next(events).data, "one\ntwo")

    def test_partial_byte_read_rejects_conversion_without_losing_remaining_bytes(self):
        with (
            server(EventHandler) as (_, url),
            Client(profile=PROFILE, protocol="h1", timeout_ms=5000) as client,
            client.get(url + "/events") as response,
        ):
            iterator = response.iter_bytes(1)
            self.assertEqual(next(iterator), PAYLOAD[:1])
            with self.assertRaises(Error) as failure:
                response.events()
            self.assertEqual(failure.exception.kind, "body_consumed")
            self.assertEqual(response.read(max_bytes=len(PAYLOAD)), PAYLOAD[1:])
            iterator.close()


class AsyncEventTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_abort_is_an_error_instead_of_event_eof(self):
        with server(EventHandler) as (_, url):
            client = AsyncClient(profile=PROFILE, protocol="h1", context="raw")
            try:
                response = await client.get(url + "/events")
                events = response.events()
                await client.abort()
                with self.assertRaises(Error) as failure:
                    await anext(events)
                self.assertEqual(failure.exception.kind, "body_closed")
            finally:
                await client.abort()

    async def test_rejected_upload_producer_close_keeps_native_events_readable(self):
        with H2Peer(event_stream=True) as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", context="raw", timeout_ms=5000
            ) as client:
                ready = asyncio.Event()
                attempted = asyncio.get_running_loop().create_future()
                closed = []
                events = None

                async def producer():
                    try:
                        yield b"start"
                        await asyncio.Future()
                    finally:
                        await ready.wait()
                        if events is not None:
                            try:
                                await events.aclose()
                            except RuntimeError as error:
                                attempted.set_result(str(error))
                            else:
                                attempted.set_exception(
                                    AssertionError("producer close was accepted")
                                )
                        closed.append(True)

                try:
                    response = await client.post(
                        peer.url + "/upload-events", body=producer()
                    )
                    events = response.events()
                    ready.set()
                    self.assertIn("own cleanup", await asyncio.wait_for(attempted, 5))
                    self.assertEqual((await anext(events)).data, "first")
                    await events.aclose()
                    await events.aclose()
                    self.assertEqual(closed, [True])
                    for path in ("/after-one", "/after-two"):
                        after = await client.get(peer.url + path)
                        self.assertEqual(await after.read(max_bytes=5), b"hello")
                finally:
                    ready.set()
        self.assertFalse(peer.premature_close)

    async def test_redirect_budget_context_and_streamed_upload_use_ordinary_request(
        self,
    ):
        with server(EventHandler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", timeout_ms=5000
            ) as client:
                budget = AttemptBudget(2)
                async with client.events(
                    "GET",
                    url + "/redirect",
                    context="fetch",
                    headers=[("Referer", url + "/page")],
                    budget=budget,
                    redirect_policy=RedirectPolicy(maximum_hops=1),
                ) as events:
                    self.assertEqual((await anext(events)).data, "one\ntwo")
                self.assertEqual(budget.remaining, 0)
                fields = {name.lower(): value for name, value in peer.records[-1][1]}
                self.assertEqual(fields["sec-fetch-mode"], "cors")
                closed = []

                async def producer():
                    try:
                        yield b"upload"
                    finally:
                        closed.append(True)

                async with client.events(
                    "POST",
                    url + "/upload",
                    context="fetch_upload",
                    headers=[("Origin", url), ("Referer", url + "/page")],
                    body=producer(),
                    body_length=6,
                ) as events:
                    self.assertEqual([event.data async for event in events], ["upload"])
                self.assertEqual(closed, [True])
                self.assertEqual(peer.records[-1][2], b"upload")

    async def test_body_failure_is_terminal_and_keeps_original_request_category(self):
        with server(EventHandler) as (_, url):
            async with (
                AsyncClient(profile=PROFILE, protocol="h1", timeout_ms=5000) as client,
                client.events("GET", url + "/broken") as events,
            ):
                self.assertEqual((await anext(events)).data, "before")
                with self.assertRaises(Error) as failure:
                    await anext(events)
                self.assertEqual(failure.exception.category, "request")
                with self.assertRaises(StopAsyncIteration):
                    await anext(events)

    async def test_shutdown_timeout_and_cancelled_read_preserve_http2_siblings(self):
        with H2Peer(event_stream=True, trailers=[("x-final", "yes")]) as peer:
            client = AsyncClient(profile=PROFILE, protocol="h2", timeout_ms=5000)
            response = await client.get(peer.url + "/stall")
            events = response.events()
            self.assertEqual((await anext(events)).data, "first")
            healthy = await client.get(peer.url + "/healthy")
            after = await client.get(peer.url + "/after")
            with self.assertRaises(TimeoutError):
                await client.close(timeout_ms=10)
            # The already-admitted body remains usable after the close timeout.
            pending = asyncio.create_task(anext(events))
            await asyncio.sleep(0)
            pending.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await pending
            self.assertTrue(await asyncio.to_thread(peer.reset.wait, 5))
            self.assertEqual(await healthy.read(max_bytes=5), b"hello")
            self.assertEqual(healthy.trailers.headers[0].value, b"yes")
            self.assertEqual(await after.read(max_bytes=5), b"hello")
            await client.close(timeout_ms=1000)
            self.assertEqual(len(peer.requests), 3)
        self.assertFalse(peer.premature_close)

    async def test_sse_http2_eof_retains_trailers_and_connection_reuse(self):
        with H2Peer(event_stream=True, trailers=[("x-final", "yes")]) as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", timeout_ms=5000
            ) as client:
                response = await client.get(peer.url + "/events")
                async with response.events() as events:
                    self.assertEqual([event.data async for event in events], ["hello"])
                self.assertEqual(response.trailers.state, "complete")
                self.assertEqual(response.trailers.headers[0].value, b"yes")
                for path in ("/after-one", "/after-two"):
                    after = await client.get(peer.url + path)
                    self.assertEqual(await after.read(max_bytes=5), b"hello")
        self.assertFalse(peer.premature_close)
