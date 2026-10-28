"""Reconnection and owner lifetimes against independent HTTP peers."""

import asyncio
import threading
import unittest

from phantom_http import (
    AsyncClient,
    Client,
    ClientClosed,
    Error,
    LastEventId,
    Profile,
    SseError,
    SseLimits,
    TimeoutError,
    TimeoutOverrides,
)
from test_http2 import H2Peer
from test_uploads import Handler, server

PROFILE = "chrome-154-windows"


class EventSourceHandler(Handler):
    def do_GET(self):
        self.server.records.append((self.path, list(self.headers.raw_items())))
        index = len(self.server.records) - 1
        status, content_type, encoding, body = self.server.responses[
            min(index, len(self.server.responses) - 1)
        ]
        release = self.server.release
        if status == -1:
            self.close_connection = True
            return
        if self.path == "/delay-head":
            self.server.started.set()
            release.wait(5)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if encoding is not None:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(body) if body is not None else 1))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.flush()
        self.server.started.set()
        if body is None:
            release.wait(5)
        else:
            self.wfile.write(body)
            self.wfile.flush()
        self.close_connection = True


def configure(peer, *bodies):
    peer.responses = [(200, "text/event-stream", None, body) for body in bodies]
    peer.release = threading.Event()
    peer.started = threading.Event()


class SyncEventSourceTests(unittest.TestCase):
    def test_initial_transport_failure_uses_the_same_reconnect_allowance(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"", b"data: recovered\n\n")
            peer.responses[0] = (-1, "text/event-stream", None, b"")
            with (
                Client(profile=PROFILE, context="raw", timeout_ms=5000) as client,
                client.event_source(
                    url, protocol="h1", initial_retry=0, max_reconnects=1
                ) as source,
            ):
                self.assertEqual(next(source).data, "recovered")
                self.assertEqual(source.reconnects, 1)
                with self.assertRaises(SseError) as caught:
                    next(source)
                self.assertEqual(caught.exception.kind, "reconnect_limit")
            self.assertEqual(len(peer.records), 2)

    def test_initial_failure_keeps_request_cause_without_exposing_values(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"")
            peer.responses[0] = (-1, "text/event-stream", None, b"")
            with (
                Client(profile=PROFILE, context="raw") as client,
                self.assertRaises(SseError) as caught,
            ):
                client.event_source(url + "/private", protocol="h1", max_reconnects=0)
            self.assertEqual(caught.exception.kind, "request")
            self.assertIsInstance(caught.exception.original, Error)
            self.assertEqual(caught.exception.original.category, "request")
            self.assertNotIn("private", str(caught.exception))
            self.assertEqual(len(peer.records), 1)

    def test_direct_override_and_inherited_proxy_keep_distinct_targets(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: routed\n\n")
            with Client(profile=PROFILE, context="raw", proxy=url) as client:
                with client.event_source(
                    url + "/events", protocol="h1", proxy=None
                ) as source:
                    self.assertEqual(next(source).data, "routed")
                with client.event_source(url + "/events", protocol="h1") as source:
                    self.assertEqual(next(source).data, "routed")
            self.assertEqual(
                [path for path, _ in peer.records], ["/events", url + "/events"]
            )

    def test_catalog_and_attached_templates_survive_fork_and_restore(self):
        attached = Profile.from_catalog(PROFILE, context="navigation")
        imported = Profile.import_json(attached.export_json())
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: inherited\n\n")
            for profile, context in (
                (PROFILE, "navigation"),
                (attached, "profile"),
                (imported, "profile"),
            ):
                with Client(profile=profile, context=context) as client:
                    key = b"s" * 32
                    with (
                        client.fork() as fork,
                        client.restore_session(
                            client.export_session(key), key
                        ) as restored,
                    ):
                        for owner in (client, fork, restored):
                            with owner.event_source(
                                url, protocol="h1", max_reconnects=0
                            ) as source:
                                self.assertEqual(next(source).data, "inherited")
            self.assertEqual(len(peer.records), 9)
            for _, headers in peer.records:
                fields = {name.lower(): value for name, value in headers}
                self.assertEqual(fields["sec-fetch-mode"], "navigate")
                self.assertEqual(fields["sec-fetch-dest"], "document")
                self.assertEqual(fields["accept"], "text/event-stream")

    def test_managed_id_position_reset_and_server_retry_survive_reconnect(self):
        with server(EventSourceHandler) as (peer, url):
            configure(
                peer, b"id: 7\nretry: 0\ndata: first\n\n", b"id:\ndata: second\n\n", b""
            )
            peer.responses[-1] = (204, "text/event-stream", None, b"")
            with (
                Client(profile=PROFILE, context="raw", timeout_ms=5000) as client,
                client.event_source(
                    url + "/events",
                    protocol="h1",
                    max_reconnects=2,
                    headers=[
                        ("X-Before", "one"),
                        LastEventId("Last-Event-ID"),
                        ("X-After", "two"),
                    ],
                ) as source,
            ):
                self.assertEqual(
                    [(event.data, event.id) for event in source],
                    [("first", "7"), ("second", "")],
                )
                self.assertTrue(source.closed)
                self.assertEqual(
                    (source.last_event_id, source.retry_ms, source.reconnects),
                    ("", 0, 2),
                )
                self.assertEqual(
                    (source.status_code, source.protocol, source.url),
                    (200, "h1", url + "/events"),
                )
                self.assertEqual(
                    source.headers.get("content-type"), b"text/event-stream"
                )
            fields = [record[1] for record in peer.records]
            self.assertNotIn("last-event-id", [name.lower() for name, _ in fields[0]])
            managed = fields[1].index(("Last-Event-ID", "7"))
            self.assertEqual(
                fields[1][managed - 1 : managed + 2],
                [("X-Before", "one"), ("Last-Event-ID", "7"), ("X-After", "two")],
            )
            self.assertNotIn("last-event-id", [name.lower() for name, _ in fields[2]])

    def test_initial_204_stops_without_an_event_or_reconnect(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"")
            peer.responses = [(204, "text/event-stream", None, b"")]
            with (
                Client(profile=PROFILE, context="raw") as client,
                client.event_source(url, protocol="h1") as source,
            ):
                self.assertEqual(list(source), [])
                self.assertEqual(
                    (source.status_code, source.closed, source.reconnects),
                    (204, True, 0),
                )
            self.assertEqual(len(peer.records), 1)

    def test_rejected_metadata_is_terminal_and_redacted(self):
        for status, content_type, encoding, kind in (
            (201, "text/event-stream", None, "unexpected_status"),
            (200, "text/plain", None, "invalid_content_type"),
            (200, "text/event-stream", "unsupported", "unsupported_content_encoding"),
        ):
            with self.subTest(kind=kind), server(EventSourceHandler) as (peer, url):
                configure(peer, b"private")
                peer.responses = [(status, content_type, encoding, b"private")]
                with (
                    Client(profile=PROFILE, context="raw") as client,
                    self.assertRaises(SseError) as caught,
                ):
                    client.event_source(
                        url, protocol="h1", initial_retry=0, max_reconnects=2
                    )
                self.assertEqual(caught.exception.kind, kind)
                self.assertNotIn("private", str(caught.exception))
                self.assertEqual(len(peer.records), 1)

    def test_limits_and_replacement_utf8_use_the_core_decoder(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: \xff\n\n", b"data: " + b"x" * 100000 + b"\n\n")
            with Client(profile=PROFILE, context="raw") as client:
                with client.event_source(
                    url, protocol="h1", max_reconnects=0
                ) as source:
                    self.assertEqual(next(source).data, "\ufffd")
                with client.event_source(
                    url,
                    protocol="h1",
                    max_reconnects=0,
                    limits=SseLimits(120000, 120000),
                ) as source:
                    self.assertEqual(len(next(source).data), 100000)
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: too long\n\n")
            with (
                Client(profile=PROFILE, context="raw") as client,
                client.event_source(
                    url, protocol="h1", limits=SseLimits(8, 40)
                ) as source,
            ):
                with self.assertRaises(SseError) as caught:
                    next(source)
                self.assertEqual(caught.exception.kind, "line_too_long")
                self.assertEqual(list(source), [])
            self.assertEqual(len(peer.records), 1)

    def test_managed_field_validation_precedes_origin_send(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"")
            with Client(profile=PROFILE, context="raw") as client:
                for headers in (
                    [("Last-Event-ID", "private")],
                    [LastEventId("X-Other")],
                ):
                    with (
                        self.subTest(headers=type(headers[0]).__name__),
                        self.assertRaises(SseError) as caught,
                    ):
                        client.event_source(url, protocol="h1", headers=headers)
                    self.assertEqual(caught.exception.kind, "invalid_request_header")
            self.assertEqual(peer.records, [])


class AsyncEventSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_options_reject_ignored_idle_and_invalid_managed_slot(self):
        from phantom_http import _native

        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"")
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                opening = client.event_source(url, protocol="h1")
                for changes in (
                    {"timeouts": [("read_idle", None)]},
                    {"timeouts": [("read_idle", 1.0)]},
                    {
                        "headers": [("Last-Event-ID", b"private", False)],
                        "last_event_id_slot": 0,
                    },
                    {
                        "headers": [("Last-Event-ID", b"", True)],
                        "last_event_id_slot": 0,
                    },
                ):
                    with (
                        self.subTest(fields=tuple(changes)),
                        self.assertRaises((ValueError, _native.NativeError)) as caught,
                    ):
                        await client._native.event_source(
                            url, "h1", **{**opening._options, **changes}
                        )
                    if "timeouts" in changes:
                        self.assertIn("idle_timeout", str(caught.exception))
            self.assertEqual(peer.records, [])

    async def test_cancelled_backoff_preserves_id_deadline_and_remaining_budget(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"id: 9\ndata: first\n\n", b"data: second\n\n")
            async with (
                AsyncClient(profile=PROFILE, context="raw") as client,
                client.event_source(
                    url, protocol="h1", initial_retry=0.2, max_reconnects=1
                ) as source,
            ):
                self.assertEqual((await anext(source)).id, "9")
                reading = asyncio.create_task(anext(source))
                await asyncio.sleep(0.03)
                reading.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await reading
                self.assertFalse(source.closed)
                self.assertEqual(len(peer.records), 1)
                self.assertEqual(
                    (await asyncio.wait_for(anext(source), 5)).data, "second"
                )
                self.assertEqual(source.reconnects, 1)
                with self.assertRaises(SseError) as caught:
                    await anext(source)
                self.assertEqual(caught.exception.kind, "reconnect_limit")
                with self.assertRaises(StopAsyncIteration):
                    await anext(source)
            self.assertEqual(len(peer.records), 2)
            self.assertIn(("Last-Event-ID", "9"), peer.records[1][1])

    async def test_graceful_timeout_keeps_source_and_fork_independent(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: first\n\n")
            client = AsyncClient(profile=PROFILE, context="raw")
            fork = client.fork()
            try:
                async with client.event_source(
                    url, protocol="h1", initial_retry=0.2, max_reconnects=1
                ) as source:
                    self.assertEqual((await anext(source)).data, "first")
                    reading = asyncio.create_task(anext(source))
                    await asyncio.sleep(0.03)
                    with self.assertRaises(TimeoutError):
                        await client.aclose(timeout_ms=10)
                    self.assertEqual((await asyncio.wait_for(reading, 5)).data, "first")
                    self.assertEqual(source.reconnects, 1)
                    async with fork.event_source(
                        url, protocol="h1", max_reconnects=0
                    ) as sibling:
                        self.assertEqual((await anext(sibling)).data, "first")
                await client.aclose()
            finally:
                await client.abort()
                await fork.abort()

    async def test_cancelled_initial_setup_releases_client_admission(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: late\n\n")
            client = AsyncClient(profile=PROFILE, context="raw")
            opening = asyncio.ensure_future(
                client.event_source(url + "/delay-head", protocol="h1")
            )
            try:
                self.assertTrue(await asyncio.to_thread(peer.started.wait, 5))
                opening.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await opening
                await client.aclose()
            finally:
                peer.release.set()
                await client.abort()

    async def test_close_stops_pending_backoff_without_another_send(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: first\n\n")
            async with (
                AsyncClient(profile=PROFILE, context="raw") as client,
                client.event_source(url, protocol="h1", initial_retry=10) as source,
            ):
                self.assertEqual((await anext(source)).data, "first")
                reading = asyncio.create_task(anext(source))
                await asyncio.sleep(0.03)
                self.assertFalse(reading.done())
                await source.aclose()
                with self.assertRaises(SseError) as caught:
                    await reading
                self.assertEqual(caught.exception.kind, "closed")
                self.assertTrue(source.closed)
            self.assertEqual(len(peer.records), 1)

    async def test_abort_during_initial_head_settles_opening(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, b"data: late\n\n")
            client = AsyncClient(profile=PROFILE, context="raw")
            opening = asyncio.ensure_future(
                client.event_source(url + "/delay-head", protocol="h1")
            )
            try:
                self.assertTrue(await asyncio.to_thread(peer.started.wait, 5))
                await client.abort()
                with self.assertRaises(ClientClosed):
                    await opening
            finally:
                peer.release.set()
                await client.abort()

    async def test_idle_reconnects_spend_one_finite_budget(self):
        with server(EventSourceHandler) as (peer, url):
            configure(peer, None)
            client = AsyncClient(profile=PROFILE, context="raw")
            try:
                async with client.event_source(
                    url,
                    protocol="h1",
                    idle_timeout=0.03,
                    initial_retry=0,
                    max_reconnects=1,
                ) as source:
                    with self.assertRaises(SseError) as caught:
                        await asyncio.wait_for(anext(source), 5)
                    self.assertEqual(caught.exception.kind, "idle_timeout")
                    self.assertEqual(source.reconnects, 1)
                    self.assertTrue(source.closed)
            finally:
                peer.release.set()
                await client.abort()
            self.assertEqual(len(peer.records), 2)

    async def test_h2_cancelled_read_preserves_source_and_unrelated_stream(self):
        with H2Peer(event_stream=True) as peer:
            async with (
                AsyncClient(profile=PROFILE, protocol="h2", context="raw") as client,
                client.event_source(
                    peer.url + "/stall", protocol="h2", max_reconnects=0
                ) as source,
            ):
                self.assertEqual((await anext(source)).data, "first")
                readers = {asyncio.create_task(anext(source)) for _ in range(2)}
                done, pending = await asyncio.wait(
                    readers, timeout=5, return_when=asyncio.FIRST_COMPLETED
                )
                self.assertEqual((len(done), len(pending)), (1, 1))
                with self.assertRaises(Error) as caught:
                    await done.pop()
                self.assertEqual(caught.exception.kind, "concurrent_event_read")
                reading = pending.pop()
                reading.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await reading
                self.assertFalse(source.closed)
                healthy = await client.get(
                    peer.url + "/healthy",
                    timeouts=TimeoutOverrides(total=None, connect=5, response_head=5),
                )
                try:
                    await source.aclose()
                    self.assertEqual(await healthy.read(max_bytes=5), b"hello")
                finally:
                    await healthy.aclose()
                async with await client.get(peer.url + "/reuse") as reused:
                    self.assertEqual(await reused.read(max_bytes=5), b"hello")
            self.assertEqual(
                [path for _, path in peer.requests], [b"/stall", b"/healthy", b"/reuse"]
            )
            self.assertEqual(peer.reset_code, 8)
            self.assertFalse(peer.premature_close)
