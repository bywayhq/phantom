"""EventSource options, iteration and failure ownership without native code."""

import asyncio
import itertools
import threading
import types
import unittest

from test_upload_errors import FACADE


class Source:
    status = 200
    protocol = "h2"
    url = "https://example.invalid/events"
    headers = [("content-type", b"text/event-stream", False)]
    last_event_id = "7"
    retry_ms = 3000
    reconnects = 1
    is_closed = False

    def __init__(self):
        self.values = [("hello", "message", "7"), None]
        self.waiting = asyncio.Event()
        self.block = None
        self.calls = 0

    async def next_event(self):
        self.calls += 1
        self.waiting.set()
        if self.block is not None:
            await self.block
        result = self.values.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def close(self):
        self.is_closed = True

    async def wait_closed(self, timeout_ms):
        self.timeout_ms = timeout_ms

    async def wait_idle(self):
        pass


class EventSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_supported_options_and_header_position_are_forwarded(self):
        calls = []
        native = Source()

        async def connect(*args, **kwargs):
            calls.append((args, kwargs))
            return native

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(event_source=connect, cookies=object())
        )
        async with client.event_source(
            "https://example.invalid/events",
            protocol="h2",
            headers=[
                ("accept", "text/event-stream"),
                FACADE.LastEventId("last-event-id"),
                FACADE.Header("x-secret", "private", sensitive=True),
            ],
            limits=FACADE.SseLimits(12, 30),
            initial_retry=0,
            min_retry=0.1,
            idle_timeout=2,
            max_reconnects=4,
            timeouts=FACADE.TimeoutOverrides(connect=1, total=None),
            proxy=None,
        ) as source:
            self.assertEqual(source.headers.get("content-type"), b"text/event-stream")
            self.assertEqual((source.status_code, source.protocol), (200, "h2"))
            self.assertEqual(
                [event async for event in source],
                [FACADE.Event("hello", "message", "7")],
            )
            self.assertEqual(
                (source.last_event_id, source.retry_ms, source.reconnects),
                ("7", 3000, 1),
            )
            self.assertEqual(native.calls, 2)
        self.assertTrue(source.closed)
        args, options = calls[0]
        self.assertEqual(args, ("https://example.invalid/events", "h2"))
        self.assertEqual(
            options["headers"],
            [
                ("accept", b"text/event-stream", False),
                ("last-event-id", b"", False),
                ("x-secret", b"private", True),
            ],
        )
        self.assertEqual(options["last_event_id_slot"], 1)
        self.assertEqual(
            (options["maximum_line_bytes"], options["maximum_event_bytes"]), (12, 30)
        )
        self.assertEqual(
            (options["initial_retry"], options["min_retry"], options["idle_timeout"]),
            (0, 0.1, 2),
        )
        self.assertEqual(options["timeouts"], [("connect", 1.0), ("total", None)])
        self.assertFalse(options["inherit_proxy"])

    async def test_defaults_inherit_route_and_keep_core_headers(self):
        options = {}

        async def connect(*_, **kwargs):
            options.update(kwargs)
            return Source()

        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(event_source=connect, cookies=object())
        )
        opening = client.event_source("/events", protocol="h1")
        source = await opening
        await source.aclose()
        self.assertIsNone(options["headers"])
        self.assertIsNone(options["last_event_id_slot"])
        self.assertTrue(options["inherit_proxy"])
        self.assertEqual(
            (options["max_reconnects"], options["initial_retry"]), (3, 3.0)
        )
        with self.assertRaisesRegex(RuntimeError, "only be awaited once"):
            await opening

    async def test_cancellation_and_concurrent_rejection_preserve_iteration(self):
        native = Source()
        native.block = asyncio.Future()
        source = FACADE.AsyncEventSource(native)
        reading = asyncio.create_task(anext(source))
        await native.waiting.wait()
        reading.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await reading
        self.assertFalse(source._finished)
        self.assertFalse(source.closed)
        native.block = None
        native.values.insert(
            0, FACADE._native.NativeError("input", "concurrent_event_read", None, None)
        )
        with self.assertRaises(FACADE.Error):
            await anext(source)
        self.assertEqual((await anext(source)).data, "hello")
        await source.aclose()

    async def test_terminal_sse_kind_retains_typed_cause_and_is_reported_once(self):
        native = Source()
        error = FACADE._native.NativeError("sse", "reconnect_limit", None, None)
        error.original = FACADE._native.NativeError(
            "request", "timeout", "h2", "connect"
        )
        native.values = [error]
        source = FACADE.AsyncEventSource(native)
        with self.assertRaises(FACADE.SseError) as failure:
            await anext(source)
        self.assertEqual(failure.exception.kind, "reconnect_limit")
        self.assertIsInstance(failure.exception.original, FACADE.TimeoutError)
        self.assertEqual(failure.exception.original.timeout_phase, "connect")
        with self.assertRaises(StopAsyncIteration):
            await anext(source)
        self.assertEqual(native.calls, 1)

    async def test_invalid_close_bound_has_no_side_effect(self):
        source = FACADE.AsyncEventSource(Source())
        with self.assertRaises(ValueError):
            await source.aclose(timeout_ms=-1)
        self.assertFalse(source.closed)
        self.assertEqual((await anext(source)).data, "hello")
        await source.aclose()


class ValidationTests(unittest.TestCase):
    def test_invalid_or_unsupported_options_fail_before_native_admission(self):
        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(cookies=object())
        )
        for changes in (
            {"protocol": "negotiated"},
            {"initial_retry": True},
            {"idle_timeout": -1},
            {"min_retry": float("inf")},
            {"max_reconnects": True},
            {"max_reconnects": -1},
            {"max_reconnects": 2**128},
            {"timeouts": object()},
            {"timeouts": FACADE.TimeoutOverrides(read_idle=None)},
            {"timeouts": FACADE.TimeoutOverrides(read_idle=1)},
            {"proxy": object()},
            {"limits": object()},
            {"headers": [FACADE.LastEventId("Last-Event-ID")] * 2},
            {"headers": itertools.repeat(("x", "y"))},
            {"headers": [("x", b"y" * 65536)]},
            {"budget": object()},
            {"context": "fetch"},
        ):
            with (
                self.subTest(fields=tuple(changes)),
                self.assertRaises((TypeError, ValueError)),
            ):
                client.event_source(
                    "https://example.invalid/events", **{"protocol": "h1", **changes}
                )

    def test_sync_wrong_thread_close_preserves_source(self):
        native = Source()
        client = object.__new__(FACADE.Client)
        client._thread = threading.get_ident()
        client._loop = asyncio.new_event_loop()
        source = FACADE.EventSource(client, FACADE.AsyncEventSource(native))
        errors = []

        def close():
            try:
                source.close()
            except RuntimeError as error:
                errors.append(error)

        worker = threading.Thread(target=close)
        worker.start()
        worker.join(5)
        try:
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertFalse(source.closed)
            self.assertEqual(next(source).data, "hello")
            source.close()
        finally:
            client._loop.close()

    def test_explicit_proxy_credentials_use_existing_native_fields(self):
        from_native = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(cookies=object())
        )
        opening = from_native.event_source(
            "/events",
            protocol="h1",
            proxy=FACADE.Proxy(
                "http://proxy.invalid:8080", username="user", password="private"
            ),
        )
        self.assertEqual(opening._options["proxy"], "http://proxy.invalid:8080")
        self.assertEqual(opening._options["proxy_username"], "user")
        self.assertEqual(opening._options["proxy_password"], "private")
        self.assertFalse(opening._options["inherit_proxy"])
