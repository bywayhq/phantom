"""Event iteration and cleanup without a native extension."""

import asyncio
import unittest

from test_upload_errors import FACADE, NativeResponse, Pump


class Decoder:
    last_event_id = ""
    retry_ms = None

    def __init__(self, events=()):
        self.events = list(events)
        self.waiting = asyncio.Event()
        self.block = None

    async def next_event(self):
        self.waiting.set()
        if self.block is not None:
            await self.block
        item = self.events.pop(0) if self.events else None
        if isinstance(item, BaseException):
            raise item
        return item


class Response(NativeResponse):
    def __init__(self, decoder):
        super().__init__()
        self.decoder = decoder
        self.limits = None

    def events(self, line, event):
        self.limits = (line, event)
        return self.decoder


class EventTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejected_producer_self_close_keeps_events_readable(self):
        native = Response(Decoder([("still live", "message", "")]))
        pump = Pump()
        pump.loop = asyncio.get_running_loop()
        pump.task = asyncio.current_task()
        # Exercise the real upload ownership checks without a native pump.
        pump.check_wait = FACADE._upload.Upload.check_wait.__get__(pump)
        pump.check_loop = FACADE._upload.Upload.check_loop.__get__(pump)
        stream = FACADE.AsyncResponse(native, pump).events()
        with self.assertRaisesRegex(RuntimeError, "own cleanup"):
            await stream.aclose()
        self.assertFalse(native.closed)
        self.assertFalse(pump.closed)
        self.assertEqual((await anext(stream)).data, "still live")
        pump.task = None
        await stream.aclose()
        await stream.aclose()
        self.assertTrue(native.closed)

    async def test_rejected_wrong_loop_close_keeps_events_readable(self):
        native = Response(Decoder([("still live", "message", "")]))
        pump = Pump()
        pump.loop = asyncio.new_event_loop()
        pump.check_loop = FACADE._upload.Upload.check_loop.__get__(pump)
        stream = FACADE.AsyncResponse(native, pump).events()
        try:
            with self.assertRaisesRegex(RuntimeError, "creating event loop"):
                stream.close()
            self.assertFalse(native.closed)
            self.assertEqual((await anext(stream)).data, "still live")
        finally:
            pump.loop.close()
            pump.loop = asyncio.get_running_loop()
            await stream.aclose()

    async def test_iteration_returns_named_events_and_stops_after_eof(self):
        decoder = Decoder([("one\ntwo", "message", "7"), ("", "custom", "7")])
        native = Response(decoder)
        response = FACADE.AsyncResponse(native)
        async with response.events() as stream:
            self.assertEqual(native.limits, (65536, 1048576))
            self.assertIs(stream.response, response)
            self.assertIsNone(stream.retry_ms)
            events = [event async for event in stream]
            self.assertEqual(
                events,
                [
                    FACADE.Event("one\ntwo", "message", "7"),
                    FACADE.Event("", "custom", "7"),
                ],
            )
            with self.assertRaises(StopAsyncIteration):
                await anext(stream)
        self.assertTrue(native.closed)
        self.assertNotIn("one", repr(events[0]))

    async def test_terminal_error_is_typed_and_reported_once(self):
        native = Response(
            Decoder([FACADE._native.NativeError("sse", "line_too_long", None, None)])
        )
        stream = FACADE.AsyncResponse(native).events(limits=FACADE.SseLimits(0, 0))
        with self.assertRaises(FACADE.SseError) as failure:
            await anext(stream)
        self.assertEqual(failure.exception.kind, "line_too_long")
        self.assertTrue(native.closed)
        with self.assertRaises(StopAsyncIteration):
            await anext(stream)

    async def test_cancellation_closes_only_owned_response(self):
        decoder = Decoder()
        decoder.block = asyncio.get_running_loop().create_future()
        native = Response(decoder)
        sibling = Response(Decoder())
        stream = FACADE.AsyncResponse(native).events()
        read = asyncio.create_task(anext(stream))
        await decoder.waiting.wait()
        read.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await read
        self.assertTrue(native.closed)
        self.assertFalse(sibling.closed)

    async def test_rejected_concurrent_read_does_not_close_other_reader(self):
        decoder = Decoder(
            [
                FACADE._native.NativeError("input", "concurrent_body_read", None, None),
                ("ok", "message", ""),
            ]
        )
        native = Response(decoder)
        stream = FACADE.AsyncResponse(native).events()
        with self.assertRaises(FACADE.Error):
            await anext(stream)
        self.assertFalse(native.closed)
        self.assertEqual((await anext(stream)).data, "ok")
        await stream.aclose()

    async def test_limits_reject_invalid_values_before_native_conversion(self):
        native = Response(Decoder())
        response = FACADE.AsyncResponse(native)
        for value in (-1, True, 1.5, 2**100):
            with self.assertRaises(ValueError):
                FACADE.SseLimits(max_line_bytes=value)
        with self.assertRaises(TypeError):
            response.events(limits=None)
        self.assertIsNone(native.limits)
        self.assertFalse(native.closed)

    async def test_client_context_uses_complete_ordinary_request_options(self):
        client = object.__new__(FACADE.AsyncClient)
        native = Response(Decoder([("value", "message", "")]))
        calls = []

        async def request(method, url, **options):
            calls.append((method, url, options))
            return FACADE.AsyncResponse(native)

        client.request = request
        body = object()
        async with client.events(
            "POST",
            "/events",
            context="fetch",
            body=body,
            timeout_ms=123,
            redirect_history_limit=2,
        ) as events:
            self.assertEqual((await anext(events)).data, "value")
        self.assertEqual(
            calls,
            [
                (
                    "POST",
                    "/events",
                    {
                        "context": "fetch",
                        "body": body,
                        "timeout_ms": 123,
                        "redirect_history_limit": 2,
                    },
                )
            ],
        )
        self.assertTrue(native.closed)


class SyncEventTests(unittest.TestCase):
    def test_rejected_wrong_thread_close_keeps_events_readable(self):
        import threading

        native = Response(Decoder([("still live", "message", "")]))
        client = object.__new__(FACADE.Client)
        client._thread = threading.get_ident()
        client._loop = asyncio.new_event_loop()
        stream = FACADE.Response(client, FACADE.AsyncResponse(native)).events()
        failures = []

        def close_from_other_thread():
            try:
                stream.close()
            except RuntimeError as error:
                failures.append(error)

        worker = threading.Thread(target=close_from_other_thread)
        try:
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(failures), 1)
            self.assertFalse(native.closed)
            self.assertEqual(next(stream).data, "still live")
            stream.close()
            stream.close()
            self.assertTrue(native.closed)
        finally:
            client._loop.close()

    def test_sync_iterator_and_close_use_client_loop(self):
        native = Response(Decoder([("hello", "message", "")]))
        client = object.__new__(FACADE.Client)
        import threading

        client._thread = threading.get_ident()
        client._loop = asyncio.new_event_loop()
        try:
            response = FACADE.Response(client, FACADE.AsyncResponse(native))
            with response.events() as events:
                self.assertEqual(next(events), FACADE.Event("hello", "message", ""))
                with self.assertRaises(StopIteration):
                    next(events)
            self.assertTrue(native.closed)
        finally:
            client._loop.close()
