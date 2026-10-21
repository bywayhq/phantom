"""Demand, custody and error controls without loading a native extension."""

import asyncio
import threading
import types
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from test_upload_errors import FACADE


class NativeMultipart:
    def __init__(self, boundary, fields, maximum):
        self.fields = fields
        self.parts = asyncio.Queue()
        self.credits = asyncio.Queue()
        self.writes = asyncio.Queue()
        self.ends = asyncio.Queue()
        self.stopped = asyncio.Event()
        self.failed = False

    @staticmethod
    def content_type_for(boundary):
        return "multipart/form-data; boundary=" + boundary

    async def next_part(self):
        return await self.parts.get()

    async def credit(self):
        return await self.credits.get()

    async def terminal(self):
        await self.stopped.wait()

    def write(self, data, offset, length):
        self.writes.put_nowait((data, offset, length))

    def finish(self):
        self.ends.put_nowait(True)

    def fail(self):
        self.failed = True

    def abort(self):
        if not self.stopped.is_set():
            self.stopped.set()
            self.parts.put_nowait(None)
            self.credits.put_nowait(False)


class Source:
    def __init__(self, values=(), failure=None, cleanup=None):
        self.values = iter(values)
        self.failure = failure
        self.cleanup = cleanup
        self.pulls = 0
        self.closes = 0
        self.operations = []

    def __aiter__(self):
        return self

    async def __anext__(self):
        self.pulls += 1
        self.operations.append(("pull", threading.get_ident()))
        if self.failure is not None:
            raise self.failure
        try:
            return next(self.values)
        except StopIteration:
            raise StopAsyncIteration from None

    async def aclose(self):
        self.closes += 1
        self.operations.append(("close", threading.get_ident()))
        if self.cleanup is not None:
            raise self.cleanup


def body(*sources):
    return FACADE.StreamingMultipartBody(
        [FACADE.MultipartPart.stream("field", source) for source in sources],
        boundary="B",
        maximum_bytes=1000000,
    )


class MultipartFacadeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.patch = patch.object(
            FACADE._native, "NativeStreamingMultipart", NativeMultipart, create=True
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)

    async def test_one_demanded_source_and_bounded_copies_before_next_part(self):
        payload = b"x" * (65536 * 2 + 1)
        first, second = Source([payload]), Source([b"last"])
        encoded = body(first, second)
        with self.assertRaises(FrozenInstanceError):
            encoded._maximum = 0
        pump = encoded._claim(True)
        encoded._prepare(pump)
        try:
            await asyncio.sleep(0)
            self.assertEqual((first.pulls, second.pulls), (0, 0))
            pump.native.parts.put_nowait(0)
            for offset, count in ((0, 65536), (65536, 65536), (131072, 1)):
                pump.native.credits.put_nowait(True)
                data, actual_offset, actual_count = await asyncio.wait_for(
                    pump.native.writes.get(), 1
                )
                self.assertIs(data, payload)
                self.assertEqual((actual_offset, actual_count), (offset, count))
                self.assertEqual(second.pulls, 0)
            pump.native.credits.put_nowait(True)
            await asyncio.wait_for(pump.native.ends.get(), 1)
            self.assertEqual(first.closes, 1)
            self.assertFalse(pump.settled.done())
            pump.native.parts.put_nowait(1)
            pump.native.credits.put_nowait(True)
            self.assertEqual((await pump.native.writes.get())[0], b"last")
        finally:
            pump.close()
            self.assertTrue(await pump.wait())
        self.assertEqual((first.closes, second.closes), (1, 1))
        self.assertEqual(
            {thread for _, thread in first.operations}, {threading.get_ident()}
        )

    async def test_validation_before_pump_start_closes_unstarted_parts_once(self):
        first, second = Source(), Source()
        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(cookies=object())
        )
        with self.assertRaises(ValueError):
            await client.request(
                "POST", "invalid", body=body(first, second), body_length=0
            )
        self.assertEqual((first.pulls, second.pulls), (0, 0))
        self.assertEqual((first.closes, second.closes), (1, 1))
        self.assertFalse(client._uploads)

    async def test_close_before_native_preparation_still_settles_started_coordinator(
        self,
    ):
        first, second = Source(), Source()
        pump = body(first, second)._claim(True)
        await asyncio.sleep(0)
        pump.close()
        self.assertTrue(await pump.wait())
        self.assertIsNone(pump.error)
        self.assertIsNone(pump.cleanup_error)
        self.assertEqual((first.closes, second.closes), (1, 1))

    async def test_native_setup_failure_retains_primary_and_all_cleanup_causes(self):
        primary = FACADE._native.NativeError("request", "connect", "h2", None)
        cleanups = (OSError("private-one"), OSError("private-two"))
        first, second = (Source(cleanup=error) for error in cleanups)

        class Client:
            cookies = object()

            async def request(self, *args, **kwargs):
                kwargs["multipart"].abort()
                await asyncio.sleep(0)
                raise primary

        client = FACADE.AsyncClient._from_native(Client())
        with self.assertRaises(FACADE.Error) as caught:
            await client.request(
                "POST", "http://example.invalid", body=body(first, second)
            )
        self.assertEqual(
            (caught.exception.kind, caught.exception.protocol), ("connect", "h2")
        )
        self.assertEqual(caught.exception.cleanup_error.errors, cleanups)
        self.assertNotIn("private", repr(caught.exception))
        self.assertEqual((first.closes, second.closes), (1, 1))
        self.assertFalse(client._uploads)

    async def test_source_and_multiple_cleanup_identities_remain_redacted(self):
        original = RuntimeError("private-source")
        cleanups = (OSError("private-first"), OSError("private-second"))
        first = Source(failure=original, cleanup=cleanups[0])
        second = Source(cleanup=cleanups[1])
        encoded = body(first, second)
        pump = encoded._claim(True)
        encoded._prepare(pump)
        pump.native.parts.put_nowait(0)
        pump.native.credits.put_nowait(True)
        await asyncio.wait_for(pump.task, 1)
        pump.close()
        self.assertTrue(await pump.wait())
        failure = FACADE._upload_error(pump)
        self.assertIs(failure.original, original)
        self.assertEqual(failure.cleanup_error.errors, cleanups)
        self.assertNotIn("private", str(failure))
        self.assertNotIn("private", repr(failure.cleanup_error))
        self.assertEqual((first.closes, second.closes), (1, 1))

    async def test_reused_part_does_not_close_the_other_requests_source(self):
        selected, untouched = Source(), Source()
        part = FACADE.MultipartPart.stream("first", selected)
        one = FACADE.StreamingMultipartBody([part], boundary="B", maximum_bytes=1000)
        first = one._claim(True)
        one._prepare(first)
        other = FACADE.StreamingMultipartBody(
            [part, FACADE.MultipartPart.stream("second", untouched)],
            boundary="B",
            maximum_bytes=1000,
        )
        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(cookies=object())
        )
        try:
            with self.assertRaises(FACADE.Error) as caught:
                await client.request("POST", "invalid", body=other)
            self.assertEqual(caught.exception.kind, "upload_used")
            self.assertEqual((selected.closes, untouched.closes), (0, 1))
            with self.assertRaises(FACADE.Error):
                one._claim(True)
        finally:
            first.close()
            self.assertTrue(await first.wait())
        self.assertEqual(selected.closes, 1)

    async def test_aliases_mode_and_metadata_failure_close_all_claimed_sources(self):
        for mode in ("alias", "metadata", "client_mode"):
            with self.subTest(mode=mode):
                source = Source()
                parts = [FACADE.MultipartPart.stream("x", source)]
                if mode == "alias":
                    parts.append(FACADE.MultipartPart.stream("y", source))
                if mode == "metadata":
                    parts.append(FACADE.MultipartPart.stream(123, Source()))
                encoded = FACADE.StreamingMultipartBody(
                    parts, boundary="B", maximum_bytes=1000
                )
                pump = encoded._claim(mode != "client_mode")
                try:
                    with self.assertRaises((TypeError, FACADE.Error)):
                        encoded._prepare(pump)
                finally:
                    pump.close()
                    self.assertTrue(await pump.wait())
                self.assertEqual(source.pulls, 0)
                self.assertEqual(source.closes, 1)

    async def test_noncooperative_cleanup_remains_owned_and_self_wait_fails(self):
        release, entered = asyncio.Event(), asyncio.Event()
        client = FACADE.AsyncClient._from_native(
            types.SimpleNamespace(cookies=object())
        )

        class Slow(Source):
            async def aclose(self):
                self.closes += 1
                entered.set()
                await release.wait()
                await client.close()

        source = Slow()
        encoded = body(source)
        pump = encoded._claim(True)
        client._uploads.add(pump)
        pump.settled.add_done_callback(lambda _: client._uploads.discard(pump))
        pump.close()
        await entered.wait()
        self.assertFalse(await pump.wait(0))
        self.assertIn(pump, client._uploads)
        release.set()
        self.assertTrue(await pump.wait())
        self.assertIsInstance(pump.cleanup_error, RuntimeError)
        self.assertEqual(source.closes, 1)

    async def test_file_is_a_path_until_native_demand_and_metadata_count_is_bounded(
        self,
    ):
        part = FACADE.MultipartPart.file("file", "not-created", filename="upload.bin")
        encoded = FACADE.StreamingMultipartBody(
            [part], boundary="B", maximum_bytes=1000
        )
        pump = encoded._claim(True)
        encoded._prepare(pump)
        self.assertEqual(
            pump.native.fields, [(3, "file", "not-created", "upload.bin", None)]
        )
        pump.close()
        self.assertTrue(await pump.wait())
        with self.assertRaises(FACADE.PreparedBodyError):
            FACADE.StreamingMultipartBody(
                [part] * 1025, boundary="B", maximum_bytes=1000
            )
        with self.assertRaises(TypeError):
            FACADE.StreamingMultipartBody(
                iter([part]), boundary="B", maximum_bytes=1000
            )
