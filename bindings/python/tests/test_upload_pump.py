"""Producer ownership controls run without loading a native extension."""

import asyncio
import importlib.util
import sys
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def upload_module():
    source = Path(__file__).parents[1] / "python/phantom_http/_upload.py"
    if not source.is_file():
        package = importlib.util.find_spec("phantom_http")
        if package is None or package.origin is None:
            raise RuntimeError("missing installed package")
        source = Path(package.origin).with_name("_upload.py")
    name = "_phantom_upload_pump_control"
    package = types.ModuleType(name)
    package.__path__ = [str(source.parent)]
    native = types.ModuleType(name + "._native")
    native.NativeError = NativeError
    sys.modules[name] = package
    sys.modules[native.__name__] = native
    spec = importlib.util.spec_from_file_location(name + "._upload", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class NativeError(Exception):
    pass


class Native:
    def __init__(self, length):
        self.length = length
        self.credits = asyncio.Queue()
        self.ended = asyncio.Event()
        self.writes = asyncio.Queue()
        self.finished = False
        self.failed = False
        self.aborted = False

    async def credit(self):
        return await self.credits.get()

    async def terminal(self):
        await self.ended.wait()

    def write(self, data, offset, length):
        self.writes.put_nowait((data, offset, length))

    def finish(self):
        self.finished = True
        self.ended.set()

    def fail(self):
        self.failed = True
        self.ended.set()

    def abort(self):
        self.aborted = True
        self.ended.set()


UPLOAD = upload_module()


class PumpTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.patch = patch.object(UPLOAD._native, "NativeUpload", Native, create=True)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    async def test_credit_before_pull_and_large_bytes_without_slicing(self):
        pulls = []
        payload = b"x" * (65536 * 2 + 3)

        async def chunks():
            pulls.append("first")
            yield payload
            pulls.append("second")

        pump = UPLOAD.Upload(chunks(), len(payload))
        await asyncio.sleep(0)
        self.assertEqual(pulls, [])
        for offset, length in ((0, 65536), (65536, 65536), (131072, 3)):
            pump.native.credits.put_nowait(True)
            data, actual_offset, actual_length = await pump.native.writes.get()
            self.assertIs(data, payload)
            self.assertEqual((actual_offset, actual_length), (offset, length))
            self.assertEqual(pulls, ["first"])
        pump.native.credits.put_nowait(True)
        self.assertTrue(await pump.wait())
        self.assertTrue(pump.native.finished)
        self.assertEqual(pulls, ["first", "second"])
        self.assertIsNone(pump.error)

    async def test_empty_chunks_keep_one_credit_and_wrong_type_is_inspectable(self):
        closed = asyncio.Event()

        async def chunks():
            try:
                yield b""
                yield b""
                yield "private-value"
            finally:
                closed.set()

        pump = UPLOAD.Upload(chunks(), None)
        pump.native.credits.put_nowait(True)
        self.assertTrue(await pump.wait())
        self.assertTrue(closed.is_set())
        self.assertTrue(pump.native.failed)
        self.assertIsInstance(pump.error, TypeError)
        self.assertNotIn("private-value", str(pump.error))
        self.assertTrue(pump.native.writes.empty())

    async def test_terminal_cancels_pending_pull_and_cleanup_once(self):
        entered = asyncio.Event()
        closes = []

        async def chunks():
            try:
                entered.set()
                await asyncio.Future()
                yield b"unreachable"
            finally:
                closes.append("closed")

        pump = UPLOAD.Upload(chunks(), None)
        pump.native.credits.put_nowait(True)
        await entered.wait()
        pump.native.ended.set()
        self.assertTrue(await pump.wait())
        pump.close()
        self.assertEqual(closes, ["closed"])
        self.assertIsNone(pump.error)
        self.assertIsNone(pump.cleanup_error)

    async def test_producer_and_cleanup_errors_are_retained_separately(self):
        original = ValueError("private-producer")
        cleanup = OSError("private-cleanup")

        class Source:
            def __aiter__(self):
                return self

            async def __anext__(self):
                raise original

            async def aclose(self):
                raise cleanup

        pump = UPLOAD.Upload(Source(), None)
        pump.native.credits.put_nowait(True)
        self.assertTrue(await pump.wait())
        self.assertIs(pump.error, original)
        self.assertIs(pump.cleanup_error, cleanup)
        self.assertTrue(pump.native.failed)

    async def test_noncooperative_cleanup_stays_owned_until_released(self):
        entered = asyncio.Event()
        cleanup = asyncio.Event()
        release = asyncio.Event()

        class Source:
            def __aiter__(self):
                return self

            async def __anext__(self):
                entered.set()
                await asyncio.Future()

            async def aclose(self):
                cleanup.set()
                await release.wait()

        pump = UPLOAD.Upload(Source(), None)
        pump.native.credits.put_nowait(True)
        await entered.wait()
        pump.close()
        await cleanup.wait()
        pump.close()
        self.assertFalse(await pump.wait(0))
        self.assertFalse(pump.task.done())
        release.set()
        self.assertTrue(await pump.wait())
        self.assertIsNone(pump.cleanup_error)

    async def test_terminal_race_with_write_or_eof_is_normal_abandonment(self):
        for operation in ("write", "finish"):
            with self.subTest(operation=operation):

                class ClosingNative(Native):
                    def write(self, data, offset, length, operation=operation):
                        if operation == "write":
                            self.ended.set()
                            raise NativeError("input", "upload_closed", None, None)
                        super().write(data, offset, length)

                    def finish(self):
                        self.ended.set()
                        raise NativeError("input", "upload_closed", None, None)

                async def chunks(operation=operation):
                    if operation == "write":
                        yield b"x"

                with patch.object(UPLOAD._native, "NativeUpload", ClosingNative):
                    pump = UPLOAD.Upload(chunks(), None)
                    pump.native.credits.put_nowait(True)
                    self.assertTrue(await pump.wait())
                    self.assertIsNone(pump.error)
                    self.assertIsNone(pump.cleanup_error)

    async def test_source_cancellation_terminates_native_demand(self):
        original = asyncio.CancelledError()

        async def chunks():
            raise original
            yield b"unreachable"

        pump = UPLOAD.Upload(chunks(), None)
        pump.native.credits.put_nowait(True)
        self.assertTrue(await pump.wait())
        self.assertIs(pump.error, original)
        self.assertTrue(pump.native.aborted)

    async def test_normal_eof_does_not_interrupt_awaited_cleanup(self):
        cleaning = asyncio.Event()
        release = asyncio.Event()

        class Source:
            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

            async def aclose(self):
                cleaning.set()
                await release.wait()

        pump = UPLOAD.Upload(Source(), None)
        pump.native.credits.put_nowait(True)
        await cleaning.wait()
        self.assertFalse(await pump.wait(0))
        self.assertFalse(pump.task.done())
        release.set()
        self.assertTrue(await pump.wait())
        self.assertIsNone(pump.cleanup_error)

    async def test_sync_iterator_runs_and_closes_on_the_owning_thread(self):
        owner = threading.get_ident()
        operations = []

        def chunks():
            try:
                operations.append(("pull", threading.get_ident()))
                yield b"a"
            finally:
                operations.append(("close", threading.get_ident()))

        pump = UPLOAD.Upload(UPLOAD.SyncSource(chunks()), 1)
        pump.native.credits.put_nowait(True)
        await pump.native.writes.get()
        pump.native.credits.put_nowait(True)
        self.assertTrue(await pump.wait())
        self.assertEqual(operations, [("pull", owner), ("close", owner)])

    def test_exact_length_validation_has_no_bool_or_integer_truncation(self):
        self.assertEqual(UPLOAD.length(2**64 - 1, True), 2**64 - 1)
        for value in (-1, 2**64):
            with self.assertRaises(ValueError):
                UPLOAD.length(value, True)
        for value in (True, 1.5):
            with self.assertRaises(TypeError):
                UPLOAD.length(value, True)
        with self.assertRaises(ValueError):
            UPLOAD.length(0, False)
