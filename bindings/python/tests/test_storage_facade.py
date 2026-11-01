"""Storage deadlines and failure ownership without loading native code."""

import asyncio
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE

KEY = b"k" * 32
storage = __import__(FACADE.__name__ + "._storage", fromlist=["_"])


class Native:
    cookies = object()

    def __init__(self, *args, **kwargs):
        self.calls = []
        self.is_closed = False

    def export_session(self, key):
        self.calls.append(("export", key))
        return b"encrypted"

    def restore_session(self, snapshot, key, routes):
        self.calls.append(("restore", snapshot, key, routes))
        return Native()

    def abort(self):
        self.is_closed = True

    async def shutdown(self, _):
        self.is_closed = True


class Store:
    def __init__(self):
        self.values = {}

    def save(self, name, snapshot):
        self.values[name] = snapshot

    def load(self, name):
        return self.values.get(name)


class SyncStorageTests(unittest.TestCase):
    def test_storage_roundtrip_and_absence_preserve_source_and_routes(self):
        with (
            patch.object(FACADE._native, "NativeClient", Native, create=True),
            FACADE.Client(profile="chrome-154-windows") as source,
        ):
            store = Store()
            source.save_session(store, "é" * 128, KEY, timeout=5)
            self.assertEqual(store.values, {"é" * 128: b"encrypted"})
            self.assertIsNone(source.load_session(store, "absent", KEY, timeout=5))
            with source.load_session(
                store, "é" * 128, KEY, timeout=5, receiving_routes=[None]
            ) as child:
                self.assertIsNot(child._async._native, source._async._native)
            self.assertFalse(source.is_closed)
            self.assertEqual(source._async._native.calls[-1][-1], [(None, None, None)])

    def test_invalid_name_backend_error_and_oversize_never_restore(self):
        original = OSError("private backend detail")
        store = Store()
        with (
            patch.object(FACADE._native, "NativeClient", Native, create=True),
            FACADE.Client(profile="chrome-154-windows") as source,
        ):
            for name in ("", "é" * 129, "a\x00", "a\x85", "\ud800"):
                with self.assertRaises(FACADE.SessionStorageError) as caught:
                    source.save_session(store, name, KEY, timeout=5)
                self.assertEqual(caught.exception.kind, "invalid_name")
            with (
                patch.object(store, "load", side_effect=original),
                self.assertRaises(FACADE.SessionStorageError) as caught,
            ):
                source.load_session(store, "session", KEY, timeout=5)
            self.assertIs(caught.exception.original, original)
            self.assertNotIn("private", str(caught.exception))
            store.values["session"] = b"x" * (32 * 1024 * 1024 + 1)
            with self.assertRaises(FACADE.SessionStorageError) as caught:
                source.load_session(store, "session", KEY, timeout=5)
            self.assertEqual(caught.exception.kind, "too_large")
            self.assertEqual(source._async._native.calls, [])
            with (
                patch.object(store, "load") as load,
                self.assertRaises(FACADE.SessionSnapshotError) as caught,
            ):
                source.load_session(store, "absent", b"short", timeout=5)
            self.assertEqual(caught.exception.kind, "invalid_key_length")
            load.assert_not_called()

    def test_one_deadline_covers_blocking_backend_and_late_restore_cleanup(self):
        clock = [0.0]
        store = Store()
        with (
            patch.object(storage, "monotonic", side_effect=lambda: clock[0]),
            patch.object(FACADE._native, "NativeClient", Native, create=True),
            FACADE.Client(profile="chrome-154-windows") as source,
        ):

            def late_save(name, snapshot):
                store.values[name] = snapshot
                clock[0] = 6

            with (
                patch.object(store, "save", side_effect=late_save),
                self.assertRaises(FACADE.TimeoutError),
            ):
                source.save_session(store, "session", KEY, timeout=5)
            self.assertEqual(store.values["session"], b"encrypted")
            child = source.restore_session(b"encrypted", KEY)

            def late_restore(*args, **kwargs):
                clock[0] = 12
                return child

            with (
                patch.object(source, "restore_session", side_effect=late_restore),
                self.assertRaises(FACADE.TimeoutError),
            ):
                source.load_session(store, "session", KEY, timeout=5)
            self.assertTrue(child.is_closed)
            self.assertFalse(source.is_closed)


class AsyncStorageTests(unittest.IsolatedAsyncioTestCase):
    async def test_expired_input_preparation_does_not_start_backend_work(self):
        clock = [0.0]
        calls = []
        source = FACADE.AsyncClient._from_native(Native())

        class Backend:
            def load(self, name):
                calls.append(name)
                return asyncio.sleep(0, result=None)

        def routes():
            clock[0] = 6
            yield None

        with (
            patch.object(storage, "monotonic", side_effect=lambda: clock[0]),
            self.assertRaises(FACADE.TimeoutError),
        ):
            await source.load_session(
                Backend(), "session", KEY, timeout=5, receiving_routes=routes()
            )
        self.assertEqual(calls, [])

    async def test_async_load_bounds_absence_and_late_cpu_owner_cleanup(self):
        clock = [0.0]
        source = FACADE.AsyncClient._from_native(Native())

        class Backend:
            snapshot = None

            async def load(self, name):
                return self.snapshot

        store = Backend()
        self.assertIsNone(await source.load_session(store, "absent", KEY, timeout=5))
        store.snapshot = b"x" * (32 * 1024 * 1024 + 1)
        with self.assertRaises(FACADE.SessionStorageError):
            await source.load_session(store, "session", KEY, timeout=5)
        self.assertEqual(source._native.calls, [])
        store.snapshot = b"encrypted"
        child = await source.load_session(
            store, "session", KEY, timeout=5, receiving_routes=[None]
        )
        self.assertEqual(source._native.calls[-1][-1], [(None, None, None)])
        await child.abort()
        late = Native()

        def restore(*args):
            clock[0] = 6
            return late

        with (
            patch.object(storage, "monotonic", side_effect=lambda: clock[0]),
            patch.object(source._native, "restore_session", side_effect=restore),
            self.assertRaises(FACADE.TimeoutError),
        ):
            await source.load_session(store, "session", KEY, timeout=5)
        self.assertTrue(late.is_closed)
        self.assertFalse(source.is_closed)

    async def test_async_backend_cancel_releases_only_its_operation_and_preserves_error(
        self,
    ):
        entered, released = asyncio.Event(), asyncio.Event()
        original = OSError("private backend detail")

        class Backend:
            async def load(self, name):
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    released.set()

            async def save(self, name, snapshot):
                raise original

        source = FACADE.AsyncClient._from_native(Native())
        pending = asyncio.create_task(
            source.load_session(Backend(), "session", KEY, timeout=5)
        )
        await asyncio.wait_for(entered.wait(), 5)
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertTrue(released.is_set())
        with self.assertRaises(FACADE.SessionStorageError) as caught:
            await source.save_session(Backend(), "session", KEY, timeout=5)
        self.assertIs(caught.exception.original, original)
        self.assertFalse(source.is_closed)

    async def test_deadline_covers_encoding_without_starting_backend(self):
        clock = [0.0]
        source = FACADE.AsyncClient._from_native(Native())
        calls = []

        async def encode(_):
            clock[0] = 6
            return b"encrypted"

        class Backend:
            async def save(self, *args):
                calls.append(args)

        with (
            patch.object(storage, "monotonic", side_effect=lambda: clock[0]),
            patch.object(source, "export_session", side_effect=encode),
            self.assertRaises(FACADE.TimeoutError),
        ):
            await source.save_session(Backend(), "session", KEY, timeout=5)
        self.assertEqual(calls, [])
