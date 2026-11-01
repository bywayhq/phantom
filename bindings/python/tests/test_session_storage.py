"""Caller storage uses the existing native checkpoint and restore contracts."""

import unittest

from phantom_http import AsyncClient, Client, SessionSnapshotError
from test_client import OPTIONS

KEY = b"k" * 32
URL = "https://example.test"


class Store:
    def __init__(self):
        self.values = {}

    def load(self, name):
        return self.values.get(name)

    def save(self, name, snapshot):
        self.values[name] = snapshot


class SyncStorageTests(unittest.TestCase):
    def test_native_roundtrip_and_wrong_key_preserve_receiving_state(self):
        store = Store()
        with Client(**OPTIONS) as source:
            source.cookies.set(URL, "state=original; Secure; Path=/")
            source.save_session(store, "job/session", KEY, timeout=5)
            self.assertNotIn(b"state=original", store.values["job/session"])
            source.cookies.set(URL, "state=changed; Secure; Path=/")
            self.assertIsNone(source.load_session(store, "absent", KEY, timeout=5))
            with source.load_session(
                store, "job/session", KEY, timeout=5, receiving_routes=[None]
            ) as child:
                self.assertEqual(child.cookies.for_url(URL), "state=original")
            with self.assertRaises(SessionSnapshotError) as caught:
                source.load_session(store, "job/session", b"x" * 32, timeout=5)
            self.assertEqual(caught.exception.kind, "authentication")
            self.assertEqual(source.cookies.for_url(URL), "state=changed")


class AsyncStorageTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_async_roundtrip_uses_the_same_checkpoint_contract(self):
        values = {}

        class Backend:
            async def save(self, name, snapshot):
                values[name] = snapshot

            async def load(self, name):
                return values.get(name)

        store = Backend()
        async with AsyncClient(**OPTIONS) as source:
            source.cookies.set(URL, "state=original; Secure; Path=/")
            await source.save_session(store, "job/session", KEY, timeout=5)
            self.assertNotIn(b"state=original", values["job/session"])
            source.cookies.set(URL, "state=changed; Secure; Path=/")
            self.assertIsNone(
                await source.load_session(store, "absent", KEY, timeout=5)
            )
            child = await source.load_session(
                store, "job/session", KEY, timeout=5, receiving_routes=[None]
            )
            async with child:
                self.assertEqual(child.cookies.for_url(URL), "state=original")
            self.assertEqual(source.cookies.for_url(URL), "state=changed")
