"""Typed transfer bounds and off-loop dispatch without loading native code."""

import asyncio
import dataclasses
import threading
import types
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE as api


def cookie(**changes):
    return api.CookieSnapshotEntry(
        source_scheme="https",
        name="id",
        value="private",
        domain="private.invalid",
        **changes,
    )


class StateTransferFacadeTests(unittest.IsolatedAsyncioTestCase):
    def test_typed_editable_round_trip_preserves_order_attributes_and_nanoseconds(self):
        original = api.CookieSnapshot(
            (
                cookie(expires_at_ns=2_000_000_000_123_456_789),
                cookie(
                    path="/page",
                    same_site="none",
                    secure=True,
                    partition_key="https://private.invalid",
                ),
            )
        )
        self.assertEqual(api.CookieSnapshot._from_fields(original._fields()), original)
        edited = dataclasses.replace(original.entries[0], value="changed")
        self.assertEqual(edited.value, "changed")
        self.assertEqual(original.entries[0].value, "private")
        self.assertNotIn("private", repr(original))
        self.assertNotIn("private", repr(edited))
        alternative = api.AltSvcSnapshotEntry(
            origin="https://private.invalid",
            alternative_host="private.invalid",
            alternative_port=443,
            expires_at_ns=2_000_000_000_123_456_789,
        )
        snapshot = api.AltSvcSnapshot((alternative,))
        self.assertEqual(api.AltSvcSnapshot._from_fields(snapshot._fields()), snapshot)
        self.assertNotIn("private", repr(alternative))

    def test_iterables_stop_at_the_bound_and_full_default_cookie_jar_fits(self):
        self.assertEqual(
            len(api.CookieSnapshot(cookie() for _ in range(3300)).entries), 3300
        )
        for kind, entry, maximum in (
            (api.CookieSnapshot, cookie(), 16384),
            (
                api.AltSvcSnapshot,
                api.AltSvcSnapshotEntry(
                    origin="https://a.invalid",
                    alternative_host="a.invalid",
                    alternative_port=443,
                    expires_at_ns=0,
                ),
                32768,
            ),
        ):
            with self.subTest(kind=kind):
                consumed = []

                def entries(maximum=maximum, consumed=consumed, entry=entry):
                    for index in range(maximum + 2):
                        consumed.append(index)
                        yield entry

                with self.assertRaises(ValueError):
                    kind(entries())
                self.assertEqual(len(consumed), maximum + 1)
                self.assertEqual(len(kind((entry,) * maximum).entries), maximum)

    def test_aggregate_utf8_is_bounded_and_forged_fields_are_rechecked(self):
        entry = cookie()
        object.__setattr__(entry, "value", "é" * (16 * 1024 * 1024))
        with self.assertRaises(ValueError):
            api.CookieSnapshot((entry,))
        for field, value in (("value", "private\ud800"), ("domain", 4)):
            entry = cookie()
            object.__setattr__(entry, field, value)
            with self.assertRaises((TypeError, ValueError)) as caught:
                api.CookieSnapshot((entry,))
            self.assertNotIn("private", str(caught.exception))
        snapshot = api.CookieSnapshot((cookie(),))
        object.__setattr__(snapshot.entries[0], "value", "\ud800")
        with self.assertRaises(ValueError):
            snapshot._fields()
        for expiry in (True, 1.5, 2**127, -(2**127) - 1):
            with self.assertRaises(ValueError):
                cookie(expires_at_ns=expiry)

    async def test_async_dispatch_preserves_disabled_empty_routes_and_failure_index(
        self,
    ):
        calls = []
        owner = threading.get_ident()

        class Native:
            cookies = object()

            def export_cookies(self):
                calls.append(("cookies", threading.get_ident()))
                return None

            def import_cookies(self, fields):
                calls.append(fields)
                failure = api._native.NativeError(
                    "cookie_snapshot", "invalid_cookie", None, None
                )
                failure.entry_index = 1
                raise failure

            def export_alt_svc(self):
                return []

            def import_alt_svc(self, fields):
                calls.append(fields)

            def export_session_tickets(self, key):
                return b"encrypted"

            def import_session_tickets(self, *args):
                calls.append(args)

        client = api.AsyncClient._from_native(Native())
        self.assertIsNone(await client.export_cookies())
        self.assertNotEqual(calls[0][1], owner)
        self.assertEqual(await client.export_alt_svc(), api.AltSvcSnapshot())
        await client.import_alt_svc(api.AltSvcSnapshot())
        self.assertEqual(await client.export_session_tickets(bytes(32)), b"encrypted")
        await client.import_session_tickets(
            b"encrypted",
            bytes(32),
            receiving_routes=(None, api.Proxy("http://private.invalid:80")),
        )
        self.assertEqual(
            calls[-1][2],
            [(None, None, None), ("http://private.invalid:80", None, None)],
        )
        with self.assertRaises(api.CookieSnapshotError) as caught:
            await client.import_cookies(api.CookieSnapshot((cookie(), cookie())))
        self.assertEqual(caught.exception.entry_index, 1)
        self.assertEqual(caught.exception.kind, "invalid_cookie")
        self.assertNotIn("private", repr(caught.exception))

    async def test_invalid_tickets_and_unbounded_routes_never_enter_native(self):
        native = types.SimpleNamespace(cookies=object())
        native.export_session_tickets = lambda *_: self.fail("native called")
        client = api.AsyncClient._from_native(native)
        for key in (b"", bytes(31), bytes(33)):
            with self.assertRaises(api.SessionTicketError) as caught:
                await client.export_session_tickets(key)
            self.assertEqual(caught.exception.kind, "invalid_key_length")
        native.import_session_tickets = lambda *_: self.fail("native called")
        with self.assertRaises(api.SessionTicketError) as caught:
            await client.import_session_tickets(bytes(16 * 1024 * 1024 + 1), bytes(32))
        self.assertEqual(caught.exception.kind, "too_large")
        consumed = []

        def routes():
            for index in range(258):
                consumed.append(index)
                yield None

        with self.assertRaises(ValueError):
            await client.import_session_tickets(
                b"encrypted", bytes(32), receiving_routes=routes()
            )
        self.assertEqual(len(consumed), 257)

    async def test_cancellation_preserves_cancelled_error_while_native_work_finishes(
        self,
    ):
        started = threading.Event()
        release = threading.Event()
        completed = threading.Event()

        class Native:
            cookies = object()

            def export_cookies(self):
                started.set()
                release.wait(5)
                completed.set()
                return []

        client = api.AsyncClient._from_native(Native())
        task = asyncio.create_task(client.export_cookies())
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 5))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(completed.is_set())
        finally:
            release.set()
            self.assertTrue(await asyncio.to_thread(completed.wait, 5))

    async def test_unrelated_failure_preserves_original_exception_identity(self):
        original = RuntimeError("private")

        class Native:
            cookies = object()

            def import_alt_svc(self, _):
                raise original

        client = api.AsyncClient._from_native(Native())
        with self.assertRaises(RuntimeError) as caught:
            await client.import_alt_svc(api.AltSvcSnapshot())
        self.assertIs(caught.exception, original)

    def test_alt_svc_capacity_is_positive_and_omitted_by_default(self):
        self.assertIsNone(api.NetworkOptions().max_alt_svc_origins)
        self.assertEqual(
            api.NetworkOptions(max_alt_svc_origins=8).max_alt_svc_origins, 8
        )
        for value in (0, -1, True, 1.5, 2**128):
            with self.assertRaises(ValueError):
                api.NetworkOptions(max_alt_svc_origins=value)

    def test_sync_dispatch_uses_same_transfers_without_an_extra_client(self):
        class Native:
            cookies = object()
            is_closed = False

            def __init__(self, *_, **__):
                self.received = []

            def export_cookies(self):
                return [cookie()._fields()]

            def import_cookies(self, entries):
                self.received.append(entries)

            async def shutdown(self, _):
                self.is_closed = True

        with (
            patch.object(api._native, "NativeClient", Native, create=True),
            api.Client(profile="exact", protocol="h1") as client,
        ):
            snapshot = client.export_cookies()
            client.import_cookies(snapshot)
            self.assertEqual(client._async._native.received, [snapshot._fields()])
