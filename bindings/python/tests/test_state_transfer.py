"""Standalone native state transfers retain validation, expiry and client isolation."""

import dataclasses
import time
import unittest

from phantom_http import (
    AltSvcSnapshot,
    AltSvcSnapshotEntry,
    AltSvcSnapshotError,
    AsyncClient,
    Client,
    CookieSnapshot,
    CookieSnapshotEntry,
    CookieSnapshotError,
    NetworkOptions,
    SessionSharing,
    SessionTicketError,
    Trust,
)
from test_client import OPTIONS
from test_settings_transport import ROOT, peer


def cookie(name="id", **changes):
    return CookieSnapshotEntry(
        source_scheme="https",
        name=name,
        value="private",
        domain="example.com",
        **changes,
    )


class StateTransferTests(unittest.TestCase):
    def test_cookie_round_trip_attributes_order_and_existing_cookie_precedence(self):
        expiry = (int(time.time()) + 3600) * 1_000_000_000
        snapshot = CookieSnapshot(
            (
                cookie("first", expires_at_ns=expiry),
                cookie("second", secure=True, http_only=True, same_site="lax"),
                cookie("expired", expires_at_ns=0),
            )
        )
        with Client(**OPTIONS) as source, Client(**OPTIONS) as receiver:
            source.import_cookies(snapshot)
            exported = source.export_cookies()
            self.assertEqual(exported.entries, snapshot.entries[:2])
            receiver.cookies.set("https://example.com/", "first=held; Secure; Path=/")
            receiver.import_cookies(exported)
            self.assertEqual(
                receiver.cookies.for_url("https://example.com/"),
                "second=private; first=held",
            )
            self.assertEqual(
                source.cookies.for_url("https://example.com/"),
                "first=private; second=private",
            )

    def test_cookie_failure_is_indexed_atomic_and_redacted(self):
        with Client(**OPTIONS) as client:
            client.import_cookies(CookieSnapshot((cookie("held"),)))
            before = client.export_cookies()
            invalid = dataclasses.replace(cookie(), domain="com", host_only=False)
            with self.assertRaises(CookieSnapshotError) as caught:
                client.import_cookies(CookieSnapshot((cookie("accepted"), invalid)))
            self.assertEqual(caught.exception.entry_index, 1)
            self.assertEqual(caught.exception.kind, "public_suffix")
            self.assertNotIn("private", repr(caught.exception))
            self.assertEqual(client.export_cookies(), before)
        with Client(**{**OPTIONS, "cookies": False}) as client:
            self.assertIsNone(client.export_cookies())
            with self.assertRaises(CookieSnapshotError) as caught:
                client.import_cookies(CookieSnapshot())
            self.assertEqual(caught.exception.kind, "disabled")
            self.assertIsNone(caught.exception.entry_index)

    def test_default_cookie_jar_can_transfer_all_3300_entries(self):
        entries = tuple(
            CookieSnapshotEntry(
                source_scheme="https",
                name="id",
                value=str(index),
                domain=f"example{index}.com",
            )
            for index in range(3300)
        )
        with Client(**OPTIONS) as source, Client(**OPTIONS) as receiver:
            source.import_cookies(CookieSnapshot(entries))
            snapshot = source.export_cookies()
            self.assertEqual(len(snapshot.entries), 3300)
            receiver.import_cookies(snapshot)
            self.assertEqual(receiver.export_cookies(), snapshot)

    def test_alt_svc_disabled_empty_atomicity_expiry_and_configuration_retention(self):
        with Client(**OPTIONS) as disabled:
            self.assertIsNone(disabled.export_alt_svc())
            with self.assertRaises(AltSvcSnapshotError) as caught:
                disabled.import_alt_svc(AltSvcSnapshot())
            self.assertEqual(caught.exception.kind, "disabled")
        with Client(**OPTIONS, network=NetworkOptions(max_alt_svc_origins=8)) as client:
            self.assertEqual(client.export_alt_svc(), AltSvcSnapshot())
            future = (int(time.time()) + 3600) * 1_000_000_000
            entry = AltSvcSnapshotEntry(
                origin="https://example.com",
                alternative_host="example.com",
                alternative_port=443,
                expires_at_ns=future + 100,
            )
            client.import_alt_svc(
                AltSvcSnapshot(
                    (
                        entry,
                        dataclasses.replace(
                            entry, origin="https://expired.example.com", expires_at_ns=0
                        ),
                    )
                )
            )
            before = client.export_alt_svc()
            self.assertEqual(len(before.entries), 1)
            self.assertEqual(before.entries[0].origin, entry.origin)
            # Core snapshots round exported expiry down to whole seconds.
            self.assertLessEqual(before.entries[0].expires_at_ns, entry.expires_at_ns)
            self.assertEqual(before.entries[0].expires_at_ns % 1_000_000_000, 0)
            invalid = dataclasses.replace(entry, origin="https://EXAMPLE.com")
            with self.assertRaises(AltSvcSnapshotError) as caught:
                client.import_alt_svc(AltSvcSnapshot((entry, invalid)))
            self.assertEqual(caught.exception.entry_index, 1)
            self.assertEqual(caught.exception.kind, "noncanonical_origin")
            self.assertEqual(client.export_alt_svc().entries[0].origin, entry.origin)
            with client.fork(sharing=SessionSharing(discovery=True)) as child:
                self.assertEqual(child.export_alt_svc().entries[0].origin, entry.origin)
            key = bytes(32)
            with client.restore_session(client.export_session(key), key) as restored:
                self.assertEqual(
                    restored.export_alt_svc().entries[0].origin, entry.origin
                )

    def test_encrypted_ticket_round_trip_and_redacted_authentication_failure(self):
        with Client(**OPTIONS) as source, Client(**OPTIONS) as receiver:
            snapshot = source.export_session_tickets(bytes(32))
            receiver.import_session_tickets(snapshot, bytes(32))
            with self.assertRaises(SessionTicketError) as caught:
                receiver.import_session_tickets(snapshot, bytes([1]) * 32)
            self.assertEqual(caught.exception.kind, "authentication")
            self.assertNotIn(str(snapshot), repr(caught.exception))

    def test_imported_tickets_resume_tls_without_consuming_source_or_cookies(self):
        trust = Trust(roots=(ROOT,))
        key = bytes([42]) * 32
        with (
            peer(tls=True) as server,
            Client(**OPTIONS, trust=trust) as source,
            Client(**OPTIONS, trust=trust) as receiver,
        ):
            source.cookies.set("https://example.com/", "id=source; Secure; Path=/")
            receiver.cookies.set("https://example.com/", "id=receiver; Secure; Path=/")
            with source.request("GET", server.url) as response:
                self.assertEqual(response.read(max_bytes=5), b"hello")
            source.refresh_connections()

            snapshot = source.export_session_tickets(key)
            receiver.import_session_tickets(snapshot, key)
            with self.assertRaises(SessionTicketError) as caught:
                receiver.import_session_tickets(snapshot, bytes(32))
            self.assertEqual(caught.exception.kind, "authentication")

            for client in (receiver, source):
                with client.request("GET", server.url) as response:
                    self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual([row[3] for row in server.requests], [False, True, True])
            self.assertEqual(
                source.cookies.for_url("https://example.com/"), "id=source"
            )
            self.assertEqual(
                receiver.cookies.for_url("https://example.com/"), "id=receiver"
            )


class AsyncStateTransferTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_transfers_work_on_async_clients_and_preserve_disabled_state(
        self,
    ):
        async with AsyncClient(
            **OPTIONS, network=NetworkOptions(max_alt_svc_origins=8)
        ) as source:
            await source.import_cookies(CookieSnapshot((cookie(),)))
            self.assertEqual((await source.export_cookies()).entries[0].name, "id")
            await source.import_alt_svc(AltSvcSnapshot())
            self.assertEqual(await source.export_alt_svc(), AltSvcSnapshot())
            snapshot = await source.export_session_tickets(bytes(32))
            await source.import_session_tickets(snapshot, bytes(32))
