"""Independent peers exercise observer lifetime separately from body ownership."""

import asyncio
import dataclasses
import socket
import sys
import unittest

from phantom_http import AsyncClient, Client, Error, RequestDiagnostics, Trust
from test_client import OPTIONS
from test_settings_transport import ROOT, peer


def body_event(diagnostics):
    timeline = diagnostics.snapshot()
    if timeline is None:
        raise AssertionError("observer was not attached")
    return next(event for event in timeline.events if event.phase == "response_body")


class DiagnosticsTests(unittest.TestCase):
    def test_complete_snapshot_connection_reuse_and_observer_outlives_client(self):
        first, second = RequestDiagnostics(), RequestDiagnostics()
        self.assertIsNone(first.snapshot())
        with peer() as origin, Client(**OPTIONS) as client:
            with self.assertRaises(Error) as invalid:
                client.request("bad method", origin.url, diagnostics=first)
            self.assertEqual(invalid.exception.kind, "invalid_method")
            self.assertIsNone(first.snapshot())
            for observer in (first, second):
                with client.request(
                    "GET", origin.url, diagnostics=observer
                ) as response:
                    self.assertEqual(response.read(max_bytes=5), b"hello")
            with self.assertRaises(Error) as caught:
                client.request("GET", origin.url, diagnostics=first)
            self.assertEqual(caught.exception.kind, "diagnostics_already_attached")
            self.assertEqual(len(origin.requests), 2)
        for observer, reused in ((first, False), (second, True)):
            timeline = observer.snapshot()
            self.assertEqual(timeline.outcome, "response_head")
            self.assertEqual(timeline.admitted_attempts, 1)
            self.assertEqual(
                [event.id for event in timeline.events],
                sorted(event.id for event in timeline.events),
            )
            connection = next(
                event.connection
                for event in timeline.events
                if event.phase == "connection_use"
            )
            self.assertEqual(connection.reused, reused)
            self.assertEqual(connection.endpoint_scope, "tcp_socket")
            self.assertTrue(connection.local_address.startswith("127.0.0.1:"))
            self.assertEqual(connection.origin_tls.state, "not_used")
            self.assertIsNone(connection.proxy_tls.info)
            self.assertFalse(
                any(event.phase == "tls_handshake" for event in timeline.events)
            )
            self.assertEqual(body_event(observer).outcome, "completed")
            with self.assertRaises(dataclasses.FrozenInstanceError):
                timeline.admitted_attempts = 0

    def test_failed_send_retains_admissions_and_capacity_one_drops_events(self):
        observer = RequestDiagnostics(1)
        with socket.socket() as refusal:
            refusal.bind(("127.0.0.1", 0))
            port = refusal.getsockname()[1]
            # XNU drops SYNs to a bound, non-listening socket instead of refusing.
            if sys.platform == "darwin":
                refusal.close()
            with Client(**OPTIONS) as client, self.assertRaises(Error) as caught:
                client.request(
                    "GET",
                    f"http://127.0.0.1:{port}",
                    diagnostics=observer,
                )
            self.assertEqual(caught.exception.kind, "connect")
        timeline = observer.snapshot()
        self.assertEqual(timeline.outcome, "failed")
        self.assertEqual(timeline.admitted_attempts, 1)
        self.assertEqual(len(timeline.events), 1)
        self.assertGreater(timeline.dropped_events, 0)
        self.assertIsInstance(timeline.send_elapsed_ns, int)

    def test_tls_snapshot_preserves_leaf_der_and_verification(self):
        observer = RequestDiagnostics()
        with (
            peer(tls=True) as origin,
            Client(**OPTIONS, trust=Trust(roots=(ROOT,))) as client,
            client.request("GET", origin.url, diagnostics=observer) as response,
        ):
            self.assertEqual(response.read(max_bytes=5), b"hello")
        timeline = observer.snapshot()
        connection = next(
            event.connection
            for event in timeline.events
            if event.phase == "connection_use"
        )
        self.assertEqual(connection.origin_tls.state, "established")
        info = connection.origin_tls.info
        self.assertTrue(info.peer_verified)
        self.assertIn(info.version_id, (0x0303, 0x0304))
        self.assertIsInstance(info.cipher_suite_id, int)
        self.assertEqual(info.peer_certificates_der[0], ROOT)
        self.assertNotIn(repr(ROOT), repr(info))


class AsyncDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def test_head_is_not_body_completion_and_abandon_is_retained(self):
        for complete in (False, True):
            with self.subTest(complete=complete), peer() as origin:
                async with AsyncClient(**OPTIONS) as client:
                    observer = RequestDiagnostics()
                    response = await client.request(
                        "GET", origin.url + "/live", diagnostics=observer
                    )
                    self.assertTrue(await asyncio.to_thread(origin.entered.wait, 5))
                    head = observer.snapshot()
                    self.assertEqual(head.outcome, "response_head")
                    self.assertEqual(body_event(observer).outcome, "pending")
                    if complete:
                        origin.release.set()
                        self.assertEqual(await response.read(max_bytes=2), b"ab")
                    else:
                        await response.aclose()
                    self.assertEqual(
                        body_event(observer).outcome,
                        "completed" if complete else "abandoned",
                    )
                    self.assertEqual(
                        observer.snapshot().send_elapsed_ns, head.send_elapsed_ns
                    )

    async def test_single_attachment_races_and_cancelled_send_remain_visible(self):
        with peer() as origin:
            async with AsyncClient(**OPTIONS) as client:
                observer = RequestDiagnostics()
                pending = asyncio.create_task(
                    client.request("GET", origin.url + "/head", diagnostics=observer)
                )
                try:
                    self.assertTrue(await asyncio.to_thread(origin.entered.wait, 5))
                    self.assertEqual(observer.snapshot().outcome, "pending")
                    with self.assertRaises(Error) as caught:
                        await client.request("GET", origin.url, diagnostics=observer)
                    self.assertEqual(
                        caught.exception.kind, "diagnostics_already_attached"
                    )
                    pending.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await pending

                    await client.close()
                    self.assertEqual(observer.snapshot().outcome, "cancelled")
                finally:
                    origin.release.set()
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
