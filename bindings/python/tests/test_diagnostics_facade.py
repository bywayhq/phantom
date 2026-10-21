"""Validation and typed immutable snapshots without loading the extension."""

import dataclasses
import sys
import types
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE


class NativeObserver:
    def __init__(self, capacity):
        self.capacity = capacity
        self.value = None

    def snapshot(self):
        return self.value


class DiagnosticsValueTests(unittest.TestCase):
    def test_exact_capacity_and_native_identity(self):
        class IntSubclass(int):
            pass

        with patch.object(
            FACADE._native, "NativeRequestDiagnostics", NativeObserver, create=True
        ):
            for value in (False, True, 1.5, "private", IntSubclass(1)):
                with self.assertRaisesRegex(TypeError, "maximum_events"):
                    FACADE.RequestDiagnostics(value)
            for value in (0, -1, 2 * sys.maxsize + 2):
                with self.assertRaisesRegex(ValueError, "maximum_events"):
                    FACADE.RequestDiagnostics(value)
            first = FACADE.RequestDiagnostics(2 * sys.maxsize + 1)
            second = FACADE.RequestDiagnostics()
            self.assertIsNone(first.snapshot())
            self.assertEqual(first._native.capacity, 2 * sys.maxsize + 1)
            self.assertEqual(second._native.capacity, 128)
            self.assertNotEqual(first, second)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                first.maximum_events = 1

    def test_nested_snapshot_is_detached_exact_and_certificate_repr_is_redacted(self):
        with patch.object(
            FACADE._native, "NativeRequestDiagnostics", NativeObserver, create=True
        ):
            observer = FACADE.RequestDiagnostics()
            certificates = [b"private-certificate"]
            connection = (
                False,
                "quic_endpoint",
                "[::]:12",
                "[::1]:34",
                ("established", (True, 0x0304, 0x1301, b"h3", False, certificates)),
                ("unavailable", None),
            )
            events = [
                (
                    7,
                    2,
                    None,
                    "h3",
                    "connection_use",
                    2**100,
                    None,
                    "pending",
                    connection,
                )
            ]
            observer._native.value = ("not_started", None, events, 3, 5)
            snapshot = observer.snapshot()
            self.assertEqual(snapshot.outcome, "not_started")
            self.assertIsNone(snapshot.send_elapsed_ns)
            self.assertEqual(snapshot.events[0].started_ns, 2**100)
            self.assertIsNone(snapshot.events[0].finished_ns)
            self.assertIsNone(snapshot.events[0].admission)
            info = snapshot.events[0].connection.origin_tls.info
            self.assertEqual(info.peer_certificates_der, (b"private-certificate",))
            self.assertNotIn("private-certificate", repr(snapshot))
            certificates.clear()
            events.clear()
            self.assertEqual(len(snapshot.events), 1)
            self.assertEqual(info.peer_certificates_der, (b"private-certificate",))
            for record, name in (
                (snapshot, "outcome"),
                (snapshot.events[0], "hop"),
                (info, "version_id"),
            ):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(record, name, None)


class DiagnosticsForwardingTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_request_keeps_owner_and_default_does_not_add_keyword(self):
        calls = []

        class NativeClient:
            cookies = object()

            async def request(self, *arguments, **options):
                calls.append(options)
                return types.SimpleNamespace(status=200, protocol="h1", headers=[])

        with patch.object(
            FACADE._native, "NativeRequestDiagnostics", NativeObserver, create=True
        ):
            observer = FACADE.RequestDiagnostics()
            client = FACADE.AsyncClient._from_native(NativeClient())
            await client.request("GET", "http://origin.invalid")
            self.assertNotIn("diagnostics", calls[-1])
            for options in (
                {},
                {"trailers": [("x-final", b"value")]},
                {"expect_continue_ms": 0},
            ):
                await client.request(
                    "GET", "http://origin.invalid", diagnostics=observer, **options
                )
                self.assertIs(calls[-1]["diagnostics"], observer._native)
            with self.assertRaisesRegex(TypeError, "diagnostics"):
                await client.request("GET", "http://origin.invalid", diagnostics={})
            self.assertEqual(len(calls), 4)

    async def test_sync_request_passes_the_same_observer(self):
        import asyncio

        calls = []

        class Async:
            cookies = object()
            _uploads = ()

            def __init__(self, **_):
                pass

            async def request(self, *_, **options):
                calls.append(options)
                return types.SimpleNamespace(status=200, protocol="h1", headers=[])

            async def close(self, **_):
                pass

        with patch.object(
            FACADE._native, "NativeRequestDiagnostics", NativeObserver, create=True
        ):
            observer = FACADE.RequestDiagnostics()

            def call():
                with (
                    patch.object(FACADE, "AsyncClient", Async),
                    FACADE.Client(profile="exact", protocol="h1") as client,
                ):
                    client.request("GET", "/", diagnostics=observer)

            await asyncio.to_thread(call)
            self.assertIs(calls[0]["diagnostics"], observer)
