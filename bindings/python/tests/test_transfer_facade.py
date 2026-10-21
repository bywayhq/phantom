"""Transfer validation and request ownership without loading the extension."""

import asyncio
import dataclasses
import types
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE


class NativeControl:
    def __init__(self, *limits):
        self.limits = limits

    def snapshot(self):
        return (2**64 - 1, 2**63 + 1, 3, 4, 5)


class TransferValueTests(unittest.TestCase):
    def test_exact_ranges_field_errors_and_immutable_values(self):
        fields = (
            "upload_bytes",
            "download_bytes",
            "upload_bytes_per_second",
            "download_bytes_per_second",
        )
        for name in fields:
            for value in (False, True, 0.5, "private", object()):
                with self.subTest(name=name), self.assertRaisesRegex(TypeError, name):
                    FACADE.TransferLimits(**{name: value})
            for value in (-1, 2**64):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, name):
                    FACADE.TransferLimits(**{name: value})
            self.assertEqual(
                getattr(FACADE.TransferLimits(**{name: 2**64 - 1}), name),
                2**64 - 1,
            )
            if name.endswith("per_second"):
                with self.assertRaisesRegex(ValueError, name):
                    FACADE.TransferLimits(**{name: 0})
            else:
                self.assertEqual(getattr(FACADE.TransferLimits(**{name: 0}), name), 0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            FACADE.TransferLimits().download_bytes = 1
        with self.assertRaises(TypeError):
            FACADE.TransferControl(limits={})

    def test_owner_identity_and_snapshot_preserve_exact_native_values(self):
        with patch.object(
            FACADE._native, "NativeTransferControl", NativeControl, create=True
        ):
            limits = FACADE.TransferLimits(upload_bytes=0, download_bytes=2**64 - 1)
            control = FACADE.TransferControl(limits=limits)
            independent = FACADE.TransferControl(limits=limits)
            self.assertNotEqual(control, independent)
            self.assertEqual(len({control, independent, control}), 2)
            self.assertEqual(control._native.limits, (0, 2**64 - 1, None, None))
            snapshot = control.snapshot()
            self.assertEqual(
                snapshot, FACADE.TransferSnapshot(2**64 - 1, 2**63 + 1, 3, 4, 5)
            )
            with self.assertRaises(dataclasses.FrozenInstanceError):
                snapshot.download_decoded_bytes = 0
            with self.assertRaises(dataclasses.FrozenInstanceError):
                control.limits = FACADE.TransferLimits()


class TransferMappingTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_native_owner_is_forwarded_and_typed_error_closes_body(self):
        calls = []

        class NativeResponse:
            status = 200
            headers = []
            protocol = "h2"
            closed = False

            async def read(self, _):
                raise FACADE._native.NativeError("request", "transfer", "h2", None)

            def close(self):
                self.closed = True

        class NativeClient:
            cookies = object()

            async def request(self, *arguments, **options):
                calls.append((arguments, options))
                return NativeResponse()

        with patch.object(
            FACADE._native, "NativeTransferControl", NativeControl, create=True
        ):
            control = FACADE.TransferControl()
            first = FACADE.AsyncClient._from_native(NativeClient())
            second = FACADE.AsyncClient._from_native(NativeClient())
            for client in (first, second):
                response = await client.request(
                    "GET", "http://origin.invalid", transfer_control=control
                )
                self.assertIs(calls[-1][1]["transfer_control"], control._native)
                with self.assertRaises(FACADE.Error) as caught:
                    await response.read(max_bytes=100)
                self.assertEqual(caught.exception.kind, "transfer")
                self.assertEqual(caught.exception.protocol, "h2")
                self.assertTrue(response._native.closed)
                self.assertEqual(str(caught.exception), "request: transfer")
            with self.assertRaises(TypeError):
                await first.request("GET", "http://origin.invalid", transfer_control={})
            self.assertEqual(len(calls), 2)

    async def test_sync_forwarding_preserves_control_without_reconstructing_it(self):
        control = object()
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

        # The sync client must run outside this test's active loop.
        def call():
            with (
                patch.object(FACADE, "AsyncClient", Async),
                FACADE.Client(profile="exact", protocol="h1") as client,
            ):
                client.request("GET", "http://origin.invalid", transfer_control=control)

        await asyncio.to_thread(call)
        self.assertIs(calls[0]["transfer_control"], control)
