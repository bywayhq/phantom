"""Prepared-owner forwarding controls without loading a native extension."""

import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from test_upload_errors import FACADE, NativeResponse


class NativeBody:
    content_type = "application/x-test"
    length = 7

    def to_bytes(self):
        return b"payload"


class PreparedFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_owner_is_reused_without_export_or_a_producer(self):
        calls = []

        class NativeClient:
            cookies = object()

            async def request(self, *arguments, **options):
                calls.append((arguments, options))
                return NativeResponse()

        native = NativeBody()
        prepared = FACADE.PreparedBody._wrap(native)
        self.assertEqual(prepared.content_type, "application/x-test")
        self.assertEqual(prepared.to_bytes(), b"payload")
        with self.assertRaises(FrozenInstanceError):
            prepared._native = NativeBody()
        with patch.object(native, "to_bytes", side_effect=AssertionError("copy")):
            for _ in range(2):
                client = FACADE.AsyncClient._from_native(NativeClient())
                await client.request("POST", "http://origin.invalid", body=prepared)
            await client.request(
                "POST", "http://origin.invalid", body=prepared, body_length=7
            )
        self.assertTrue(all(call[0][3] is None for call in calls))
        self.assertTrue(all(call[1]["prepared_body"] is native for call in calls))
        self.assertTrue(all("producer" not in call[1] for call in calls))
        self.assertEqual(calls[-1][1]["body_length"], 7)
        before = len(calls)
        for length in (True, -1, 0, 8, 7.0):
            with self.subTest(length=length), self.assertRaises(ValueError):
                await client.request(
                    "POST", "http://origin.invalid", body=prepared, body_length=length
                )
        with self.assertRaises(ValueError):
            await client.request(
                "POST", "http://origin.invalid", body=prepared, upload="unused"
            )
        self.assertEqual(len(calls), before)

    def test_ordered_metadata_is_copied_to_a_native_owner_once(self):
        calls = []

        class Constructor:
            @staticmethod
            def form(*arguments):
                calls.append(arguments)
                return NativeBody()

            multipart = form

        with patch.object(
            FACADE._native, "NativePreparedBody", Constructor, create=True
        ):
            FACADE.PreparedBody.form((("tag", "one"), ("tag", "two")), maximum_bytes=99)
            part = FACADE.MultipartPart("tag", b"secret", filename="private.bin")
            self.assertNotIn("secret", repr(part))
            self.assertNotIn("private", repr(part))
            with self.assertRaises(FrozenInstanceError):
                part.value = b"changed"
            FACADE.PreparedBody.multipart(
                [part], boundary="explicit", maximum_bytes=999
            )
        self.assertEqual(
            calls,
            [
                ([("tag", "one"), ("tag", "two")], 99),
                ("explicit", [("tag", b"secret", "private.bin", None)], 999),
            ],
        )

    def test_validation_is_bounded_and_core_error_kinds_remain_redacted(self):
        for maximum in (True, -1, 0.5, 2**100):
            with (
                self.subTest(maximum=maximum),
                self.assertRaises((TypeError, ValueError)),
            ):
                FACADE.PreparedBody.form([], maximum_bytes=maximum)
        pulled = []

        def parts():
            for index in range(2000):
                pulled.append(index)
                yield FACADE.MultipartPart("tag", b"data")

        with self.assertRaises(FACADE.PreparedBodyError) as failed:
            FACADE.PreparedBody.multipart(parts(), boundary="B", maximum_bytes=10**6)
        self.assertEqual(failed.exception.kind, "too_many_parts")
        self.assertEqual(len(pulled), 1025)
        with self.assertRaises(TypeError):
            FACADE.MultipartPart("tag", iter([b"data"]))
        with self.assertRaises(TypeError):
            FACADE.PreparedBody()

        class Constructor:
            @staticmethod
            def form(*_):
                raise FACADE._native.NativeError(
                    "prepared_body", "too_large", None, None
                )

        with (
            patch.object(
                FACADE._native, "NativePreparedBody", Constructor, create=True
            ),
            self.assertRaises(FACADE.PreparedBodyError) as failed,
        ):
            FACADE.PreparedBody.form([("private", "secret")], maximum_bytes=4)
        self.assertEqual(failed.exception.category, "prepared_body")
        self.assertEqual(failed.exception.kind, "too_large")
        self.assertNotIn("private", repr(failed.exception))
        self.assertNotIn("secret", str(failed.exception))
