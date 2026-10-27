"""Request-field ownership and validation without loading the extension."""

import unittest

from test_upload_errors import FACADE, NativeResponse


class RequestFieldTests(unittest.IsolatedAsyncioTestCase):
    async def test_order_duplicates_sensitivity_and_expect_continue_defaults(self):
        calls = []

        class NativeClient:
            cookies = object()

            async def request(
                self,
                *arguments,
                producer=None,
                transfer_control=None,
                trailers=None,
                expect_continue_ms=None,
            ):
                calls.append(
                    (
                        arguments,
                        {
                            "producer": producer,
                            "transfer_control": transfer_control,
                            "trailers": trailers,
                            "expect_continue_ms": expect_continue_ms,
                        },
                    )
                )
                return NativeResponse()

        client = FACADE.AsyncClient._from_native(NativeClient())
        await client.request("POST", "http://origin.invalid", body=b"data")
        self.assertEqual(calls[-1][0][3], b"data")
        self.assertEqual(
            calls[-1][1],
            {
                "producer": None,
                "transfer_control": None,
                "trailers": None,
                "expect_continue_ms": None,
            },
        )
        await client.request(
            "POST",
            "http://origin.invalid",
            headers=(("X-First", "head"),),
            trailers=(
                FACADE.Header("X-Repeat", b"one", sensitive=True),
                ("x-repeat", "two"),
            ),
            expect_continue_ms=0,
        )
        self.assertEqual(calls[-1][0][2], [("X-First", b"head", False)])
        self.assertEqual(
            calls[-1][1],
            {
                "producer": None,
                "transfer_control": None,
                "trailers": [("X-Repeat", b"one", True), ("x-repeat", b"two", False)],
                "expect_continue_ms": 0,
            },
        )
        await client.request("POST", "http://origin.invalid", trailers=())
        self.assertIsNone(calls[-1][1]["trailers"])
        self.assertIsNone(calls[-1][1]["expect_continue_ms"])
        await client.request("POST", "http://origin.invalid", expect_continue_ms=None)
        self.assertIsNone(calls[-1][1]["expect_continue_ms"])

    async def test_validation_stops_before_native_submission(self):
        class NativeClient:
            cookies = object()

            def request(self, *_, **__):
                self.fail = True
                raise AssertionError("unexpected submission")

        client = FACADE.AsyncClient._from_native(NativeClient())
        for value, exception in (
            (True, TypeError),
            (-1, ValueError),
            (0.5, TypeError),
            (2**64, ValueError),
        ):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(exception, "expect_continue_ms"),
            ):
                await client.request(
                    "POST", "http://origin.invalid", expect_continue_ms=value
                )
        for fields in (
            {"headers": [("X", b"a")] * 256, "trailers": [("Y", b"b")]},
            {"headers": [("X", b"a" * 65535)], "trailers": [("Y", b"b")]},
            {"trailers": [("\u00e9" * 32769, b"")]},
        ):
            with (
                self.subTest(fields=tuple(fields)),
                self.assertRaisesRegex(ValueError, "headers and trailers exceed"),
            ):
                await client.request("POST", "http://origin.invalid", **fields)

    def test_exact_aggregate_boundary_and_bounded_iterable_consumption(self):
        self.assertEqual(
            FACADE._request_fields((("X", b"a" * 65535),), ())[0][0][0], "X"
        )
        pulled = []

        def fields():
            for index in range(1000):
                pulled.append(index)
                yield ("X", b"")

        with self.assertRaises(ValueError):
            FACADE._request_fields((), fields())
        self.assertEqual(len(pulled), 257)
