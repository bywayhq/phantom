"""Configuration validation and exact facade-to-native mapping."""

import dataclasses
import math
import types
import unittest
from unittest.mock import patch

import phantom_http
from phantom_http import (
    INHERIT,
    AsyncClient,
    Header,
    Proxy,
    TimeoutOverrides,
    Timeouts,
    Trust,
)


class SettingsTests(unittest.TestCase):
    def test_timeout_states_remain_distinct_and_immutable(self):
        self.assertEqual(TimeoutOverrides()._native_fields(), [])
        self.assertEqual(
            TimeoutOverrides(connect=INHERIT, total=None, read_idle=0)._native_fields(),
            [("read_idle", 0.0), ("total", None)],
        )
        self.assertEqual(Timeouts(total=0)._native_fields()[-1], ("total", 0.0))
        self.assertEqual(
            Timeouts()._native_fields(),
            [
                ("pool_admission", None),
                ("connect", None),
                ("response_head", None),
                ("read_idle", None),
                ("total", None),
            ],
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            Timeouts().total = 5

    def test_invalid_settings_fail_without_exposing_values(self):
        for value in (-1, math.inf, -math.inf, math.nan, 10**1000):
            for settings in (Timeouts, TimeoutOverrides):
                with (
                    self.subTest(value=type(value), settings=settings),
                    self.assertRaises(ValueError),
                ):
                    settings(total=value)
        for value in (True, "secret", object()):
            with self.assertRaises(TypeError):
                Timeouts(total=value)
        for arguments in ({"username": "secret"}, {"password": "secret"}):
            with self.assertRaisesRegex(ValueError, "together"):
                Proxy("http://proxy.invalid", **arguments)
        with self.assertRaises(TypeError):
            Trust(roots=[b"DER"])
        with self.assertRaises(TypeError):
            Trust(proxy_roots=("secret",))
        with self.assertRaises(TypeError):
            Header("X-Secret", "secret", sensitive=1)
        for value in (
            Proxy("http://secret.invalid", "secret", "secret"),
            Trust(roots=(b"secret",)),
            Header("X-Secret", "secret", True),
        ):
            self.assertNotIn("secret", repr(value))


class FacadeMappingTests(unittest.IsolatedAsyncioTestCase):
    async def test_typed_configuration_headers_and_lifecycle_are_forwarded(self):
        construction = []
        requests = []
        calls = []

        class FakeNative:
            cookies = object()
            is_closed = False

            def __init__(self, *arguments):
                construction.append(arguments)

            async def request(self, *arguments):
                requests.append(arguments)
                return types.SimpleNamespace(status=200, protocol="h2", headers=[])

            async def close_idle_connections(self):
                calls.append("idle")

            async def refresh_connections(self):
                calls.append("refresh")

            def clear_session_tickets(self):
                calls.append("tickets")
                return 3

            def clear_dns_cache(self):
                calls.append("dns")

            def clear_client_hints(self):
                calls.append("hints")

            def clear_alt_svc(self):
                calls.append("alt-svc")

            def clear_alt_svc_racing_history(self):
                calls.append("races")

        with patch.object(phantom_http._native, "NativeClient", FakeNative):
            client = AsyncClient(
                profile="exact",
                protocol="h2",
                base_url="https://origin.invalid/api/",
                proxy=Proxy("https://proxy.invalid", "user", "password"),
                trust=Trust(roots=(b"origin",), proxy_roots=(b"proxy",)),
                timeouts=Timeouts(connect=1, response_head=2, total=0),
            )
            self.assertEqual(
                construction,
                [
                    (
                        "exact",
                        "h2",
                        None,
                        "https://proxy.invalid",
                        True,
                        None,
                        "https://origin.invalid/api/",
                        [b"origin"],
                        [b"proxy"],
                        "user",
                        "password",
                        Timeouts(connect=1, response_head=2, total=0)._native_fields(),
                    )
                ],
            )
            await client.request(
                "GET",
                "child",
                headers=iter(
                    [
                        ("X-First", "one"),
                        Header("X-Secret", b"two", True),
                        ("X-First", b"three"),
                    ]
                ),
                timeouts=TimeoutOverrides(connect=None, read_idle=0),
            )
            self.assertEqual(
                requests,
                [
                    (
                        "GET",
                        "child",
                        [
                            ("X-First", b"one", False),
                            ("X-Secret", b"two", True),
                            ("X-First", b"three", False),
                        ],
                        None,
                        None,
                        None,
                        None,
                        [("connect", None), ("read_idle", 0.0)],
                        None,
                    )
                ],
            )
            await client.close_idle_connections()
            await client.refresh_connections()
            self.assertEqual(client.clear_session_tickets(), 3)
            client.clear_dns_cache()
            client.clear_client_hints()
            client.clear_alt_svc()
            client.clear_alt_svc_racing_history()
        self.assertEqual(
            calls, ["idle", "refresh", "tickets", "dns", "hints", "alt-svc", "races"]
        )

    async def test_timeout_conflicts_fail_before_native_construction_or_request(self):
        with patch.object(phantom_http._native, "NativeClient") as native:
            with self.assertRaises(ValueError):
                AsyncClient(
                    profile="exact", protocol="h1", timeout_ms=1, timeouts=Timeouts()
                )
            native.assert_not_called()
            client = AsyncClient(profile="exact", protocol="h1")
            with self.assertRaises(ValueError):
                await client.request(
                    "GET",
                    "https://origin.invalid",
                    timeout_ms=1,
                    timeouts=TimeoutOverrides(),
                )
            native.return_value.request.assert_not_called()
