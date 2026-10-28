"""Encrypted resolver configuration before native construction."""

import dataclasses
import math
import types
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE


class DnsSettingsTests(unittest.TestCase):
    def settings(self, transport, **changes):
        values = {"bootstrap": ("127.0.0.1",), "timeout": 2, "max_concurrent": 4}
        if transport is FACADE.DnsOverHttps:
            values["endpoint"] = "https://private.invalid/dns-query"
        else:
            values["server_name"] = "private.invalid"
            values["bootstrap"] = ("127.0.0.1:853",)
        values.update(changes)
        return transport(**values)

    def test_named_settings_preserve_wire_padding_and_cache_choices(self):
        for transport in (FACADE.DnsOverHttps, FACADE.DnsOverTls):
            settings = self.settings(transport)
            self.assertIs(settings.padding_block, FACADE.INHERIT)
            self.assertIsNone(
                self.settings(transport, padding_block=None).padding_block
            )
            self.assertEqual(
                self.settings(transport, padding_block=128).padding_block, 128
            )
            self.assertNotIn("private", repr(settings))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                settings.timeout = 1
        https = self.settings(FACADE.DnsOverHttps, wire="chromium154", query_id=42)
        self.assertEqual((https.wire, https.query_id), ("chromium154", 42))
        self.assertIs(FACADE.NetworkOptions(dns=https).dns_cache, FACADE.INHERIT)
        calls = []

        def native(*arguments, **keywords):
            calls.append(keywords)
            return types.SimpleNamespace(cookies=object())

        network = FACADE.NetworkOptions(dns=https, dns_cache=None)
        with patch.object(FACADE._native, "NativeClient", native, create=True):
            FACADE.AsyncClient(profile="exact", network=network)
        self.assertIs(calls[0]["network"], network)
        self.assertIsNone(network.dns_cache)

    def test_invalid_options_are_redacted_and_rechecked_before_construction(self):
        for transport in (FACADE.DnsOverHttps, FACADE.DnsOverTls):
            for changes in (
                {"timeout": 0},
                {"timeout": math.inf},
                {"timeout": True},
                {"max_concurrent": True},
                {"max_concurrent": 0},
                {"bootstrap": ()},
                {"bootstrap": ["private"]},
                {"bootstrap": ("private\ud800",)},
                {"roots": ("private",)},
                {"families": "private"},
                {"padding_block": 0},
                {"padding_block": True},
                {"padding_block": 65536},
                {"roots": (b"private" * 10000,)},
            ):
                with self.subTest(transport=transport, field=tuple(changes)):
                    with self.assertRaises((TypeError, ValueError)) as caught:
                        self.settings(transport, **changes)
                    self.assertNotIn("private", str(caught.exception))
        for changes in ({"query_id": True}, {"query_id": 65536}, {"wire": "other"}):
            with self.assertRaises((TypeError, ValueError)):
                self.settings(FACADE.DnsOverHttps, **changes)
        with self.assertRaises(ValueError):
            self.settings(FACADE.DnsOverTls, max_concurrent=32768)
        for changes in ({"dns": {}}, {"dns_cache": True}):
            with self.assertRaises(TypeError):
                FACADE.NetworkOptions(**changes)
        dns = self.settings(FACADE.DnsOverHttps)
        network = FACADE.NetworkOptions(dns=dns)
        object.__setattr__(dns, "max_concurrent", False)
        with patch.object(FACADE._native, "NativeClient", create=True) as native:
            with self.assertRaises(TypeError):
                FACADE.AsyncClient(profile="exact", network=network)
            native.assert_not_called()
