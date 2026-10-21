"""Pin validation and forwarding without loading the native extension."""

import dataclasses
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE


class PinSettingsTests(unittest.TestCase):
    def test_optional_policies_are_immutable_and_never_display_digests(self):
        digest = b"private" + bytes(25)
        self.assertEqual(len(digest), 32)
        for field in ("server_spki_pins", "proxy_server_spki_pins"):
            with self.subTest(field=field):
                trust = FACADE.Trust(**{field: (digest, digest)})
                self.assertEqual(getattr(trust, field), (digest, digest))
                self.assertNotIn("private", repr(trust))
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(trust, field, None)
                for value in ([], b"private", ("private",), (bytearray(32),)):
                    with self.assertRaises(TypeError) as caught:
                        FACADE.Trust(**{field: value})
                    self.assertIn(field, str(caught.exception))
                    self.assertNotIn("private", str(caught.exception))
                for value in ((), (b"short",), (bytes(33),), (digest,) * 33):
                    with self.assertRaises(ValueError) as caught:
                        FACADE.Trust(**{field: value})
                    self.assertIn(field, str(caught.exception))
                    self.assertNotIn("private", str(caught.exception))
                self.assertEqual(
                    len(getattr(FACADE.Trust(**{field: (digest,) * 32}), field)), 32
                )
        self.assertIsNone(FACADE.Trust().server_spki_pins)
        self.assertIsNone(FACADE.Trust().proxy_server_spki_pins)

    def test_sync_and_async_forward_only_configured_pin_policies(self):
        calls = []

        class Native:
            cookies = object()

            def __init__(self, *args, **kwargs):
                calls.append((args, kwargs))

            async def shutdown(self, _):
                pass

        with patch.object(FACADE._native, "NativeClient", Native, create=True):
            for owner in (FACADE.AsyncClient, FACADE.Client):
                for trust, expected in (
                    (None, {}),
                    (
                        FACADE.Trust(server_spki_pins=(bytes(32),)),
                        {"server_spki_pins": (bytes(32),)},
                    ),
                    (
                        FACADE.Trust(proxy_server_spki_pins=(bytes([1]) * 32,)),
                        {"proxy_server_spki_pins": (bytes([1]) * 32,)},
                    ),
                    (
                        FACADE.Trust(
                            server_spki_pins=(bytes(32),),
                            proxy_server_spki_pins=(bytes(32),),
                        ),
                        {
                            "server_spki_pins": (bytes(32),),
                            "proxy_server_spki_pins": (bytes(32),),
                        },
                    ),
                ):
                    client = owner(profile="exact", protocol="h1", trust=trust)
                    self.assertEqual(calls[-1][1], expected)
                    self.assertEqual(len(calls[-1][0]), 14)
                    if isinstance(client, FACADE.Client):
                        client.close()
