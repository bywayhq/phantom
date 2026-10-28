"""Strict profile documents and explicit template ownership through public clients."""

import dataclasses
import json
import types
import unittest
from unittest.mock import patch

import phantom_http
from phantom_http import AsyncClient, Client, Error, Profile, ProfileError
from test_client import PROFILE, server


def edited_profile(value="first"):
    document = Profile.from_catalog(PROFILE, context="fetch").describe()
    template = document["profile"]["request_template"]
    for protocol in ("http1_fields", "http2_fields", "http3_fields"):
        if template[protocol] is not None:
            template[protocol][:0] = [
                {"variant": "Literal", "name": "x-profile-first", "value": value},
                {"variant": "Literal", "name": "x-profile-second", "value": "second"},
            ]
    return Profile.import_json(json.dumps(document).encode())


class ProfileFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_owned_profile_is_immutable_and_forwarded_without_serialization(self):
        document = b'{"profile":{"request_template":null}}'
        native = types.SimpleNamespace(catalog_id=PROFILE, export_json=lambda: document)
        factory = types.SimpleNamespace(
            from_catalog=lambda *args: native, import_json=lambda value: native
        )
        received = []

        class NativeClient:
            cookies = object()

            def __init__(self, *arguments):
                received.append(arguments)

        with (
            patch.object(phantom_http._native, "NativeProfile", factory, create=True),
            patch.object(phantom_http._native, "NativeClient", NativeClient),
        ):
            profile = Profile.from_catalog(PROFILE, context="fetch")
            self.assertEqual(profile.catalog_id, PROFILE)
            self.assertEqual(profile.export_json(), document)
            first = profile.describe()
            first["profile"] = "edited"
            self.assertIsInstance(profile.describe()["profile"], dict)
            self.assertNotIn("request_template", repr(profile))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                profile._native = object()
            with self.assertRaises(TypeError):
                Profile()
            with self.assertRaises(TypeError):
                Profile.import_json("secret")
            AsyncClient(profile=profile, protocol="h1", context="profile")
            self.assertIs(received[0][0], native)
            self.assertEqual(received[0][2], "profile")

    async def test_document_errors_retain_only_kind_and_canonical_field(self):
        native_error = type("NativeProfileError", (Exception,), {})

        def reject(_):
            raise native_error("invalid_value", "request_template.fields.name")

        with (
            patch.object(
                phantom_http._native, "NativeProfileError", native_error, create=True
            ),
            patch.object(
                phantom_http._native,
                "NativeProfile",
                types.SimpleNamespace(import_json=reject),
                create=True,
            ),
            self.assertRaises(ProfileError) as caught,
        ):
            Profile.import_json(b"secret")
        self.assertEqual(caught.exception.kind, "invalid_value")
        self.assertEqual(caught.exception.field, "request_template.fields.name")
        self.assertNotIn("secret", str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)


class ProfileDocumentTests(unittest.TestCase):
    def test_catalog_and_import_round_trip_and_fresh_description(self):
        original = Profile.from_catalog(PROFILE, context="fetch")
        encoded = original.export_json()
        imported = Profile.import_json(encoded)
        self.assertEqual(original.catalog_id, PROFILE)
        self.assertIsNone(imported.catalog_id)
        self.assertEqual(imported.export_json(), encoded)
        changed = imported.describe()
        changed["profile"]["request_template"] = None
        self.assertIsNotNone(imported.describe()["profile"]["request_template"])
        without_template = Profile.from_catalog(PROFILE)
        self.assertIsNone(without_template.describe()["profile"]["request_template"])
        with self.assertRaises(Error) as caught:
            AsyncClient(profile=without_template, protocol="h1", context="profile")
        self.assertEqual(caught.exception.kind, "context_unavailable")

    def test_strict_errors_are_redacted_and_legacy_import_has_no_contexts(self):
        for document, kind, field in (
            (b'{"secret":', "malformed_json", "document"),
            (b'{"format":"secret","format":"other"}', "duplicate_field", "document"),
            (b" " * (16 * 1024 * 1024 + 1), "too_large", "document"),
        ):
            with self.subTest(kind=kind), self.assertRaises(ProfileError) as caught:
                Profile.import_json(document)
            self.assertEqual(
                (caught.exception.kind, caught.exception.field), (kind, field)
            )
            self.assertNotIn("secret", str(caught.exception))
        document = Profile.from_catalog(PROFILE).describe()
        document["secret"] = "secret"
        with self.assertRaises(ProfileError) as caught:
            Profile.import_json(json.dumps(document).encode())
        self.assertNotIn("secret", str(caught.exception))
        document = Profile.from_catalog(PROFILE, context="fetch").describe()
        document["profile"]["request_template"]["restarts_for_connection_accept_ch"] = (
            "secret"
        )
        with self.assertRaises(ProfileError) as caught:
            Profile.import_json(json.dumps(document).encode())
        self.assertEqual(caught.exception.kind, "invalid_value")
        self.assertEqual(
            caught.exception.field, "request_template.restarts_for_connection_accept_ch"
        )
        self.assertNotIn("secret", str(caught.exception))
        document = Profile.from_catalog(PROFILE).describe()
        document["version"] = 1
        del document["profile"]["request_contexts"]
        imported = Profile.import_json(json.dumps(document).encode())
        for context in ("navigation", "fetch"):
            with self.subTest(context=context), self.assertRaises(Error) as caught:
                AsyncClient(profile=imported, protocol="h1", context=context)
            self.assertEqual(caught.exception.kind, "context_unavailable")
        with self.assertRaises(Error) as caught:
            Profile.from_catalog("chrome/not-an-exact-build")
        self.assertEqual(caught.exception.kind, "unknown_profile")

    def test_sync_profile_template_order_raw_and_existing_client_ownership(self):
        original = edited_profile()
        with (
            server() as (peer, url),
            Client(profile=original, protocol="h1", context="profile") as selected,
            Client(profile=original, protocol="h1", context="raw") as raw,
        ):
            changed = edited_profile("changed")
            for client in (selected, raw):
                with client.request("GET", url) as r:
                    self.assertEqual(r.read(max_bytes=5), b"hello")
            with (
                Client(profile=changed, protocol="h1", context="profile") as newer,
                newer.request("GET", url) as r,
            ):
                self.assertEqual(r.read(max_bytes=5), b"hello")
        first = peer.requests[0][2]
        names = [name.lower() for name, _ in first]
        self.assertLess(names.index("x-profile-first"), names.index("x-profile-second"))
        self.assertEqual(dict(first)["x-profile-first"], "first")
        self.assertNotIn("x-profile-first", dict(peer.requests[1][2]))
        self.assertEqual(dict(peer.requests[2][2])["x-profile-first"], "changed")


class AsyncProfileTests(unittest.IsolatedAsyncioTestCase):
    async def test_imported_http2_template_order_and_reuse(self):
        from test_http2 import H2Peer

        profile = edited_profile()
        with H2Peer() as peer:
            async with AsyncClient(
                profile=profile, protocol="h2", context="profile", timeout_ms=5000
            ) as client:
                for path in ("/first", "/second", "/third"):
                    async with await client.request("GET", peer.url + path) as response:
                        self.assertEqual(response.protocol, "h2")
                        self.assertEqual(await response.read(max_bytes=5), b"hello")
        self.assertFalse(peer.premature_close)
        self.assertEqual(len(peer.headers), 3)
        for fields in peer.headers:
            self.assertEqual(
                [field for field in fields if field[0].startswith(b"x-profile-")],
                [(b"x-profile-first", b"first"), (b"x-profile-second", b"second")],
            )

    async def test_async_catalog_contexts_and_imported_attached_template(self):
        catalog = Profile.from_catalog(PROFILE, context="fetch")
        imported = Profile.import_json(catalog.export_json())
        with server() as (peer, url):
            for profile, context in (
                (catalog, "navigation"),
                (catalog, "fetch"),
                (imported, "profile"),
                (imported, None),
            ):
                async with (
                    AsyncClient(profile=profile, protocol="h1", context=context) as c,
                    await c.request("GET", url) as r,
                ):
                    self.assertEqual(await r.read(max_bytes=5), b"hello")
        modes = [
            {name.lower(): value for name, value in request[2]}.get("sec-fetch-mode")
            for request in peer.requests
        ]
        self.assertEqual(modes, ["navigate", "cors", "cors", None])
