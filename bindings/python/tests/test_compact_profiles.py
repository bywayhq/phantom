"""Compact observations supplement an explicit profile without catalog identity."""

import dataclasses
import types
import unittest
from unittest.mock import patch

import phantom_http
from phantom_http import (
    AsyncClient,
    Client,
    Error,
    ImportedProfile,
    Profile,
    ProfileError,
)
from test_client import PROFILE, server

# Independent retained Chrome154 Windows ClientHello fields, normalized for GREASE:
# fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt.
CIPHERS = "1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035"
EXTENSIONS = "001b,002d,000b,000a,0005,ca34,000d,0000,44cd,0012,0023,fe0d,0010,0033,0017,002b,ff01"
SIGNATURES = "0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
GROUPS = "11ec,001d,0017,0018"

# Supported parameter subsequence in retained wire order and original widths:
# fixtures/http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-1.txt,
# extension57. VersionInformation, Google options and GREASE are deliberately
# excluded: the compact importer rejects those, rather than guessing policies.
QUIC = bytes.fromhex(
    "08024064 070480600000 040480f00000 09024067 060480600000"
    "010480007530 200480010000 030245c0 050480600000 0f00"
)
AKAMAI = "6:131072;4:16777216;2:0;1:65536|16711681|0|m,p,a,s"


def ja3(ciphers=CIPHERS):
    def decimal(values):
        return "-".join(str(int(value, 16)) for value in values.split(","))

    return f"771,{decimal(ciphers)},{decimal(EXTENSIONS)},{decimal(GROUPS)},0"


def ja4(*, sorted_input=False, ciphers=CIPHERS):
    extensions = EXTENSIONS.split(",")
    if sorted_input:
        ciphers = ",".join(sorted(ciphers.split(",")))
        extensions = sorted(
            value for value in extensions if value not in ("0000", "0010")
        )
    return f"t13d1517h2_{ciphers}_{','.join(extensions)}_{SIGNATURES}"


class CompactFacadeTests(unittest.TestCase):
    def test_imports_forward_exact_input_base_and_fresh_immutable_report(self):
        base_native = types.SimpleNamespace(catalog_id=PROFILE)
        imported_native = types.SimpleNamespace(catalog_id=None)
        base = Profile._wrap(base_native)
        observed = ["tls.cipher_suites", "tls.groups"]
        supplemented = ["http2", "tls.ech"]
        calls = []

        def imported(*arguments):
            calls.append(arguments)
            return imported_native, observed, supplemented

        factory = types.SimpleNamespace(
            **dict.fromkeys(
                (
                    "import_ja3",
                    "import_client_hello",
                    "import_akamai",
                    "import_ja4",
                    "import_quic_transport",
                ),
                imported,
            )
        )
        with patch.object(phantom_http._native, "NativeProfile", factory):
            for method, value, options in (
                (Profile.import_ja3, "raw JA3", {}),
                (Profile.import_client_hello, b"handshake", {}),
                (Profile.import_akamai, "raw Akamai", {}),
                (Profile.import_ja4, "raw JA4", {"format": "sorted"}),
                (Profile.import_quic_transport, b"parameters", {}),
            ):
                with self.subTest(method=method.__name__):
                    result = method(value, base=base, **options)
                    self.assertIsInstance(result, ImportedProfile)
                    self.assertIsNone(result.profile.catalog_id)
                    self.assertIs(result.profile._native, imported_native)
                    self.assertEqual(result.observed_fields, tuple(observed))
                    self.assertEqual(result.supplemented_fields, tuple(supplemented))
                    self.assertIs(calls[-1][-1], base_native)
                    self.assertIs(calls[-1][0], value)
                    with self.assertRaises(dataclasses.FrozenInstanceError):
                        result.profile = base
            self.assertEqual(calls[3], ("raw JA4", "sorted", base_native))
        observed.append("changed")
        supplemented.clear()
        self.assertEqual(result.observed_fields, ("tls.cipher_suites", "tls.groups"))
        self.assertEqual(result.supplemented_fields, ("http2", "tls.ech"))

    def test_base_and_input_types_are_explicit_and_errors_are_redacted(self):
        base = Profile._wrap(types.SimpleNamespace(catalog_id=None))
        for method, value in (
            (Profile.import_ja3, b"secret"),
            (Profile.import_akamai, b"secret"),
            (Profile.import_client_hello, bytearray(b"secret")),
            (Profile.import_quic_transport, "secret"),
        ):
            with self.subTest(method=method.__name__), self.assertRaises(TypeError):
                method(value, base=base)
        with self.assertRaises(TypeError):
            Profile.import_ja3("secret", base=PROFILE)
        with self.assertRaises(TypeError):
            Profile.import_ja3("secret")
        with self.assertRaises(TypeError):
            Profile.import_ja4("secret", base=base)

        def reject(*_):
            raise phantom_http._native.NativeProfileError("lossy_description", "ja4")

        with (
            patch.object(
                phantom_http._native,
                "NativeProfile",
                types.SimpleNamespace(import_ja4=reject),
            ),
            self.assertRaises(ProfileError) as caught,
        ):
            Profile.import_ja4("secret", format="sorted", base=base)
        self.assertEqual(
            (caught.exception.kind, caught.exception.field),
            ("lossy_description", "ja4"),
        )
        self.assertNotIn("secret", str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)


class CompactProfileTests(unittest.TestCase):
    def test_ja3_and_original_ja4_apply_order_while_sorted_ja4_retains_base(self):
        base = Profile.from_catalog(PROFILE, context="fetch")
        before = base.export_json()
        ordered = CIPHERS.split(",")
        ordered[:2] = reversed(ordered[:2])
        changed = ",".join(ordered)
        expected = base.describe()["profile"]["tls"]["cipher_suites"]
        expected[:2] = reversed(expected[:2])
        for result in (
            Profile.import_ja3(ja3(changed), base=base),
            Profile.import_ja4(ja4(ciphers=changed), format="original", base=base),
        ):
            self.assertIsNone(result.profile.catalog_id)
            document = result.profile.describe()["profile"]
            self.assertEqual(document["tls"]["cipher_suites"], expected)
            self.assertEqual(document["tls"]["extension_order"]["kind"], "Fixed")
            self.assertEqual(document["http2"], base.describe()["profile"]["http2"])
            self.assertIn("tls.extension_order", result.observed_fields)
            self.assertIn("tls.ech", result.supplemented_fields)
            self.assertEqual(
                Profile.import_json(result.profile.export_json()).export_json(),
                result.profile.export_json(),
            )
        fixed_base = result.profile
        result = Profile.import_ja4(
            ja4(sorted_input=True), format="sorted", base=fixed_base
        )
        self.assertEqual(
            result.profile.describe()["profile"]["tls"],
            fixed_base.describe()["profile"]["tls"],
        )
        self.assertNotIn("tls.extension_order", result.observed_fields)
        self.assertIn("tls.extension_order", result.supplemented_fields)
        self.assertEqual(base.export_json(), before)

    def test_akamai_order_template_and_custom_profile_client_are_preserved(self):
        base = Profile.from_catalog(PROFILE, context="fetch")
        result = Profile.import_akamai(AKAMAI, base=base)
        document = result.profile.describe()["profile"]
        self.assertEqual(
            [entry["kind"] for entry in document["http2"]["initial_settings"]],
            ["MaxHeaderListSize", "InitialWindowSize", "EnablePush", "HeaderTableSize"],
        )
        self.assertEqual(
            document["http2"]["pseudo_header_order"],
            ["Method", "Path", "Authority", "Scheme"],
        )
        self.assertEqual(
            document["request_template"], base.describe()["profile"]["request_template"]
        )
        self.assertIn("tls", result.supplemented_fields)
        with (
            server() as (_, url),
            Client(profile=result.profile, protocol="h1", context="profile") as client,
            client.request("GET", url) as response,
        ):
            self.assertEqual(response.read(max_bytes=5), b"hello")
        with self.assertRaises(Error) as caught:
            AsyncClient(profile=result.profile, protocol="h1", context="fetch")
        self.assertEqual(caught.exception.kind, "context_unavailable")

    def test_supported_quic_projection_preserves_captured_parameter_order_and_widths(
        self,
    ):
        base = Profile.from_catalog(PROFILE)
        result = Profile.import_quic_transport(QUIC, base=base)
        quic = result.profile.describe()["profile"]["http3"]["quic_transport"]
        parameters = quic["wire_parameters"]
        self.assertEqual(quic["parameter_order"], "Fixed")
        self.assertEqual(
            [value["kind"]["kind"] for value in parameters],
            [
                "InitialMaxStreamsBidi",
                "InitialMaxStreamDataUni",
                "InitialMaxData",
                "InitialMaxStreamsUni",
                "InitialMaxStreamDataBidiRemote",
                "MaxIdleTimeout",
                "MaxDatagramFrameSize",
                "MaxUdpPayloadSize",
                "InitialMaxStreamDataBidiLocal",
                "InitialSourceConnectionId",
            ],
        )
        self.assertEqual(parameters[0]["kind"]["value_width"], "Two")
        self.assertEqual(parameters[0]["length_width"], "One")
        self.assertEqual(quic["initial_max_data"], 15728640)
        self.assertIn("http3.tls", result.supplemented_fields)
        self.assertIn("http3.quic_transport.initial_max_data", result.observed_fields)
        self.assertIsNone(result.profile.catalog_id)
        self.assertEqual(
            Profile.import_json(result.profile.export_json()).export_json(),
            result.profile.export_json(),
        )

    def test_hashes_malformed_and_oversized_inputs_retain_exact_redacted_errors(self):
        base = Profile.from_catalog(PROFILE)
        for method, value, options, kind, field in (
            (Profile.import_ja3, "a" * 32, {}, "lossy_description", "ja3"),
            (Profile.import_akamai, "b" * 64, {}, "lossy_description", "akamai"),
            (
                Profile.import_ja4,
                "t13d1516h2_8daaf6152771_b186095e22b6",
                {"format": "original"},
                "lossy_description",
                "ja4",
            ),
            (Profile.import_ja3, "secret", {}, "invalid_value", "ja3.version"),
            (
                Profile.import_client_hello,
                b"secret",
                {},
                "malformed_description",
                "client_hello",
            ),
            (
                Profile.import_client_hello,
                b"x" * 65537,
                {},
                "too_large",
                "client_hello",
            ),
            (
                Profile.import_quic_transport,
                b"\x01",
                {},
                "malformed_description",
                "http3.quic_transport",
            ),
            (Profile.import_ja3, "x" * 32769, {}, "too_large", "ja3"),
            (
                Profile.import_ja4,
                "secret",
                {"format": "guess"},
                "invalid_value",
                "ja4.format",
            ),
        ):
            with (
                self.subTest(method=method.__name__, kind=kind),
                self.assertRaises(ProfileError) as caught,
            ):
                method(value, base=base, **options)
            self.assertEqual(
                (caught.exception.kind, caught.exception.field), (kind, field)
            )
            self.assertNotIn("secret", str(caught.exception))
