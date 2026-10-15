import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.dev.profile_catalog import cli as generator
from scripts.dev.profile_catalog import declarations, registry

REPO = Path(__file__).resolve().parents[3]


class CatalogDeclarationTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(generator.RECORDS.read_text(encoding="utf-8"))

    def reject(self, document):
        with self.assertRaises(generator.DeclarationError):
            generator.validate(document)

    def test_android_tcp_evidence_is_source_only_and_limited_to_chrome_and_firefox(
        self,
    ):
        for profile in self.document["profiles"]:
            if profile["metadata"]["platform"] != "Android":
                continue
            tcp = next(layer for layer in profile["layers"] if layer["layer"] == "Tcp")
            if profile["target"] in ("ChromeAndroid154", "FirefoxAndroid156"):
                self.assertEqual(tcp["support"], "Configured")
                self.assertEqual(tcp["verified_fields"], [])
                self.assertEqual(
                    {reference["kind"] for reference in tcp["references"]},
                    {"Source", "Recipe"},
                )
                self.assertIsNotNone(profile["composition"]["Tcp"])
            else:
                self.assertEqual(tcp["support"], "Unavailable")
                self.assertIsNone(profile["composition"]["Tcp"])

    def test_generation_is_independent_of_record_and_layer_object_order(self):
        expected = generator.generate(generator.validate(self.document))
        self.document["profiles"].reverse()
        for profile in self.document["profiles"]:
            profile["layers"].reverse()
        self.assertEqual(
            generator.generate(generator.validate(self.document)), expected
        )
        self.assertEqual(generator.OUTPUT.read_text(encoding="utf-8"), expected)

    def test_unknown_fields_targets_layers_and_enums_are_rejected(self):
        for key, value in (("target", "std::process::exit"), ("unexpected", True)):
            with self.subTest(key=key):
                document = copy.deepcopy(self.document)
                document["profiles"][0][key] = value
                self.reject(document)
        for key, value in (("layer", "AutomaticFallback"), ("support", "Assumed")):
            with self.subTest(key=key):
                document = copy.deepcopy(self.document)
                document["profiles"][0]["layers"][0][key] = value
                self.reject(document)

    def test_duplicate_identifiers_layers_and_json_keys_are_rejected(self):
        document = copy.deepcopy(self.document)
        document["profiles"].append(copy.deepcopy(document["profiles"][0]))
        self.reject(document)

        document = copy.deepcopy(self.document)
        layers = document["profiles"][0]["layers"]
        layers[1] = copy.deepcopy(layers[0])
        self.reject(document)

        with self.assertRaises(generator.DeclarationError):
            json.loads(
                '{"schema":1,"schema":1,"profiles":[]}',
                object_pairs_hook=declarations.object_pairs,
            )

    def test_metadata_and_availability_cannot_disagree_with_the_recipe(self):
        document = copy.deepcopy(self.document)
        document["profiles"][0]["metadata"]["platform"] = "Macos"
        self.reject(document)

        document = copy.deepcopy(self.document)
        document["profiles"][0]["layers"][0]["support"] = "Unavailable"
        self.reject(document)

        document = copy.deepcopy(self.document)
        document["profiles"][0]["metadata"]["revision"] = True
        self.reject(document)

    def test_a_known_target_cannot_be_relabelled_as_another_build_or_target(self):
        for field, value in (
            ("build", "999.0"),
            ("platform_release", "android-99"),
            ("architecture", "arm64"),
            ("revision", 2),
        ):
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                entry = next(
                    profile
                    for profile in document["profiles"]
                    if profile["target"] == "BraveAndroid153"
                )
                entry["metadata"][field] = value
                metadata = entry["metadata"]
                entry["id"] = (
                    f"brave/{metadata['build']}/{metadata['platform_release']}"
                    f"/r{metadata['revision']}"
                )
                self.reject(document)

    def test_missing_escaping_or_mislabelled_capture_evidence_is_rejected(self):
        for location in (
            "../README.md",
            "C:/outside.txt",
            "fixtures/no-such-capture.txt",
            "Cargo.toml",
        ):
            with self.subTest(location=location):
                document = copy.deepcopy(self.document)
                references = document["profiles"][0]["layers"][0]["references"]
                references[0] = {
                    "kind": "Capture",
                    "location": location,
                    "build": "test",
                }
                self.reject(document)

    def test_observed_fields_require_direct_capture_support(self):
        document = copy.deepcopy(self.document)
        layer = document["profiles"][0]["layers"][0]
        layer["references"] = [
            {"kind": "Recipe", "location": "Cargo.toml", "build": "test"}
        ]
        layer["verified_fields"] = ["cipher suites"]
        self.reject(document)

    def test_capture_reference_build_matches_the_fixture_not_the_target(self):
        generator.validate(self.document)
        chrome = next(
            profile
            for profile in self.document["profiles"]
            if profile["target"] == "ChromeWindows154"
        )
        layer = next(layer for layer in chrome["layers"] if layer["layer"] == "TcpTls")
        capture = next(ref for ref in layer["references"] if ref["kind"] == "Capture")
        self.assertEqual(chrome["metadata"]["build"], "154.0.8037.97")
        self.assertEqual(capture["build"], "154.0.8037.58")
        capture["build"] = chrome["metadata"]["build"]
        with self.assertRaisesRegex(generator.DeclarationError, "retained metadata"):
            generator.validate(self.document)

    def test_retained_edge_versions_keep_exact_identity_and_partial_layer_contracts(
        self,
    ):
        profiles = generator.validate(self.document)
        old = next(entry for entry in profiles if entry["target"] == "EdgeWindows153")
        new = next(entry for entry in profiles if entry["target"] == "EdgeWindows154")
        self.assertEqual(old["id"], "edge/153.0.4234.48/windows-11-26200/r1")
        self.assertEqual(new["id"], "edge/154.0.4258.48/windows-11-26200/r1")
        self.assertIsNone(old["metadata"]["architecture"])
        supplied = {
            layer["layer"]
            for layer in old["layers"]
            if layer["support"] == "Configured"
        }
        self.assertEqual(
            supplied,
            {
                "TcpTls",
                "Http2",
                "QuicTls",
                "QuicTransport",
                "Http3",
                "Http3Request",
                "ClientHints",
            },
        )
        absent = {
            layer["layer"]
            for layer in old["layers"]
            if layer["support"] == "Unavailable"
        }
        self.assertEqual(
            absent,
            {
                "Tcp",
                "Udp",
                "Dns",
                "Http1",
                "WebSocket",
                "ProxyConnect",
                "CookiePlacement",
            },
        )
        for layer in old["layers"]:
            if layer["layer"] in supplied:
                captures = [
                    ref for ref in layer["references"] if ref["kind"] == "Capture"
                ]
                self.assertTrue(captures)
                self.assertTrue(
                    all(ref["build"] == "153.0.4234.48" for ref in captures)
                )
                if layer["layer"] != "ClientHints":
                    self.assertTrue(
                        any(ref["kind"] == "Reused" for ref in layer["references"])
                    )
            else:
                self.assertEqual(layer["references"], [])
                self.assertEqual(layer["verified_fields"], [])
                self.assertIsNone(old["composition"][layer["layer"]])
        for field, value in (
            ("build", "153.0.4234.49"),
            ("architecture", "x86_64"),
            ("revision", 2),
        ):
            document = copy.deepcopy(self.document)
            entry = next(
                row for row in document["profiles"] if row["target"] == "EdgeWindows153"
            )
            entry["metadata"][field] = value
            with self.subTest(field=field):
                self.reject(document)
        document = copy.deepcopy(self.document)
        entry = next(
            row for row in document["profiles"] if row["target"] == "EdgeWindows153"
        )
        next(layer for layer in entry["layers"] if layer["layer"] == "WebSocket")[
            "support"
        ] = "Configured"
        self.reject(document)

    def test_brave_android_http2_names_the_older_session_control_without_new_coverage(
        self,
    ):
        brave = next(
            profile
            for profile in self.document["profiles"]
            if profile["target"] == "BraveAndroid153"
        )
        layer = next(layer for layer in brave["layers"] if layer["layer"] == "Http2")
        self.assertEqual(
            brave["metadata"]["platform_release"], "android-17-pixel7-emulator"
        )
        self.assertIsNone(brave["metadata"]["architecture"])
        self.assertEqual(layer["verified_fields"], [])
        capture = next(ref for ref in layer["references"] if ref["kind"] == "Capture")
        self.assertEqual(
            capture["location"],
            "fixtures/websocket/brave-android/153.1.95.104/android-35-emulator/accept.txt",
        )
        self.assertEqual(capture["build"], "153.1.95.104")
        self.assertTrue(
            any("Android 15 (API 35)" in item for item in layer["limitations"])
        )
        self.assertTrue(any(ref["kind"] == "Reused" for ref in layer["references"]))
        generator.validate(self.document)

    def test_capture_metadata_requires_one_complete_ascii_build_in_the_prefix(self):
        invalid = (
            b"format=test\noperating_system=unknown\n",
            b"browser_version=\n",
            b"browser_version=1\nclient_version=1\n",
            b"client_version=1\nclient_version=2\n",
            b"browser_version=\xff\n",
            b"payload=" + b"x" * 8192 + b"\nclient_version=1\n",
            b"payload=" + b"x" * 8180 + b"\nclient_version=1\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.txt"
            for value in invalid:
                with self.subTest(prefix=value[:48]):
                    path.write_bytes(value)
                    with self.assertRaises(generator.DeclarationError):
                        registry.capture_build(path)
            for value in (b"browser_version=1\n", b"client_version=1\r\n"):
                path.write_bytes(value + b"payload=" + b"x" * 16000)
                self.assertEqual(registry.capture_build(path), "1")

    def test_capture_metadata_read_failure_is_a_declaration_error(self):
        with (
            mock.patch.object(Path, "open", side_effect=OSError("unreadable")),
            self.assertRaisesRegex(generator.DeclarationError, "cannot read"),
        ):
            registry.capture_build(Path("capture.txt"))

    def test_capture_metadata_validation_does_not_parse_source_or_recipe_citations(
        self,
    ):
        document = copy.deepcopy(self.document)
        layer = document["profiles"][0]["layers"][0]
        layer["references"] = [
            {
                "kind": "Source",
                "location": "https://example.com/upstream",
                "build": "unknown",
            },
            {"kind": "Recipe", "location": "Cargo.toml", "build": "unknown"},
        ]
        layer["verified_fields"] = []
        generator.validate(document)

    def test_malformed_source_urls_and_recipe_as_source_are_rejected(self):
        for location in (
            "https://[invalid",
            "https://",
            "https://user:secret@example.com/source",
            "crates/phantom-profile/src/browser/brave/android.rs",
        ):
            with self.subTest(location=location):
                document = copy.deepcopy(self.document)
                layer = document["profiles"][0]["layers"][0]
                layer["references"] = [
                    {"kind": "Source", "location": location, "build": "test"}
                ]
                layer["verified_fields"] = []
                self.reject(document)

    def test_byte_depth_count_and_string_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversize.json"
            path.write_bytes(b" " * 65)
            with (
                mock.patch.object(declarations, "MAX_BYTES", 64),
                self.assertRaises(generator.DeclarationError),
            ):
                generator.load(path)
        nested = []
        for _ in range(declarations.MAX_DEPTH + 1):
            nested = [nested]
        with self.assertRaises(generator.DeclarationError):
            declarations.check_depth(nested)

        document = copy.deepcopy(self.document)
        with mock.patch.object(registry, "MAX_PROFILES", 1):
            self.reject(document)
        document["profiles"][0]["id"] = "x" * (declarations.MAX_STRING + 1)
        self.reject(document)

    def test_template_targets_require_explicit_known_kinds_and_identifiers(self):
        for value in (
            None,
            [],
            {"Automatic": "test"},
            {"Navigation": None},
            {"Navigation": "std::process::exit"},
        ):
            document = copy.deepcopy(self.document)
            document["profiles"][0]["templates"] = value
            with self.subTest(value=value):
                self.reject(document)

        document = copy.deepcopy(self.document)
        document["profiles"][0]["templates"] = {}
        generator.validate(document)

    def test_template_target_object_order_does_not_change_generated_records(self):
        expected = generator.generate(generator.validate(self.document))
        for entry in self.document["profiles"]:
            entry["templates"] = dict(reversed(list(entry["templates"].items())))
        self.assertEqual(
            generator.generate(generator.validate(self.document)), expected
        )


if __name__ == "__main__":
    unittest.main()
