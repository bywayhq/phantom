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
        self.document["profiles"] = generator.validate(self.document)

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

    def test_macos_tcp_is_source_only_and_missing_layers_stay_explicit(self):
        profile = next(
            p for p in self.document["profiles"] if p["target"] == "ChromeMacos154"
        )
        self.assertEqual(profile["metadata"]["identity"]["environment"], "Desktop")
        self.assertEqual(profile["composition"]["Tcp"], "chromium_154_macos_tcp")
        layers = {layer["layer"]: layer for layer in profile["layers"]}
        self.assertEqual(layers["Tcp"]["verified_fields"], [])
        self.assertEqual(
            {r["kind"] for r in layers["Tcp"]["references"]}, {"Source", "Recipe"}
        )
        for name in ("Udp", "Dns"):
            self.assertEqual(layers[name]["support"], "Unavailable")
            self.assertIsNone(profile["composition"][name])
        profile["metadata"]["identity"]["environment"] = "Emulator"
        self.reject(self.document)

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

    def test_new_version_needs_no_python_target_or_metadata_registration(self):
        entry = copy.deepcopy(self.document["profiles"][0])
        entry["metadata"]["identity"]["build"] = "999.0.1"
        entry["metadata"]["revision"] = 2
        metadata = entry["metadata"]
        entry["target"] = metadata["browser"] + metadata["platform"] + "999"
        entry["selector"] = (
            f"{metadata['browser'].lower()}-999-{metadata['platform'].lower()}"
        )
        entry["id"] = (
            f"{metadata['browser'].lower()}/{metadata['identity']['build']}/"
            f"{metadata['identity']['platform_release']}/r2"
        )
        # Reusing older components does not relabel their retained observations.
        self.document["profiles"].append(entry)
        profiles = generator.validate(self.document)
        output = registry.generate_constructors(profiles)
        self.assertIn("pub fn v999_android()", output)
        self.assertIn(entry["target"].upper() + ".instantiate()", output)
        self.assertIn(entry["id"], generator.generate(profiles))
        added = next(p for p in profiles if p["id"] == entry["id"])
        self.assertEqual(added["metadata"]["revision"], 2)

    def test_selectors_are_explicit_bounded_names_and_unique_across_identifiers(self):
        for value in (
            "",
            "Chrome-154",
            "chrome/latest",
            "chrome--154",
            "-chrome",
            "chrome-",
            "é",
            "x" * 65,
        ):
            with self.subTest(value=value):
                document = copy.deepcopy(self.document)
                document["profiles"][0]["selector"] = value
                with self.assertRaisesRegex(
                    generator.DeclarationError, "profile selector"
                ):
                    generator.validate(document)
        document = copy.deepcopy(self.document)
        del document["profiles"][0]["selector"]
        self.reject(document)
        document = copy.deepcopy(self.document)
        document["profiles"][1]["selector"] = document["profiles"][0]["selector"]
        with self.assertRaisesRegex(
            generator.DeclarationError, "duplicate profile selector"
        ):
            generator.validate(document)
        for earlier_id in (True, False):
            document = copy.deepcopy(self.document)
            first, second = document["profiles"][:2]
            if earlier_id:
                second["selector"] = first["id"]
            else:
                second["id"] = first["selector"]
            with self.assertRaisesRegex(generator.DeclarationError, "conflicts with"):
                generator.validate(document)

    def test_selector_generation_retains_declared_name_and_identifier_order(self):
        document = copy.deepcopy(self.document)
        document["profiles"][0]["selector"] = "x" * 64
        profiles = generator.validate(document)
        self.assertEqual(profiles[0]["selector"], "x" * 64)
        self.assertIn('selector: "' + "x" * 64 + '",', generator.generate(profiles))
        self.assertEqual([p["id"] for p in profiles], sorted(p["id"] for p in profiles))

    def test_targets_require_matching_identity_and_unique_public_names(self):
        for field, value in (
            ("build", "999.0"),
            ("browser", "Chrome"),
            ("platform", "Windows"),
        ):
            document = copy.deepcopy(self.document)
            metadata = document["profiles"][0]["metadata"]
            (metadata["identity"] if field == "build" else metadata)[field] = value
            with self.subTest(field=field):
                self.reject(document)
        for field, value in (
            ("browser", "Other"),
            ("platform", "Other"),
            ("build", "999;exit"),
            ("build", "01.2"),
        ):
            document = copy.deepcopy(self.document)
            metadata = document["profiles"][0]["metadata"]
            (metadata["identity"] if field == "build" else metadata)[field] = value
            with self.subTest(field=field, value=value):
                self.reject(document)
        document = copy.deepcopy(self.document)
        duplicate = copy.deepcopy(document["profiles"][0])
        duplicate["metadata"]["revision"] = 2
        duplicate["id"] = duplicate["id"][:-1] + "2"
        document["profiles"].append(duplicate)
        self.reject(document)

    def test_compact_evidence_expands_absence_without_inventing_support(self):
        document = json.loads(generator.RECORDS.read_text(encoding="utf-8"))
        before = copy.deepcopy(document)
        profiles = generator.validate(document)
        self.assertEqual(document, before)
        self.assertTrue(
            any(len(p["layers"]) < len(registry.LAYERS) for p in document["profiles"])
        )
        for profile in profiles:
            self.assertEqual(len(profile["layers"]), len(registry.LAYERS))
            for layer in profile["layers"]:
                if layer["support"] == "Unavailable":
                    self.assertEqual(layer["references"], [])
        entry = document["profiles"][0]
        entry["layers"] = []
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
        self.assertEqual(chrome["metadata"]["identity"]["build"], "154.0.8037.97")
        self.assertEqual(capture["build"], "154.0.8037.58")
        capture["build"] = chrome["metadata"]["identity"]["build"]
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
        self.assertIsNone(old["metadata"]["identity"]["architecture"])
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
            ("revision", 2),
        ):
            document = copy.deepcopy(self.document)
            entry = next(
                row for row in document["profiles"] if row["target"] == "EdgeWindows153"
            )
            (entry["metadata"]["identity"] if field == "build" else entry["metadata"])[
                field
            ] = value
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
            brave["metadata"]["identity"]["platform_release"],
            "android-17-pixel7-emulator",
        )
        self.assertIsNone(brave["metadata"]["identity"]["architecture"])
        self.assertEqual(layer["verified_fields"], [])
        capture = next(ref for ref in layer["references"] if ref["kind"] == "Capture")
        self.assertEqual(
            capture["location"],
            "fixtures/websocket/brave-android/153.1.95.104/android-35-emulator/accept.txt",
        )
        self.assertEqual(capture["build"], "153.1.95.104")
        with (REPO / capture["location"]).open(encoding="utf-8") as fixture:
            operating_system = next(
                line.partition("=")[2]
                for line in fixture.read(8192).splitlines()
                if line.startswith("operating_system=")
            )
        self.assertTrue(operating_system.startswith("Android 15 (API 35) "))
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
