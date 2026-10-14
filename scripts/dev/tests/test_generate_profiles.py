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

    def test_generation_is_independent_of_record_and_layer_object_order(self):
        expected = generator.generate(generator.validate(self.document))
        self.document["profiles"].reverse()
        for profile in self.document["profiles"]:
            profile["layers"].reverse()
        self.assertEqual(
            generator.generate(generator.validate(self.document)), expected
        )
        self.assertEqual(generator.OUTPUT.read_text(encoding="utf-8"), expected)

    def test_unknown_fields_bindings_layers_and_enums_are_rejected(self):
        for key, value in (("binding", "std::process::exit"), ("unexpected", True)):
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

    def test_a_known_factory_cannot_be_relabelled_as_another_build_or_target(self):
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
                    if profile["binding"] == "BraveAndroid153"
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

    def test_template_bindings_require_explicit_known_kinds_and_identifiers(self):
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

    def test_template_binding_object_order_does_not_change_generated_records(self):
        expected = generator.generate(generator.validate(self.document))
        for entry in self.document["profiles"]:
            entry["templates"] = dict(reversed(list(entry["templates"].items())))
        self.assertEqual(
            generator.generate(generator.validate(self.document)), expected
        )


if __name__ == "__main__":
    unittest.main()
