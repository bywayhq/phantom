"""Typed HTTP/3 component declarations, inheritance, and committed output."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.dev.profile_catalog import cli as generator
from scripts.dev.profile_catalog import components, declarations

REPO = Path(__file__).resolve().parents[3]


class Http3ComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(
            generator.COMPONENT_RECORDS.read_text(encoding="utf-8")
        )

    def reject(self, document):
        with self.assertRaises(generator.DeclarationError):
            generator.validate_components(document)

    def test_committed_output_is_deterministic_and_keeps_runtime_policies(self):
        expected = generator.generate_components(
            generator.validate_components(self.document)
        )
        self.document["components"].reverse()
        for component in self.document["components"]:
            component["values"] = dict(reversed(component["values"].items()))
        self.assertEqual(
            generator.generate_components(generator.validate_components(self.document)),
            expected,
        )
        self.assertEqual(
            generator.COMPONENT_OUTPUT.read_text(encoding="utf-8"), expected
        )
        self.assertIn("crate::Http3Setting::RandomizedGrease", expected)
        self.assertIn("Http3SettingOrder::Ascending", expected)
        self.assertIn("reserved_frame_after_settings: true", expected)
        self.assertNotIn("draw_", expected)

    def test_same_kind_inheritance_replaces_complete_ordered_lists(self):
        inherited = {
            "id": "derived_settings",
            "kind": "Http3Settings",
            "base": "chromium_154_http3",
            "values": {
                "initial_settings": [{"kind": "H3Datagram", "value": False}],
                "setting_order": "Fixed",
            },
        }
        self.document["components"].append(inherited)
        resolved = {
            component["id"]: component
            for component in generator.validate_components(self.document)
        }
        self.assertEqual(
            resolved["derived_settings"]["values"]["initial_settings"],
            [{"kind": "H3Datagram", "value": False}],
        )
        self.assertEqual(
            resolved["chromium_154_http3"]["values"]["initial_settings"],
            self.document["components"][0]["values"]["initial_settings"],
        )
        firefox = resolved["firefox_157_http3_request"]["values"]
        self.assertIsNone(firefox["extended_connect_pseudo_header_order"])
        self.assertEqual(
            firefox["pseudo_header_order"], ["Method", "Scheme", "Authority", "Path"]
        )

    def test_unknown_fields_kinds_enum_values_and_callable_paths_are_rejected(self):
        for key, value in (
            ("id", "std::process::exit"),
            ("id", "fn"),
            ("kind", "RustFactory"),
            ("factory", "chrome::v154_http3"),
        ):
            with self.subTest(key=key, value=value):
                document = copy.deepcopy(self.document)
                document["components"][0][key] = value
                self.reject(document)
        for key, value in (
            ("qpack_encoding", "BrowserDefault"),
            ("unknown_override", 3),
            ("qpack_decoder_stream", {"factory": "evaluate"}),
        ):
            with self.subTest(field=key):
                document = copy.deepcopy(self.document)
                document["components"][0]["values"][key] = value
                self.reject(document)

    def test_missing_fields_duplicates_bad_references_and_cycles_are_rejected(self):
        document = copy.deepcopy(self.document)
        del document["components"][0]["values"]["qpack_encoding"]
        self.reject(document)
        document = copy.deepcopy(self.document)
        document["components"].append(copy.deepcopy(document["components"][0]))
        self.reject(document)
        for reference in ("missing_component", "firefox_157_http3_request"):
            with self.subTest(reference=reference):
                document = copy.deepcopy(self.document)
                document["components"][0]["base"] = reference
                self.reject(document)
        document = copy.deepcopy(self.document)
        document["components"][0]["base"] = "firefox_157_http3"
        document["components"][2]["base"] = "chromium_154_http3"
        self.reject(document)
        document = copy.deepcopy(self.document)
        document["components"][1]["values"]["alt_used"] = "Unknown"
        # A valid derived override must not hide an invalid base declaration.
        self.reject(document)

    def test_setting_types_limits_duplicates_and_datagram_consistency_are_checked(self):
        invalid = (
            [{"kind": "QpackMaxTableCapacity", "value": 1 << 30}],
            [{"kind": "QpackBlockedStreams", "value": 1 << 62}],
            [{"kind": "MaxFieldSectionSize", "value": -1}],
            [{"kind": "QpackBlockedStreams", "value": True}],
            [{"kind": "QpackBlockedStreams", "value": 1.0}],
            [{"kind": "H3Datagram", "value": 1}],
            [{"kind": "RandomizedGrease", "value": 99}],
            [{"kind": "EnableWebTransportDraft02", "value": True}],
            [{"kind": "H3DatagramDraft04", "value": True}],
            [{"kind": "UnknownSetting", "value": 0}],
            [{"kind": "H3Datagram", "value": True}] * 2,
        )
        for settings in invalid:
            with self.subTest(settings=settings):
                document = copy.deepcopy(self.document)
                document["components"][0]["values"]["initial_settings"] = settings
                self.reject(document)
        document = copy.deepcopy(self.document)
        document["components"][0]["values"]["reserved_frame_after_settings"] = 1
        self.reject(document)

    def test_boundary_settings_and_extended_connect_order_are_supported(self):
        values = self.document["components"][0]["values"]
        values["initial_settings"] = [
            {"kind": "QpackMaxTableCapacity", "value": (1 << 30) - 1},
            {"kind": "MaxFieldSectionSize", "value": (1 << 62) - 1},
            {"kind": "QpackBlockedStreams", "value": 0},
        ]
        self.document["components"][1]["values"][
            "extended_connect_pseudo_header_order"
        ] = ["Method", "Protocol", "Scheme", "Authority", "Path"]
        generated = generator.generate_components(
            generator.validate_components(self.document)
        )
        self.assertIn("4611686018427387903", generated)
        self.assertIn("Some(vec![crate::Http3PseudoHeader::Method", generated)

    def test_request_orders_types_and_duplicates_are_checked(self):
        for field, value in (
            ("pseudo_header_order", ["Method", "Scheme", "Path", "Path"]),
            ("pseudo_header_order", ["Method", "Scheme", "Path", "Protocol"]),
            ("pseudo_header_order", "Method,Scheme,Authority,Path"),
            ("extended_connect_pseudo_header_order", []),
            ("extended_connect_pseudo_header_order", False),
            ("cookie_crumbs", "Automatic"),
            ("alt_used", True),
        ):
            with self.subTest(field=field, value=value):
                document = copy.deepcopy(self.document)
                document["components"][1]["values"][field] = value
                self.reject(document)

    def test_inheritance_and_collection_limits_do_not_depend_on_resolution_cache(self):
        root = copy.deepcopy(self.document["components"][0])
        root["id"] = "chain_00"
        chain = [root]
        for index in range(1, declarations.MAX_COMPONENT_CHAIN + 1):
            chain.append(
                {
                    "id": f"chain_{index:02}",
                    "kind": "Http3Settings",
                    "base": f"chain_{index - 1:02}",
                    "values": {},
                }
            )
        document = {"schema": 1, "components": chain}
        self.reject(document)
        document["components"].reverse()
        self.reject(document)
        document["components"] = sorted(chain, key=lambda item: item["id"])[:-1]
        self.assertEqual(
            len(generator.validate_components(document)),
            declarations.MAX_COMPONENT_CHAIN,
        )
        with mock.patch.object(components, "MAX_COMPONENTS", 1):
            self.reject(self.document)
        document = copy.deepcopy(self.document)
        document["components"][0]["values"]["initial_settings"] = [{}] * 65
        self.reject(document)

    def test_loader_bounds_invalid_json_duplicate_keys_and_deep_inputs(self):
        inputs = (
            b'{"schema":1,"schema":1,"components":[]}',
            b"{" + b'"integer":' + b"9" * 5000 + b"}",
            b'"\xff"',
            b"[" * (declarations.MAX_DEPTH + 2) + b"]" * (declarations.MAX_DEPTH + 2),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "components.json"
            for raw in inputs:
                with self.subTest(raw=raw[:24]):
                    path.write_bytes(raw)
                    with self.assertRaises(generator.DeclarationError):
                        generator.load_components(path)
            path.write_bytes(b" " * 65)
            with (
                mock.patch.object(declarations, "MAX_BYTES", 64),
                self.assertRaises(generator.DeclarationError),
            ):
                generator.load_components(path)

    def test_check_rejects_either_stale_generated_output(self):
        expected = generator.generate(generator.load())
        components = generator.generate_components(generator.load_components())
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "registry.rs"
            component_output = Path(directory) / "components.rs"
            for stale_registry in (True, False):
                with self.subTest(stale_registry=stale_registry):
                    registry.write_text("stale" if stale_registry else expected)
                    component_output.write_text(
                        components if stale_registry else "stale"
                    )
                    with (
                        mock.patch.object(generator, "OUTPUT", registry),
                        mock.patch.object(
                            generator, "COMPONENT_OUTPUT", component_output
                        ),
                        mock.patch.object(
                            sys, "argv", ["generate_profiles.py", "--check"]
                        ),
                        mock.patch.object(generator.sys, "stderr"),
                    ):
                        self.assertEqual(generator.main(), 1)

    def test_invalid_component_input_preserves_both_existing_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "registry.rs"
            components = Path(directory) / "components.rs"
            registry.write_text("existing registry")
            components.write_text("existing components")
            with (
                mock.patch.object(generator, "OUTPUT", registry),
                mock.patch.object(generator, "COMPONENT_OUTPUT", components),
                mock.patch.object(
                    generator,
                    "load_components",
                    side_effect=generator.DeclarationError("invalid components"),
                ),
                mock.patch.object(sys, "argv", ["generate_profiles.py"]),
                mock.patch.object(generator.sys, "stderr"),
            ):
                self.assertEqual(generator.main(), 1)
            self.assertEqual(registry.read_text(), "existing registry")
            self.assertEqual(components.read_text(), "existing components")


if __name__ == "__main__":
    unittest.main()
