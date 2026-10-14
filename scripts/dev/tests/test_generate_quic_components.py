"""QUIC policy, wire encoding, typed overrides, and generation controls."""

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "generate_profiles_quic", REPO / "scripts/dev/generate_profiles.py"
)
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class QuicComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(generator.QUIC_COMPONENT_RECORDS.read_text())
        self.values = self.document["components"][0]["values"]

    def resolve(self, document=None):
        return generator.validate_components(
            self.document if document is None else document, ("QuicTransportSettings",)
        )

    def reject_field(self, field, value):
        document = copy.deepcopy(self.document)
        document["components"][0]["values"][field] = value
        with self.assertRaises(generator.DeclarationError):
            self.resolve(document)

    def parameter(self, kind, values=None):
        return next(
            item
            for item in (self.values if values is None else values)["wire_parameters"]
            if item["kind"]["kind"] == kind
        )

    def test_generation_preserves_order_policies_and_is_deterministic(self):
        expected = generator.generate_components(self.resolve(), "quic-components.json")
        self.document["components"].reverse()
        for component in self.document["components"]:
            component["values"] = dict(reversed(component["values"].items()))
            for parameter in component["values"]["wire_parameters"]:
                parameter["kind"] = dict(reversed(parameter["kind"].items()))
        self.assertEqual(
            generator.generate_components(self.resolve(), "quic-components.json"),
            expected,
        )
        self.assertEqual(generator.QUIC_COMPONENT_OUTPUT.read_text(), expected)
        self.assertIn("QuicTransportParameterOrder::Permuted", expected)
        self.assertIn("QuicConnectionIdLength::MaskedRandom", expected)
        self.assertIn("QuicVersionGrease::First", expected)
        self.assertNotIn("draw_", expected)

    def test_inheritance_replaces_whole_wire_list_and_policy(self):
        wire = list(reversed(copy.deepcopy(self.values["wire_parameters"])))
        self.document["components"].append(
            {
                "id": "derived_quic",
                "kind": "QuicTransportSettings",
                "base": "chromium_154_quic",
                "values": {
                    "wire_parameters": wire,
                    "parameter_order": "Fixed",
                    "initial_destination_connection_id": {"kind": "Fixed", "length": 8},
                },
            }
        )
        derived = next(
            item["values"] for item in self.resolve() if item["id"] == "derived_quic"
        )
        self.assertEqual(derived["wire_parameters"], wire)
        self.assertEqual(derived["parameter_order"], "Fixed")
        self.assertEqual(self.values["parameter_order"], "Permuted")

    def test_references_cycles_missing_fields_and_callable_names_fail(self):
        for override in (
            {"base": "missing"},
            {"base": "chromium_154_quic"},
            {"id": "crate::factory"},
            {"kind": "TlsSettings"},
            {"factory": "chrome::v154_quic"},
        ):
            document = copy.deepcopy(self.document)
            document["components"][0].update(override)
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)
        del self.values["early_data"]
        with self.assertRaises(generator.DeclarationError):
            self.resolve()

    def test_cross_layer_base_is_rejected(self):
        other = json.loads(generator.COMPONENT_RECORDS.read_text())["components"][0]
        self.document["components"].append(other)
        self.document["components"][0]["base"] = other["id"]
        with self.assertRaises(generator.DeclarationError):
            generator.validate_components(self.document)

    def test_numeric_and_boolean_limits_reject_wrong_types(self):
        for field, bad in (
            ("max_idle_timeout_ms", 1 << 62),
            ("initial_max_data", -1),
            ("initial_max_streams_uni", (1 << 60) + 1),
            ("max_udp_payload_size", 1199),
            ("max_udp_payload_size", 65528),
            ("max_ack_delay_ms", 16384),
            ("active_connection_id_limit", 1),
            ("active_connection_id_limit", 9),
            ("max_datagram_frame_size", True),
            ("early_data", 1),
            ("reset_stream_at", "false"),
            ("parameter_order", "automatic"),
            ("initial_path_mtu", 1247),
            ("initial_path_mtu", 1501),
            ("initial_path_mtu", 1 << 16),
        ):
            with self.subTest(field=field, value=bad):
                self.reject_field(field, bad)

    def test_connection_id_policies_check_full_possible_range(self):
        for policy in (
            0,
            {"kind": "Fixed", "length": 7},
            {"kind": "Fixed", "length": 21},
            {"kind": "MaskedRandom", "minimum": 8, "base": 6},
            {"kind": "MaskedRandom", "minimum": 7, "base": 0},
            {"kind": "MaskedRandom", "minimum": 21, "base": 0},
            {"kind": "Fixed", "length": 8, "base": 0},
        ):
            self.reject_field("initial_destination_connection_id", policy)
        for policy in (
            {"kind": "Fixed", "length": 20},
            {"kind": "MaskedRandom", "minimum": 20, "base": 5},
        ):
            self.values["initial_destination_connection_id"] = policy
            self.resolve()

    def test_duplicate_missing_and_unknown_parameter_records_fail(self):
        wire = self.values["wire_parameters"]
        for invalid in (
            [],
            wire * 2,
            wire + [copy.deepcopy(wire[0])],
            [
                item
                for item in wire
                if item["kind"]["kind"] != "InitialSourceConnectionId"
            ],
            [item for item in wire if item["kind"]["kind"] != "InitialMaxData"],
        ):
            self.reject_field("wire_parameters", invalid)
        for record in (
            {"kind": "Unknown"},
            {"kind": "InitialRtt", "value": 10},
            "InitialRtt",
        ):
            invalid = copy.deepcopy(wire)
            invalid[-1]["kind"] = record
            self.reject_field("wire_parameters", invalid)

    def test_widths_must_encode_identifiers_values_and_lengths(self):
        for kind, field, width in (
            ("InitialMaxData", "value_width", "Two"),
            ("GoogleConnectionOptions", "id_width", "One"),
            ("InitialRtt", "length_width", "Unknown"),
        ):
            wire = copy.deepcopy(self.values["wire_parameters"])
            parameter = next(item for item in wire if item["kind"]["kind"] == kind)
            (parameter["kind"] if field == "value_width" else parameter)[field] = width
            self.reject_field("wire_parameters", wire)
        firefox = self.document["components"][1]["values"]
        self.parameter("MinAckDelay", firefox)["id_width"] = "Four"
        with self.assertRaises(generator.DeclarationError):
            self.resolve()

    def test_optional_parameter_presence_matches_semantics(self):
        self.reject_field("max_datagram_frame_size", None)
        self.reject_field("reset_stream_at", True)
        self.reject_field("min_ack_delay_us", 1000)
        firefox = self.document["components"][1]["values"]
        for field, value in (
            ("reset_stream_at", False),
            ("min_ack_delay_us", None),
            ("min_ack_delay_us", 2000),
            ("max_ack_delay_ms", 0),
        ):
            document = copy.deepcopy(self.document)
            document["components"][1]["values"][field] = value
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)
        firefox["wire_parameters"] = [
            item
            for item in firefox["wire_parameters"]
            if item["kind"]["kind"] not in ("MinAckDelay", "ResetStreamAt")
        ]
        firefox.update(min_ack_delay_us=None, reset_stream_at=False)
        self.resolve()

    def test_version_grease_google_options_and_source_id_payloads_are_closed(self):
        for kind, overrides in (
            ("VersionInformation", {"available_version_count": 0}),
            ("VersionInformation", {"available_version_count": 3}),
            ("VersionInformation", {"grease": "Random"}),
            ("GoogleConnectionOptions", {"options": []}),
            ("GoogleConnectionOptions", {"options": ["RequestOriginFrame"] * 2}),
            ("InitialSourceConnectionId", {"length": 21}),
            ("Grease", {"maximum_payload_length": 16}),
            ("Grease", {"minimum_payload_length": 15, "maximum_payload_length": 14}),
        ):
            wire = copy.deepcopy(self.values["wire_parameters"])
            next(item["kind"] for item in wire if item["kind"]["kind"] == kind).update(
                overrides
            )
            self.reject_field("wire_parameters", wire)

    def test_largest_scalar_and_width_boundaries_are_accepted(self):
        for kind, (field, _, _) in generator.QUIC_SCALARS.items():
            if kind in ("MaxUdpPayloadSize", "MaxAckDelay", "ActiveConnectionIdLimit"):
                continue
            self.values[field] = 1 << 60 if "Streams" in kind else (1 << 62) - 1
            self.parameter(kind)["kind"]["value_width"] = "Eight"
        self.resolve()
        self.values["initial_path_mtu"] = 1248
        self.resolve()

    def test_varint_width_boundaries_reject_overflow_and_nonintegers(self):
        for width, size in generator.QUIC_WIDTHS.items():
            maximum = (1 << (size * 8 - 2)) - 1
            self.assertEqual(generator.quic_width(width, maximum), size)
            self.assertEqual(generator.quic_width(width, 0), size)
            for invalid in (-1, maximum + 1, True, False, 1.0, "1", None):
                with (
                    self.subTest(width=width, value=invalid),
                    self.assertRaises(generator.DeclarationError),
                ):
                    generator.quic_width(width, invalid)
        with self.assertRaises(generator.DeclarationError):
            generator.quic_width("Minimal", 1)

    def test_default_scalars_can_be_omitted_and_zero_datagrams_still_advertise(self):
        for field, _, default in generator.QUIC_SCALARS.values():
            self.values[field] = default
        self.values["wire_parameters"] = [self.parameter("InitialSourceConnectionId")]
        self.resolve()
        self.values["max_datagram_frame_size"] = 0
        self.values["wire_parameters"].append(
            {
                "kind": {"kind": "MaxDatagramFrameSize", "value_width": "One"},
                "id_width": "One",
                "length_width": "One",
            }
        )
        self.resolve()

    def test_check_covers_every_generated_output_and_invalid_input_preserves_them(self):
        names = (
            "OUTPUT",
            "COMPONENT_OUTPUT",
            "HTTP2_COMPONENT_OUTPUT",
            "TLS_COMPONENT_OUTPUT",
            "QUIC_COMPONENT_OUTPUT",
        )
        with tempfile.TemporaryDirectory() as directory:
            paths = {name: Path(directory) / (name + ".rs") for name in names}
            originals = {name: getattr(generator, name).read_text() for name in names}
            for stale in names:
                for name in names:
                    paths[name].write_text(
                        "stale" if name == stale else originals[name]
                    )
                with (
                    mock.patch.multiple(generator, **paths),
                    mock.patch.object(sys, "argv", ["generate_profiles.py", "--check"]),
                    mock.patch.object(generator.sys, "stderr"),
                ):
                    self.assertEqual(generator.main(), 1)
            invalid = Path(directory) / "bad.json"
            self.values["early_data"] = "false"
            invalid.write_text(json.dumps(self.document))
            for name in names:
                paths[name].write_text("sentinel")
            # Loader defaults are bound at definition; provide the invalid path explicitly.
            with (
                mock.patch.multiple(generator, **paths, QUIC_COMPONENT_RECORDS=invalid),
                mock.patch.object(sys, "argv", ["generate_profiles.py"]),
                mock.patch.object(generator.sys, "stderr"),
                mock.patch.object(
                    generator,
                    "load_quic_components",
                    side_effect=lambda: generator.validate_components(
                        generator.read_document(invalid), ("QuicTransportSettings",)
                    ),
                ),
            ):
                self.assertEqual(generator.main(), 1)
            self.assertTrue(
                all(path.read_text() == "sentinel" for path in paths.values())
            )


if __name__ == "__main__":
    unittest.main()
