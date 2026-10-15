"""HTTP/2 component bounds, complete overrides, and committed generation."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.dev.profile_catalog import cli as generator
from scripts.dev.profile_catalog import http2

REPO = Path(__file__).resolve().parents[3]


class Http2ComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(
            generator.HTTP2_COMPONENT_RECORDS.read_text(encoding="utf-8")
        )
        self.values = self.document["components"][0]["values"]

    def resolve(self, document=None):
        return generator.validate_components(
            self.document if document is None else document, ("Http2Settings",)
        )

    def reject(self, document=None):
        with self.assertRaises(generator.DeclarationError):
            self.resolve(document)

    def test_committed_output_preserves_policies_and_order_deterministically(self):
        expected = generator.generate_components(
            self.resolve(), "http2-components.json"
        )
        self.document["components"].reverse()
        for component in self.document["components"]:
            values = component["values"]
            for field in ("hpack", "streams", "headers_priority"):
                values[field] = dict(reversed(values[field].items()))
            component["values"] = dict(reversed(values.items()))
        self.assertEqual(
            generator.generate_components(self.resolve(), "http2-components.json"),
            expected,
        )
        self.assertEqual(
            generator.HTTP2_COMPONENT_OUTPUT.read_text(encoding="utf-8"), expected
        )
        self.assertIn("Http2HuffmanCoding::AlwaysIncludingEmpty", expected)
        self.assertIn("Http2CookieCrumbs::NeverIndexShort", expected)
        self.assertIn("Duration::new(170, 0)", expected)
        self.assertNotIn("draw_", expected)

    def test_opening_stream_target_is_optional_bounded_and_rendered(self):
        self.assertIsNone(self.values["initial_stream_window_target"])
        self.assertEqual(
            self.document["components"][1]["values"]["initial_stream_window_target"],
            12_582_912,
        )
        for target in (None, 6_291_456, (1 << 31) - 1):
            self.values["initial_stream_window_target"] = target
            self.resolve()
        for target in (True, -1, 0, 6_291_455, 1 << 31, "12582912"):
            self.values["initial_stream_window_target"] = target
            self.reject()
        self.values["initial_stream_window_target"] = None
        derived = copy.deepcopy(self.document["components"][0])
        derived.update(id="derived_http2", base="firefox_157_http2")
        derived["values"] = {"initial_stream_window_target": None}
        self.document["components"].append(derived)
        resolved = {item["id"]: item["values"] for item in self.resolve()}
        self.assertIsNone(resolved["derived_http2"]["initial_stream_window_target"])
        del self.values["initial_stream_window_target"]
        self.reject()

    def test_inheritance_replaces_whole_nested_values_and_ordered_lists(self):
        overrides = {
            "initial_settings": [{"kind": "InitialWindowSize", "value": 0}],
            "hpack": copy.deepcopy(self.document["components"][1]["values"]["hpack"]),
            "streams": {
                "first_stream_id": 5,
                "assumed_max_concurrent_streams": None,
                "max_concurrent_streams_cap": None,
            },
            "headers_priority": None,
        }
        self.document["components"].append(
            {
                "id": "derived_http2",
                "kind": "Http2Settings",
                "base": "chromium_154_http2",
                "values": overrides,
            }
        )
        resolved = {
            component["id"]: component["values"] for component in self.resolve()
        }
        for field, value in overrides.items():
            self.assertEqual(resolved["derived_http2"][field], value)
        self.assertEqual(resolved["chromium_154_http2"], self.values)
        del overrides["hpack"]["static_name_index"]
        self.reject()

    def test_unknown_fields_layer_kinds_and_callable_names_are_rejected(self):
        for field, value in (
            ("id", "crate::factory"),
            ("kind", "Http3Settings"),
            ("factory", "chrome::v154_http2"),
        ):
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document["components"][0][field] = value
                self.reject(document)
        for field, value in (("unknown", 1), ("hpack", {"factory": "anything"})):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"][field] = value
            self.reject(document)
        del self.values["streams"]
        self.reject()

    def test_unknown_references_cycles_and_incompatible_bases_are_rejected(self):
        self.document["components"][0]["base"] = "missing"
        self.reject()
        self.document["components"][0]["base"] = "firefox_157_http2"
        self.document["components"][1]["base"] = "chromium_154_http2"
        self.reject()
        document = json.loads(generator.HTTP2_COMPONENT_RECORDS.read_text())
        http3 = json.loads(generator.COMPONENT_RECORDS.read_text())["components"][0]
        document["components"].append(http3)
        document["components"][0]["base"] = http3["id"]
        with self.assertRaises(generator.DeclarationError):
            generator.validate_components(document)

    def test_settings_reject_duplicates_missing_window_and_wrong_types(self):
        invalid = (
            [],
            [{"kind": "HeaderTableSize", "value": 0}],
            [{"kind": "InitialWindowSize", "value": 0}] * 2,
            [{"kind": "InitialWindowSize", "value": True}],
            [{"kind": "InitialWindowSize", "value": 1.0}],
            [{"kind": "InitialWindowSize", "value": -1}],
            [{"kind": "InitialWindowSize", "value": 1 << 31}],
            [{"kind": "Unknown", "value": 0}],
            [{}] * 65,
        )
        for settings in invalid:
            with self.subTest(settings=settings):
                self.values["initial_settings"] = settings
                self.reject()
        for kind, value in (
            ("EnablePush", 0),
            ("EnableConnectProtocol", "false"),
            ("NoRfc7540Priorities", None),
            ("HeaderTableSize", 1 << 32),
            ("MaxConcurrentStreams", -1),
            ("MaxHeaderListSize", True),
            ("MaxFrameSize", (1 << 14) - 1),
            ("MaxFrameSize", 1 << 24),
        ):
            with self.subTest(kind=kind, value=value):
                self.values["initial_settings"] = [
                    {"kind": "InitialWindowSize", "value": 0},
                    {"kind": kind, "value": value},
                ]
                self.reject()

    def test_numeric_boundaries_and_optional_priority_values_are_supported(self):
        self.values["initial_settings"] = [
            {"kind": "InitialWindowSize", "value": (1 << 31) - 1},
            {"kind": "HeaderTableSize", "value": (1 << 32) - 1},
            {"kind": "MaxFrameSize", "value": (1 << 24) - 1},
            {"kind": "EnableConnectProtocol", "value": True},
            {"kind": "NoRfc7540Priorities", "value": False},
        ]
        self.values["initial_connection_window_size"] = (1 << 31) - 1
        self.values["headers_priority"] = {
            "dependency_stream_id": (1 << 31) - 1,
            "weight": 1,
            "exclusive": False,
        }
        self.values["extended_connect_priority"] = None
        self.values["extended_connect_pseudo_header_order"] = None
        self.resolve()
        self.values["initial_connection_window_size"] = 65_535
        self.resolve()

    def test_connection_window_and_priority_bounds_are_checked(self):
        for value in (65_534, 1 << 31, True, 65_535.0):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["initial_connection_window_size"] = (
                value
            )
            self.reject(document)
        for field, value in (
            ("dependency_stream_id", -1),
            ("dependency_stream_id", 1 << 31),
            ("weight", 0),
            ("weight", 257),
            ("weight", True),
            ("exclusive", 1),
            ("extra", False),
        ):
            with self.subTest(field=field, value=value):
                document = copy.deepcopy(self.document)
                document["components"][0]["values"]["headers_priority"][field] = value
                self.reject(document)

    def test_stream_identifiers_limits_and_closed_records_are_checked(self):
        for field, value in (
            ("first_stream_id", 0),
            ("first_stream_id", 2),
            ("first_stream_id", 1 << 31),
            ("first_stream_id", True),
            ("assumed_max_concurrent_streams", 0),
            ("assumed_max_concurrent_streams", 1 << 32),
            ("max_concurrent_streams_cap", -1),
            ("max_concurrent_streams_cap", False),
            ("unknown", 1),
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["streams"][field] = value
            self.reject(document)
        self.values["streams"] = {
            "first_stream_id": (1 << 31) - 1,
            "assumed_max_concurrent_streams": (1 << 32) - 1,
            "max_concurrent_streams_cap": None,
        }
        self.resolve()

    def test_hpack_enums_and_header_orders_are_closed(self):
        for field in http2.HTTP2_HPACK_ENUMS:
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["hpack"][field] = "Default"
            self.reject(document)
        for field, value in (
            ("pseudo_header_order", ["Method", "Path", "Scheme", "Scheme"]),
            ("pseudo_header_order", ["Method", "Path", "Scheme", "Protocol"]),
            ("extended_connect_pseudo_header_order", []),
            ("extended_connect_pseudo_header_order", "automatic"),
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"][field] = value
            self.reject(document)
        for headers in (["Method", "Method"], ["Unknown"], ["Method"] * 6, "Method"):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["hpack"]["literal_pseudo_headers"] = (
                headers
            )
            self.reject(document)

    def test_duration_representation_rejects_noncanonical_and_wrong_fields(self):
        invalid = (
            {"seconds": -1, "nanoseconds": 0},
            {"seconds": 1 << 64, "nanoseconds": 0},
            {"seconds": 1, "nanoseconds": 1_000_000_000},
            {"seconds": True, "nanoseconds": 0},
            {"seconds": 1, "nanoseconds": False},
            {"seconds": 1},
            {"seconds": 1, "nanoseconds": 0, "clock": "native"},
            10,
        )
        for duration in invalid:
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["preface_ping_after"] = duration
            self.reject(document)
        # Native validation, rather than a fabricated portable ceiling, checks
        # whether these stored durations fit the host's monotonic clock.
        self.values["preface_ping_after"] = {
            "seconds": (1 << 64) - 1,
            "nanoseconds": 999_999_999,
        }
        self.resolve()

    def test_ping_dependencies_positive_deadlines_and_retry_bounds_are_checked(self):
        for field in ("ping_timeout", "idle_ping_after", "idle_ping_timeout"):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"][field] = {
                "seconds": 0,
                "nanoseconds": 0,
            }
            self.reject(document)
        for after, timeout in (
            ("preface_ping_after", "ping_timeout"),
            ("idle_ping_after", "idle_ping_timeout"),
        ):
            document = copy.deepcopy(self.document)
            values = document["components"][0]["values"]
            values[after] = None
            values[timeout] = {"seconds": 0, "nanoseconds": 1}
            self.reject(document)
        self.values["preface_ping_after"] = {"seconds": 0, "nanoseconds": 0}
        self.resolve()  # The native settings permit an immediate preface PING.
        for retries in (-1, 256, True):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["ping_failure_retries"] = retries
            self.reject(document)
        self.values["ping_timeout"] = None
        self.values["idle_ping_timeout"] = None
        self.reject()
        self.values["ping_failure_retries"] = 0
        self.resolve()

    def test_idle_timer_range_and_variant_payload_are_checked(self):
        for duration in (
            {"seconds": 0, "nanoseconds": 999_999_999},
            {"seconds": 65_535, "nanoseconds": 1},
            {"seconds": 65_536, "nanoseconds": 0},
            None,
        ):
            self.values["idle_timeout"] = {
                "kind": "ClosedOnTimer",
                "duration": duration,
            }
            self.reject()
        for seconds, nanoseconds in ((1, 0), (65_534, 999_999_999), (65_535, 0)):
            self.values["idle_timeout"] = {
                "kind": "ClosedOnTimer",
                "duration": {"seconds": seconds, "nanoseconds": nanoseconds},
            }
            self.resolve()
        self.values["idle_timeout"] = {
            "kind": "Unlimited",
            "duration": {"seconds": 0, "nanoseconds": 0},
        }
        self.reject()
        self.values["idle_timeout"] = {"kind": "Default", "duration": None}
        self.reject()

    def test_check_rejects_each_of_the_three_stale_outputs(self):
        outputs = (
            ("OUTPUT", generator.generate(generator.load())),
            (
                "COMPONENT_OUTPUT",
                generator.generate_components(generator.load_components()),
            ),
            (
                "HTTP2_COMPONENT_OUTPUT",
                generator.generate_components(self.resolve(), "http2-components.json"),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            paths = {name: Path(directory) / f"{name}.rs" for name, _ in outputs}
            for stale in paths:
                with self.subTest(stale=stale):
                    for name, content in outputs:
                        paths[name].write_text("stale" if name == stale else content)
                    with (
                        mock.patch.multiple(generator, **paths),
                        mock.patch.object(
                            sys, "argv", ["generate_profiles.py", "--check"]
                        ),
                        mock.patch.object(generator.sys, "stderr"),
                    ):
                        self.assertEqual(generator.main(), 1)

    def test_invalid_http2_input_preserves_all_existing_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {
                name: Path(directory) / f"{name}.rs"
                for name in ("OUTPUT", "COMPONENT_OUTPUT", "HTTP2_COMPONENT_OUTPUT")
            }
            for path in paths.values():
                path.write_text("existing output")
            with (
                mock.patch.multiple(generator, **paths),
                mock.patch.object(
                    generator,
                    "load_http2_components",
                    side_effect=generator.DeclarationError(
                        "invalid HTTP/2 declaration"
                    ),
                ),
                mock.patch.object(sys, "argv", ["generate_profiles.py"]),
                mock.patch.object(generator.sys, "stderr"),
            ):
                self.assertEqual(generator.main(), 1)
            for path in paths.values():
                self.assertEqual(path.read_text(), "existing output")


if __name__ == "__main__":
    unittest.main()
