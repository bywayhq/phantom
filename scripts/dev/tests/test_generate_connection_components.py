"""HTTP/1.1, DNS cache, and UDP declaration controls."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.dev.profile_catalog import cli as generator

REPO = Path(__file__).resolve().parents[3]


class ConnectionComponentTests(unittest.TestCase):
    def setUp(self):
        self.http1 = json.loads(generator.HTTP1_COMPONENT_RECORDS.read_text())
        self.dns = json.loads(generator.DNS_COMPONENT_RECORDS.read_text())
        self.udp = json.loads(generator.UDP_COMPONENT_RECORDS.read_text())

    def reject(self, document, kind):
        with self.assertRaises(generator.DeclarationError):
            generator.validate_components(document, (kind,))

    def test_all_domain_outputs_are_deterministic(self):
        for document, kind, source, output in (
            (
                self.http1,
                "Http1Settings",
                "http1-components.json",
                generator.HTTP1_COMPONENT_OUTPUT,
            ),
            (
                self.dns,
                "DnsCacheSettings",
                "dns-components.json",
                generator.DNS_COMPONENT_OUTPUT,
            ),
            (
                self.udp,
                "UdpSettings",
                "udp-components.json",
                generator.UDP_COMPONENT_OUTPUT,
            ),
        ):
            values = generator.validate_components(document, (kind,))
            generated = generator.generate_components(values, source)
            self.assertEqual(output.read_text(), generated)
            document["components"].reverse()
            for component in document["components"]:
                component["values"] = dict(reversed(component["values"].items()))
            self.assertEqual(
                generator.generate_components(
                    generator.validate_components(document, (kind,)), source
                ),
                generated,
            )
            self.assertNotIn("draw_", generated)
            if kind != "UdpSettings":
                self.assertIn("const { match std::num::NonZeroUsize::new(", generated)
                self.assertNotIn("unwrap_or", generated)

    def test_nonzero_limits_are_portable_and_do_not_change_custom_api_bounds(self):
        for document, kind, field in (
            (self.http1, "Http1Settings", "max_connections_per_origin"),
            (self.dns, "DnsCacheSettings", "max_entries"),
        ):
            for value in (-1, 0, True, False, 1.0, "6", None, 1 << 32):
                invalid = copy.deepcopy(document)
                invalid["components"][0]["values"][field] = value
                self.reject(invalid, kind)
            for value in (1, (1 << 32) - 1):
                document["components"][0]["values"][field] = value
                generator.validate_components(document, (kind,))

    def test_http1_timer_checks_exact_native_bounds_and_allows_zero(self):
        timeout = self.http1["components"][0]["values"]["idle_timeout"]
        timeout["kind"] = "ClosedOnTimer"
        for seconds, nanos in ((0, 0), (0, 999999999), (65535, 0)):
            timeout["duration"] = {"seconds": seconds, "nanoseconds": nanos}
            generator.validate_components(self.http1, ("Http1Settings",))
        for seconds, nanos in ((65535, 1), (65536, 0)):
            timeout["duration"] = {"seconds": seconds, "nanoseconds": nanos}
            self.reject(self.http1, "Http1Settings")
        timeout["kind"] = "CheckedOnRequest"
        timeout["duration"] = {"seconds": (1 << 64) - 1, "nanoseconds": 999999999}
        generator.validate_components(self.http1, ("Http1Settings",))

    def test_http1_timeout_variant_payloads_are_closed(self):
        for value in (
            None,
            "Unlimited",
            {"kind": "Unlimited", "duration": None},
            {"kind": "CheckedOnRequest"},
            {"kind": "ClosedOnTimer", "duration": None},
            {"kind": "Never", "duration": {"seconds": 1, "nanoseconds": 0}},
        ):
            document = copy.deepcopy(self.http1)
            document["components"][0]["values"]["idle_timeout"] = value
            self.reject(document, "Http1Settings")
        self.http1["components"][0]["values"]["idle_timeout"] = {"kind": "Unlimited"}
        generator.validate_components(self.http1, ("Http1Settings",))

    def test_duration_records_reject_noncanonical_types_and_unknown_fields(self):
        for invalid in (
            None,
            60,
            {"seconds": -1, "nanoseconds": 0},
            {"seconds": 1 << 64, "nanoseconds": 0},
            {"seconds": 1, "nanoseconds": 1000000000},
            {"seconds": True, "nanoseconds": 0},
            {"seconds": 1, "nanoseconds": False},
            {"seconds": 1},
            {"seconds": 1, "nanoseconds": 0, "clock": "host"},
        ):
            for field in ("ttl", "min_record_ttl", "negative_ttl"):
                if invalid is None and field == "negative_ttl":
                    continue
                document = copy.deepcopy(self.dns)
                document["components"][0]["values"][field] = invalid
                self.reject(document, "DnsCacheSettings")
            document = copy.deepcopy(self.http1)
            document["components"][0]["values"]["idle_timeout"]["duration"] = invalid
            self.reject(document, "Http1Settings")

    def test_dns_zero_and_full_duration_representations_are_preserved(self):
        values = self.dns["components"][0]["values"]
        for duration in (
            {"seconds": 0, "nanoseconds": 0},
            {"seconds": (1 << 64) - 1, "nanoseconds": 999999999},
        ):
            for field in ("ttl", "min_record_ttl", "negative_ttl"):
                values[field] = duration
            generator.validate_components(self.dns, ("DnsCacheSettings",))
        values["negative_ttl"] = None
        generated = generator.generate_components(
            generator.validate_components(self.dns), "dns-components.json"
        )
        self.assertIn("negative_ttl: None", generated)
        self.assertIn("negative_ttl: Some(std::time::Duration::new(60, 0))", generated)

    def test_system_dns_ttl_policies_are_closed_typed_values(self):
        for invalid in (None, True, 0, {}, [], "WindowsCache", "firefoxwindows"):
            document = copy.deepcopy(self.dns)
            document["components"][0]["values"]["system_ttl"] = invalid
            self.reject(document, "DnsCacheSettings")
        missing = copy.deepcopy(self.dns)
        del missing["components"][0]["values"]["system_ttl"]
        self.reject(missing, "DnsCacheSettings")
        for policy in ("Ignore", "FirefoxWindows"):
            self.dns["components"][0]["values"]["system_ttl"] = policy
            generated = generator.generate_components(
                generator.validate_components(self.dns), "dns-components.json"
            )
            self.assertIn(f"system_ttl: crate::SystemDnsTtlPolicy::{policy}", generated)

    def test_udp_port_randomization_is_boolean_and_preserves_false(self):
        values = self.udp["components"][0]["values"]
        for value in (0, 1, "true", None, [], {}):
            values["port_randomization"] = value
            self.reject(self.udp, "UdpSettings")
        values["port_randomization"] = False
        generated = generator.generate_components(
            generator.validate_components(self.udp), "udp-components.json"
        )
        self.assertIn("port_randomization: false", generated)

    def test_inheritance_replaces_complete_duration_and_idle_policy(self):
        self.dns["components"].append(
            {
                "id": "custom_dns",
                "kind": "DnsCacheSettings",
                "base": "chromium_154_dns_cache",
                "values": {
                    "ttl": {"seconds": 0, "nanoseconds": 1},
                    "negative_ttl": None,
                },
            }
        )
        resolved = {
            item["id"]: item["values"]
            for item in generator.validate_components(self.dns)
        }
        self.assertEqual(
            resolved["custom_dns"]["ttl"], {"seconds": 0, "nanoseconds": 1}
        )
        self.assertEqual(
            resolved["chromium_154_dns_cache"]["ttl"], {"seconds": 60, "nanoseconds": 0}
        )
        self.dns["components"][-1]["values"]["ttl"] = {"seconds": 1}
        self.reject(self.dns, "DnsCacheSettings")
        self.http1["components"].append(
            {
                "id": "custom_http1",
                "kind": "Http1Settings",
                "base": "chromium_154_http1",
                "values": {"idle_timeout": {"kind": "Unlimited"}},
            }
        )
        resolved = {
            item["id"]: item["values"]
            for item in generator.validate_components(self.http1)
        }
        self.assertEqual(
            resolved["custom_http1"]["idle_timeout"], {"kind": "Unlimited"}
        )

    def test_missing_fields_unknown_kinds_paths_references_and_cycles_fail(self):
        for original, kind in (
            (self.http1, "Http1Settings"),
            (self.dns, "DnsCacheSettings"),
            (self.udp, "UdpSettings"),
        ):
            for override in (
                {"base": "missing"},
                {"base": original["components"][0]["id"]},
                {"id": "crate::factory"},
                {"kind": "TlsSettings"},
                {"factory": "anything"},
            ):
                document = copy.deepcopy(original)
                document["components"][0].update(override)
                self.reject(document, kind)
            for values in ({}, {"unknown": 1}):
                document = copy.deepcopy(original)
                document["components"][0]["values"] = values
                self.reject(document, kind)
        document = copy.deepcopy(self.http1)
        document["components"].append(self.udp["components"][0])
        document["components"][0]["base"] = document["components"][-1]["id"]
        with self.assertRaises(generator.DeclarationError):
            generator.validate_components(document)

    def test_check_covers_eight_outputs_and_invalid_last_input_preserves_all(self):
        names = (
            "OUTPUT",
            "COMPONENT_OUTPUT",
            "HTTP2_COMPONENT_OUTPUT",
            "TLS_COMPONENT_OUTPUT",
            "QUIC_COMPONENT_OUTPUT",
            "HTTP1_COMPONENT_OUTPUT",
            "DNS_COMPONENT_OUTPUT",
            "UDP_COMPONENT_OUTPUT",
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
            for path in paths.values():
                path.write_text("sentinel")
            invalid = Path(directory) / "bad.json"
            self.udp["components"][0]["values"]["port_randomization"] = "false"
            invalid.write_text(json.dumps(self.udp))
            with (
                mock.patch.multiple(generator, **paths),
                mock.patch.object(sys, "argv", ["generate_profiles.py"]),
                mock.patch.object(generator.sys, "stderr"),
                mock.patch.object(
                    generator,
                    "load_udp_components",
                    side_effect=lambda: generator.validate_components(
                        generator.read_document(invalid), ("UdpSettings",)
                    ),
                ),
            ):
                self.assertEqual(generator.main(), 1)
            self.assertTrue(
                all(path.read_text() == "sentinel" for path in paths.values())
            )


if __name__ == "__main__":
    unittest.main()
