"""TCP socket-policy records and native validation boundary controls."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.dev.profile_catalog import cli as generator

REPO = Path(__file__).resolve().parents[3]


def duration(seconds, nanoseconds=0):
    return {"seconds": seconds, "nanoseconds": nanoseconds}


class TcpComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(generator.TCP_COMPONENT_RECORDS.read_text())
        self.values = self.document["components"][0]["values"]

    def resolve(self, document=None):
        return generator.validate_components(
            self.document if document is None else document, ("TcpSettings",)
        )

    def reject_field(self, field, value):
        document = copy.deepcopy(self.document)
        document["components"][0]["values"][field] = value
        with self.assertRaises(generator.DeclarationError):
            self.resolve(document)

    def test_committed_output_preserves_policies_and_is_deterministic(self):
        generated = generator.generate_components(self.resolve(), "tcp-components.json")
        self.assertEqual(generator.TCP_COMPONENT_OUTPUT.read_text(), generated)
        self.document["components"].reverse()
        for component in self.document["components"]:
            component["values"] = dict(reversed(component["values"].items()))
            for field in ("keepalive", "address_selection"):
                if field in component["values"]:
                    component["values"][field] = dict(
                        reversed(component["values"][field].items())
                    )
        self.assertEqual(
            generator.generate_components(self.resolve(), "tcp-components.json"),
            generated,
        )
        self.assertIn("TcpKeepalivePolicy::Schedule", generated)
        self.assertIn("TcpAddressSelection::Backup", generated)
        self.assertIn("std::num::NonZeroU32::new(524288)", generated)
        self.assertNotIn("draw_", generated)

    def test_socket_boolean_send_buffer_and_port_bounds_match_native_types(self):
        for value in (0, "true", None):
            self.reject_field("nodelay", value)
        for value in (0, -1, True, 1.0, (1 << 31), 1 << 32):
            self.reject_field("send_buffer_size", value)
        for value in (1, (1 << 31) - 1, None):
            self.values["send_buffer_size"] = value
            self.resolve()
        for value in (-1, True, 1 << 32):
            self.reject_field("port_randomization", {"minimum_windows_build": value})
        for value in (0, (1 << 32) - 1):
            self.values["port_randomization"] = {"minimum_windows_build": value}
            self.resolve()

    def test_schedule_socket_setters_are_required_booleans(self):
        schedule = self.document["components"][1]["values"]["keepalive"]
        for field in ("set_interval", "set_probe_count"):
            for invalid in (None, 0, 1, "true", []):
                document = copy.deepcopy(self.document)
                document["components"][1]["values"]["keepalive"][field] = invalid
                with (
                    self.subTest(field=field, invalid=invalid),
                    self.assertRaises(generator.DeclarationError),
                ):
                    self.resolve(document)
            document = copy.deepcopy(self.document)
            del document["components"][1]["values"]["keepalive"][field]
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)
            for value in (False, True):
                schedule[field] = value
                self.resolve()

    def test_fixed_keepalive_bounds_and_optional_interval_are_preserved(self):
        for field in ("idle", "interval"):
            for invalid in (duration(0), duration(32768), duration(1, 1), None):
                if invalid is None and field == "interval":
                    continue
                policy = copy.deepcopy(self.values["keepalive"])
                policy[field] = invalid
                self.reject_field("keepalive", policy)
        for seconds in (1, 32767):
            self.values["keepalive"] = {
                "kind": "Fixed",
                "idle": duration(seconds),
                "interval": None,
            }
            self.resolve()
            self.values["keepalive"]["interval"] = duration(seconds)
            self.resolve()

    def test_scheduled_keepalive_limits_reject_fractional_or_out_of_range_values(self):
        schedule = self.document["components"][1]["values"]["keepalive"]
        for field, maximum in (
            ("short_lived_idle", 32767),
            ("long_lived_idle", 32767),
            ("minimum_interval", 32767),
            ("short_lived_time", 300),
        ):
            for invalid in (duration(0), duration(maximum + 1), duration(1, 1)):
                policy = copy.deepcopy(schedule)
                policy[field] = invalid
                self.reject_field("keepalive", policy)
            for seconds in (1, maximum):
                self.values["keepalive"] = copy.deepcopy(schedule)
                self.values["keepalive"][field] = duration(seconds)
                self.resolve()
        for count in (0, 128, True):
            policy = copy.deepcopy(schedule)
            policy["probe_count"] = count
            self.reject_field("keepalive", policy)
        for count in (1, 127):
            self.values["keepalive"] = copy.deepcopy(schedule)
            self.values["keepalive"]["probe_count"] = count
            self.resolve()

    def test_racing_and_backup_delay_limits_preserve_subsecond_values(self):
        for kind, field in (("Racing", "fallback_delay"), ("Backup", "delay")):
            policy = {"kind": kind, field: duration(0, 1)}
            if kind == "Backup":
                policy["known_family_backup_timeout"] = None
                policy["socks_proxy_dns_feedback"] = "AllConnectFailures"
            for valid in (duration(0, 1), duration(10)):
                policy[field] = valid
                self.values["address_selection"] = policy
                self.resolve()
            for invalid in (duration(0), duration(10, 1), duration(11)):
                policy[field] = invalid
                self.reject_field("address_selection", policy)

    def test_socks_feedback_is_required_and_has_explicit_closed_values(self):
        for value in ("AllConnectFailures", "InitialConnectFailures"):
            self.document["components"][1]["values"]["address_selection"][
                "socks_proxy_dns_feedback"
            ] = value
            self.assertIn(
                f"SocksProxyDnsFeedback::{value}",
                generator.generate_components(self.resolve(), "tcp-components.json"),
            )
        for value in (None, True, 1, "all", "", []):
            document = copy.deepcopy(self.document)
            document["components"][1]["values"]["address_selection"][
                "socks_proxy_dns_feedback"
            ] = value
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)
        document = copy.deepcopy(self.document)
        del document["components"][1]["values"]["address_selection"][
            "socks_proxy_dns_feedback"
        ]
        with self.assertRaisesRegex(
            generator.DeclarationError, "socks_proxy_dns_feedback"
        ):
            self.resolve(document)

    def test_known_family_backup_timeouts_are_optional_whole_seconds(self):
        backup = self.document["components"][1]["values"]["address_selection"]
        for invalid in (duration(0), duration(601), duration(1, 1)):
            policy = copy.deepcopy(backup)
            policy["known_family_backup_timeout"] = invalid
            self.reject_field("address_selection", policy)
        for valid in (None, duration(1), duration(600)):
            self.values["address_selection"] = copy.deepcopy(backup)
            self.values["address_selection"]["known_family_backup_timeout"] = valid
            self.resolve()

    def test_unchanged_and_sequential_policies_have_closed_payloads(self):
        for policy in (
            None,
            "Unchanged",
            {"kind": "Disabled"},
            {"kind": "Unchanged", "idle": duration(1)},
            {"kind": "Fixed", "idle": duration(1)},
        ):
            self.reject_field("keepalive", policy)
        for policy in (
            None,
            "Sequential",
            {"kind": "First"},
            {"kind": "Sequential", "advance": "All"},
            {"kind": "Sequential", "advance": "AfterAnyFailure", "delay": duration(1)},
        ):
            self.reject_field("address_selection", policy)
        self.values["keepalive"] = {"kind": "Unchanged"}
        for advance in ("AfterAnyFailure", "AfterRefusalOrTimeout"):
            self.values["address_selection"] = {
                "kind": "Sequential",
                "advance": advance,
            }
            self.resolve()

    def test_typed_inheritance_replaces_complete_nested_policies(self):
        self.document["components"].append(
            {
                "id": "custom_tcp",
                "kind": "TcpSettings",
                "base": "chromium_154_tcp",
                "values": {
                    "keepalive": {"kind": "Unchanged"},
                    "address_selection": {
                        "kind": "Sequential",
                        "advance": "AfterAnyFailure",
                    },
                },
            }
        )
        resolved = {
            component["id"]: component["values"] for component in self.resolve()
        }
        self.assertEqual(resolved["custom_tcp"]["keepalive"], {"kind": "Unchanged"})
        self.assertEqual(resolved["chromium_154_tcp"]["keepalive"]["kind"], "Fixed")
        self.document["components"][-1]["values"]["keepalive"] = {
            "kind": "Fixed",
            "idle": duration(1),
        }
        with self.assertRaises(generator.DeclarationError):
            self.resolve()

    def test_bad_references_missing_fields_unknown_kinds_and_paths_are_rejected(self):
        for override in (
            {"base": "missing"},
            {"base": "chromium_154_tcp"},
            {"id": "crate::factory"},
            {"kind": "Http1Settings"},
            {"factory": "any"},
        ):
            document = copy.deepcopy(self.document)
            document["components"][0].update(override)
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)
        for values in ({}, {"unknown": 1}):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"] = values
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)
        self.document["components"].append(
            json.loads(generator.UDP_COMPONENT_RECORDS.read_text())["components"][0]
        )
        self.document["components"][0]["base"] = self.document["components"][-1]["id"]
        with self.assertRaises(generator.DeclarationError):
            generator.validate_components(self.document)

    def test_check_covers_nine_outputs_and_invalid_tcp_preserves_all(self):
        names = (
            "OUTPUT",
            "COMPONENT_OUTPUT",
            "HTTP2_COMPONENT_OUTPUT",
            "TLS_COMPONENT_OUTPUT",
            "QUIC_COMPONENT_OUTPUT",
            "HTTP1_COMPONENT_OUTPUT",
            "DNS_COMPONENT_OUTPUT",
            "UDP_COMPONENT_OUTPUT",
            "TCP_COMPONENT_OUTPUT",
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
            self.values["send_buffer_size"] = 0
            with (
                mock.patch.multiple(generator, **paths),
                mock.patch.object(sys, "argv", ["generate_profiles.py"]),
                mock.patch.object(generator.sys, "stderr"),
                mock.patch.object(
                    generator,
                    "load_tcp_components",
                    side_effect=lambda: generator.validate_components(
                        self.document, ("TcpSettings",)
                    ),
                ),
            ):
                self.assertEqual(generator.main(), 1)
            self.assertTrue(
                all(path.read_text() == "sentinel" for path in paths.values())
            )


if __name__ == "__main__":
    unittest.main()
