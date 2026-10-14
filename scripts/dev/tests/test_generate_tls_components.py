"""Closed TLS policy declarations, byte bounds, and deterministic output."""

import copy
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.dev.profile_catalog import cli as generator
from scripts.dev.profile_catalog import declarations

REPO = Path(__file__).resolve().parents[3]


class TlsComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(generator.TLS_COMPONENT_RECORDS.read_text())
        self.values = self.document["components"][0]["values"]

    def resolve(self, document=None):
        return generator.validate_components(
            self.document if document is None else document, ("TlsSettings",)
        )

    def reject(self, document=None):
        with self.assertRaises(generator.DeclarationError):
            self.resolve(document)

    def test_committed_generation_retains_inherited_values_and_runtime_policies(self):
        expected = generator.generate_components(self.resolve(), "tls-components.json")
        self.document["components"].reverse()
        for component in self.document["components"]:
            component["values"] = dict(reversed(component["values"].items()))
        self.assertEqual(
            generator.generate_components(self.resolve(), "tls-components.json"),
            expected,
        )
        self.assertEqual(generator.TLS_COMPONENT_OUTPUT.read_text(), expected)
        self.assertIn("TrustAnchorOrder::valid_recipe_ids", expected)
        self.assertIn("ClientHelloExtensionOrder::PermutedWithTail", expected)
        self.assertIn("maximum_name_length: 100", expected)
        self.assertIn("EchGreaseAead::ChaCha20Poly1305", expected)
        self.assertIn("SessionTicketOrder::OldestConnectionFirst", expected)
        self.assertNotIn("draw_", expected)
        self.assertNotIn("expect(", expected)
        self.assertNotIn("unwrap(", expected)

    def test_private_generated_names_cannot_collide_with_component_identifiers(self):
        for identifier in (
            "valid_recipe_trust_candidates",
            "trust_candidate_assertion_accepts_declared_count_ceilings",
        ):
            document = copy.deepcopy(self.document)
            document["components"].append(
                {
                    "id": identifier,
                    "kind": "TlsSettings",
                    "base": "chromium_154_tcp_tls",
                    "values": {},
                }
            )
            output = generator.generate_components(
                self.resolve(document), "tls-components.json"
            )
            self.assertEqual(output.count(f"fn {identifier}"), 1)
            self.assertIn("const fn _valid_recipe_trust_candidates", output)
        for identifier in (
            "_valid_recipe_trust_candidates",
            "_trust_candidate_assertion_accepts_declared_count_ceilings",
        ):
            with self.assertRaises(generator.DeclarationError):
                declarations.component_identifier(identifier)

    def test_quic_overrides_replace_complete_typed_fields(self):
        resolved = {item["id"]: item["values"] for item in self.resolve()}
        chrome_tcp = resolved["chromium_154_tcp_tls"]
        chrome_quic = resolved["chromium_154_quic_tls"]
        firefox_tcp = resolved["firefox_157_tcp_tls"]
        firefox_quic = resolved["firefox_157_quic_tls"]
        self.assertEqual(len(chrome_tcp["cipher_suites"]), 15)
        self.assertEqual(len(chrome_quic["cipher_suites"]), 3)
        self.assertEqual(
            chrome_tcp["requested_trust_anchor_ids"],
            chrome_quic["requested_trust_anchor_ids"],
        )
        self.assertEqual(chrome_quic["alps"]["protocol"], [104, 51])
        self.assertEqual(
            firefox_quic["certificate_compression"], ["Zlib", "Zstd", "Brotli"]
        )
        self.assertTrue(firefox_tcp["tcp_early_data"])
        self.assertFalse(firefox_quic["tcp_early_data"])
        del self.document["components"][1]["values"]["alps"]["use_new_codepoint"]
        self.reject()

    def test_branded_and_android_overrides_replace_only_original_fields(self):
        resolved = {item["id"]: item["values"] for item in self.resolve()}
        for brand in ("edge", "brave"):
            for transport in ("tcp", "quic"):
                expected = copy.deepcopy(resolved[f"chromium_154_{transport}_tls"])
                expected["requested_trust_anchor_ids"] = None
                self.assertEqual(resolved[f"{brand}_154_{transport}_tls"], expected)
        grease = {
            "kind": "Grease",
            "settings": {
                "payload_length": {"kind": "BackendDefault", "value": None},
                "aeads": [],
            },
        }
        for brand, version in (("chromium", 154), ("edge", 153), ("brave", 153)):
            for transport in ("tcp", "quic"):
                expected = copy.deepcopy(resolved[f"{brand}_154_{transport}_tls"])
                expected["ech"] = grease
                self.assertEqual(
                    resolved[f"{brand}_{version}_android_{transport}_tls"], expected
                )
        expected = copy.deepcopy(resolved["firefox_157_tcp_tls"])
        expected["session_ticket_order"] = "OldestFirst"
        self.assertEqual(resolved["firefox_156_android_tcp_tls"], expected)
        expected = copy.deepcopy(resolved["chromium_154_tcp_tls"])
        expected.update(ech=grease, requested_trust_anchor_ids=None)
        self.assertEqual(resolved["opera_102_android_tcp_tls"], expected)

    def test_opera_retains_all_candidate_slots_with_native_multiset_assertions(self):
        resolved = {item["id"]: item["values"] for item in self.resolve()}
        for transport, kind, weights in (
            ("tcp", "PerClient", [5, 4, 3, 2, 2, 2, 2] + [1] * 9),
            ("quic", "PerConnection", [2] + [1] * 18),
        ):
            values = resolved[f"opera_136_{transport}_tls"]
            anchors = values["requested_trust_anchor_ids"]
            self.assertEqual(anchors["kind"], kind)
            self.assertEqual(len(anchors["orders"]), sum(weights))
            self.assertEqual(
                [len(list(group)) for _, group in itertools.groupby(anchors["orders"])],
                weights,
            )
            self.assertTrue(all(len(order) == 32 for order in anchors["orders"]))
            expected = copy.deepcopy(resolved[f"chromium_154_{transport}_tls"])
            expected["requested_trust_anchor_ids"] = anchors
            self.assertEqual(values, expected)
        generated = generator.generate_components(self.resolve(), "tls-components.json")
        self.assertEqual(
            generated.count("const _: () = assert!(_valid_recipe_trust_candidates("), 2
        )
        self.assertIn("trust_candidate_assertion_preserves_multisets", generated)
        self.values["requested_trust_anchor_ids"] = {
            "kind": "PerClient",
            "orders": [[]] * 65,
        }
        self.reject()

    def test_unknown_values_fields_and_wrong_layer_are_rejected(self):
        for field, value in (
            ("grease", 1),
            ("session_ticket_order", "Latest"),
            ("factory", "chrome::v154_tcp_tls"),
            ("cipher_suites", ["Unknown"]),
            ("groups", ["Unknown"]),
            ("signature_schemes", ["Unknown"]),
            ("certificate_compression", ["Unknown"]),
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"][field] = value
            self.reject(document)
        self.document["components"][0]["kind"] = "Http2Settings"
        self.reject()

    def test_version_endpoints_and_ranges_are_checked(self):
        for versions in (
            {"min": "Tls13", "max": "Tls12"},
            {"min": "Tls12", "max": "Latest"},
            {"min": 12, "max": 13},
            {"min": "Tls12"},
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["versions"] = versions
            self.reject(document)

    def test_nonempty_algorithm_lists_and_key_share_membership_are_checked(self):
        for field in ("cipher_suites", "groups", "signature_schemes", "key_shares"):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"][field] = []
            self.reject(document)
        self.values["key_shares"] = ["Ffdhe2048"]
        self.reject()
        self.values["key_shares"] = ["X25519"] * 65
        self.reject()

    def test_allowed_repeated_algorithm_values_keep_their_positions(self):
        self.values["cipher_suites"] = ["Aes128GcmSha256", "Aes128GcmSha256"]
        self.values["groups"] = ["X25519", "X25519"]
        self.values["key_shares"] = ["X25519", "X25519"]
        self.values["signature_schemes"] = ["EcdsaSha1", "EcdsaSha1"]
        resolved = {item["id"]: item["values"] for item in self.resolve()}
        self.assertEqual(
            resolved["chromium_154_tcp_tls"]["groups"], ["X25519", "X25519"]
        )

    def test_tls12_rejects_tls13_only_settings_and_accepts_eligible_values(self):
        base = copy.deepcopy(self.values)
        base.update(
            versions={"min": "Tls12", "max": "Tls12"},
            key_shares=[],
            delegated_credential_schemes=[],
            certificate_compression=[],
            requested_trust_anchor_ids=None,
            alps=None,
            tcp_early_data=False,
            ech={"kind": "Disabled", "settings": None},
        )
        document = {
            "schema": 1,
            "components": [
                {
                    "id": "tls12",
                    "kind": "TlsSettings",
                    "base": None,
                    "values": base,
                }
            ],
        }
        self.resolve(document)
        for field, value in (
            ("key_shares", ["X25519"]),
            ("delegated_credential_schemes", ["EcdsaSha1"]),
            ("certificate_compression", ["Brotli"]),
            ("tcp_early_data", True),
            ("requested_trust_anchor_ids", {"kind": "Fixed", "orders": [[]]}),
            ("alps", self.values["alps"]),
            ("ech", self.values["ech"]),
        ):
            invalid = copy.deepcopy(document)
            invalid["components"][0]["values"][field] = value
            self.reject(invalid)

    def test_delegated_schemes_and_repeated_compression_are_rejected(self):
        self.values["delegated_credential_schemes"] = ["RsaPssRsaeSha256"]
        self.reject()
        self.values["delegated_credential_schemes"] = ["EcdsaSha1"]
        self.resolve()
        self.values["certificate_compression"] = ["Brotli", "Brotli"]
        self.reject()

    def test_ticket_payload_limits_and_early_data_dependency_are_checked(self):
        for value in (0, 11, True, 2.0, None):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["session_tickets"]["tcp_per_origin"] = (
                value
            )
            self.reject(document)
        for value in (1, 10):
            self.values["session_tickets"]["tcp_per_origin"] = value
            self.resolve()
        self.values["session_tickets"] = {"enabled": False, "tcp_per_origin": None}
        self.resolve()
        self.values["tcp_early_data"] = True
        self.reject()
        self.values["tcp_early_data"] = False
        self.values["session_tickets"]["tcp_per_origin"] = 2
        self.reject()

    def test_alpn_protocol_bytes_and_encoded_list_bounds_are_checked(self):
        for protocols in ([], [[]], [[256]], [[True]], [[0] * 256], [[104]] * 256):
            document = copy.deepcopy(self.document)
            values = document["components"][0]["values"]
            values["alps"] = None
            values["alpn_protocols"] = protocols
            if protocols == [[104]] * 256:
                self.resolve(
                    document
                )  # Repeated protocol bytes are permitted natively.
            else:
                self.reject(document)
        self.values["alps"] = None
        self.values["alpn_protocols"] = [[0] * 255] * 256
        self.reject()
        self.values["alpn_protocols"][-1] = [0] * 254
        self.resolve()

    def test_alps_protocol_payload_and_codepoint_are_checked(self):
        for field, value in (
            ("protocol", [104, 51]),
            ("settings", [0] * 65_536),
            ("settings", [-1]),
            ("use_new_codepoint", 1),
            ("extra", 1),
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["alps"][field] = value
            self.reject(document)
        self.values["alps"]["settings"] = [0] * 65_535
        self.resolve()

    def test_trust_candidates_preserve_duplicates_order_and_draw_weight(self):
        self.values["requested_trust_anchor_ids"] = {
            "kind": "PerClient",
            "orders": [[[2], [1], [1]], [[1], [2], [1]], [[2], [1], [1]]],
        }
        resolved = {item["id"]: item["values"] for item in self.resolve()}
        self.assertEqual(
            resolved["chromium_154_tcp_tls"]["requested_trust_anchor_ids"],
            self.values["requested_trust_anchor_ids"],
        )
        generated = generator.generate_components(self.resolve(), "tls-components.json")
        self.assertIn("TrustAnchorIds::PerClient", generated)
        self.assertIn("TrustAnchorOrders::from_recipe", generated)
        self.assertIn("&[(&[1], 2), (&[2], 1)]", generated)
        self.assertIn("_valid_recipe_trust_candidates", generated)
        self.values["requested_trust_anchor_ids"]["kind"] = "PerConnection"
        self.resolve()
        self.values["requested_trust_anchor_ids"]["orders"][-1] = [[2], [1]]
        self.reject()

    def test_trust_id_byte_limits_empty_orders_and_encoded_bound_are_checked(self):
        for value in (
            {"kind": "Fixed", "orders": []},
            {"kind": "Fixed", "orders": [[], []]},
            {"kind": "PerClient", "orders": []},
            {"kind": "Fixed", "orders": [[[]]]},
            {"kind": "Fixed", "orders": [[[0] * 256]]},
            {"kind": "Fixed", "orders": [[[False]]]},
            {"kind": "Unknown", "orders": [[]]},
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["requested_trust_anchor_ids"] = value
            self.reject(document)
        self.values["requested_trust_anchor_ids"] = {"kind": "Fixed", "orders": [[]]}
        self.resolve()
        self.values["requested_trust_anchor_ids"] = {
            "kind": "PerClient",
            "orders": [[], []],
        }
        self.resolve()
        self.values["requested_trust_anchor_ids"] = {
            "kind": "Fixed",
            "orders": [[[0] * 255] * 255 + [[0] * 254]],
        }
        self.reject()  # Encoded length 65535 exceeds the extension's 65533.
        self.values["requested_trust_anchor_ids"]["orders"][0][-1] = [0] * 252
        self.resolve()

    def test_ech_modes_payloads_and_aead_choices_are_checked(self):
        for payload in (
            {"kind": "Exact", "value": 0},
            {"kind": "Exact", "value": 65_494},
            {"kind": "FromClientHello", "value": 256},
            {"kind": "BackendDefault", "value": 1},
            {"kind": "Unknown", "value": None},
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["ech"]["settings"]["payload_length"] = (
                payload
            )
            self.reject(document)
        for aeads in (["Aes128Gcm", "Aes128Gcm"], ["Unknown"], [False]):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["ech"]["settings"]["aeads"] = aeads
            self.reject(document)
        for value in (1, 65_493):
            self.values["ech"]["settings"]["payload_length"] = {
                "kind": "Exact",
                "value": value,
            }
            self.resolve()
        self.values["ech"]["kind"] = "Disabled"
        self.reject()
        self.values["ech"]["settings"] = None
        self.resolve()

    def test_extension_policy_lists_and_record_size_bounds_are_checked(self):
        for order in (
            {"kind": "Permuted", "extensions": ["ServerName"]},
            {"kind": "Fixed", "extensions": []},
            {"kind": "PermutedWithTail", "extensions": ["Alpn", "Alpn"]},
            {"kind": "Fixed", "extensions": ["Unknown"]},
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["extension_order"] = order
            self.reject(document)
        for limit in (63, 16_386, True):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["record_size_limit"] = limit
            self.reject(document)
        for limit in (64, 16_385):
            self.values["record_size_limit"] = limit
            self.resolve()

    def test_check_rejects_each_of_four_stale_outputs(self):
        outputs = {
            "OUTPUT": generator.generate(generator.load()),
            "COMPONENT_OUTPUT": generator.generate_components(
                generator.load_components()
            ),
            "HTTP2_COMPONENT_OUTPUT": generator.generate_components(
                generator.load_http2_components(), "http2-components.json"
            ),
            "TLS_COMPONENT_OUTPUT": generator.generate_components(
                self.resolve(), "tls-components.json"
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = {name: Path(directory) / f"{name}.rs" for name in outputs}
            for stale in paths:
                for name, content in outputs.items():
                    paths[name].write_text("stale" if name == stale else content)
                with (
                    mock.patch.multiple(generator, **paths),
                    mock.patch.object(sys, "argv", ["generate_profiles.py", "--check"]),
                    mock.patch.object(generator.sys, "stderr"),
                ):
                    self.assertEqual(generator.main(), 1)

    def test_invalid_tls_preserves_all_existing_generated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {
                name: Path(directory) / f"{name}.rs"
                for name in (
                    "OUTPUT",
                    "COMPONENT_OUTPUT",
                    "HTTP2_COMPONENT_OUTPUT",
                    "TLS_COMPONENT_OUTPUT",
                )
            }
            for path in paths.values():
                path.write_text("existing output")
            with (
                mock.patch.multiple(generator, **paths),
                mock.patch.object(
                    generator,
                    "load_tls_components",
                    side_effect=generator.DeclarationError("invalid TLS"),
                ),
                mock.patch.object(sys, "argv", ["generate_profiles.py"]),
                mock.patch.object(generator.sys, "stderr"),
            ):
                self.assertEqual(generator.main(), 1)
            for path in paths.values():
                self.assertEqual(path.read_text(), "existing output")


if __name__ == "__main__":
    unittest.main()
