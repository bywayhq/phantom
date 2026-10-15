"""WebSocket declarations preserve typed policy and ordered field values."""

import copy
import json
import unittest

from scripts.dev.profile_catalog import cli as generator
from scripts.dev.profile_catalog.declarations import MAX_U64


class WebSocketComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(generator.WEBSOCKET_COMPONENT_RECORDS.read_text())
        self.values = self.document["components"][0]["values"]

    def resolve(self, document=None):
        return generator.validate_components(
            self.document if document is None else document, ("WebSocketSettings",)
        )

    def reject(self, field, value):
        document = copy.deepcopy(self.document)
        document["components"][0]["values"][field] = value
        with self.assertRaises(generator.DeclarationError):
            self.resolve(document)

    def test_original_field_counts_and_committed_output_are_deterministic(self):
        resolved = self.resolve()
        self.assertEqual(
            [
                [
                    len(item["values"][field])
                    for field in ("http1_fields", "http2_fields")
                ]
                for item in resolved
            ],
            [[13, 9], [14, 10], [17, 14]],
        )
        actual = generator.generate_components(resolved, "websocket-components.json")
        self.assertEqual(generator.WEBSOCKET_COMPONENT_OUTPUT.read_text(), actual)
        self.document["components"].reverse()
        for component in self.document["components"]:
            component["values"] = dict(reversed(component["values"].items()))
            for field in ("http1_fields", "http2_fields"):
                component["values"][field] = [
                    dict(reversed(item.items())) for item in component["values"][field]
                ]
        self.assertEqual(
            generator.generate_components(self.resolve(), "websocket-components.json"),
            actual,
        )

    def test_explicit_override_replaces_whole_lists_and_connection_policies(self):
        child = {
            "id": "derived_websocket",
            "kind": "WebSocketSettings",
            "base": self.document["components"][0]["id"],
            "values": {"http2_fields": [], "handshake_timeout": None},
        }
        self.document["components"].append(child)
        inherited = next(item for item in self.resolve() if item["id"] == child["id"])
        self.assertEqual(inherited["values"]["http2_fields"], [])
        self.assertIsNone(inherited["values"]["handshake_timeout"])
        self.assertEqual(inherited["values"]["connection"], self.values["connection"])
        child["values"]["connection"] = {"without_http2_session": "Http1Upgrade"}
        with self.assertRaises(generator.DeclarationError):
            self.resolve()

    def test_unknown_refs_cycles_kinds_and_top_level_fields_fail(self):
        for mode in ("unknown", "cycle", "duplicate", "missing", "extra", "kind"):
            document = copy.deepcopy(self.document)
            first, second = document["components"][:2]
            if mode == "unknown":
                first["base"] = "unknown_websocket"
            elif mode == "cycle":
                first["base"], second["base"] = second["id"], first["id"]
            elif mode == "duplicate":
                document["components"].append(copy.deepcopy(first))
            elif mode == "missing":
                del first["values"]["connection"]
            elif mode == "extra":
                first["values"]["browser"] = "Chromium"
            else:
                first["kind"] = "ProxyConnectTemplate"
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)

    def test_base_of_another_supported_kind_is_rejected(self):
        self.document["components"].append(
            {
                "id": "udp_base",
                "kind": "UdpSettings",
                "base": None,
                "values": {"port_randomization": True},
            }
        )
        self.document["components"][0]["base"] = "udp_base"
        with self.assertRaises(generator.DeclarationError):
            generator.validate_components(self.document)

    def test_connection_records_and_enum_variants_are_closed(self):
        for connection in (
            None,
            {},
            [],
            "connection",
            {**self.values["connection"], "extra": True},
        ):
            self.reject("connection", connection)
        for field in (
            "without_http2_session",
            "with_incapable_http2_session",
            "refused_stream_retry",
            "proxied_http2_session",
        ):
            for invalid in (None, True, 1, "", "Unknown", {"kind": "Reuse"}):
                connection = copy.deepcopy(self.values["connection"])
                connection[field] = invalid
                self.reject("connection", connection)
        for invalid in (None, True, 1, "", "Unknown"):
            self.reject("empty_message_compression", invalid)

    def test_all_connection_and_compression_variants_emit_exact_names(self):
        connection = self.values["connection"]
        connection["without_http2_session"] = "Http2ExtendedConnect"
        connection["with_incapable_http2_session"] = "Http2ExtendedConnect"
        connection["refused_stream_retry"] = "None"
        connection["proxied_http2_session"] = "Ignore"
        self.values["empty_message_compression"] = "Uncompressed"
        generated = generator.generate_components(
            self.resolve(), "websocket-components.json"
        )
        for name in ("Http2ExtendedConnect", "None", "Ignore", "Uncompressed"):
            self.assertIn("::" + name, generated)

    def test_reacquire_twice_is_explicit_and_preserves_existing_rules(self):
        self.values["connection"]["refused_stream_retry"] = "ReacquireTwice"
        resolved = self.resolve()
        self.assertEqual(
            resolved[0]["values"]["connection"]["refused_stream_retry"],
            "ReacquireTwice",
        )
        self.assertIn(
            "crate::WebSocketRefusedStreamRetry::ReacquireTwice",
            generator.generate_components(resolved, "websocket-components.json"),
        )
        for invalid in ("ReacquireOnce", "ReacquireThreeTimes", 2):
            self.reject(
                "connection",
                {**self.values["connection"], "refused_stream_retry": invalid},
            )

    def test_upgrade_alpn_requires_http1_and_excludes_http2(self):
        for invalid in (
            None,
            {},
            "http/1.1",
            [],
            [list(b"h2")],
            [list(b"http/1.1"), list(b"h2")],
        ):
            connection = copy.deepcopy(self.values["connection"])
            connection["http1_alpn_protocols"] = invalid
            self.reject("connection", connection)

    def test_alpn_byte_bounds_and_order_preserve_duplicates(self):
        for invalid in ([], [False], [-1], [256], [0] * 256, "http/1.1"):
            connection = copy.deepcopy(self.values["connection"])
            connection["http1_alpn_protocols"].append(invalid)
            self.reject("connection", connection)
        protocols = [list(b"other"), list(b"http/1.1"), list(b"http/1.1")] + [
            [0] * 255
        ] * 61
        self.values["connection"]["http1_alpn_protocols"] = protocols
        self.assertEqual(
            self.resolve()[0]["values"]["connection"]["http1_alpn_protocols"], protocols
        )
        self.reject(
            "connection",
            {**self.values["connection"], "http1_alpn_protocols": protocols + [[1]]},
        )

    def test_fields_require_exact_variant_shapes(self):
        for invalid in (
            None,
            [],
            "Literal",
            {},
            {"kind": "Unknown", "name": "x"},
            {"kind": "Literal", "name": "x"},
            {"kind": "Caller", "name": "x", "value": "extra"},
            {"kind": "ByTrust", "name": "x", "trustworthy": None},
        ):
            self.reject("http2_fields", [invalid])
        for invalid in (None, {}, "fields"):
            self.reject("http2_fields", invalid)

    def test_name_tokens_case_and_offline_length_bounds(self):
        for name in ("", "bad name", "bad:name", "x\n", "ä", "x" * 257, 1, None):
            self.reject("http2_fields", [{"kind": "Caller", "name": name}])
        self.reject("http2_fields", [{"kind": "Caller", "name": "User-Agent"}])
        names = ["!#$%&'*+-.^_`|~012az", "x" * 256]
        self.values["http2_fields"] = [
            {"kind": "Caller", "name": name} for name in names
        ]
        self.resolve()
        self.values["http1_fields"].append({"kind": "Caller", "name": "USER-AGENT"})
        self.resolve()

    def test_generated_placeholders_follow_native_counts(self):
        original = self.values["http1_fields"]
        for kind in ("Authority", "Key"):
            self.reject(
                "http1_fields", [item for item in original if item["kind"] != kind]
            )
            record = next(item for item in original if item["kind"] == kind)
            self.reject("http1_fields", original + [record])
            self.reject("http2_fields", [{"kind": kind, "name": "x"}])
        for kind in ("PerMessageDeflate", "ClientCookies"):
            record = {"kind": kind, "name": "x"}
            self.reject("http2_fields", [record, record])
        self.values["http2_fields"] = []
        self.resolve()

    def test_fixed_values_allow_empty_tabs_and_ascii_escaping(self):
        for value in ("", "\t", ' \tvalue"\\~', "x" * 4096):
            self.values["http2_fields"] = [
                {"kind": "Literal", "name": "x", "value": value}
            ]
            self.resolve()
            generated = generator.generate_components(
                self.resolve(), "websocket-components.json"
            )
            self.assertNotIn(r"\u", generated)
        for value in (
            None,
            False,
            1,
            "\r",
            "\n",
            "\x00",
            "\x7f",
            "ä",
            "\ud800",
            "x" * 4097,
        ):
            self.reject(
                "http2_fields", [{"kind": "Literal", "name": "x", "value": value}]
            )

    def test_trust_defaults_preserve_none_and_quoted_empty_values(self):
        self.values["http2_fields"] = [
            {"kind": "ByTrust", "name": "x", "trustworthy": "", "untrustworthy": None}
        ]
        actual = generator.generate_components(
            self.resolve(), "websocket-components.json"
        )
        self.assertIn('trustworthy: Some("".into()), untrustworthy: None', actual)
        for value in (False, 1, "\r", "ä", "x" * 4097):
            for trust in ("trustworthy", "untrustworthy"):
                record = copy.deepcopy(self.values["http2_fields"][0])
                record[trust] = value
                self.reject("http2_fields", [record])
        self.values["http2_fields"][0]["trustworthy"] = None
        self.resolve()

    def test_offline_field_ceiling_preserves_repeated_ordinary_fields(self):
        fields = [{"kind": "Caller", "name": "repeated"}] * 256
        self.values["http2_fields"] = fields
        self.assertEqual(self.resolve()[0]["values"]["http2_fields"], fields)
        self.reject("http2_fields", fields + [fields[0]])

    def test_all_deflate_variants_and_optional_client_width_emit(self):
        offer = [
            {"kind": "ServerNoContextTakeover"},
            {"kind": "ClientNoContextTakeover"},
            {"kind": "ServerMaxWindowBits", "bits": 8},
            {"kind": "ClientMaxWindowBits", "bits": None},
        ]
        self.values["permessage_deflate_offer"] = offer
        generated = generator.generate_components(
            self.resolve(), "websocket-components.json"
        )
        for parameter in offer:
            self.assertIn("::" + parameter["kind"], generated)
        self.assertIn("::ClientMaxWindowBits(None)", generated)
        for bits in (8, 15):
            offer[-1]["bits"] = bits
            generated = generator.generate_components(
                self.resolve(), "websocket-components.json"
            )
            self.assertIn(f"::ClientMaxWindowBits(Some({bits}))", generated)

    def test_deflate_shapes_duplicates_and_window_bounds_fail(self):
        for invalid in (
            None,
            {},
            "offer",
            [{"kind": "Unknown"}],
            [None],
            [{"kind": "ServerMaxWindowBits"}],
            [{"kind": "ClientMaxWindowBits"}],
            [{"kind": "ServerNoContextTakeover", "bits": None}],
            [{"kind": "ClientNoContextTakeover"}] * 2,
            [{"kind": "ServerNoContextTakeover"}] * 5,
        ):
            self.reject("permessage_deflate_offer", invalid)
        for kind in ("ServerMaxWindowBits", "ClientMaxWindowBits"):
            for bits in (False, 7, 16, "8", 8.0):
                self.reject("permessage_deflate_offer", [{"kind": kind, "bits": bits}])
        self.reject(
            "permessage_deflate_offer", [{"kind": "ServerMaxWindowBits", "bits": None}]
        )

    def test_optional_timeout_keeps_full_duration_range_but_excludes_zero(self):
        for timeout in (
            None,
            {"seconds": 0, "nanoseconds": 1},
            {"seconds": MAX_U64, "nanoseconds": 999_999_999},
        ):
            self.values["handshake_timeout"] = timeout
            self.resolve()
        for timeout in (
            0,
            False,
            {},
            {"seconds": 0, "nanoseconds": 0},
            {"seconds": True, "nanoseconds": 0},
            {"seconds": -1, "nanoseconds": 0},
            {"seconds": MAX_U64 + 1, "nanoseconds": 0},
            {"seconds": 1, "nanoseconds": 1_000_000_000},
            {"seconds": 1, "nanoseconds": 0, "extra": False},
        ):
            self.reject("handshake_timeout", timeout)

    def test_edge_android_keeps_source_slot_order_and_explicit_retry_policy(self):
        edge = next(
            item["values"]
            for item in self.resolve()
            if item["id"] == "edge_android_153_websocket"
        )
        self.assertEqual(
            edge["connection"],
            {
                "without_http2_session": "Http1Upgrade",
                "with_incapable_http2_session": "Http1Upgrade",
                "http1_alpn_protocols": [list(b"http/1.1")],
                "refused_stream_retry": "ReacquireTwice",
                "proxied_http2_session": "Reuse",
            },
        )
        self.assertEqual(
            [field["name"] for field in edge["http1_fields"]],
            [
                "Host",
                "Connection",
                "Pragma",
                "Cache-Control",
                "User-Agent",
                "Upgrade",
                "Origin",
                "Sec-WebSocket-Version",
                "Accept-Encoding",
                "Accept-Language",
                "Cookie",
                "Sec-WebSocket-Key",
                "Sec-WebSocket-Extensions",
                "Sec-WebSocket-Protocol",
            ],
        )
        self.assertEqual(
            [field["name"] for field in edge["http2_fields"]],
            [
                "pragma",
                "cache-control",
                "user-agent",
                "origin",
                "sec-websocket-version",
                "accept-encoding",
                "accept-language",
                "cookie",
                "sec-websocket-extensions",
                "sec-websocket-protocol",
            ],
        )


if __name__ == "__main__":
    unittest.main()
