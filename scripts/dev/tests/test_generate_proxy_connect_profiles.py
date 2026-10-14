"""CONNECT declaration controls mirror native template validation."""

import copy
import json
import unittest

from scripts.dev.profile_catalog import cli as generator


class ProxyConnectComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(
            generator.PROXY_CONNECT_COMPONENT_RECORDS.read_text()
        )
        self.values = self.document["components"][0]["values"]

    def resolve(self, document=None):
        return generator.validate_components(
            self.document if document is None else document, ("ProxyConnectTemplate",)
        )

    def reject_field(self, field, value):
        document = copy.deepcopy(self.document)
        document["components"][0]["values"][field] = value
        with self.assertRaises(generator.DeclarationError):
            self.resolve(document)

    def test_committed_output_and_dictionary_order_are_deterministic(self):
        actual = generator.generate_components(
            self.resolve(), "proxy-connect-components.json"
        )
        self.assertEqual(generator.PROXY_CONNECT_COMPONENT_OUTPUT.read_text(), actual)
        self.document["components"].reverse()
        for component in self.document["components"]:
            component["values"] = dict(reversed(component["values"].items()))
            for field in ("http1_fields", "http2_fields"):
                if field in component["values"]:
                    component["values"][field] = [
                        dict(reversed(record.items()))
                        for record in component["values"][field]
                    ]
        self.assertEqual(
            generator.generate_components(
                self.resolve(), "proxy-connect-components.json"
            ),
            actual,
        )
        for variant in (
            "Authority",
            "Literal",
            "FromRequest",
            "ProxyAuthorization",
            "EndStream",
            "LeaveOpen",
            "Shared",
            "ByPurpose",
        ):
            self.assertIn("::" + variant, actual)

    def test_shared_http2_base_and_explicit_overrides_keep_order(self):
        records = self.resolve()
        self.assertEqual(
            records[0]["values"]["http2_fields"], records[1]["values"]["http2_fields"]
        )
        self.values["http2_fields"].reverse()
        self.assertEqual(
            self.resolve()[1]["values"]["http2_fields"], self.values["http2_fields"]
        )
        self.document["components"][1]["values"]["http2_fields"] = [
            {"kind": "ProxyAuthorization", "name": "proxy-authorization"}
        ]
        self.assertEqual(len(self.resolve()[1]["values"]["http2_fields"]), 1)

    def test_closed_policy_enum_domains_reject_nonvariants(self):
        for field in ("http2_rejected", "http2_connections"):
            for bad in (None, True, 1, "", "Unknown", {"kind": "Shared"}):
                self.reject_field(field, bad)

    def test_field_records_reject_missing_extra_and_unknown_shapes(self):
        for bad in (
            None,
            "Authority",
            {},
            {"kind": "Unknown", "name": "x"},
            {"kind": "Literal", "name": "x"},
            {"kind": "FromRequest", "name": "x", "value": "extra"},
            {"kind": "Authority", "name": "Host", "extra": False},
        ):
            self.reject_field("http1_fields", [bad] + self.values["http1_fields"][1:])
        for bad in (None, {}, "fields"):
            self.reject_field("http1_fields", bad)

    def test_names_reject_non_tokens_and_case_insensitive_duplicates(self):
        for name in ("", "bad name", "bad:name", "bad\nname", "Ã¤", "x" * 4097, 1):
            record = {"kind": "FromRequest", "name": name}
            self.reject_field("http1_fields", self.values["http1_fields"] + [record])
        self.reject_field(
            "http1_fields",
            self.values["http1_fields"]
            + [{"kind": "FromRequest", "name": "USER-AGENT"}],
        )
        valid = {"kind": "FromRequest", "name": "!#$%&'*+-.^_`|~012azAZ"}
        self.values["http1_fields"].append(valid)
        self.resolve()

    def test_authority_and_credentials_counts_and_spelling_are_exact(self):
        for kind in ("Authority", "ProxyAuthorization"):
            original = self.values["http1_fields"]
            self.reject_field(
                "http1_fields",
                [record for record in original if record["kind"] != kind],
            )
            self.reject_field(
                "http1_fields",
                original
                + [next(record for record in original if record["kind"] == kind)],
            )
            replaced = copy.deepcopy(original)
            next(record for record in replaced if record["kind"] == kind)["name"] = (
                "x-wrong"
            )
            self.reject_field("http1_fields", replaced)
        self.reject_field(
            "http2_fields", [{"kind": "FromRequest", "name": "user-agent"}]
        )
        self.reject_field(
            "http2_fields",
            self.values["http2_fields"] + [{"kind": "Authority", "name": "host"}],
        )
        self.values["http1_fields"][0]["name"] = "hOsT"
        self.values["http1_fields"][-1]["name"] = "pRoXy-AuThOrIzAtIoN"
        self.resolve()

    def test_framing_and_generated_fields_cannot_be_literals_or_copies(self):
        for kind in ("Literal", "FromRequest"):
            for name in (
                "Host",
                "Proxy-Authorization",
                "Content-Length",
                "Transfer-Encoding",
            ):
                record = {"kind": kind, "name": name}
                if kind == "Literal":
                    record["value"] = "value"
                self.reject_field(
                    "http1_fields", self.values["http1_fields"] + [record]
                )

    def test_request_copy_does_not_export_origin_credentials(self):
        for name in ("Authorization", "Cookie", "cOoKiE2"):
            self.reject_field(
                "http1_fields",
                self.values["http1_fields"] + [{"kind": "FromRequest", "name": name}],
            )

    def test_http2_requires_lowercase_and_refuses_connection_fields(self):
        self.reject_field(
            "http2_fields",
            self.values["http2_fields"]
            + [{"kind": "FromRequest", "name": "User-Agent"}],
        )
        for name in ("connection", "keep-alive", "proxy-connection", "te", "upgrade"):
            for kind in ("Literal", "FromRequest"):
                record = {"kind": kind, "name": name}
                if kind == "Literal":
                    record["value"] = "keep-alive"
                self.reject_field(
                    "http2_fields", self.values["http2_fields"] + [record]
                )

    def test_literal_values_allow_empty_tab_and_visible_ascii_only(self):
        for value in ("", "\t", ' \tvalue"\\~', "x" * 4096):
            self.values["http1_fields"][1]["value"] = value
            self.resolve()
            generated = generator.generate_components(
                self.resolve(), "proxy-connect-components.json"
            )
            self.assertNotIn(r"\u", generated)
        for value in (
            None,
            1,
            True,
            "\r",
            "\n",
            "\x00",
            "\x7f",
            "Ã¤",
            "\ud800",
            "x" * 4097,
        ):
            records = copy.deepcopy(self.values["http1_fields"])
            records[1]["value"] = value
            self.reject_field("http1_fields", records)

    def test_offline_list_ceiling_does_not_merge_or_sort_fields(self):
        original = self.values["http1_fields"]
        self.values["http1_fields"] = original + [
            {"kind": "FromRequest", "name": f"x-{n}"} for n in range(60)
        ]
        self.assertEqual(len(self.resolve()[0]["values"]["http1_fields"]), 64)
        self.reject_field(
            "http1_fields",
            self.values["http1_fields"] + [{"kind": "FromRequest", "name": "x-extra"}],
        )

    def test_component_refs_cycles_missing_and_unknown_fields_fail(self):
        for mode in ("unknown", "cycle", "duplicate", "missing", "extra", "kind"):
            document = copy.deepcopy(self.document)
            if mode == "unknown":
                document["components"][1]["base"] = "unknown_connect"
            elif mode == "cycle":
                document["components"][0]["base"] = document["components"][1]["id"]
            elif mode == "duplicate":
                document["components"].append(copy.deepcopy(document["components"][0]))
            elif mode == "missing":
                del document["components"][0]["values"]["http2_rejected"]
            elif mode == "extra":
                document["components"][0]["values"]["credentials"] = (
                    "not-a-component-field"
                )
            else:
                document["components"][0]["kind"] = "CookiePlacement"
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)


if __name__ == "__main__":
    unittest.main()
