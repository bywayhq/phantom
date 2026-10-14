"""Ordered hint declarations and existing model parameters stay closed."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.dev.profile_catalog import cli as generator
from scripts.dev.profile_catalog import declarations


class ClientHintComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(generator.CLIENT_HINTS_COMPONENT_RECORDS.read_text())
        self.values = self.document["components"][0]["values"]

    def resolve(self, document=None):
        return generator.validate_components(
            self.document if document is None else document, ("ClientHintSettings",)
        )

    def reject_hints(self, hints):
        document = copy.deepcopy(self.document)
        document["components"][0]["values"]["hints"] = hints
        with self.assertRaises(generator.DeclarationError):
            self.resolve(document)

    @staticmethod
    def literal(name="x-hint", value="", delivery="Default"):
        return {
            "name": name,
            "delivery": delivery,
            "value": {"kind": "Literal", "value": value},
        }

    @staticmethod
    def model(default="Pixel 7"):
        return {
            "name": "sec-ch-ua-model",
            "delivery": "AcceptCh",
            "value": {"kind": "Model", "default": default},
        }

    def test_all_factories_order_flags_and_model_slots_are_explicit(self):
        components = self.resolve()
        original = [c for c in components if c["id"] != "edge_windows_153_client_hints"]
        self.assertEqual(len(original), 11)
        self.assertEqual(sum(len(c["values"]["hints"]) for c in original), 117)
        self.assertEqual(len(components), 12)
        self.assertEqual(sum(len(c["values"]["hints"]) for c in components), 128)
        models = []
        for component in components:
            hints = component["values"]["hints"]
            self.assertEqual(
                [h["name"] for h in hints if h["delivery"] == "Default"],
                ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"],
            )
            if component["id"].startswith("brave_"):
                self.assertEqual(len(hints), 9)
                self.assertNotIn("sec-ch-ua-full-version", [h["name"] for h in hints])
                self.assertNotIn("sec-ch-ua-form-factors", [h["name"] for h in hints])
            else:
                self.assertEqual(len(hints), 11)
            for hint in hints:
                if hint["value"]["kind"] == "Model":
                    models.append(component["id"])
                    self.assertEqual(hint["value"]["default"], "Pixel 7")
        self.assertEqual(
            models,
            [
                "chrome_android_154_client_hints",
                "edge_android_153_client_hints",
                "opera_android_102_client_hints",
            ],
        )

    def test_historical_edge_hints_preserve_all_ordered_literal_values(self):
        component = next(
            c for c in self.resolve() if c["id"] == "edge_windows_153_client_hints"
        )
        expected = [
            (
                "sec-ch-ua",
                '"Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
                "Default",
            ),
            ("sec-ch-ua-mobile", "?0", "Default"),
            ("sec-ch-ua-full-version", '"153.0.4234.48"', "AcceptCh"),
            ("sec-ch-ua-arch", '"x86"', "AcceptCh"),
            ("sec-ch-ua-platform", '"Windows"', "Default"),
            ("sec-ch-ua-platform-version", '"19.0.0"', "AcceptCh"),
            ("sec-ch-ua-model", '""', "AcceptCh"),
            ("sec-ch-ua-bitness", '"64"', "AcceptCh"),
            ("sec-ch-ua-wow64", "?0", "AcceptCh"),
            (
                "sec-ch-ua-full-version-list",
                '"Microsoft Edge";v="153.0.4234.48", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.53"',
                "AcceptCh",
            ),
            ("sec-ch-ua-form-factors", '"Desktop"', "AcceptCh"),
        ]
        self.assertEqual(
            [
                (h["name"], h["value"]["value"], h["delivery"])
                for h in component["values"]["hints"]
            ],
            expected,
        )
        self.assertTrue(
            all(h["value"]["kind"] == "Literal" for h in component["values"]["hints"])
        )

    def test_committed_output_and_object_order_are_deterministic(self):
        actual = generator.generate_components(
            self.resolve(), "client-hints-components.json"
        )
        self.assertEqual(generator.CLIENT_HINTS_COMPONENT_OUTPUT.read_text(), actual)
        self.document["components"].reverse()
        for component in self.document["components"]:
            component["values"]["hints"] = [
                dict(reversed(hint.items())) for hint in component["values"]["hints"]
            ]
            for hint in component["values"]["hints"]:
                hint["value"] = dict(reversed(hint["value"].items()))
        self.assertEqual(
            generator.generate_components(
                self.resolve(), "client-hints-components.json"
            ),
            actual,
        )
        self.assertEqual(actual.count("model_value(model)"), 3)
        self.assertEqual(actual.count('_for_model("Pixel 7")'), 3)
        self.assertIn("crate::ClientHintSettings::new(vec![", actual)
        self.assertNotIn("draw_", actual)

    def test_literal_empty_quoted_empty_tab_and_escaping_are_preserved(self):
        for value in ("", '""', "\t", ' \tvalue"\\~', "x" * 4096):
            self.values["hints"] = [self.literal(value=value)]
            self.assertEqual(
                self.resolve()[0]["values"]["hints"][0]["value"]["value"], value
            )
            output = generator.generate_components(
                self.resolve(), "client-hints-components.json"
            )
            self.assertNotIn(r"\u", output)
        self.values["hints"] = []
        self.assertEqual(self.resolve()[0]["values"]["hints"], [])

    def test_native_name_syntax_and_exact_duplicates_are_checked(self):
        for name in (
            "",
            "0hint",
            "_hint",
            "A",
            "x-Hint",
            "x hint",
            "x:hint",
            "x\n",
            "ä",
            "x" * 4097,
            1,
            None,
        ):
            self.reject_hints([self.literal(name=name)])
        self.reject_hints([self.literal(), self.literal()])
        self.values["hints"] = [self.literal(name="x!#$%&'*+-.^_`|~012az")]
        self.resolve()

    def test_invalid_literal_bytes_and_types_fail(self):
        for value in (
            None,
            1,
            True,
            "\r",
            "\n",
            "\x00",
            "\x7f",
            "ä",
            "\ud800",
            "x" * 4097,
        ):
            self.reject_hints([self.literal(value=value)])

    def test_model_defaults_preserve_runtime_encoder_input_domain(self):
        for value in ("", " ~", 'a"b\\c', "x" * 4096):
            self.values["hints"] = [self.model(value)]
            self.assertEqual(
                self.resolve()[0]["values"]["hints"][0]["value"]["default"], value
            )
        for value in (
            None,
            True,
            1,
            "\t",
            "\n",
            "\x00",
            "\x7f",
            "ä",
            "\ud800",
            "x" * 4097,
        ):
            self.reject_hints([self.model(value)])

    def test_model_is_only_the_requested_model_field(self):
        for field, value in (("name", "x-model"), ("delivery", "Default")):
            hint = self.model()
            hint[field] = value
            self.reject_hints([hint])
        self.reject_hints([self.model(), self.model()])

    def test_closed_record_shapes_delivery_and_value_kinds_fail(self):
        for bad in (None, "hint", {}, {"name": "x"}, {**self.literal(), "extra": 1}):
            self.reject_hints([bad])
        for delivery in (None, True, 1, "", "accept-ch", "Unknown"):
            self.reject_hints([self.literal(delivery=delivery)])
        for value in (
            None,
            1,
            "Literal",
            {},
            {"kind": "Callback"},
            {"kind": "Literal"},
            {"kind": "Literal", "value": "", "extra": 1},
            {"kind": "Model", "value": "Pixel 7"},
        ):
            self.reject_hints([{**self.literal(), "value": value}])

    def test_offline_list_ceiling_is_separate_from_native_custom_api(self):
        for value in (None, "hints", {}):
            self.reject_hints(value)
        self.values["hints"] = [self.literal(name=f"x-{i}") for i in range(64)]
        self.resolve()
        self.reject_hints(self.values["hints"] + [self.literal(name="x-64")])

    def test_inheritance_replaces_complete_ordered_list(self):
        derived = self.document["components"][1]
        derived["base"] = self.document["components"][0]["id"]
        derived["values"] = {}
        self.assertEqual(self.resolve()[1]["values"], self.values)
        replacement = [self.literal(name="z"), self.literal(name="a")]
        derived["values"] = {"hints": replacement}
        self.assertEqual(self.resolve()[1]["values"]["hints"], replacement)

    def test_unknown_refs_cycles_kinds_fields_and_duplicate_ids_fail(self):
        for mode in ("unknown", "cycle", "duplicate", "missing", "extra", "kind"):
            document = copy.deepcopy(self.document)
            if mode == "unknown":
                document["components"][1]["base"] = "unknown_hints"
            elif mode == "cycle":
                document["components"][0]["base"] = document["components"][1]["id"]
                document["components"][1]["base"] = document["components"][0]["id"]
            elif mode == "duplicate":
                document["components"].append(copy.deepcopy(document["components"][0]))
            elif mode == "missing":
                document["components"][0]["values"] = {}
            elif mode == "extra":
                document["components"][0]["values"]["callback"] = "model_value"
            else:
                document["components"][0]["kind"] = "CookiePlacement"
            with self.assertRaises(generator.DeclarationError):
                self.resolve(document)

    def test_model_helper_name_collisions_fail_in_both_component_orders(self):
        model = copy.deepcopy(
            next(
                c
                for c in self.document["components"]
                if c["id"] == "chrome_android_154_client_hints"
            )
        )
        model["id"] = "custom"
        conflict = {
            "id": "custom_for_model",
            "kind": "ClientHintSettings",
            "base": None,
            "values": {"hints": []},
        }
        for components in ([model, conflict], [conflict, model]):
            with self.assertRaises(generator.DeclarationError):
                self.resolve({"schema": 1, "components": components})

    def test_incompatible_base_and_duplicate_json_keys_are_rejected(self):
        document = {
            "schema": 1,
            "components": [
                {
                    "id": "cookie",
                    "kind": "CookiePlacement",
                    "base": None,
                    "values": {"before": []},
                },
                {
                    "id": "hints",
                    "kind": "ClientHintSettings",
                    "base": "cookie",
                    "values": {"hints": []},
                },
            ],
        }
        with self.assertRaises(generator.DeclarationError):
            generator.validate_components(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hints.json"
            path.write_text('{"schema": 1, "schema": 1, "components": []}')
            with self.assertRaises(generator.DeclarationError):
                declarations.read_document(path)


if __name__ == "__main__":
    unittest.main()
