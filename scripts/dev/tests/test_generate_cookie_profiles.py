"""Cookie placement declarations retain ordered matching names."""

import copy
import json
import unittest

from scripts.dev.profile_catalog import cli as generator


class CookieComponentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(generator.COOKIE_COMPONENT_RECORDS.read_text())
        self.values = self.document["components"][0]["values"]

    def resolve(self, document=None):
        return generator.validate_components(
            self.document if document is None else document, ("CookiePlacement",)
        )

    def reject(self, document):
        with self.assertRaises(generator.DeclarationError):
            self.resolve(document)

    def test_committed_output_is_deterministic_and_uses_existing_constructor(self):
        actual = generator.generate_components(self.resolve(), "cookie-components.json")
        self.assertEqual(generator.COOKIE_COMPONENT_OUTPUT.read_text(), actual)
        self.document["components"].reverse()
        self.assertEqual(
            generator.generate_components(self.resolve(), "cookie-components.json"),
            actual,
        )
        self.assertIn("CookiePlacement::before_fields", actual)
        self.assertNotIn("before:", actual)
        self.assertNotIn("draw_", actual)

    def test_lists_preserve_case_order_and_allow_empty_placement(self):
        for names in (
            [],
            ["Priority", "priority", "x-custom"],
            ['quoted"name', "back\\slash", "non-ascii-Ã¤"],
        ):
            self.values["before"] = names
            self.assertEqual(self.resolve()[0]["values"]["before"], names)
            output = generator.generate_components(
                self.resolve(), "cookie-components.json"
            )
            self.assertIn("before_fields::<_, &str>([", output)

    def test_list_and_string_resource_bounds_reject_malformed_values(self):
        for bad in (
            None,
            "priority",
            [1],
            [""],
            ["priority", "priority"],
            ["bad\nname"],
            ["bad\x7fname"],
            ["\ud800"],
            ["x" * 4097],
            [f"field-{n}" for n in range(65)],
        ):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"]["before"] = bad
            self.reject(document)
        self.values["before"] = [f"field-{n}" for n in range(64)]
        self.resolve()
        self.values["before"] = ["x" * 4096]
        self.resolve()

    def test_inheritance_replaces_whole_list_without_sorting_names(self):
        derived = self.document["components"][1]
        derived["base"] = self.document["components"][0]["id"]
        derived["values"] = {"before": ["z", "a"]}
        self.assertEqual(self.resolve()[1]["values"]["before"], ["z", "a"])
        derived["values"] = {}
        self.assertEqual(self.resolve()[1]["values"], self.values)

    def test_closed_fields_missing_fields_and_layer_kinds_are_rejected(self):
        for values in ({}, {"before": [], "after": []}):
            document = copy.deepcopy(self.document)
            document["components"][0]["values"] = values
            self.reject(document)
        document = copy.deepcopy(self.document)
        document["components"][0]["kind"] = "ProxyConnectTemplate"
        self.reject(document)

    def test_duplicate_identifiers_unknown_refs_and_cycles_are_rejected(self):
        for mode in ("duplicate", "unknown", "cycle"):
            document = copy.deepcopy(self.document)
            if mode == "duplicate":
                document["components"].append(copy.deepcopy(document["components"][0]))
            elif mode == "unknown":
                document["components"][1]["base"] = "unknown_cookie"
            else:
                document["components"][0]["base"] = document["components"][1]["id"]
                document["components"][1]["base"] = document["components"][0]["id"]
            self.reject(document)


if __name__ == "__main__":
    unittest.main()
