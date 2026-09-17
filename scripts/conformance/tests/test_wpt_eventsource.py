import json
import tempfile
import unittest
from pathlib import Path

from scripts.conformance.wpt_eventsource import (
    WPT_REVISION,
    load_case_ids,
    parse_adapter_output,
)


class WptEventSourceTests(unittest.TestCase):
    def test_smoke_cases_are_a_subset_of_full_cases(self) -> None:
        root = Path(__file__).resolve().parents[3]
        manifests = root / "scripts" / "conformance" / "wpt-eventsource"
        smoke = load_case_ids(manifests / "smoke.json")
        full = load_case_ids(manifests / "full.json")

        self.assertTrue(set(smoke) < set(full))

    def test_loads_an_ordered_unique_case_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cases.json"
            path.write_text(
                json.dumps(
                    {
                        "revision": WPT_REVISION,
                        "cases": ["eventsource/a.any.js", "eventsource/b.any.js"],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                load_case_ids(path),
                ("eventsource/a.any.js", "eventsource/b.any.js"),
            )

            path.write_text(
                json.dumps({"revision": WPT_REVISION, "cases": ["same", "same"]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unique"):
                load_case_ids(path)

    def test_rejects_duplicate_manifest_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cases.json"
            path.write_text(
                f'{{"revision":"{WPT_REVISION}","cases":["a"],"cases":["b"]}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_case_ids(path)

    def test_parses_exact_pass_and_failure_results(self) -> None:
        summary = parse_adapter_output(
            "CASE\tPASS\ta\nCASE\tFAIL\tb\tbad response\nSUMMARY\t2\t1\n",
            ("a", "b"),
        )

        self.assertEqual(summary.cases["a"], {"status": "pass"})
        self.assertEqual(
            summary.cases["b"], {"status": "fail", "detail": "bad response"}
        )
        self.assertEqual(summary.failures, ("b: bad response",))

    def test_rejects_case_set_and_summary_mismatches(self) -> None:
        with self.assertRaisesRegex(ValueError, "case set differed"):
            parse_adapter_output("CASE\tPASS\ta\nSUMMARY\t1\t0\n", ("a", "b"))
        with self.assertRaisesRegex(ValueError, "adapter summary"):
            parse_adapter_output("CASE\tPASS\ta\nSUMMARY\t2\t0\n", ("a",))


if __name__ == "__main__":
    unittest.main()
