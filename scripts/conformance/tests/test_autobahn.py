import unittest

from scripts.conformance.autobahn import summarize_report


class AutobahnReportTests(unittest.TestCase):
    def test_accepts_strict_and_informational_results(self) -> None:
        report = {
            "phantom": {
                "1.1.1": {"behavior": "OK", "behaviorClose": "OK"},
                "7.13.1": {
                    "behavior": "INFORMATIONAL",
                    "behaviorClose": "INFORMATIONAL",
                },
            }
        }

        summary = summarize_report(
            report,
            "phantom",
            {"1.1.1", "7.13.1"},
            expected_case_count=2,
        )

        self.assertEqual(summary.case_count, 2)
        self.assertEqual(summary.warnings, ())
        self.assertEqual(summary.failures, ())

    def test_separates_warnings_from_failures(self) -> None:
        report = {
            "phantom": {
                "3.1": {
                    "behavior": "NON-STRICT",
                    "behaviorClose": "WRONG CODE",
                },
                "6.3.1": {"behavior": "FAILED", "behaviorClose": "UNCLEAN"},
            }
        }

        summary = summarize_report(report, "phantom")

        self.assertEqual(
            summary.warnings,
            ("3.1: behavior=NON-STRICT", "3.1: behaviorClose=WRONG CODE"),
        )
        self.assertEqual(
            summary.failures,
            ("6.3.1: behavior=FAILED", "6.3.1: behaviorClose=UNCLEAN"),
        )

    def test_rejects_missing_cases_and_unexpected_agents(self) -> None:
        with self.assertRaisesRegex(ValueError, "unexpected agents"):
            summarize_report({"other": {"1.1.1": {}}}, "phantom")
        with self.assertRaisesRegex(ValueError, "case set differed"):
            summarize_report(
                {"phantom": {"1.1.1": {"behavior": "OK", "behaviorClose": "OK"}}},
                "phantom",
                {"1.1.1", "1.2.1"},
            )
        with self.assertRaisesRegex(ValueError, "expected 2"):
            summarize_report(
                {"phantom": {"1.1.1": {"behavior": "OK", "behaviorClose": "OK"}}},
                "phantom",
                expected_case_count=2,
            )


if __name__ == "__main__":
    unittest.main()
