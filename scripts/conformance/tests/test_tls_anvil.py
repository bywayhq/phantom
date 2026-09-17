import unittest

from scripts.conformance.tls_anvil import EXPECTED_TEST_IDS, summarize_reports


def complete_report() -> dict[str, object]:
    return {
        "Running": False,
        "TotalTests": 2,
        "FinishedTests": 2,
        "StrictlySucceededTests": 2,
        "ConceptuallySucceededTests": 0,
        "DisabledTests": 0,
        "PartiallyFailedTests": 0,
        "FullyFailedTests": 0,
        "TestSuiteErrorTests": 0,
    }


class TlsAnvilReportTests(unittest.TestCase):
    def test_accepts_complete_strict_smoke_report(self) -> None:
        summary = summarize_reports(
            complete_report(),
            {"STRICTLY_SUCCEEDED": sorted(EXPECTED_TEST_IDS)},
        )

        self.assertEqual(summary.total_tests, 2)
        self.assertEqual(summary.finished_tests, 2)
        self.assertEqual(summary.strictly_succeeded_tests, 2)
        self.assertEqual(set(summary.test_ids), EXPECTED_TEST_IDS)

    def test_rejects_running_or_incomplete_report(self) -> None:
        report = complete_report()
        report["Running"] = True
        with self.assertRaisesRegex(ValueError, "incomplete"):
            summarize_reports(
                report,
                {"STRICTLY_SUCCEEDED": sorted(EXPECTED_TEST_IDS)},
            )

        report = complete_report()
        report["FinishedTests"] = 1
        with self.assertRaisesRegex(ValueError, "did not finish"):
            summarize_reports(
                report,
                {"STRICTLY_SUCCEEDED": sorted(EXPECTED_TEST_IDS)},
            )

    def test_rejects_missing_disabled_or_failed_tests(self) -> None:
        report = complete_report()
        report["StrictlySucceededTests"] = 1
        report["DisabledTests"] = 1
        with self.assertRaisesRegex(ValueError, "strictly pass"):
            summarize_reports(
                report,
                {
                    "STRICTLY_SUCCEEDED": ["5246-jsdAL1vDy5"],
                    "DISABLED": ["8446-jVohiUKi4u"],
                },
            )

        with self.assertRaisesRegex(ValueError, "test set differed"):
            summarize_reports(
                complete_report(),
                {"STRICTLY_SUCCEEDED": ["5246-jsdAL1vDy5"]},
            )

    def test_rejects_duplicate_test_ids(self) -> None:
        duplicate = "5246-jsdAL1vDy5"
        with self.assertRaisesRegex(ValueError, "duplicate test IDs"):
            summarize_reports(
                complete_report(),
                {
                    "STRICTLY_SUCCEEDED": sorted(EXPECTED_TEST_IDS),
                    "CONCEPTUALLY_SUCCEEDED": [duplicate],
                },
            )


if __name__ == "__main__":
    unittest.main()
