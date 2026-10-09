import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.conformance import tls_anvil
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


class TlsAnvilCleanupTests(unittest.TestCase):
    def exercise(self, *, removal_status=0):
        with tempfile.TemporaryDirectory(prefix="tls-anvil-cleanup-test-") as temporary:
            reports = Path(temporary)
            calls = []

            def subprocess_run(command, **options):
                calls.append((command, options))
                if command[:2] == ["docker", "build"]:
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[:2] == ["docker", "run"]:
                    output = next(
                        Path(value.removesuffix(":/output"))
                        for value in command
                        if value.endswith(":/output")
                    )
                    suite = output / "suite"
                    suite.mkdir()
                    (suite / "report.json").write_text(
                        json.dumps(complete_report()), encoding="utf-8"
                    )
                    (suite / "result_map.json").write_text(
                        json.dumps(
                            {
                                "STRICTLY_SUCCEEDED": [
                                    "5246-jsdAL1vDy5",
                                    "8446-jVohiUKi4u",
                                ]
                            }
                        ),
                        encoding="utf-8",
                    )
                    options["stdout"].write("controlled complete suite report\n")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[:2] == ["docker", "rm"]:
                    diagnostic = (
                        "controlled daemon removal failure" if removal_status else ""
                    )
                    return subprocess.CompletedProcess(
                        command, removal_status, "", diagnostic
                    )
                raise AssertionError(f"unexpected subprocess: {command!r}")

            stderr = io.StringIO()
            with (
                mock.patch.object(
                    tls_anvil.platform, "platform", return_value="test host"
                ),
                mock.patch.object(
                    tls_anvil, "_git_revision", return_value="test revision"
                ),
                mock.patch.object(
                    tls_anvil.subprocess, "run", side_effect=subprocess_run
                ),
                mock.patch.object(
                    sys, "argv", ["tls_anvil.py", "--report-root", str(reports)]
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                try:
                    tls_anvil.main()
                    status = 0
                except SystemExit as error:
                    status = error.code

            summaries = list(reports.glob("smoke-*/summary.json"))
            self.assertEqual(len(summaries), 1)
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            self.assertEqual(
                summary["test_ids"], ["5246-jsdAL1vDy5", "8446-jVohiUKi4u"]
            )
            self.assertEqual(summary["strictly_succeeded_tests"], 2)
            return status, summary, calls, stderr.getvalue()

    def test_complete_two_test_positive_control(self):
        status, summary, calls, _ = self.exercise()

        self.assertEqual(status, 0)
        self.assertEqual(summary["runner_exit_status"], 0)
        self.assertEqual([command[1] for command, _ in calls], ["build", "run", "rm"])

    def test_failed_removal_fails_cli_and_retains_its_cause(self):
        status, _, _, stderr = self.exercise(removal_status=1)

        self.assertNotEqual(status, 0)
        self.assertIn("controlled daemon removal failure", stderr)

    def test_removal_has_a_finite_deadline(self):
        _, _, calls, _ = self.exercise()
        _, options = next(call for call in calls if call[0][:2] == ["docker", "rm"])

        self.assertGreater(options.get("timeout", 0), 0)


if __name__ == "__main__":
    unittest.main()
