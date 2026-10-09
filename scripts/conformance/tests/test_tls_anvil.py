import contextlib
import io
import json
import math
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
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="tls-anvil-cleanup-test-")
        self.addCleanup(temporary.cleanup)
        self.reports = Path(temporary.name)
        self.calls = []
        self.container_id = "b3" * 32
        self.removal_status = 0
        self.removal_error = None
        self.run_status = 0
        self.run_error = None
        self.build_error = None
        self.inspection_status = 0
        self.inspection_diagnostic = ""
        self.inspection_output = None
        self.invalid_report = False
        self.owner = None

    def subprocess_run(self, command, **options):
        self.calls.append((command, options))
        if command[:2] == ["docker", "build"]:
            if self.build_error is not None:
                raise self.build_error
            return subprocess.CompletedProcess(command, 0, "", "")

        if command[:2] == ["docker", "run"]:
            self.owner = command[command.index("--label") + 1].split("=", 1)[1]
            if self.run_error is not None:
                raise self.run_error
            output = next(
                Path(value.removesuffix(":/output"))
                for value in command
                if value.endswith(":/output")
            )
            suite = output / "suite"
            suite.mkdir()
            report = complete_report()
            if self.invalid_report:
                report["StrictlySucceededTests"] = 1
            (suite / "report.json").write_text(json.dumps(report), encoding="utf-8")
            (suite / "result_map.json").write_text(
                json.dumps(
                    {"STRICTLY_SUCCEEDED": ["5246-jsdAL1vDy5", "8446-jVohiUKi4u"]}
                ),
                encoding="utf-8",
            )
            options["stdout"].write("controlled complete suite report\n")
            return subprocess.CompletedProcess(command, self.run_status, "", "")

        if command[:2] == ["docker", "inspect"]:
            output = self.inspection_output
            if output is None:
                output = f"{self.container_id}\n" + json.dumps(
                    {"io.byway.phantom.tls-anvil.owner": self.owner}
                )
            return subprocess.CompletedProcess(
                command, self.inspection_status, output, self.inspection_diagnostic
            )

        if command[:2] == ["docker", "rm"]:
            if self.removal_error is not None:
                raise self.removal_error
            diagnostic = (
                "controlled daemon removal failure" if self.removal_status else ""
            )
            return subprocess.CompletedProcess(
                command, self.removal_status, "", diagnostic
            )
        raise AssertionError(f"unexpected subprocess: {command!r}")

    def exercise(self):
        stderr = io.StringIO()
        with (
            mock.patch.object(tls_anvil.platform, "platform", return_value="test host"),
            mock.patch.object(tls_anvil, "_git_revision", return_value="test revision"),
            mock.patch.object(
                tls_anvil.subprocess, "run", side_effect=self.subprocess_run
            ),
            mock.patch.object(
                sys, "argv", ["tls_anvil.py", "--report-root", str(self.reports)]
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(stderr),
        ):
            try:
                tls_anvil.main()
                status = 0
            except SystemExit as error:
                status = error.code

        summaries = list(self.reports.glob("smoke-*/summary.json"))
        self.assertLessEqual(len(summaries), 1)
        summary = None
        if summaries:
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        return status, summary, self.calls, stderr.getvalue()

    def test_complete_two_test_positive_control(self):
        status, summary, calls, _ = self.exercise()

        self.assertEqual(status, 0)
        self.assertEqual(summary["runner_exit_status"], 0)
        self.assertEqual(summary["test_ids"], ["5246-jsdAL1vDy5", "8446-jVohiUKi4u"])
        self.assertEqual(summary["strictly_succeeded_tests"], 2)
        self.assertTrue(summary["suite_report_validated"])
        self.assertEqual(summary["failures"], [])
        self.assertEqual(
            [command[1] for command, _ in calls], ["build", "run", "inspect", "rm"]
        )

        _, build_options = next(
            call for call in calls if call[0][:2] == ["docker", "build"]
        )
        launch, launch_options = next(
            call for call in calls if call[0][:2] == ["docker", "run"]
        )
        self.assertEqual(build_options["timeout"], 1200)
        self.assertEqual(launch_options["timeout"], 300)
        self.assertEqual(launch[launch.index("--network") + 1], "none")
        self.assertEqual(launch[-2:], ["-tlsAnvilConfig", "/config/client.json"])

    def test_failed_removal_fails_cli_and_retains_its_cause(self):
        self.removal_status = 1

        status, summary, _, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("controlled daemon removal failure", stderr)
        self.assertIn(
            "controlled daemon removal failure", " ".join(summary["failures"])
        )
        self.assertEqual(summary["test_ids"], ["5246-jsdAL1vDy5", "8446-jVohiUKi4u"])
        self.assertEqual(summary["strictly_succeeded_tests"], 2)

    def test_removal_has_a_finite_deadline(self):
        _, _, calls, _ = self.exercise()
        for operation in ("inspect", "rm"):
            _, options = next(
                call for call in calls if call[0][:2] == ["docker", operation]
            )
            with self.subTest(operation=operation):
                self.assertGreater(options["timeout"], 0)
                self.assertTrue(math.isfinite(options["timeout"]))

    def test_unique_owner_label_and_verified_immutable_id_scope_removal(self):
        _, _, calls, _ = self.exercise()
        launch = next(
            command for command, _ in calls if command[:2] == ["docker", "run"]
        )
        name = launch[launch.index("--name") + 1]
        label = launch[launch.index("--label") + 1]
        metadata_path = next(self.reports.glob("smoke-*/metadata.json"))
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

        self.assertRegex(self.owner, "^[0-9a-f]{32}$")
        self.assertEqual(label, f"io.byway.phantom.tls-anvil.owner={self.owner}")
        self.assertEqual(name, f"phantom-tls-anvil-{self.owner}")
        self.assertEqual(metadata["container_name"], name)
        self.assertEqual(metadata["container_owner"], self.owner)
        self.assertEqual(
            metadata["container_owner_label"], "io.byway.phantom.tls-anvil.owner"
        )
        removal = next(
            command for command, _ in calls if command[:2] == ["docker", "rm"]
        )
        self.assertEqual(removal, ["docker", "rm", "--force", self.container_id])
        self.assertNotEqual(removal[-1], name)

    def test_launch_timeout_still_removes_only_the_verified_owner(self):
        self.run_error = subprocess.TimeoutExpired(["docker", "run"], 300)

        status, summary, calls, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("timed out", stderr)
        self.assertFalse(summary["suite_report_validated"])
        self.assertEqual(summary["test_ids"], [])
        self.assertIsNone(summary["runner_exit_status"])
        self.assertEqual(calls[-1][0], ["docker", "rm", "--force", self.container_id])

    def test_name_collision_preserves_foreign_container_and_both_causes(self):
        self.run_error = subprocess.CalledProcessError(
            125, ["docker", "run"], stderr="controlled name collision"
        )
        self.inspection_output = (
            self.container_id
            + "\n"
            + json.dumps({"io.byway.phantom.tls-anvil.owner": "foreign-owner"})
        )

        status, summary, calls, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("controlled name collision", stderr)
        self.assertIn("left the container untouched", stderr)
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command, _ in calls))
        failures = " ".join(summary["failures"])
        self.assertIn("controlled name collision", failures)
        self.assertIn("left the container untouched", failures)

    def test_daemon_inspection_failure_is_not_treated_as_a_missing_owner(self):
        self.inspection_status = 1
        self.inspection_diagnostic = "controlled daemon unavailable"

        status, summary, calls, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("controlled daemon unavailable", stderr)
        self.assertIn("controlled daemon unavailable", " ".join(summary["failures"]))
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command, _ in calls))

    def test_exact_missing_owner_is_reported_without_removing_any_container(self):
        original_run = self.subprocess_run

        def missing_owner(command, **options):
            result = original_run(command, **options)
            if command[:2] == ["docker", "inspect"]:
                result.returncode = 1
                result.stderr = f"Error: No such object: {command[-1]}"
            return result

        with mock.patch.object(self, "subprocess_run", side_effect=missing_owner):
            status, summary, calls, _ = self.exercise()

        self.assertEqual(status, 0)
        self.assertEqual(
            summary["cleanup"], ["container cleanup: named container not found"]
        )
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command, _ in calls))

    def test_malformed_inspection_id_never_reaches_removal(self):
        self.inspection_output = "short-id\n{}"

        status, _, calls, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("invalid ID", stderr)
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command, _ in calls))

    def test_removal_timeout_is_retained_and_fails_successful_suite(self):
        self.removal_error = subprocess.TimeoutExpired(["docker", "rm"], 30)

        status, summary, _, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("timed out", stderr)
        self.assertEqual(summary["strictly_succeeded_tests"], 2)
        self.assertIn("timed out", " ".join(summary["failures"]))

    def test_suite_validation_and_cleanup_failure_both_reach_report_and_cli(self):
        self.invalid_report = True
        self.removal_status = 1

        status, summary, _, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("strictly pass", stderr)
        self.assertIn("controlled daemon removal failure", stderr)
        self.assertFalse(summary["suite_report_validated"])
        self.assertEqual(summary["test_ids"], [])
        failures = " ".join(summary["failures"])
        self.assertIn("strictly pass", failures)
        self.assertIn("controlled daemon removal failure", failures)

    def test_nonzero_suite_exit_and_cleanup_failure_both_remain_visible(self):
        self.run_status = 42
        self.removal_status = 1

        status, summary, _, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertEqual(summary["runner_exit_status"], 42)
        self.assertEqual(summary["strictly_succeeded_tests"], 2)
        self.assertIn("42", stderr)
        self.assertIn("controlled daemon removal failure", stderr)

    def test_build_failure_does_not_inspect_or_remove_an_unlaunched_owner(self):
        self.build_error = subprocess.TimeoutExpired(["docker", "build"], 1200)

        status, summary, calls, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("timed out", stderr)
        self.assertEqual([command[1] for command, _ in calls], ["build"])
        self.assertFalse(summary["suite_report_validated"])

    def test_launch_interrupt_cleans_owner_and_preserves_original_interrupt(self):
        error = KeyboardInterrupt()
        self.run_error = error

        with self.assertRaises(KeyboardInterrupt) as failed:
            self.exercise()

        self.assertIs(failed.exception, error)
        self.assertEqual(
            self.calls[-1][0], ["docker", "rm", "--force", self.container_id]
        )
        summary = json.loads(
            next(self.reports.glob("smoke-*/summary.json")).read_text()
        )
        self.assertIn("KeyboardInterrupt", " ".join(summary["failures"]))
        self.assertFalse(summary["suite_report_validated"])

    def test_cleanup_interrupt_is_reported_before_original_interrupt_is_raised(self):
        error = KeyboardInterrupt()
        self.removal_error = error

        with self.assertRaises(KeyboardInterrupt) as failed:
            self.exercise()

        self.assertIs(failed.exception, error)
        summary = json.loads(
            next(self.reports.glob("smoke-*/summary.json")).read_text()
        )
        self.assertIn("KeyboardInterrupt", " ".join(summary["failures"]))
        self.assertEqual(summary["strictly_succeeded_tests"], 2)

    def test_log_retention_failure_does_not_skip_owned_removal(self):
        with mock.patch.object(
            tls_anvil, "_bound_log", side_effect=OSError("controlled log retention")
        ):
            status, summary, calls, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIn("controlled log retention", stderr)
        self.assertIn("controlled log retention", " ".join(summary["failures"]))
        self.assertEqual(calls[-1][0], ["docker", "rm", "--force", self.container_id])

    def test_log_retention_interrupt_preserves_suite_and_cleanup_failures(self):
        self.run_status = 7
        self.removal_status = 9
        error = KeyboardInterrupt("controlled log retention interrupt")

        with mock.patch.object(
            tls_anvil, "_bound_log", side_effect=[error, None]
        ) as retention:
            try:
                status, summary, calls, stderr = self.exercise()
            except KeyboardInterrupt:
                self.fail("log retention interruption escaped before failure aggregation")

        self.assertNotEqual(status, 0)
        self.assertEqual(summary["runner_exit_status"], 7)
        self.assertEqual(summary["strictly_succeeded_tests"], 2)
        self.assertEqual(retention.call_count, 2)
        self.assertEqual(
            [call.args[0].name for call in retention.call_args_list],
            ["container.log", "adapter.log"],
        )
        self.assertEqual(calls[-1][0], ["docker", "rm", "--force", self.container_id])
        for cause in (
            "status 7",
            "status 9",
            "controlled daemon removal failure",
            "controlled log retention interrupt",
        ):
            self.assertIn(cause, " ".join(summary["failures"]))
            self.assertIn(cause, stderr)

    def test_lone_log_retention_interrupt_is_reported_before_reraising(self):
        error = KeyboardInterrupt("controlled lone retention interrupt")

        with (
            mock.patch.object(
                tls_anvil, "_bound_log", side_effect=[error, None]
            ) as retention,
            self.assertRaises(KeyboardInterrupt) as failed,
        ):
            self.exercise()

        self.assertIs(failed.exception, error)
        self.assertEqual(retention.call_count, 2)
        summary = json.loads(
            next(self.reports.glob("smoke-*/summary.json")).read_text(encoding="utf-8")
        )
        self.assertEqual(summary["runner_exit_status"], 0)
        self.assertEqual(summary["strictly_succeeded_tests"], 2)
        self.assertIn(
            "controlled lone retention interrupt", " ".join(summary["failures"])
        )

    def test_existing_log_read_failure_is_not_treated_as_absence(self):
        log = self.reports / "retained.log"
        log.write_text("retained diagnostic", encoding="utf-8")
        error = PermissionError("controlled log read denial")

        with (
            mock.patch.object(Path, "read_bytes", side_effect=error),
            self.assertRaises(PermissionError) as failed,
        ):
            tls_anvil._bound_log(log)

        self.assertIs(failed.exception, error)
        self.assertEqual(log.read_text(encoding="utf-8"), "retained diagnostic")

        tls_anvil._bound_log(self.reports / "absent.log")

    def test_summary_write_failure_preserves_existing_cleanup_cause(self):
        self.removal_status = 1
        write_text = Path.write_text

        def retain(path, *args, **options):
            if path.name == "summary.json":
                raise OSError("controlled summary retention")
            return write_text(path, *args, **options)

        with mock.patch.object(Path, "write_text", new=retain):
            status, summary, _, stderr = self.exercise()

        self.assertNotEqual(status, 0)
        self.assertIsNone(summary)
        self.assertIn("controlled daemon removal failure", stderr)
        self.assertIn("controlled summary retention", stderr)

    def test_summary_retention_interrupt_preserves_existing_failure_causes(self):
        self.run_status = 7
        self.removal_status = 9
        error = KeyboardInterrupt("controlled summary retention interrupt")
        write_text = Path.write_text

        def retain(path, *args, **options):
            if path.name == "summary.json":
                raise error
            return write_text(path, *args, **options)

        with mock.patch.object(Path, "write_text", new=retain):
            try:
                status, summary, calls, stderr = self.exercise()
            except KeyboardInterrupt:
                self.fail("summary interruption discarded existing failure causes")

        self.assertNotEqual(status, 0)
        self.assertIsNone(summary)
        self.assertEqual(calls[-1][0], ["docker", "rm", "--force", self.container_id])
        for cause in (
            "status 7",
            "status 9",
            "controlled daemon removal failure",
            "controlled summary retention interrupt",
        ):
            self.assertIn(cause, stderr)


if __name__ == "__main__":
    unittest.main()
