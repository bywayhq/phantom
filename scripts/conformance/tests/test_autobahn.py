import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.conformance import autobahn
from scripts.conformance.autobahn import summarize_report
from scripts.conformance.loopback_tls import LoopbackCertificate

SMOKE_CASE_IDS = ("1.1.3", "1.2.3", "2.2", "3.1", "4.1.1", "5.8", "6.3.1", "7.1.1")


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


class ControlledProcesses:
    def __init__(self, adapter: Path) -> None:
        self.adapter = adapter
        self.commands: list[tuple[list[str], dict[str, object]]] = []
        self.container_name: str | None = None
        self.launch_error: subprocess.TimeoutExpired | None = None
        self.log_error: OSError | None = None
        self.log_status = 0
        self.remove_status = 0

    def run(self, command: list[str], **options: object) -> subprocess.CompletedProcess:
        self.commands.append((list(command), dict(options)))
        status, stdout, stderr = 0, "", ""
        if command == ["git", "rev-parse", "HEAD"]:
            stdout = "controlled-revision\n"
        elif command[:2] == ["docker", "run"]:
            self.container_name = command[command.index("--name") + 1]
            if self.launch_error is not None:
                raise self.launch_error
            stdout = "controlled-container-id\n"
        elif command[0] == str(self.adapter) and "--url" in command:
            pass
        elif command == ["docker", "logs", self.container_name]:
            if self.log_error is not None:
                raise self.log_error
            status = self.log_status
            stdout = "controlled server log\n"
            stderr = "controlled log failure" if status else ""
        elif command == ["docker", "rm", "--force", self.container_name]:
            status = self.remove_status
            stderr = "controlled removal failure" if status else ""
        else:
            raise AssertionError(f"unexpected subprocess request: {command!r}")

        if status and options.get("check"):
            raise subprocess.CalledProcessError(status, command, stdout, stderr)
        return subprocess.CompletedProcess(command, status, stdout, stderr)

    def calls(self, operation: str) -> list[tuple[list[str], dict[str, object]]]:
        return [call for call in self.commands if call[0][:2] == ["docker", operation]]


class AutobahnRunTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="autobahn-cleanup-test-")
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name).resolve() / "repository"
        self.report_root = Path(temporary.name).resolve() / "reports"
        config = self.repository / "scripts" / "conformance" / "autobahn" / "smoke.json"
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({"cases": list(SMOKE_CASE_IDS)}), encoding="utf-8")
        self.report = {
            autobahn.AGENT: {
                case: {"behavior": "OK", "behaviorClose": "OK"}
                for case in SMOKE_CASE_IDS
            }
        }
        adapter = self.repository / "controlled-adapter"
        self.processes = ControlledProcesses(adapter)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for target, replacement in [
            ("_build_adapter", mock.Mock(return_value=adapter)),
            ("_available_port", mock.Mock(return_value=49123)),
            ("_wait_for_tls", mock.Mock()),
            ("_copy_container_report", mock.Mock(side_effect=self.copy_report)),
            (
                "generate_loopback_certificate",
                mock.Mock(
                    return_value=LoopbackCertificate(
                        self.repository / "root.der",
                        self.repository / "server.key",
                        self.repository / "server.pem",
                    )
                ),
            ),
        ]:
            stack.enter_context(mock.patch.object(autobahn, target, replacement))
        stack.enter_context(
            mock.patch.object(autobahn.subprocess, "run", self.processes.run)
        )
        stack.enter_context(
            mock.patch.object(autobahn.platform, "platform", return_value="controlled")
        )
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def copy_report(self, container_name: str, destination: Path) -> None:
        self.assertEqual(container_name, self.processes.container_name)
        destination.write_text(json.dumps(self.report), encoding="utf-8")

    def summary(self) -> dict[str, object]:
        summaries = list(self.report_root.glob("*/summary.json"))
        self.assertEqual(len(summaries), 1)
        return json.loads(summaries[0].read_text(encoding="utf-8"))

    def test_successful_suite_returns_only_after_scoped_cleanup(self) -> None:
        directory = autobahn.run("smoke", self.repository, self.report_root)

        self.assertEqual(directory.parent, self.report_root)
        self.assertEqual(self.summary()["case_count"], 8)
        self.assertEqual(self.summary()["failure_count"], 0)
        self.assertEqual(len(self.processes.calls("logs")), 1)
        removals = self.processes.calls("rm")
        self.assertEqual(len(removals), 1)
        self.assertEqual(
            removals[0][0],
            ["docker", "rm", "--force", self.processes.container_name],
        )

    def test_removal_failure_fails_an_independently_successful_suite(self) -> None:
        self.processes.remove_status = 1

        with self.assertRaises((OSError, RuntimeError, subprocess.SubprocessError)):
            autobahn.run("smoke", self.repository, self.report_root)

        summary = self.summary()
        self.assertGreater(summary["failure_count"], 0)
        self.assertIn("remov", " ".join(summary["failures"]).lower())
        self.assertEqual(len(self.processes.calls("rm")), 1)

    def test_log_exit_failure_fails_suite_and_still_attempts_removal(self) -> None:
        self.processes.log_status = 1

        with self.assertRaises((OSError, RuntimeError, subprocess.SubprocessError)):
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertEqual(len(self.processes.calls("logs")), 1)
        self.assertEqual(len(self.processes.calls("rm")), 1)
        self.assertGreater(self.summary()["failure_count"], 0)

    def test_cli_retains_suite_log_and_removal_failures(self) -> None:
        self.report[autobahn.AGENT][SMOKE_CASE_IDS[0]]["behavior"] = "FAILED"
        self.processes.log_error = OSError("controlled log failure")
        self.processes.remove_status = 1
        stderr = io.StringIO()
        script = self.repository / "scripts" / "conformance" / "autobahn.py"
        with (
            mock.patch.object(autobahn, "__file__", str(script)),
            mock.patch.object(
                sys,
                "argv",
                [str(script), "smoke", "--report-root", str(self.report_root)],
            ),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit) as stopped,
        ):
            autobahn.main()

        self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(len(self.processes.calls("logs")), 1)
        self.assertEqual(len(self.processes.calls("rm")), 1)
        self.assertIn("conformance failures", stderr.getvalue())
        self.assertIn("controlled log failure", stderr.getvalue())
        self.assertIn("controlled removal failure", stderr.getvalue())
        self.assertGreater(self.summary()["failure_count"], 0)

    def test_uncertain_detached_launch_timeout_attempts_scoped_removal(self) -> None:
        timeout_error = subprocess.TimeoutExpired(["docker", "run"], 300)
        self.processes.launch_error = timeout_error

        with self.assertRaises(subprocess.TimeoutExpired) as failed:
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertIs(failed.exception, timeout_error)
        removals = self.processes.calls("rm")
        self.assertEqual(len(removals), 1)
        self.assertEqual(
            removals[0][0],
            ["docker", "rm", "--force", self.processes.container_name],
        )

    def test_log_collection_and_removal_have_finite_deadlines(self) -> None:
        autobahn.run("smoke", self.repository, self.report_root)

        for operation in ("logs", "rm"):
            with self.subTest(operation=operation):
                calls = self.processes.calls(operation)
                self.assertEqual(len(calls), 1)
                deadline = calls[0][1].get("timeout")
                self.assertIsInstance(deadline, (int, float))
                self.assertGreater(deadline, 0)
                self.assertLessEqual(deadline, 30)


class AutobahnReadinessTests(unittest.TestCase):
    def test_inspection_uses_the_remaining_readiness_deadline(self) -> None:
        now = 100.0
        inspections = []

        def unavailable(*_args: object, **_options: object) -> None:
            nonlocal now
            # Model a scheduling delay before inspection, without waiting in the test.
            now = 129.75
            raise ConnectionRefusedError("controlled listener unavailable")

        def inspect(
            command: list[str], **options: object
        ) -> subprocess.CompletedProcess:
            nonlocal now
            self.assertEqual(
                command,
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    "owned-fixture",
                ],
            )
            inspections.append(options)
            now = 130.0
            return subprocess.CompletedProcess(command, 0, "true\n", "")

        with (
            mock.patch.object(autobahn.time, "monotonic", side_effect=lambda: now),
            mock.patch.object(autobahn.time, "sleep"),
            mock.patch.object(autobahn.socket, "create_connection", unavailable),
            mock.patch.object(autobahn.subprocess, "run", inspect),
            self.assertRaises(TimeoutError),
        ):
            autobahn._wait_for_tls(49123, "owned-fixture")

        self.assertEqual(len(inspections), 1)
        deadline = inspections[0].get("timeout")
        self.assertIsInstance(deadline, (int, float))
        self.assertGreater(deadline, 0)
        self.assertLessEqual(deadline, 0.25)


if __name__ == "__main__":
    unittest.main()
