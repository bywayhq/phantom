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
        self.container_id = "a" * 64
        self.owner: str | None = None
        self.inspection = "owned"
        self.launch_error: subprocess.SubprocessError | None = None
        self.log_error: Exception | KeyboardInterrupt | None = None
        self.log_timeout = False
        self.remove_timeout = False
        self.log_status = 0
        self.remove_status = 0

    def run(self, command: list[str], **options: object) -> subprocess.CompletedProcess:
        self.commands.append((list(command), dict(options)))
        status, stdout, stderr = 0, "", ""
        if command == ["git", "rev-parse", "HEAD"]:
            stdout = "controlled-revision\n"
        elif command[:2] == ["docker", "run"]:
            self.container_name = command[command.index("--name") + 1]
            label = command[command.index("--label") + 1]
            key, self.owner = label.split("=", 1)
            if key != "io.byway.phantom.autobahn.owner" or not self.owner:
                raise AssertionError("launch omitted a unique ownership label")
            if self.launch_error is not None:
                raise self.launch_error
            stdout = "controlled-container-id\n"
        elif command[0] == str(self.adapter) and "--url" in command:
            pass
        elif command == [
            "docker",
            "inspect",
            "--type",
            "container",
            "--format",
            "{{.Id}}\n{{json .Config.Labels}}",
            self.container_name,
        ]:
            if self.inspection == "missing":
                status, stderr = 1, f"Error: No such object: {self.container_name}"
            elif self.inspection == "daemon failure":
                status, stderr = 1, "Cannot connect to the Docker daemon"
            else:
                owner = self.owner if self.inspection == "owned" else "foreign-owner"
                labels = {"io.byway.phantom.autobahn.owner": owner}
                stdout = f"{self.container_id}\n{json.dumps(labels)}\n"
                if self.inspection == "invalid ID":
                    stdout = "foreign-name\n{}\n"
                elif self.inspection == "invalid labels":
                    stdout = f"{self.container_id}\n[\n"
        elif command == ["docker", "logs", self.container_id]:
            if self.log_timeout:
                raise subprocess.TimeoutExpired(command, options.get("timeout"))
            if self.log_error is not None:
                raise self.log_error
            status = self.log_status
            stdout = "controlled server log\n"
            stderr = "controlled log failure" if status else ""
        elif command == ["docker", "rm", "--force", self.container_id]:
            if self.remove_timeout:
                raise subprocess.TimeoutExpired(command, options.get("timeout"))
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
        self.assertTrue(self.processes.calls("run")[0][1]["capture_output"])
        self.assertEqual(len(self.processes.calls("logs")), 1)
        removals = self.processes.calls("rm")
        self.assertEqual(len(removals), 1)
        self.assertEqual(
            removals[0][0],
            ["docker", "rm", "--force", self.processes.container_id],
        )
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["container_name"], self.processes.container_name)
        self.assertEqual(metadata["container_owner"], self.processes.owner)
        self.assertEqual(
            metadata["container_owner_label"], "io.byway.phantom.autobahn.owner"
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
            ["docker", "rm", "--force", self.processes.container_id],
        )

    def test_log_collection_and_removal_have_finite_deadlines(self) -> None:
        autobahn.run("smoke", self.repository, self.report_root)

        for operation in ("inspect", "logs", "rm"):
            with self.subTest(operation=operation):
                calls = self.processes.calls(operation)
                self.assertEqual(len(calls), 1)
                deadline = calls[0][1].get("timeout")
                self.assertIsInstance(deadline, (int, float))
                self.assertGreater(deadline, 0)
                self.assertLessEqual(deadline, 30)

    def test_foreign_name_collision_preserves_launch_cause_without_cleanup(
        self,
    ) -> None:
        self.processes.inspection = "foreign"
        self.processes.launch_error = subprocess.CalledProcessError(
            125, ["docker", "run"], stderr="Conflict: container name is already in use"
        )

        with self.assertRaises(RuntimeError) as failed:
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertIn(
            "Conflict: container name is already in use", str(failed.exception)
        )
        self.assertIn("ownership did not match", str(failed.exception))
        self.assertEqual(self.processes.calls("logs"), [])
        self.assertEqual(self.processes.calls("rm"), [])
        failures = " ".join(self.summary()["failures"])
        self.assertIn("Conflict: container name is already in use", failures)
        self.assertIn("ownership did not match", failures)

    def test_cli_preserves_launch_stderr_when_no_container_needs_cleanup(self) -> None:
        self.processes.inspection = "missing"
        self.processes.launch_error = subprocess.CalledProcessError(
            125, ["docker", "run"], stderr="controlled launch permission denied"
        )
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
        self.assertIn("controlled launch permission denied", stderr.getvalue())
        self.assertIn(
            "controlled launch permission denied", " ".join(self.summary()["failures"])
        )
        self.assertEqual(self.processes.calls("logs"), [])
        self.assertEqual(self.processes.calls("rm"), [])

    def test_uncertain_launch_distinguishes_missing_container_from_daemon_failure(
        self,
    ) -> None:
        timeout_error = subprocess.TimeoutExpired(["docker", "run"], 300)
        self.processes.launch_error = timeout_error
        self.processes.inspection = "missing"

        with self.assertRaises(subprocess.TimeoutExpired) as failed:
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertIs(failed.exception, timeout_error)
        self.assertEqual(self.processes.calls("logs"), [])
        self.assertEqual(self.processes.calls("rm"), [])
        self.assertEqual(
            self.summary()["cleanup"], ["container cleanup: named container not found"]
        )

    def test_daemon_failure_preserves_timeout_without_guessing_ownership(self) -> None:
        self.processes.launch_error = subprocess.TimeoutExpired(["docker", "run"], 300)
        self.processes.inspection = "daemon failure"

        with self.assertRaises(RuntimeError) as failed:
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertIn("timed out after 300 seconds", str(failed.exception))
        self.assertIn("Cannot connect to the Docker daemon", str(failed.exception))
        self.assertEqual(self.processes.calls("logs"), [])
        self.assertEqual(self.processes.calls("rm"), [])
        self.assertEqual(self.summary()["cleanup"], [])
        self.assertIn(
            "Cannot connect to the Docker daemon", " ".join(self.summary()["failures"])
        )

    def test_cleanup_timeouts_fail_the_retained_run_and_removal_still_follows_logs(
        self,
    ) -> None:
        self.processes.log_timeout = True
        self.processes.remove_timeout = True

        with self.assertRaises(RuntimeError) as failed:
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertEqual(len(self.processes.calls("logs")), 1)
        self.assertEqual(len(self.processes.calls("rm")), 1)
        self.assertIn("container log collection", str(failed.exception))
        self.assertIn("container removal", str(failed.exception))
        failures = " ".join(self.summary()["failures"])
        self.assertIn("container log collection", failures)
        self.assertIn("container removal", failures)

    def test_invalid_inspection_does_not_authorize_logs_or_removal(self) -> None:
        self.processes.inspection = "invalid ID"

        with self.assertRaisesRegex(RuntimeError, "invalid ID"):
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertEqual(self.processes.calls("logs"), [])
        self.assertEqual(self.processes.calls("rm"), [])
        self.assertIn("invalid ID", " ".join(self.summary()["failures"]))

    def test_invalid_ownership_labels_do_not_authorize_logs_or_removal(self) -> None:
        self.processes.inspection = "invalid labels"

        with self.assertRaisesRegex(RuntimeError, "invalid labels"):
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertEqual(self.processes.calls("logs"), [])
        self.assertEqual(self.processes.calls("rm"), [])

    def test_interrupted_log_collection_still_removes_owned_id_then_reraises(
        self,
    ) -> None:
        interruption = KeyboardInterrupt()
        self.processes.log_error = interruption

        with self.assertRaises(KeyboardInterrupt) as failed:
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertIs(failed.exception, interruption)
        self.assertEqual(len(self.processes.calls("rm")), 1)
        self.assertIn("KeyboardInterrupt", " ".join(self.summary()["failures"]))

    def test_log_status_and_log_retention_failures_both_survive_removal(self) -> None:
        self.processes.log_status = 1
        write_text = Path.write_text

        def retained(path: Path, *args: object, **options: object) -> int:
            if path.name == "container.log":
                raise OSError("controlled log retention failure")
            return write_text(path, *args, **options)

        with (
            mock.patch.object(Path, "write_text", retained),
            self.assertRaises(RuntimeError) as failed,
        ):
            autobahn.run("smoke", self.repository, self.report_root)

        self.assertEqual(len(self.processes.calls("rm")), 1)
        self.assertIn("controlled log failure", str(failed.exception))
        self.assertIn("controlled log retention failure", str(failed.exception))
        failures = " ".join(self.summary()["failures"])
        self.assertIn("controlled log failure", failures)
        self.assertIn("controlled log retention failure", failures)


class AutobahnReadinessTests(unittest.TestCase):
    def test_expired_readiness_budget_does_not_start_a_socket_or_inspection(
        self,
    ) -> None:
        with (
            mock.patch.object(autobahn.time, "monotonic", side_effect=[100, 100, 130]),
            mock.patch.object(autobahn.socket, "create_connection") as connection,
            mock.patch.object(autobahn.subprocess, "run") as inspection,
            self.assertRaises(TimeoutError),
        ):
            autobahn._wait_for_tls(49123, "owned-fixture")

        connection.assert_not_called()
        inspection.assert_not_called()

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
