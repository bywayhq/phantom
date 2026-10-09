import json
import math
import subprocess
import unittest
from unittest import mock

from scripts.conformance import docker_owner

NAME = "controlled-run-name"
LABEL = "io.example.conformance.owner"
OWNER = "independent-run-owner"
CONTAINER_ID = "a1" * 32


class DockerOwnerTests(unittest.TestCase):
    def inspect(self, *, status=0, output=None, diagnostic=""):
        if output is None:
            output = f"{CONTAINER_ID}\n{json.dumps({LABEL: OWNER})}\n"
        result = subprocess.CompletedProcess(
            ["docker", "inspect", NAME], status, output, diagnostic
        )
        operation = mock.patch.object(
            docker_owner.subprocess, "run", return_value=result
        )
        with operation as run:
            value = docker_owner.verified_container_id(NAME, LABEL, OWNER, timeout=5)

        return value, run.call_args

    def test_matching_owner_returns_full_id_with_bounded_inspection(self):
        value, call = self.inspect()

        self.assertEqual(value, CONTAINER_ID)
        self.assertEqual(call.args[0][-1], NAME)
        self.assertEqual(call.args[0][2:4], ["--type", "container"])
        self.assertGreater(call.kwargs["timeout"], 0)
        self.assertTrue(math.isfinite(call.kwargs["timeout"]))

    def test_only_exact_missing_name_diagnostics_allow_absence(self):
        for diagnostic in (
            f"Error: No such object: {NAME}",
            f"Error response from daemon: No such container: {NAME}",
        ):
            with self.subTest(diagnostic=diagnostic):
                value, _ = self.inspect(status=1, diagnostic=diagnostic)
                self.assertIsNone(value)

    def test_daemon_failure_retains_command_status_and_cause(self):
        with self.assertRaisesRegex(
            RuntimeError, "controlled daemon unavailable"
        ) as failed:
            self.inspect(status=1, diagnostic="controlled daemon unavailable")

        cause = failed.exception.__cause__
        self.assertIsInstance(cause, subprocess.CalledProcessError)
        self.assertEqual(cause.returncode, 1)
        self.assertEqual(cause.stderr, "controlled daemon unavailable")

    def test_other_status_or_other_name_is_not_treated_as_absence(self):
        for status, diagnostic in (
            (2, f"Error: No such object: {NAME}"),
            (1, "Error: No such object: a-different-name"),
            (1, f"Error: No such object: {NAME}\ncontrolled extra error"),
        ):
            with (
                self.subTest(status=status, diagnostic=diagnostic),
                self.assertRaises(RuntimeError),
            ):
                self.inspect(status=status, diagnostic=diagnostic)

    def test_malformed_ids_are_rejected_before_removal(self):
        for value in ("", "abc", "a" * 63, "a" * 65, "G" * 64, "A" * 64, NAME):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "invalid ID"):
                    self.inspect(output=f"{value}\n{json.dumps({LABEL: OWNER})}")

                with (
                    mock.patch.object(docker_owner.subprocess, "run") as run,
                    self.assertRaisesRegex(ValueError, "full immutable ID"),
                ):
                    docker_owner.remove_container(value, timeout=5)

                run.assert_not_called()

    def test_extra_inspection_lines_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid ID"):
            self.inspect(output=f"{CONTAINER_ID}\n{{}}\nunexpected")

    def test_malformed_label_json_retains_parse_cause(self):
        with self.assertRaisesRegex(ValueError, "invalid labels") as failed:
            self.inspect(output=f"{CONTAINER_ID}\nnot-json")

        self.assertIsInstance(failed.exception.__cause__, json.JSONDecodeError)

    def test_foreign_missing_and_nonobject_labels_are_rejected(self):
        for labels in ({LABEL: "foreign-owner"}, {}, None, [], OWNER):
            with (
                self.subTest(labels=labels),
                self.assertRaisesRegex(RuntimeError, "left the container untouched"),
            ):
                self.inspect(output=f"{CONTAINER_ID}\n{json.dumps(labels)}")

    def test_removal_uses_full_id_with_a_finite_deadline(self):
        result = subprocess.CompletedProcess(["docker", "rm", CONTAINER_ID], 0, "", "")
        with mock.patch.object(
            docker_owner.subprocess, "run", return_value=result
        ) as run:
            docker_owner.remove_container(CONTAINER_ID, timeout=5)

        self.assertEqual(
            run.call_args.args[0], ["docker", "rm", "--force", CONTAINER_ID]
        )
        self.assertGreater(run.call_args.kwargs["timeout"], 0)
        self.assertTrue(math.isfinite(run.call_args.kwargs["timeout"]))

    def test_removal_failure_retains_its_original_subprocess_cause(self):
        result = subprocess.CompletedProcess(
            ["docker", "rm", CONTAINER_ID], 9, "", "controlled removal cause"
        )
        with (
            mock.patch.object(docker_owner.subprocess, "run", return_value=result),
            self.assertRaisesRegex(RuntimeError, "controlled removal cause") as failed,
        ):
            docker_owner.remove_container(CONTAINER_ID, timeout=5)

        cause = failed.exception.__cause__
        self.assertIsInstance(cause, subprocess.CalledProcessError)
        self.assertEqual(cause.returncode, 9)

    def test_both_commands_preserve_timeout_and_interrupt_objects(self):
        for error in (subprocess.TimeoutExpired(["docker"], 5), KeyboardInterrupt()):
            for operation in (
                lambda: docker_owner.verified_container_id(
                    NAME, LABEL, OWNER, timeout=5
                ),
                lambda: docker_owner.remove_container(CONTAINER_ID, timeout=5),
            ):
                with self.subTest(error=type(error).__name__, operation=operation):
                    with (
                        mock.patch.object(
                            docker_owner.subprocess, "run", side_effect=error
                        ),
                        self.assertRaises(type(error)) as failed,
                    ):
                        operation()

                    self.assertIs(failed.exception, error)

    def test_nonpositive_and_nonfinite_deadlines_reject_before_any_command(self):
        for timeout in (0, -1, float("inf"), float("-inf"), float("nan")):
            with self.subTest(timeout=timeout):
                with mock.patch.object(docker_owner.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "finite and positive"):
                        docker_owner.verified_container_id(
                            NAME, LABEL, OWNER, timeout=timeout
                        )

                    with self.assertRaisesRegex(ValueError, "finite and positive"):
                        docker_owner.remove_container(CONTAINER_ID, timeout=timeout)

                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
