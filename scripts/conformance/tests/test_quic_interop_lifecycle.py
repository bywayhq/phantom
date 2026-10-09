"""Outer-runner contracts with controlled processes and Docker responses."""

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts.conformance import docker_owner, quic_interop

SUCCESS_RESULT = b'{"clients":["phantom"],"servers":["controlled"],"tests":{"3":{"name":"http3","desc":"HTTP/3"}},"results":[[{"abbr":"3","name":"http3","result":"succeeded"}]]}'
OWNED_CONTAINER = "1" * 64
OWNED_NETWORK = "2" * 64
OWNED_HELPER = "3" * 64
FOREIGN_CONTAINER = "4" * 64
OWNER_LABEL = "org.phantom.quic-interop.owner"


class ControlledRunner:
    """Observe actual run/main ordering without starting external resources."""

    def __init__(self, root, outcome="success", restore_failure=False):
        self.root = root
        self.runner = root / "runner"
        self.runner.mkdir()
        self.original = {
            "implementations_quic.json": b'{"controlled":{"image":"server:original","role":"server"}}\n',
            "docker-compose.yml": (
                Path(__file__).parent / "fixtures/quic-runner/docker-compose.yml"
            ).read_bytes(),
            "testcase.py": (
                Path(__file__).parent / "fixtures/quic-runner/testcase.py.txt"
            ).read_bytes(),
        }
        for name, content in self.original.items():
            (self.runner / name).write_bytes(content)
        (self.runner / "run.py").write_text("# never executed\n", encoding="utf-8")
        self.outcome = outcome
        self.restore_failure = restore_failure
        self.cleanup_failure = False
        self.reap_failure = False
        self.foreign_endpoint = False
        self.foreign_name = False
        self.foreign_container_label = False
        self.interrupt_on_launch = False
        self.cleanup_sigint_handlers = []
        self.change_daemon_after_launch = False
        self.events = []
        self.removed = []
        self.restores = []
        self.scratch = []
        self.launches = 0
        self.active_process = False
        self.resources = set()
        self.launch_environment = None
        self.primary = None
        self.testcase_at_launch = None
        self.compose_at_launch = []
        self.real_write = Path.write_bytes
        self.real_temporary = tempfile.TemporaryDirectory

    def begin(self, command, options):
        self.launches += 1
        self.active_process = True
        self.resources = {OWNED_CONTAINER, OWNED_HELPER, OWNED_NETWORK}
        self.launch_environment = dict(options["env"])
        self.testcase_at_launch = (self.runner / "testcase.py").read_bytes()
        selection = self.launch_environment.get("COMPOSE_FILE", "docker-compose.yml")
        for entry in selection.split(os.pathsep):
            path = Path(entry)
            if not path.is_absolute():
                path = self.runner / path
            self.compose_at_launch.append(path.read_bytes())
        self.events.append("launch")
        if self.change_daemon_after_launch:
            os.environ["DOCKER_HOST"] = "unix:///changed-unowned-daemon.sock"
        self.result_path = Path(command[command.index("--json") + 1])
        if self.outcome == "success":
            self.result_path.write_bytes(SUCCESS_RESULT)

    def outcome_result(self, command):
        if self.outcome == "timeout":
            self.primary = subprocess.TimeoutExpired(command, 1200)
            raise self.primary
        if self.outcome == "interrupt":
            self.primary = KeyboardInterrupt("controlled interruption")
            raise self.primary
        self.active_process = False
        return subprocess.CompletedProcess(
            command, 0, "literal stdout\n", "literal stderr\n"
        )

    def run_command(self, command, **options):
        if command == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(
                command, 0, quic_interop.RUNNER_REVISION + "\n", ""
            )
        if command == ["git", "status", "--porcelain=v1", "--untracked-files=all"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if len(command) > 1 and command[1] == "run.py":
            self.begin(command, options)
            return self.outcome_result(command)
        if command[0] != "docker":
            raise AssertionError(f"uncontrolled command: {command!r}")
        return self.docker(command, options)

    def docker(self, command, options):
        if self.launches:
            self.cleanup_sigint_handlers.append(signal.getsignal(signal.SIGINT))
        if self.launch_environment is not None and options.get("env", {}).get(
            "DOCKER_HOST"
        ) != self.launch_environment.get("DOCKER_HOST"):
            raise AssertionError("cleanup changed the immutable daemon selection")
        owner = (self.launch_environment or options.get("env", {})).get(
            "PHANTOM_QUIC_OWNER", "controlled-old-owner"
        )
        is_network = "network" in command
        if "inspect" in command:
            identity = command[-1]
            if self.foreign_name and identity == "sim":
                document = {
                    "Id": FOREIGN_CONTAINER,
                    "Name": "/sim",
                    "Config": {"Labels": {OWNER_LABEL: "foreign"}},
                }
                return subprocess.CompletedProcess(
                    command, 0, json.dumps([document]), ""
                )
            if identity not in {OWNED_CONTAINER, OWNED_HELPER, OWNED_NETWORK}:
                return subprocess.CompletedProcess(
                    command, 1, "", f"Error: No such object: {identity}"
                )
            self.events.append("inspect:" + identity)
            labels = {OWNER_LABEL: owner}
            if self.foreign_container_label and identity == OWNED_CONTAINER:
                labels = {OWNER_LABEL: "foreign"}
            document = {"Id": identity, "Config": {"Labels": labels}}
            if is_network:
                document = {
                    "Id": identity,
                    "Labels": labels,
                    "Containers": {FOREIGN_CONTAINER: {"Name": "foreign"}}
                    if self.foreign_endpoint
                    else {},
                }
            if "--format" in command:
                return subprocess.CompletedProcess(
                    command, 0, identity + "\n" + json.dumps(labels) + "\n", ""
                )
            return subprocess.CompletedProcess(command, 0, json.dumps([document]), "")
        if "ls" in command or "ps" in command:
            ids = {OWNED_NETWORK} if is_network else {OWNED_CONTAINER, OWNED_HELPER}
            selected = sorted(ids & self.resources)
            return subprocess.CompletedProcess(
                command, 0, "\n".join(selected) + "\n", ""
            )
        if "rm" in command:
            identity = command[-1]
            if identity not in self.resources:
                raise AssertionError("cleanup used a name or an unowned identity")
            if identity == OWNED_NETWORK and self.foreign_endpoint:
                raise AssertionError("cleanup attempted to remove a foreign endpoint")
            self.events.append("remove:" + identity)
            if self.cleanup_failure:
                return subprocess.CompletedProcess(
                    command, 1, "", "controlled cleanup failure"
                )
            self.resources.remove(identity)
            self.removed.append(identity)
            return subprocess.CompletedProcess(command, 0, identity + "\n", "")
        raise AssertionError(f"uncontrolled Docker operation: {command!r}")

    def popen(self, command, **options):
        self.begin(command, options)
        owner = self

        class Process:
            pid = 43210

            def poll(self):
                return None if owner.active_process else 0

            def wait(self, timeout=None):
                if owner.reap_failure:
                    raise subprocess.TimeoutExpired(command, timeout)
                if not owner.active_process:
                    return -15
                result = owner.outcome_result(command)
                return result.returncode

        if self.outcome == "success" and options.get("stdout") is not None:
            stream = options["stdout"]
            if hasattr(stream, "write"):
                stream.write(b"literal stdout\nliteral stderr\n")
        if self.interrupt_on_launch:
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
        return Process()

    def end_group(self, group, signum):
        self.events.append("group_exit")
        if not self.reap_failure:
            self.active_process = False

    def write_bytes(self, path, content):
        if path.parent == self.runner and content == self.original.get(path.name):
            self.restores.append(path.name)
            self.events.append("restore:" + path.name)
            if self.active_process:
                self.events.append("unsafe_restore")
            if self.restore_failure and path.name == "implementations_quic.json":
                raise PermissionError("controlled restoration failure")
        return self.real_write(path, content)

    def temporary(self, **options):
        owner = self
        temporary = self.real_temporary(dir=self.root, **options)
        self.scratch.append(Path(temporary.name))

        class Directory:
            name = temporary.name

            def __enter__(self):
                return self.name

            def cleanup(self):
                owner.events.append("scratch_cleanup")
                temporary.cleanup()

            def __exit__(self, *args):
                self.cleanup()

        return Directory()

    def invoke(self, entry="run", system="linux"):
        commands = types.SimpleNamespace(
            run=self.run_command,
            Popen=self.popen,
            SubprocessError=subprocess.SubprocessError,
            CalledProcessError=subprocess.CalledProcessError,
            TimeoutExpired=subprocess.TimeoutExpired,
            PIPE=subprocess.PIPE,
            STDOUT=subprocess.STDOUT,
            DEVNULL=subprocess.DEVNULL,
        )

        def owned_scratch(**options):
            directory = Path(tempfile.mkdtemp(dir=self.root, **options))
            self.scratch.append(directory)
            return str(directory)

        temporary = types.SimpleNamespace(
            TemporaryDirectory=self.temporary,
            mkdtemp=owned_scratch,
        )
        error = None
        with (
            mock.patch.object(quic_interop, "subprocess", commands),
            mock.patch.object(docker_owner, "subprocess", commands),
            mock.patch.object(quic_interop, "checkout_runner", self.checkout),
            mock.patch.object(quic_interop, "tempfile", temporary),
            mock.patch.object(sys, "platform", system),
            mock.patch.object(os, "killpg", self.end_group, create=True),
            mock.patch.object(signal, "SIGKILL", 9, create=True),
            mock.patch.object(
                quic_interop,
                "_group_has_live_members",
                lambda identity: self.active_process,
            ),
            mock.patch.object(
                Path,
                "write_bytes",
                lambda path, content: self.write_bytes(path, content),
            ),
            mock.patch.dict(
                os.environ,
                {
                    "COMPOSE_PROJECT_NAME": "foreign-project",
                    "COMPOSE_FILE": "docker-compose.yml",
                    "DOCKER_HOST": "unix:///controlled-daemon.sock",
                },
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            try:
                if entry == "run":
                    quic_interop.run(
                        self.runner,
                        self.root,
                        self.root / "reports",
                        "controlled-client:literal",
                        "controlled",
                        "controlled-server:literal",
                    )
                else:
                    argv = [
                        "quic_interop.py",
                        "--runner",
                        str(self.runner),
                        "--report-root",
                        str(self.root / "reports"),
                        "--server",
                        "controlled",
                    ]
                    if entry == "checkout":
                        del argv[1:3]
                    with mock.patch.object(sys, "argv", argv):
                        quic_interop.main()
            except BaseException as caught:
                error = caught
        reports = list((self.root / "reports").glob("*/summary.json"))
        summary = json.loads(reports[0].read_text()) if reports else None
        return error, summary

    def checkout(self, destination):
        destination.mkdir()
        for name, content in self.original.items():
            (destination / name).write_bytes(content)
        (destination / "run.py").write_text("# never executed\n", encoding="utf-8")
        self.runner = destination


class QuicInteropLifecycleTests(unittest.TestCase):
    def fixture(self, *args, **kwargs):
        temporary = tempfile.TemporaryDirectory(prefix="quic-outer-contract-")
        self.addCleanup(temporary.cleanup)
        return ControlledRunner(Path(temporary.name), *args, **kwargs)

    def assert_safe_finish(self, control):
        self.assertEqual(control.launches, 1)
        self.assertFalse(control.active_process)
        self.assertEqual(
            set(control.removed), {OWNED_CONTAINER, OWNED_HELPER, OWNED_NETWORK}
        )
        self.assertNotIn("unsafe_restore", control.events)
        self.assertEqual(set(control.restores), set(control.original))
        first_restore = next(
            i for i, event in enumerate(control.events) if event.startswith("restore:")
        )
        last_remove = max(
            i for i, event in enumerate(control.events) if event.startswith("remove:")
        )
        self.assertLess(last_remove, first_restore)

    def test_timeout_cleans_owned_resources_before_restoring_files(self):
        control = self.fixture("timeout")
        error, summary = control.invoke()
        self.assertIsNotNone(error)
        self.assertEqual(summary["status"], "failed")
        self.assert_safe_finish(control)

    def test_main_interruption_reports_failure_and_finishes_cleanup(self):
        control = self.fixture("interrupt")
        error, summary = control.invoke("main")
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["status"], "failed")
        self.assert_safe_finish(control)

    def test_literal_success_requires_cleanup_and_exact_restoration(self):
        control = self.fixture()
        error, summary = control.invoke()
        self.assertIsNone(error)
        self.assertEqual(
            summary,
            {
                "client": "phantom",
                "server": "controlled",
                "status": "succeeded",
                "test": "http3",
            },
        )
        self.assertEqual(control.result_path.read_bytes(), SUCCESS_RESULT)
        self.assert_safe_finish(control)
        for name, content in control.original.items():
            self.assertEqual((control.runner / name).read_bytes(), content)

    def test_literal_result_and_restoration_control_observe_outer_execution(self):
        control = self.fixture()
        error, summary = control.invoke()

        self.assertIsNone(error)
        self.assertEqual(control.launches, 1)
        self.assertEqual(
            summary,
            {
                "client": "phantom",
                "server": "controlled",
                "status": "succeeded",
                "test": "http3",
            },
        )
        self.assertEqual(control.result_path.read_bytes(), SUCCESS_RESULT)
        self.assertEqual(set(control.restores), set(control.original))
        for name, content in control.original.items():
            self.assertEqual((control.runner / name).read_bytes(), content)

    def test_restoration_fault_does_not_skip_other_backups_or_primary_cause(self):
        control = self.fixture("timeout", restore_failure=True)
        error, summary = control.invoke()
        self.assertIsNotNone(error)
        self.assertEqual(set(control.restores), set(control.original))
        self.assertEqual(summary["status"], "failed")
        self.assertIn("timed out", json.dumps(summary))
        self.assertIn("controlled restoration failure", json.dumps(summary))
        for name in ["docker-compose.yml", "testcase.py"]:
            self.assertEqual(
                (control.runner / name).read_bytes(), control.original[name]
            )

    def test_cleanup_failure_cannot_publish_success(self):
        control = self.fixture()
        control.cleanup_failure = True
        error, summary = control.invoke()
        self.assertIsNotNone(error)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("controlled cleanup failure", json.dumps(summary))
        self.assertEqual(set(control.restores), set(control.original))

    def test_primary_cleanup_and_restoration_causes_are_all_retained(self):
        control = self.fixture("timeout", restore_failure=True)
        control.cleanup_failure = True
        error, summary = control.invoke()

        self.assertIsNotNone(error)
        self.assertEqual(summary["status"], "failed")
        detail = json.dumps(summary)
        self.assertIn("timed out", detail)
        self.assertIn("controlled cleanup failure", detail)
        self.assertIn("controlled restoration failure", detail)
        self.assertEqual(set(control.restores), set(control.original))
        self.assertIs(error.__cause__, control.primary)
        self.assertTrue(
            all(isinstance(cause, BaseException) for _, cause in error.failures)
        )

    def test_alpine_helper_and_compose_have_private_owner_not_ambient_project(self):
        control = self.fixture()
        control.invoke()
        owner = control.launch_environment.get("PHANTOM_QUIC_OWNER")
        self.assertTrue(owner)
        self.assertNotEqual(
            control.launch_environment["COMPOSE_PROJECT_NAME"], "foreign-project"
        )
        self.assertIn(b'"--label"', control.testcase_at_launch)
        self.assertIn(OWNER_LABEL.encode(), control.testcase_at_launch)
        self.assertTrue(
            any(
                OWNER_LABEL.encode() in content for content in control.compose_at_launch
            )
        )

    def test_failed_reaping_retains_scratch_and_modified_checkout(self):
        control = self.fixture("timeout")
        control.reap_failure = True
        error, summary = control.invoke()
        self.assertIsNotNone(error)
        self.assertEqual(control.launches, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertTrue(control.scratch)
        self.assertTrue(all(path.exists() for path in control.scratch))
        for path in control.scratch:
            self.assertIn(json.dumps(str(path))[1:-1], json.dumps(summary))
        self.assertEqual(control.restores, [])
        self.assertNotEqual(
            (control.runner / "docker-compose.yml").read_bytes(),
            control.original["docker-compose.yml"],
        )
        for name, content in control.original.items():
            self.assertEqual(
                (control.scratch[0] / "originals" / name).read_bytes(), content
            )

    def test_network_with_foreign_endpoint_is_not_removed(self):
        control = self.fixture("timeout")
        control.foreign_endpoint = True
        error, summary = control.invoke()
        self.assertIsNotNone(error)
        self.assertIn("inspect:" + OWNED_NETWORK, control.events)
        self.assertNotIn(OWNED_NETWORK, control.removed)
        self.assertNotIn(FOREIGN_CONTAINER, control.removed)
        self.assertEqual(summary["status"], "failed")

    def test_cleanup_keeps_frozen_daemon_selection_and_immutable_ids(self):
        control = self.fixture()
        control.change_daemon_after_launch = True
        error, summary = control.invoke()

        self.assertIsNone(error)
        self.assertEqual(summary["status"], "succeeded")
        self.assert_safe_finish(control)

    def test_existing_foreign_fixed_name_is_refused_without_launch(self):
        control = self.fixture()
        control.foreign_name = True
        error, _ = control.invoke()

        self.assertIsNotNone(error)
        self.assertEqual(control.launches, 0)
        self.assertNotIn(FOREIGN_CONTAINER, control.removed)
        for name, content in control.original.items():
            self.assertEqual((control.runner / name).read_bytes(), content)

    def test_windows_actual_runner_rejects_before_mutation_or_launch(self):
        control = self.fixture()
        error, summary = control.invoke(system="win32")
        self.assertIsInstance(error, ValueError)
        self.assertEqual(control.launches, 0)
        self.assertIsNone(summary)
        self.assertFalse((control.root / "reports").exists())
        self.assertEqual(control.restores, [])
        for name, content in control.original.items():
            self.assertEqual((control.runner / name).read_bytes(), content)

    def test_launch_interruption_records_owner_then_finishes_and_restores_handler(self):
        control = self.fixture()
        control.interrupt_on_launch = True
        previous = signal.getsignal(signal.SIGINT)

        error, summary = control.invoke()

        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertEqual(summary["status"], "failed")
        self.assert_safe_finish(control)
        self.assertTrue(control.cleanup_sigint_handlers)
        self.assertTrue(
            all(
                handler == signal.SIG_IGN for handler in control.cleanup_sigint_handlers
            )
        )
        self.assertIs(signal.getsignal(signal.SIGINT), previous)

    def test_auto_checkout_is_retained_when_owned_runner_cannot_be_reaped(self):
        control = self.fixture("timeout")
        control.reap_failure = True

        error, summary = control.invoke("checkout")

        self.assertIsNotNone(error)
        self.assertEqual(control.launches, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(control.restores, [])
        self.assertTrue(control.runner.exists())
        self.assertTrue(all(path.exists() for path in control.scratch))
        self.assertIn(str(control.runner), summary["retained_paths"])

    def test_failed_restoration_keeps_original_bytes_in_owned_scratch(self):
        control = self.fixture("timeout", restore_failure=True)

        error, summary = control.invoke()

        self.assertIsNotNone(error)
        self.assertEqual(set(control.restores), set(control.original))
        self.assertIn(str(control.scratch[0]), summary["retained_paths"])
        for name, content in control.original.items():
            self.assertEqual(
                (control.scratch[0] / "originals" / name).read_bytes(), content
            )

    def test_container_with_wrong_owner_label_is_left_untouched(self):
        control = self.fixture()
        control.foreign_container_label = True

        error, summary = control.invoke()

        self.assertIsNotNone(error)
        self.assertEqual(summary["status"], "failed")
        self.assertNotIn(OWNED_CONTAINER, control.removed)
        self.assertIn(OWNED_HELPER, control.removed)
        self.assertEqual(set(control.restores), set(control.original))

    def test_windows_main_refuses_before_creating_an_automatic_checkout(self):
        control = self.fixture()

        error, summary = control.invoke("checkout", system="win32")

        self.assertIsInstance(error, SystemExit)
        self.assertEqual(error.code, 2)
        self.assertEqual(control.launches, 0)
        self.assertEqual(control.scratch, [])
        self.assertEqual(control.restores, [])
        self.assertIsNone(summary)
        self.assertFalse((control.root / "reports").exists())

    def test_log_inspection_failure_retains_primary_and_finishes_other_cleanup(self):
        control = self.fixture("timeout")
        original_exists = Path.exists

        def denied_log_inspection(path):
            if path.name == "runner-output.log":
                raise PermissionError("controlled log inspection failure")
            return original_exists(path)

        with mock.patch.object(Path, "exists", denied_log_inspection):
            error, summary = control.invoke()

        self.assertIsNotNone(summary)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("timed out", json.dumps(summary))
        self.assertIn("controlled log inspection failure", json.dumps(summary))
        self.assertIs(error.__cause__, control.primary)
        self.assertTrue(
            any(isinstance(cause, PermissionError) for _, cause in error.failures)
        )
        self.assert_safe_finish(control)
        for name, content in control.original.items():
            self.assertEqual((control.runner / name).read_bytes(), content)

        owner_scratch = control.scratch[0]
        self.assertTrue(owner_scratch.exists())
        self.assertIn(str(owner_scratch), summary["retained_paths"])
        self.assertIn(owner_scratch, error.retained_paths)
        for name, content in control.original.items():
            self.assertEqual((owner_scratch / "originals" / name).read_bytes(), content)

    def test_main_cleanup_failure_keeps_all_previously_retained_recovery_paths(self):
        control = self.fixture("timeout")
        control.cleanup_failure = True
        original_remove = quic_interop.shutil.rmtree
        original_report = quic_interop._report_failure
        reported = []
        checkout_cleanup_attempts = []

        def denied_checkout_cleanup(path, *args, **kwargs):
            if control.scratch and Path(path) == control.scratch[0]:
                checkout_cleanup_attempts.append(Path(path))
                raise PermissionError("controlled temporary checkout cleanup failure")
            return original_remove(path, *args, **kwargs)

        def observe_failure_report(*args, **kwargs):
            failure = original_report(*args, **kwargs)
            reported.append(failure)
            return failure

        with (
            mock.patch.object(quic_interop.shutil, "rmtree", denied_checkout_cleanup),
            mock.patch.object(quic_interop, "_report_failure", observe_failure_report),
        ):
            error, summary = control.invoke("checkout")

        self.assertIsInstance(error, SystemExit)
        self.assertEqual(error.code, 2)
        self.assertEqual(control.launches, 1)
        self.assertFalse(control.active_process)
        self.assertEqual(len(control.scratch), 2)
        checkout, owner_scratch = control.scratch
        self.assertEqual(checkout_cleanup_attempts, [checkout])
        self.assertEqual(len(reported), 2)
        self.assertEqual(set(control.restores), set(control.original))
        self.assertNotIn("unsafe_restore", control.events)

        self.assertEqual(summary["status"], "failed")
        self.assertIn("timed out", json.dumps(summary))
        self.assertIn("controlled cleanup failure", json.dumps(summary))
        self.assertIn(
            "controlled temporary checkout cleanup failure", json.dumps(summary)
        )
        self.assertEqual(
            set(summary["retained_paths"]), {str(checkout), str(owner_scratch)}
        )
        self.assertEqual(set(reported[-1].retained_paths), {checkout, owner_scratch})
        self.assertIs(reported[-1].__cause__, control.primary)
        self.assertTrue(all(path.exists() for path in control.scratch))
        for name, content in control.original.items():
            self.assertEqual((control.runner / name).read_bytes(), content)
            self.assertEqual((owner_scratch / "originals" / name).read_bytes(), content)
