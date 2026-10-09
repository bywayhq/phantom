import contextlib
import io
import json
import logging.handlers
import multiprocessing
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.conformance import wpt_eventsource as runner
from scripts.conformance.wpt_eventsource import (
    WPT_REVISION,
    load_case_ids,
    parse_adapter_output,
)

FULL_CASES = (
    "eventsource/event-data.any.js",
    "eventsource/format-bom-2.any.js",
    "eventsource/format-bom.any.js",
    "eventsource/format-data-before-final-empty-line.any.js",
    "eventsource/format-field-event.any.js",
    "eventsource/format-field-id-3.window.js#persists",
    "eventsource/format-field-id-3.window.js#resets-colon",
    "eventsource/format-field-id-3.window.js#resets-no-colon",
    "eventsource/format-field-id-null.window.js#nul-nul",
    "eventsource/format-field-id-null.window.js#nul-prefix",
    "eventsource/format-field-id-null.window.js#nul-suffix",
    "eventsource/format-field-id-null.window.js#nul-surrounded",
    "eventsource/format-field-id-null.window.js#space-nul",
    "eventsource/format-field-id.any.js",
    "eventsource/format-field-parsing.any.js",
    "eventsource/format-field-retry-bogus.any.js",
    "eventsource/format-mime-trailing-semicolon.any.js",
    "eventsource/format-mime-valid-bogus.any.js",
    "eventsource/format-newlines.any.js",
    "eventsource/format-utf-8.any.js",
    "eventsource/request-accept.any.js",
    "eventsource/request-cache-control.any.js#same-origin",
    "eventsource/request-status-error.window.js#204",
    "eventsource/request-status-error.window.js#205",
    "eventsource/request-status-error.window.js#210",
    "eventsource/request-status-error.window.js#299",
    "eventsource/request-status-error.window.js#404",
    "eventsource/request-status-error.window.js#410",
    "eventsource/request-status-error.window.js#503",
)


class ServerFixture:
    def __init__(self, *, start_error=None, stop_error=None):
        self.start_error = start_error
        self.stop_error = stop_error
        self.started = False
        self.closed = False
        self.stop_calls = 0
        self.port = 49123
        self.source = None
        self.certificate = None
        self.resources_at_stop = False
        self.httpd = SimpleNamespace(server_close=self.close)

    def construct(self, **kwargs):
        self.source = Path(kwargs["doc_root"])
        self.certificate = Path(kwargs["certificate"])
        return self

    def start(self):
        if self.start_error is not None:
            raise self.start_error
        self.started = True

    def stop(self):
        self.stop_calls += 1
        self.resources_at_stop = self.source.exists() and self.certificate.exists()
        if self.stop_error is not None:
            raise self.stop_error
        self.close()

    def close(self):
        self.closed = True
        self.started = False


class PipeFixture:
    def __init__(self, *, child=False, messages=None):
        self.child = child
        self.messages = messages if messages is not None else []
        self.closed = False
        self.sent = []
        self.waits = []

    def poll(self, timeout):
        self.waits.append(timeout)
        return bool(self.messages)

    def recv(self):
        return "stop" if self.child else self.messages.pop(0)

    def send(self, message):
        self.sent.append(message)
        if self.child:
            self.messages.append(message)

    def close(self):
        self.closed = True


class ProcessFixture:
    def __init__(
        self,
        target,
        args,
        *,
        execute=True,
        terminate_reaps=True,
        kill_reaps=True,
        start_error=None,
    ):
        self.target = target
        self.args = args
        self.execute = execute
        self.terminate_reaps = terminate_reaps
        self.kill_reaps = kill_reaps
        self.start_error = start_error
        self.pid = None
        self.exitcode = None
        self.alive = False
        self.closed = False
        self.events = []

    def start(self):
        self.events.append("start")
        if self.start_error is not None:
            raise self.start_error
        self.pid = 123
        self.alive = True
        if self.execute:
            self.target(*self.args)

    def join(self, timeout):
        self.events.append(("join", timeout))
        if self.execute:
            self.alive = False
            self.exitcode = 0

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.events.append("terminate")
        if self.terminate_reaps:
            self.alive = False
            self.exitcode = -15

    def kill(self):
        self.events.append("kill")
        if self.kill_reaps:
            self.alive = False
            self.exitcode = -9

    def close(self):
        if self.alive:
            raise AssertionError("closed an unreaped process")
        self.events.append("close")
        self.closed = True


class SpawnFixture:
    def __init__(self, **process_options):
        messages = []
        self.parent = PipeFixture(messages=messages)
        self.child = PipeFixture(child=True, messages=messages)
        self.options = process_options
        self.process = None

    def Pipe(self):
        return self.parent, self.child

    def Process(self, *, target, args):
        self.process = ProcessFixture(target, args, **self.options)
        return self.process


class WptRunFixture(unittest.TestCase):
    def exercise(
        self,
        *,
        server=None,
        scenario_failure=False,
        adapter_error=None,
        log_error=None,
        spawn=None,
    ):
        server = server or ServerFixture()
        repository = Path(__file__).resolve().parents[3]
        manifest = repository / "scripts/conformance/wpt-eventsource/full.json"
        self.assertEqual(load_case_ids(manifest), FULL_CASES)
        output = (
            "".join(
                f"CASE\t{'FAIL' if scenario_failure and index == 0 else 'PASS'}\t{case}"
                + ("\tscenario marker" if scenario_failure and index == 0 else "")
                + "\n"
                for index, case in enumerate(FULL_CASES)
            )
            + f"SUMMARY\t29\t{int(scenario_failure)}\n"
        )
        handlers = []
        handler_type = logging.handlers.RotatingFileHandler
        log_observations = []

        def checkout(source):
            source.mkdir()
            for case in FULL_CASES:
                path = source / case.split("#", 1)[0]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

        def certificate(directory):
            # These are file-lifetime markers, not a native TLS fixture.
            for name in ("key.pem", "leaf.pem", "root.der"):
                (directory / name).write_text("controlled boundary artifact")
            return SimpleNamespace(
                private_key_pem=directory / "key.pem",
                certificate_pem=directory / "leaf.pem",
                root_der=directory / "root.der",
            )

        def handler_factory(*args, **kwargs):
            handler = handler_type(*args, **kwargs)
            close = handler.close
            handlers.append((handler, close))

            def observed_close():
                log_observations.append(server.stop_calls)
                close()
                if log_error is not None:
                    raise log_error

            handler.close = observed_close
            return handler

        with tempfile.TemporaryDirectory() as temporary:
            reports = Path(temporary).resolve()
            reports.relative_to(Path(tempfile.gettempdir()).resolve())
            stdout = io.StringIO()
            stderr = io.StringIO()
            observed_error = None
            spawn = spawn or SpawnFixture()
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    patch.object(
                        runner.multiprocessing, "get_context", return_value=spawn
                    )
                )
                stack.enter_context(patch.object(runner, "_checkout_wpt", checkout))
                stack.enter_context(
                    patch.object(runner, "generate_loopback_certificate", certificate)
                )
                stack.enter_context(
                    patch.object(
                        runner,
                        "_load_server_types",
                        return_value=(lambda value: value, server.construct),
                    )
                )
                stack.enter_context(
                    patch.object(
                        runner, "_git_revision", return_value="fixture revision"
                    )
                )
                stack.enter_context(
                    patch.object(
                        runner.platform, "platform", return_value="fixture host"
                    )
                )
                adapter = stack.enter_context(
                    patch.object(
                        runner.subprocess,
                        "run",
                        side_effect=adapter_error,
                        return_value=subprocess.CompletedProcess(
                            [], int(scenario_failure), output, ""
                        ),
                    )
                )
                stack.enter_context(
                    patch.object(
                        logging.handlers,
                        "RotatingFileHandler",
                        side_effect=handler_factory,
                    )
                )
                stack.enter_context(
                    patch.object(
                        sys,
                        "argv",
                        ["wpt_eventsource.py", "full", "--report-root", str(reports)],
                    )
                )
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                try:
                    runner.main()
                except (Exception, KeyboardInterrupt, SystemExit) as error:
                    observed_error = error
                finally:
                    for handler, close in handlers:
                        handler.close = close
                        close()

            summaries = list(reports.glob("full-*/summary.json"))
            self.assertEqual(len(summaries), 1)
            summary = json.loads(summaries[0].read_text())
            if adapter.called:
                command = adapter.call_args.args[0]
                requested = tuple(
                    command[index + 1]
                    for index, value in enumerate(command)
                    if value == "--case"
                )
                self.assertEqual(requested, FULL_CASES)
                self.assertEqual(adapter.call_args.kwargs["timeout"], 420)

            return SimpleNamespace(
                summary=summary,
                error=observed_error,
                stdout=stdout.getvalue(),
                stderr=stderr.getvalue(),
                server=server,
                log_observations=log_observations,
                handler_count=len(handlers),
                spawn=spawn,
            )

    def assert_case_results(self, result, *, failures=0):
        self.assertEqual(result.summary["case_count"], 29)
        self.assertEqual(result.summary["failure_count"], failures)
        self.assertEqual(set(result.summary["cases"]), set(FULL_CASES))
        self.assertEqual(
            [
                case
                for case, value in result.summary["cases"].items()
                if value["status"] == "fail"
            ],
            list(FULL_CASES[:failures]),
        )


class WptLifecycleTests(WptRunFixture):
    def test_complete_full_case_set_passes(self):
        result = self.exercise()

        self.assert_case_results(result)
        self.assertIsNone(result.error)
        self.assertTrue(result.server.closed)
        self.assertEqual(result.server.stop_calls, 1)

    def test_scenario_failure_keeps_observed_cases(self):
        result = self.exercise(scenario_failure=True)

        self.assert_case_results(result, failures=1)
        self.assertIn("scenario marker", result.summary["failures"][0])
        self.assertIn("scenarios reported failures", result.stderr)
        self.assertTrue(result.server.closed)

    def test_server_resources_remain_until_stop(self):
        result = self.exercise()

        self.assertTrue(result.server.resources_at_stop)
        self.assertFalse(result.server.source.exists())
        self.assertFalse(result.server.certificate.exists())

    def test_start_failure_closes_acquired_unstarted_server(self):
        result = self.exercise(
            server=ServerFixture(start_error=OSError("start marker"))
        )

        self.assertIsInstance(result.error, SystemExit)
        self.assertIn("start marker", result.stderr)
        self.assertTrue(result.server.closed)
        self.assertEqual(result.server.stop_calls, 0)
        self.assertEqual(result.summary["case_count"], 0)

    def test_stop_failure_fails_run_without_inventing_case_failures(self):
        result = self.exercise(server=ServerFixture(stop_error=OSError("stop marker")))

        self.assert_case_results(result)
        self.assertIsInstance(result.error, SystemExit)
        self.assertTrue(result.summary.get("run_failed", False))
        self.assertIn(
            "stop marker", " ".join(result.summary.get("infrastructure_failures", []))
        )
        self.assertNotIn("29 cases, 0 failures", result.stdout)

    def test_scenario_and_stop_failures_retain_both_causes(self):
        result = self.exercise(
            server=ServerFixture(stop_error=OSError("stop marker")),
            scenario_failure=True,
        )

        self.assert_case_results(result, failures=1)
        self.assertIn("scenario marker", result.summary["failures"][0])
        self.assertIn(
            "stop marker", " ".join(result.summary.get("infrastructure_failures", []))
        )
        self.assertIn("scenarios reported failures", result.stderr)
        self.assertIn("stop marker", result.stderr)

    def test_log_close_failure_fails_run_and_reports_cause(self):
        result = self.exercise(log_error=OSError("log close marker"))

        self.assert_case_results(result)
        self.assertTrue(result.summary.get("run_failed", False))
        self.assertIn(
            "log close marker",
            " ".join(result.summary.get("infrastructure_failures", [])),
        )
        self.assertIn("log close marker", result.stderr)

    def test_all_cleanup_owners_are_attempted_and_causes_retained(self):
        result = self.exercise(
            server=ServerFixture(stop_error=OSError("stop marker")),
            log_error=OSError("log close marker"),
        )

        self.assert_case_results(result)
        self.assertEqual(result.server.stop_calls, 1)
        self.assertEqual(result.log_observations, [1])
        self.assertFalse(result.server.source.exists())
        self.assertIn("stop marker", result.stderr)
        self.assertIn("log close marker", result.stderr)

    def test_adapter_interrupt_preserves_identity_and_cleans_owners(self):
        interrupt = KeyboardInterrupt("adapter interrupt marker")
        result = self.exercise(adapter_error=interrupt)

        self.assertIs(result.error, interrupt)
        self.assertTrue(result.server.closed)
        self.assertEqual(result.log_observations, [1])
        self.assertEqual(result.summary["case_count"], 0)
        self.assertEqual(result.summary["failure_count"], 0)
        self.assertTrue(result.summary["run_failed"])

    def test_cleanup_interrupt_still_closes_other_owners(self):
        interrupt = KeyboardInterrupt("stop interrupt marker")
        result = self.exercise(server=ServerFixture(stop_error=interrupt))

        # A child exception is reported across IPC; parent interrupt identity
        # is covered separately by the adapter interruption control.
        self.assertIsInstance(result.error, SystemExit)
        self.assertEqual(result.log_observations, [1])
        self.assertFalse(result.server.source.exists())
        self.assert_case_results(result)
        self.assertTrue(result.summary.get("run_failed", False))
        self.assertIn(
            "stop interrupt marker",
            " ".join(result.summary.get("infrastructure_failures", [])),
        )

    def test_unreaped_owner_retains_and_reports_temporary_files(self):
        spawn = SpawnFixture(execute=False, terminate_reaps=False, kill_reaps=False)
        spawn.parent.messages.append(("ready", 49123))
        result = self.exercise(spawn=spawn)
        source = spawn.process.args[0]
        temporary_root = source.parent.resolve()
        temporary_root.relative_to(Path(tempfile.gettempdir()).resolve())
        self.addCleanup(shutil.rmtree, temporary_root)

        self.assert_case_results(result)
        self.assertTrue(result.summary["run_failed"])
        self.assertTrue(source.exists())
        self.assertTrue(spawn.process.args[1].certificate_pem.exists())
        self.assertIn(
            str(temporary_root), " ".join(result.summary["infrastructure_failures"])
        )
        self.assertFalse(spawn.process.closed)

    def test_child_exit_failure_preserves_observed_case_results(self):
        original_join = ProcessFixture.join

        def abnormal_exit(process, timeout):
            original_join(process, timeout)
            process.exitcode = 17

        with patch.object(ProcessFixture, "join", abnormal_exit):
            result = self.exercise()

        self.assert_case_results(result)
        self.assertTrue(result.summary["run_failed"])
        self.assertIn("exited with status 17", result.stderr)
        self.assertIn(
            "exited with status 17", " ".join(result.summary["infrastructure_failures"])
        )

    def test_adapter_failure_and_cleanup_error_retain_both_causes(self):
        result = self.exercise(
            server=ServerFixture(stop_error=OSError("stop marker")),
            adapter_error=subprocess.TimeoutExpired(["controlled adapter"], 420),
        )

        self.assertEqual(result.summary["case_count"], 0)
        self.assertEqual(result.summary["failure_count"], 0)
        self.assertEqual(result.summary["cases"], {})
        self.assertIn("TimeoutExpired", result.stderr)
        self.assertIn("stop marker", result.stderr)
        self.assertEqual(len(result.summary["infrastructure_failures"]), 2)

    def test_repeated_sigint_during_file_cleanup_preserves_summary(self):
        original_rmtree = shutil.rmtree
        previous = signal.getsignal(signal.SIGINT)

        def interrupted_cleanup(path, *args, **kwargs):
            if Path(path).name.startswith("phantom-wpt-eventsource-"):
                signal.raise_signal(signal.SIGINT)
                signal.raise_signal(signal.SIGINT)
            return original_rmtree(path, *args, **kwargs)

        with patch.object(runner.shutil, "rmtree", interrupted_cleanup):
            result = self.exercise()

        self.assert_case_results(result)
        self.assertIsInstance(result.error, KeyboardInterrupt)
        self.assertTrue(result.summary["run_failed"])
        self.assertTrue(result.server.closed)
        self.assertFalse(result.server.source.exists())
        self.assertIs(signal.getsignal(signal.SIGINT), previous)


class WptProcessOwnershipTests(WptRunFixture):
    def owner(self, spawn):
        with patch.object(runner.multiprocessing, "get_context", return_value=spawn):
            return runner._ServerOwner(Path("source"), None, Path("server.log"))

    def test_startup_timeout_reaps_process_and_closes_connections(self):
        spawn = SpawnFixture(execute=False)
        result = self.exercise(spawn=spawn)

        self.assertIsInstance(result.error, SystemExit)
        self.assertIn("server startup exceeded", result.stderr)
        self.assertIn("server shutdown exceeded", result.stderr)
        self.assertFalse(spawn.process.alive)
        self.assertTrue(spawn.process.closed)
        self.assertTrue(spawn.parent.closed)
        self.assertTrue(spawn.child.closed)
        self.assertIn("terminate", spawn.process.events)
        self.assertTrue(all(0 < timeout <= 10 for timeout in spawn.parent.waits))

    def test_shutdown_timeout_escalates_to_kill_and_observes_reaping(self):
        spawn = SpawnFixture(execute=False, terminate_reaps=False)
        owner = self.owner(spawn)
        owner.start()
        spawn.parent.messages.append(("ready", 49123))
        owner.wait_ready()

        with self.assertRaisesRegex(RuntimeError, "shutdown exceeded"):
            owner.stop()

        self.assertFalse(spawn.process.alive)
        self.assertTrue(spawn.process.closed)
        self.assertEqual(
            [event for event in spawn.process.events if isinstance(event, str)],
            ["start", "terminate", "kill", "close"],
        )
        joins = [event[1] for event in spawn.process.events if isinstance(event, tuple)]
        self.assertEqual(len(joins), 2)
        self.assertTrue(all(0 < timeout <= 5 for timeout in joins))

    def test_unreaped_process_is_reported_and_not_closed(self):
        spawn = SpawnFixture(execute=False, terminate_reaps=False, kill_reaps=False)
        owner = self.owner(spawn)
        owner.start()
        spawn.parent.messages.append(("ready", 49123))
        owner.wait_ready()

        with self.assertRaises(runner._ServerFailure) as raised:
            owner.stop()

        self.assertTrue(raised.exception.unreaped)
        self.assertTrue(spawn.process.alive)
        self.assertFalse(spawn.process.closed)
        self.assertTrue(spawn.parent.closed)

    def test_native_spawn_import_and_reaping_keep_files_alive(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            certificate_path = source / "leaf.pem"
            certificate_path.write_text("file lifetime marker")
            certificate = SimpleNamespace(
                certificate_pem=certificate_path, private_key_pem=certificate_path
            )
            tools = source / "tools"
            package = tools / "wptserve"
            package.mkdir(parents=True)
            (tools / "localpaths.py").touch()
            (package / "__init__.py").touch()
            (package / "config.py").write_text("class Config(dict):\n    pass\n")
            # An independent public server interface exercises the actual child
            # target and Windows spawn imports without a TLS/WPT handshake.
            (package / "server.py").write_text(
                """import json
import logging
from pathlib import Path
from types import SimpleNamespace
from scripts.conformance import wpt_eventsource

class WebTestHttpd:
    def __init__(self, **kwargs):
        self.source = Path(kwargs['doc_root'])
        self.certificate = Path(kwargs['certificate'])
        self.port = 49123
        self.started = False
        self.httpd = SimpleNamespace(server_close=lambda: None)

    def start(self):
        self.started = True
        logging.getLogger('fixture').warning('fixture server started')

    def stop(self):
        marker = {
            'module': wpt_eventsource.__name__,
            'source_alive': self.source.exists(),
            'certificate_alive': self.certificate.exists(),
            'started': self.started,
        }
        (self.source / 'child-status.json').write_text(json.dumps(marker))
        self.started = False
        self.httpd = None
"""
            )
            owner = runner._ServerOwner(source, certificate, source / "server.log")
            process = owner.process
            try:
                owner.start()
                owner.wait_ready()
                self.assertIsNotNone(process.pid)
            finally:
                owner.stop()

            marker = json.loads((source / "child-status.json").read_text())
            self.assertEqual(marker["module"], "scripts.conformance.wpt_eventsource")
            self.assertTrue(marker["started"])
            self.assertTrue(marker["source_alive"])
            self.assertTrue(marker["certificate_alive"])
            self.assertIn("fixture server started", (source / "server.log").read_text())
            self.assertNotIn(process, multiprocessing.active_children())

    def test_process_start_error_closes_unstarted_owner_and_keeps_cause(self):
        error = OSError("process start marker")
        spawn = SpawnFixture(start_error=error)
        result = self.exercise(spawn=spawn)

        self.assertIsInstance(result.error, SystemExit)
        self.assertIn("process start marker", result.stderr)
        self.assertTrue(result.summary["run_failed"])
        self.assertTrue(spawn.process.closed)
        self.assertTrue(spawn.parent.closed)
        self.assertTrue(spawn.child.closed)
        self.assertFalse(
            any(isinstance(event, tuple) for event in spawn.process.events)
        )

    def test_repeated_sigint_during_shutdown_still_reaps_and_restores_handler(self):
        spawn = SpawnFixture(execute=False)
        owner = self.owner(spawn)
        owner.start()
        previous = signal.getsignal(signal.SIGINT)

        def interrupted_poll(timeout):
            signal.raise_signal(signal.SIGINT)
            signal.raise_signal(signal.SIGINT)
            return False

        with (
            patch.object(spawn.parent, "poll", side_effect=interrupted_poll),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            owner.stop()

        self.assertIn("interrupted during shutdown", str(raised.exception))
        self.assertTrue(spawn.process.closed)
        self.assertFalse(spawn.process.alive)
        self.assertIs(signal.getsignal(signal.SIGINT), previous)
        self.assertIn("shutdown exceeded", " ".join(raised.exception.shutdown_failures))


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
