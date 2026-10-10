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
import time
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
        self.acquisition_uncertain = False

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

    def recover_start_failure(self):
        # This fixture's start_error occurs before its simulated acquisition.
        pass

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
                stack.enter_context(
                    patch.object(runner, "_ServerProcess", spawn.Process)
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
    def test_cleanup_interrupt_after_adapter_failure_keeps_identity_and_causes(self):
        for operation in ("temporary files", "rotated log", "summary"):
            with self.subTest(operation=operation):
                interrupt = KeyboardInterrupt(f"{operation} interruption marker")
                remove = shutil.rmtree
                unlink = Path.unlink
                write = Path.write_text

                def interrupted_remove(
                    path, *args, _remove=remove, _interrupt=interrupt, **kwargs
                ):
                    result = _remove(path, *args, **kwargs)
                    if Path(path).name.startswith("phantom-wpt-eventsource-"):
                        raise _interrupt
                    return result

                def interrupted_unlink(
                    path, *args, _unlink=unlink, _interrupt=interrupt, **kwargs
                ):
                    result = _unlink(path, *args, **kwargs)
                    if path.name == "server.log.1":
                        raise _interrupt
                    return result

                def interrupted_write(
                    path, *args, _write=write, _interrupt=interrupt, **kwargs
                ):
                    result = _write(path, *args, **kwargs)
                    if path.name == "summary.json":
                        raise _interrupt
                    return result

                target, replacement = {
                    "temporary files": ((shutil, "rmtree"), interrupted_remove),
                    "rotated log": ((Path, "unlink"), interrupted_unlink),
                    "summary": ((Path, "write_text"), interrupted_write),
                }[operation]
                with patch.object(*target, replacement):
                    result = self.exercise(
                        adapter_error=OSError("adapter failure marker")
                    )

                self.assertIs(result.error, interrupt)
                self.assertTrue(result.server.closed)
                self.assertIn("adapter failure marker", result.stderr)
                self.assertIn(f"{operation} interruption marker", result.stderr)

    def test_summary_sigint_keeps_original_adapter_interrupt_identity(self):
        interrupt = KeyboardInterrupt("original adapter interruption marker")
        write = Path.write_text
        signaled = False

        def signaled_write(path, *args, **kwargs):
            nonlocal signaled
            result = write(path, *args, **kwargs)
            if path.name == "summary.json" and not signaled:
                signaled = True
                signal.raise_signal(signal.SIGINT)
            return result

        with patch.object(Path, "write_text", signaled_write):
            result = self.exercise(adapter_error=interrupt)

        self.assertIs(result.error, interrupt)
        self.assertTrue(result.server.closed)
        self.assertTrue(result.summary["run_failed"])
        failures = " ".join(result.summary["infrastructure_failures"])
        self.assertIn("original adapter interruption marker", failures)
        self.assertIn("summary publication: KeyboardInterrupt", failures)

    def test_summary_sigint_and_write_failure_preserve_interruption_and_all_causes(
        self,
    ):
        for prior_interrupt in (False, True):
            with self.subTest(prior_interrupt=prior_interrupt):
                adapter_error = (
                    KeyboardInterrupt("first adapter interruption marker")
                    if prior_interrupt
                    else OSError("first adapter failure marker")
                )
                write = Path.write_text

                def failed_write(path, *args, _write=write, **kwargs):
                    result = _write(path, *args, **kwargs)
                    if path.name == "summary.json":
                        signal.raise_signal(signal.SIGINT)
                        raise OSError("summary write failure marker")
                    return result

                with patch.object(Path, "write_text", failed_write):
                    result = self.exercise(adapter_error=adapter_error)

                self.assertIsInstance(result.error, KeyboardInterrupt)
                if prior_interrupt:
                    self.assertIs(result.error, adapter_error)
                self.assertTrue(result.server.closed)
                self.assertIn(str(adapter_error), result.stderr)
                self.assertIn("summary write failure marker", result.stderr)
                self.assertIn("summary publication: KeyboardInterrupt", result.stderr)

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
    def test_construction_interrupt_and_control_close_failure_keep_identity(self):
        interrupt = KeyboardInterrupt("construction interruption marker")
        spawn = SpawnFixture()
        close = spawn.child.close

        def failed_construct(**kwargs):
            raise interrupt

        def failed_close():
            close()
            raise OSError("construction child control marker")

        with (
            patch.object(spawn, "Process", failed_construct),
            patch.object(spawn.child, "close", failed_close),
        ):
            result = self.exercise(spawn=spawn)

        self.assertIs(result.error, interrupt)
        self.assertTrue(spawn.child.closed)
        self.assertTrue(spawn.parent.closed)
        failures = " ".join(result.summary["infrastructure_failures"])
        self.assertIn("construction interruption marker", failures)
        self.assertIn("construction child control marker", failures)

    def test_construction_failure_and_control_close_interrupt_keep_both_causes(self):
        interrupt = KeyboardInterrupt("construction control interruption marker")
        spawn = SpawnFixture()
        close = spawn.child.close

        def failed_construct(**kwargs):
            raise OSError("construction failure marker")

        def interrupted_close():
            close()
            raise interrupt

        with (
            patch.object(spawn, "Process", failed_construct),
            patch.object(spawn.child, "close", interrupted_close),
        ):
            result = self.exercise(spawn=spawn)

        self.assertIs(result.error, interrupt)
        self.assertTrue(spawn.child.closed)
        self.assertTrue(spawn.parent.closed)
        self.assertIn("construction failure marker", result.stderr)
        self.assertIn("construction control interruption marker", result.stderr)

    def test_start_failure_and_control_close_interrupt_keep_both_causes(self):
        interrupt = KeyboardInterrupt("start control interruption marker")
        spawn = SpawnFixture(start_error=OSError("start failure marker"))
        close = spawn.child.close

        def interrupted_close():
            close()
            raise interrupt

        with patch.object(spawn.child, "close", interrupted_close):
            result = self.exercise(spawn=spawn)

        self.assertIs(result.error, interrupt)
        self.assertTrue(spawn.child.closed)
        self.assertTrue(spawn.process.closed)
        self.assertIn("start failure marker", result.stderr)
        self.assertIn("start control interruption marker", result.stderr)

    def test_shutdown_control_interrupt_and_process_close_failure_keep_identity(self):
        spawn = SpawnFixture(execute=False)
        owner = self.owner(spawn)
        owner.start()
        spawn.process.execute = True
        spawn.parent.messages.append(("stopped", []))
        control_close = spawn.parent.close
        process_close = spawn.process.close
        interrupt = KeyboardInterrupt("shutdown control interruption marker")

        def interrupted_close():
            control_close()
            raise interrupt

        def failed_close():
            process_close()
            raise OSError("shutdown process close marker")

        with (
            patch.object(spawn.parent, "close", interrupted_close),
            patch.object(spawn.process, "close", failed_close),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            owner.stop()

        self.assertIs(raised.exception, interrupt)
        self.assertTrue(spawn.parent.closed)
        self.assertTrue(spawn.process.closed)
        self.assertFalse(spawn.process.alive)
        failures = " ".join(raised.exception.shutdown_failures)
        self.assertIn("shutdown control interruption marker", failures)
        self.assertIn("shutdown process close marker", failures)

    def owner(self, spawn):
        with (
            patch.object(runner.multiprocessing, "get_context", return_value=spawn),
            patch.object(runner, "_ServerProcess", spawn.Process),
        ):
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

    def test_start_interrupt_and_control_close_failure_keep_identity_and_causes(self):
        interrupt = KeyboardInterrupt("start interruption marker")
        spawn = SpawnFixture(start_error=interrupt)
        close = spawn.child.close

        def failed_close():
            close()
            raise OSError("child control close marker")

        with patch.object(spawn.child, "close", failed_close):
            result = self.exercise(spawn=spawn)

        self.assertIs(result.error, interrupt)
        self.assertTrue(spawn.process.closed)
        self.assertTrue(spawn.child.closed)
        self.assertTrue(result.summary["run_failed"])
        failures = " ".join(result.summary["infrastructure_failures"])
        self.assertIn("start interruption marker", failures)
        self.assertIn("child control close marker", failures)


class WptAcquisitionTests(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "POSIX writes bootstrap data after spawn")
    def test_native_bootstrap_write_failure_observes_child_exit_before_cleanup(self):
        from multiprocessing import popen_spawn_posix

        constructor = popen_spawn_posix.Popen
        initialize = constructor.__init__
        native = []
        failure = OSError("native bootstrap write marker")
        open_file = open

        def captured_constructor(popen, process):
            native.append(popen)
            initialize(popen, process)

        @contextlib.contextmanager
        def failed_writer(*args, **kwargs):
            with open_file(*args, **kwargs):
                self.assertIsNotNone(native[0].pid)

                def write(data):
                    raise failure

                yield SimpleNamespace(write=write)

        try:
            with (
                patch.object(constructor, "__init__", captured_constructor),
                patch.object(popen_spawn_posix, "open", failed_writer, create=True),
            ):
                context = multiprocessing.get_context("spawn")
                spawn = SimpleNamespace(
                    Pipe=context.Pipe, Process=runner._ServerProcess
                )
                result = WptRunFixture().exercise(spawn=spawn)

            self.assertIsNotNone(
                native[0].returncode, "owner did not observe child exit"
            )
            self.assertNotEqual(native[0].returncode, 0)
            self.assertTrue(result.summary["run_failed"])
            self.assertIn("native bootstrap write marker", result.stderr)
            self.assertIn("exited with status", result.stderr)
        finally:
            for popen in native:
                if popen.poll() is None:
                    popen.terminate()
                self.assertIsNotNone(
                    popen.wait(8), "native fixture child was not reaped"
                )
                popen.close()

    @unittest.skipUnless(
        sys.platform == "win32", "Windows serializes after native spawn"
    )
    def test_native_serialization_failure_observes_child_exit_before_file_cleanup(self):
        from multiprocessing import popen_spawn_win32, reduction

        constructor = popen_spawn_win32.Popen
        initialize = constructor.__init__
        dump = reduction.dump
        native = []
        failure = OSError("native serialization write marker")

        def captured_constructor(popen, process):
            native.append(popen)
            initialize(popen, process)

        def failed_dump(value, destination, protocol=None):
            if isinstance(value, multiprocessing.process.BaseProcess):
                self.assertIsNotNone(native[0].pid)
                raise failure
            return dump(value, destination, protocol)

        try:
            # The child is real; only the serialization write after CreateProcess
            # fails. Its EOF exit must be observed by the production owner.
            with (
                patch.object(constructor, "__init__", captured_constructor),
                patch.object(reduction, "dump", failed_dump),
            ):
                context = multiprocessing.get_context("spawn")
                spawn = SimpleNamespace(
                    Pipe=context.Pipe, Process=runner._ServerProcess
                )
                result = WptRunFixture().exercise(spawn=spawn)

            observed_exit = native[0].returncode
            self.assertIsNotNone(
                observed_exit, "owner did not observe acquired child exit"
            )
            self.assertNotEqual(observed_exit, 0)
            self.assertTrue(result.summary["run_failed"])
            self.assertIn("native serialization write marker", result.stderr)
            self.assertIn("exited with status", result.stderr)
        finally:
            for popen in native:
                if popen.poll() is None:
                    popen.terminate()
                self.assertIsNotNone(
                    popen.wait(8), "native fixture child was not reaped"
                )
                popen.close()

    def exercise_native_acquisition(self, *, interrupt=None, start_error=None):
        process_type = runner._ServerProcess
        original_popen = process_type._Popen
        native = []
        resources = []
        repository = Path(__file__).resolve().parents[3]
        cases = load_case_ids(
            repository / "scripts/conformance/wpt-eventsource/smoke.json"
        )
        output = "".join(f"CASE\tPASS\t{case}\n" for case in cases)
        output += f"SUMMARY\t{len(cases)}\t0\n"
        previous = signal.getsignal(signal.SIGINT)

        with tempfile.TemporaryDirectory() as temporary:
            reports = Path(temporary)
            marker = reports / "child-lifetime.json"
            started_marker = reports / "child-started.txt"

            def checkout(source):
                resources.append(source.parent)
                source.mkdir()
                for case in cases:
                    case_path = source / case.split("#", 1)[0]
                    case_path.parent.mkdir(parents=True, exist_ok=True)
                    case_path.touch()
                package = source / "tools/wptserve"
                package.mkdir(parents=True)
                (package.parent / "localpaths.py").touch()
                (package / "__init__.py").touch()
                (package / "config.py").write_text("class Config(dict):\n    pass\n")
                (package / "server.py").write_text(
                    """import json
from pathlib import Path
from types import SimpleNamespace

class WebTestHttpd:
    def __init__(self, **kwargs):
        self.source = Path(kwargs['doc_root'])
        self.certificate = Path(kwargs['certificate'])
        self.started = False
        self.port = 49123
        self.httpd = SimpleNamespace(server_close=lambda: None)

    def start(self):
        self.started = True
        Path(STARTED_MARKER).write_text('server start observed')

    def stop(self):
        Path(MARKER).write_text(json.dumps({
            'source_alive': self.source.exists(),
            'certificate_alive': self.certificate.exists(),
        }))
        self.started = False
""".replace("STARTED_MARKER", repr(str(started_marker))).replace(
                        "MARKER", repr(str(marker))
                    )
                )

            def certificate(directory):
                leaf = directory / "leaf.pem"
                leaf.write_text("controlled file lifetime marker")
                return SimpleNamespace(
                    certificate_pem=leaf, private_key_pem=leaf, root_der=leaf
                )

            def acquire(process):
                popen = original_popen(process)
                native.append(popen)
                # BaseProcess.start has not installed the returned native handle.
                self.assertIsNone(process.pid)
                deadline = time.monotonic() + 8
                while not started_marker.exists():
                    if time.monotonic() >= deadline or popen.poll() is not None:
                        raise AssertionError("native child did not reach startup")
                    time.sleep(0.01)
                if interrupt is not None:
                    signal.raise_signal(signal.SIGINT)
                if start_error is not None:
                    raise start_error
                return popen

            def interrupted(signum, frame):
                raise interrupt

            observed_error = None
            try:
                if interrupt is not None:
                    signal.signal(signal.SIGINT, interrupted)
                with (
                    patch.object(process_type, "_Popen", staticmethod(acquire)),
                    patch.object(runner, "_checkout_wpt", checkout),
                    patch.object(runner, "generate_loopback_certificate", certificate),
                    patch.object(
                        runner, "_git_revision", return_value="fixture revision"
                    ),
                    patch.object(
                        runner.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], 0, output, ""),
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    try:
                        runner.run("smoke", repository, reports / "reports")
                    except (Exception, KeyboardInterrupt) as error:
                        observed_error = error
                alive_after_run = native[0].poll() is None
                scratch_after_run = resources[0].exists()
                child_exit = native[0].wait(8)
                self.assertIsNotNone(child_exit, "native fixture child was not reaped")
                lifetime = json.loads(marker.read_text())
                summary_path = next((reports / "reports").glob("*/summary.json"))
                summary = json.loads(summary_path.read_text())
                return SimpleNamespace(
                    error=observed_error,
                    alive=alive_after_run,
                    scratch=scratch_after_run,
                    lifetime=lifetime,
                    summary=summary,
                    exitcode=child_exit,
                )
            finally:
                signal.signal(signal.SIGINT, previous)
                for popen in native:
                    if popen.poll() is None:
                        popen.terminate()
                        self.assertIsNotNone(
                            popen.wait(8), "fixture cleanup did not reap"
                        )
                    popen.close()
                for root in resources:
                    if root.exists():
                        root.resolve().relative_to(
                            Path(tempfile.gettempdir()).resolve()
                        )
                        shutil.rmtree(root)

    def test_native_acquisition_positive_control_reaps_before_file_cleanup(self):
        result = self.exercise_native_acquisition()

        self.assertIsNone(result.error)
        self.assertFalse(result.alive)
        self.assertFalse(result.scratch)
        self.assertEqual(result.exitcode, 0)
        self.assertEqual(
            result.lifetime, {"source_alive": True, "certificate_alive": True}
        )
        self.assertFalse(result.summary["run_failed"])

    def test_native_acquisition_sigint_keeps_identity_and_reaps_before_cleanup(self):
        interrupt = KeyboardInterrupt("native acquisition boundary marker")
        result = self.exercise_native_acquisition(interrupt=interrupt)

        self.assertIs(result.error, interrupt)
        self.assertFalse(
            result.alive, "run returned before observing native child exit"
        )
        self.assertFalse(result.scratch)
        self.assertEqual(result.exitcode, 0)
        self.assertEqual(
            result.lifetime, {"source_alive": True, "certificate_alive": True}
        )
        self.assertTrue(result.summary["run_failed"])
        self.assertIn(
            "native acquisition boundary marker",
            " ".join(result.summary["infrastructure_failures"]),
        )

    def test_native_start_failure_reaps_child_and_reports_cause(self):
        result = self.exercise_native_acquisition(
            start_error=OSError("acquisition error marker")
        )

        self.assertFalse(result.alive)
        self.assertFalse(result.scratch)
        self.assertEqual(result.exitcode, 0)
        self.assertEqual(
            result.lifetime, {"source_alive": True, "certificate_alive": True}
        )
        self.assertTrue(result.summary["run_failed"])
        failures = " ".join(result.summary["infrastructure_failures"])
        self.assertIn("acquisition error marker", failures)
        self.assertIn("acquisition", failures)

    def test_incomplete_native_acquisition_retains_and_reports_scratch(self):
        spawn = SpawnFixture(start_error=OSError("incomplete acquisition marker"))
        original_start = ProcessFixture.start

        def incomplete_start(process):
            process.acquisition_uncertain = True
            original_start(process)

        with patch.object(ProcessFixture, "start", incomplete_start):
            result = WptRunFixture().exercise(spawn=spawn)
        root = spawn.process.args[0].parent.resolve()
        root.relative_to(Path(tempfile.gettempdir()).resolve())
        self.addCleanup(shutil.rmtree, root)

        self.assertTrue(root.exists())
        self.assertFalse(spawn.process.closed)
        self.assertTrue(result.summary["run_failed"])
        failures = " ".join(result.summary["infrastructure_failures"])
        self.assertIn("incomplete native handle", failures)
        self.assertIn("files retained", failures)


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
