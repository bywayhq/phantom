import contextlib
import io
import json
import logging.handlers
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


class WptLifecycleTests(unittest.TestCase):
    def exercise(
        self, *, server=None, scenario_failure=False, adapter_error=None, log_error=None
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
            with contextlib.ExitStack() as stack:
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

        self.assertIs(result.error, interrupt)
        self.assertEqual(result.log_observations, [1])
        self.assertFalse(result.server.source.exists())
        self.assert_case_results(result)
        self.assertTrue(result.summary.get("run_failed", False))
        self.assertIn(
            "stop interrupt marker",
            " ".join(result.summary.get("infrastructure_failures", [])),
        )


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
