import io
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.capture import chrome_ech
from scripts.capture.browser_failures import BrowserLaunchFailures
from scripts.capture.browser_launch import LaunchedBrowser as BrowserOwner
from scripts.capture.process_container import ProcessCleanupError, ProcessContainer

RUN = chrome_ech.CaptureRun(
    browser="chrome",
    browser_path=Path("unused-browser"),
    client_version="1",
    operating_system="test",
    scenario="accept",
    origin="127.0.0.1:443",
    capture_binary=Path("unused-capture"),
    headless=True,
)
READY = "ready doh_template=https://127.0.0.1:5/dns-query origin=127.0.0.1:443"


class EchProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        browser_patch = patch.object(chrome_ech, "LaunchedBrowser")
        self.addCleanup(browser_patch.stop)
        self.browser = browser_patch.start()
        timeout_patch = patch.object(chrome_ech, "CAPTURE_TIMEOUT_SECONDS", 5)
        self.addCleanup(timeout_patch.stop)
        timeout_patch.start()
        self.containers = []

        def acquire(command, **options):
            owner = ProcessContainer(command, **options)
            self.containers.append(owner)
            return owner

        container_patch = patch.object(chrome_ech, "ProcessContainer", acquire)
        self.addCleanup(container_patch.stop)
        container_patch.start()
        self.addCleanup(self.stop_all)

    def stop_all(self) -> None:
        for owner in self.containers:
            owner.close()

    def capture(self, script: str, **options) -> str:
        command = [sys.executable, "-c", script]
        with patch.object(chrome_ech, "capture_arguments", return_value=command):
            return chrome_ech.capture(options.pop("run", RUN), **options)

    def assert_stopped(self) -> None:
        self.assertEqual(len(self.containers), 1)
        self.assertTrue(self.containers[0]._cleanup_complete)
        self.assertIsNotNone(self.containers[0]._process.returncode)

    def test_completed_fixture_and_final_diagnostic_are_preserved(self) -> None:
        reported = []
        fixture = self.capture(
            f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
            "sys.stdout.write('format=ech\\n'); "
            "sys.stderr.write('finished')",
            report=reported.append,
        )

        self.assertEqual(fixture, "format=ech\n")
        self.assertEqual(reported, ["finished"])
        self.browser.assert_called_once()
        self.assert_stopped()

    def test_fixture_over_limit_fails_instead_of_publishing(self) -> None:
        with (
            patch.object(chrome_ech, "MAX_CAPTURE_OUTPUT", 8),
            self.assertRaisesRegex(ValueError, "fixture exceeds"),
        ):
            self.capture(
                f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
                "sys.stdout.write('x' * 9)"
            )
        self.assert_stopped()

    def test_mixed_newlines_keep_the_original_text_reader_contract(self) -> None:
        reported = []
        fixture = self.capture(
            f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
            "sys.stdout.buffer.write(b'a\\r\\nb\\rc\\n'); "
            "sys.stderr.buffer.write(b'first\\r\\nsecond\\rthird\\n')",
            report=reported.append,
        )
        self.assertEqual(fixture, "a\nb\nc\n")
        self.assertEqual(reported, ["first", "second", "third"])
        self.assert_stopped()

    def test_fixture_at_limit_is_preserved(self) -> None:
        with patch.object(chrome_ech, "MAX_CAPTURE_OUTPUT", 8):
            fixture = self.capture(
                f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
                "sys.stdout.write('x' * 8)"
            )
        self.assertEqual(fixture, "x" * 8)
        self.assert_stopped()

    def test_original_fixture_decode_error_reaches_caller(self) -> None:
        with self.assertRaises(UnicodeDecodeError) as raised:
            self.capture(
                f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
                "sys.stdout.buffer.write(b'\\xff')"
            )
        self.assertEqual(raised.exception.object, b"\xff")
        self.assert_stopped()

    def test_original_diagnostic_decode_error_reaches_caller(self) -> None:
        with self.assertRaises(UnicodeDecodeError):
            self.capture(
                f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
                "sys.stderr.buffer.write(b'\\xff\\n')"
            )
        self.assert_stopped()

    def test_original_reporter_failure_reaches_caller(self) -> None:
        failure = OSError("reporter failed")

        def report(_line):
            raise failure

        with self.assertRaises(OSError) as raised:
            self.capture(
                f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
                "print('diagnostic', file=sys.stderr, flush=True)",
                report=report,
            )
        self.assertIs(raised.exception, failure)
        self.assert_stopped()

    def test_exit_before_readiness_fails_without_browser_launch(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "before it was ready"):
            self.capture("raise SystemExit(3)")
        self.browser.assert_not_called()
        self.assert_stopped()

    def test_failed_server_after_readiness_does_not_publish(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exit code 3"):
            self.capture(
                f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
                "print('partial'); raise SystemExit(3)"
            )
        self.assert_stopped()

    def test_failed_server_and_browser_cleanup_keep_both_original_failures(
        self,
    ) -> None:
        cleanup = OSError("browser cleanup failed")
        browser = BrowserOwner(chrome_ech.launch_plan(RUN), chrome_ech.URL)
        self.browser.return_value.__exit__.side_effect = lambda *details: (
            browser.__exit__(*details)
        )
        with (
            patch.object(browser, "_cleanup", return_value=(cleanup,)),
            self.assertRaises(BrowserLaunchFailures) as raised,
        ):
            self.capture(
                f"import sys; print({READY!r}, file=sys.stderr, flush=True); "
                "raise SystemExit(3)"
            )
        self.assertIsInstance(raised.exception.primary, RuntimeError)
        self.assertEqual(
            str(raised.exception.primary), "capture server failed with exit code 3"
        )
        self.assertIs(raised.exception.cleanup[0], cleanup)
        self.assert_stopped()

    def test_observer_setup_failure_stops_the_already_acquired_container(self) -> None:
        failure = OSError("observer setup failed")
        with (
            patch.object(chrome_ech, "_CaptureOutput", side_effect=failure),
            self.assertRaises(OSError) as raised,
        ):
            self.capture("import time; time.sleep(60)")
        self.assertIs(raised.exception, failure)
        self.browser.assert_not_called()
        self.assert_stopped()

    def test_silent_server_has_an_absolute_readiness_deadline(self) -> None:
        with patch.object(chrome_ech, "CAPTURE_TIMEOUT_SECONDS", 0.5):
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                self.capture("import time; time.sleep(60)")
        self.assertLess(time.monotonic() - started, 10)
        self.browser.assert_not_called()
        self.assert_stopped()

    def test_active_server_has_an_absolute_capture_deadline(self) -> None:
        with (
            patch.object(chrome_ech, "CAPTURE_TIMEOUT_SECONDS", 1),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            self.capture(
                f"import sys, time; print({READY!r}, file=sys.stderr, flush=True); "
                "time.sleep(60)"
            )
        self.browser.assert_called_once()
        self.assert_stopped()

    def test_browser_launch_error_is_preserved_and_server_stops(self) -> None:
        failure = OSError("browser launch failed")
        self.browser.return_value.__enter__.side_effect = failure
        with self.assertRaises(OSError) as raised:
            self.capture(
                f"import sys, time; print({READY!r}, file=sys.stderr, flush=True); "
                "time.sleep(60)"
            )
        self.assertIs(raised.exception, failure)
        self.assert_stopped()

    def test_bare_cr_readiness_is_observed_while_the_server_is_alive(self) -> None:
        with (
            patch.object(chrome_ech, "CAPTURE_TIMEOUT_SECONDS", 1),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            self.capture(
                f"import sys, time; sys.stderr.buffer.write({READY.encode()!r} "
                "+ b'\\rstarted\\r\\n'); sys.stderr.flush(); time.sleep(60)",
                report=lambda _: None,
            )
        self.browser.assert_called_once()
        self.assert_stopped()

    def test_mismatched_server_template_fails_before_browser_launch(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "server listens"):
            self.capture(
                f"import sys; print({READY!r}, file=sys.stderr, flush=True)",
                run=replace(RUN, doh_port=6),
            )
        self.browser.assert_not_called()
        self.assert_stopped()

    def test_cleanup_failure_keeps_original_failure_and_owner(self) -> None:
        primary = OSError("browser launch failed")
        cleanup = OSError("injected close failure")
        self.browser.return_value.__enter__.side_effect = primary
        close = ProcessContainer.close

        def close_with_failure(owner):
            close(owner)
            raise cleanup

        with (
            patch.object(ProcessContainer, "close", close_with_failure),
            self.assertRaises(OSError) as raised,
        ):
            self.capture(
                f"import sys, time; print({READY!r}, file=sys.stderr, flush=True); "
                "time.sleep(60)"
            )
        self.assertIs(raised.exception, primary)
        retained = primary.__cause__
        self.assertIsInstance(retained, ProcessCleanupError)
        self.assertIs(retained.primary, primary)
        self.assertIs(retained.container, self.containers[0])
        self.assertIs(retained.failures[0][1], cleanup)
        self.assert_stopped()

    def test_directory_failure_keeps_the_primary_and_previous_process_owner(
        self,
    ) -> None:
        primary = OSError("browser launch failed")
        process_cleanup = OSError("injected process close failure")
        directory_cleanup = PermissionError("injected output removal failure")
        self.browser.return_value.__enter__.side_effect = primary

        def close_with_failure(_owner):
            raise process_cleanup

        with (
            patch.object(ProcessContainer, "close", close_with_failure),
            patch.object(
                tempfile.TemporaryDirectory, "cleanup", side_effect=directory_cleanup
            ),
            self.assertRaises(OSError) as raised,
        ):
            self.capture(
                f"import sys, time; print({READY!r}, file=sys.stderr, flush=True); "
                "time.sleep(60)"
            )
        self.assertIs(raised.exception, primary)
        directory_failure = primary.__cause__
        self.assertIsInstance(directory_failure, ProcessCleanupError)
        directory = directory_failure.output_directory
        try:
            self.assertIs(directory_failure.primary, primary)
            self.assertIs(directory_failure.failures[0][1], directory_cleanup)
            previous = directory_failure.previous_cause
            self.assertIsInstance(previous, ProcessCleanupError)
            self.assertIs(previous.container, self.containers[0])
            self.assertIs(previous.primary, primary)
            self.assertIs(previous.failures[0][1], process_cleanup)
            self.assertTrue(Path(directory.name).is_dir())
            self.assertFalse(previous.container._cleanup_complete)
            self.assertIsNone(previous.container.poll())
        finally:
            self.containers[0].close()
            directory.cleanup()
        self.assert_stopped()


class DiagnosticExtentTests(unittest.TestCase):
    def observer(self, data: bytes):
        return chrome_ech._CaptureOutput(io.BytesIO(), io.BytesIO(data), lambda _: None)

    def test_diagnostics_over_limit_fail(self) -> None:
        with (
            patch.object(chrome_ech, "MAX_CAPTURE_DIAGNOSTICS", 8),
            self.assertRaisesRegex(ValueError, "diagnostics exceed"),
        ):
            self.observer(b"x\n" * 5).poll()

    def test_complete_line_over_limit_fails(self) -> None:
        with (
            patch.object(chrome_ech, "MAX_DIAGNOSTIC_LINE", 8),
            self.assertRaisesRegex(ValueError, "line exceeds"),
        ):
            self.observer(b"x" * 9 + b"\n").poll()

    def test_unterminated_line_over_limit_fails(self) -> None:
        with (
            patch.object(chrome_ech, "MAX_DIAGNOSTIC_LINE", 8),
            self.assertRaisesRegex(ValueError, "line exceeds"),
        ):
            self.observer(b"x" * 9).poll()

    def test_complete_line_at_limit_is_accepted(self) -> None:
        with patch.object(chrome_ech, "MAX_DIAGNOSTIC_LINE", 8):
            self.observer(b"x" * 8 + b"\n").poll()

    def test_policy_query_receives_a_finite_timeout_and_keeps_original_failure(
        self,
    ) -> None:
        failure = subprocess.TimeoutExpired(["reg"], chrome_ech.POLICY_TIMEOUT_SECONDS)
        with (
            patch.object(chrome_ech.subprocess, "run", side_effect=failure) as query,
            self.assertRaises(subprocess.TimeoutExpired) as raised,
        ):
            chrome_ech.read_policy("unused", run=query)
        self.assertIs(raised.exception, failure)
        self.assertEqual(
            query.call_args.kwargs["timeout"], chrome_ech.POLICY_TIMEOUT_SECONDS
        )
