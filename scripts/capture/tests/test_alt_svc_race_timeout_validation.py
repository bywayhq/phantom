"""Finite capture margins are validated before dispatch or resource preparation."""

import asyncio
import math
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scripts.capture import alt_svc_race as race


class CaptureDispatchReached(RuntimeError):
    pass


class CertificateEntryReached(RuntimeError):
    pass


class CliTimeoutTests(unittest.TestCase):
    def arguments(self, root, margin):
        arguments = [
            "alt_svc_race",
            "--browser-path",
            str(root / "browser.exe"),
            "--client-version",
            "test-version",
            "--operating-system",
            "test-platform",
            "--scenario",
            "race-after-learning",
            "--repeat",
            "1",
            "--netlog-dir",
            str(root / "netlogs"),
            "--output-dir",
            str(root / "fixtures"),
        ]
        if margin is not None:
            arguments.append(f"--timeout={margin}")

        return arguments

    def assert_nonfinite_margin_rejected(self, margin):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "fixtures"
            output.mkdir()
            fixture = output / "race-after-learning.txt"
            previous = b"format=retained-timeout-test\nruns=1\n"
            fixture.write_bytes(previous)
            marker = CaptureDispatchReached("non-finite capture dispatch reached")
            awaited = []
            stdout = StringIO()
            stderr = StringIO()
            observed = None

            async def observe_capture(scenario, **options):
                awaited.append((scenario, options))
                raise marker

            with (
                patch.object(sys, "argv", self.arguments(root, margin)),
                patch.object(
                    race, "capture_run", side_effect=observe_capture
                ) as capture,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                try:
                    race.main()
                except BaseException as error:
                    observed = error

            fixture_bytes = fixture.read_bytes()
            output_files = list(output.iterdir())
            netlog_created = (root / "netlogs").exists()

            if observed is marker:
                capture.assert_awaited_once()
                self.assertEqual(len(awaited), 1)
                scenario, options = awaited[0]
                self.assertIs(scenario, race.SCENARIOS["race-after-learning"])
                if margin == "nan":
                    self.assertTrue(math.isnan(options["timeout"]))
                else:
                    self.assertTrue(math.isinf(options["timeout"]))
                    if margin == "-inf":
                        self.assertLess(options["timeout"], 0)
                    else:
                        self.assertGreater(options["timeout"], 0)

            self.assertIsInstance(observed, SystemExit, repr(observed))
            self.assertEqual(observed.code, 2)
            self.assertIn("timeout", stderr.getvalue())
            self.assertIn("finite", stderr.getvalue())
            capture.assert_not_called()
            self.assertEqual(capture.await_count, 0)

            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(netlog_created)
            self.assertEqual(fixture_bytes, previous)
            self.assertEqual(output_files, [fixture])

    def assert_finite_margin_dispatched(self, margin, expected_timeout):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "fixtures"
            output.mkdir()
            fixture = output / "race-after-learning.txt"
            previous = b"format=retained-timeout-test\nruns=1\n"
            fixture.write_bytes(previous)
            marker = CaptureDispatchReached("finite capture dispatch reached")
            awaited = []
            stdout = StringIO()
            stderr = StringIO()
            observed = None

            async def observe_capture(scenario, **options):
                awaited.append((scenario, options))
                raise marker

            with (
                patch.object(sys, "argv", self.arguments(root, margin)),
                patch.object(
                    race, "capture_run", side_effect=observe_capture
                ) as capture,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                try:
                    race.main()
                except BaseException as error:
                    observed = error

            fixture_bytes = fixture.read_bytes()
            output_files = list(output.iterdir())
            netlog_created = (root / "netlogs").exists()

            self.assertIs(observed, marker)
            capture.assert_called_once()
            capture.assert_awaited_once()
            self.assertEqual(len(awaited), 1)
            scenario, options = awaited[0]
            self.assertIs(scenario, race.SCENARIOS["race-after-learning"])
            self.assertEqual(options["timeout"], expected_timeout)
            self.assertEqual(options["listen_host"], "127.0.0.1")
            self.assertEqual(options["browser"], "chrome")
            self.assertEqual(options["executable"], root / "browser.exe")
            self.assertTrue(options["headless"])
            self.assertEqual(
                options["netlog"], root / "netlogs/race-after-learning-0.json"
            )

            self.assertTrue(netlog_created)
            self.assertEqual(fixture_bytes, previous)
            self.assertEqual(output_files, [fixture])
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

    def test_infinite_margin_is_rejected_before_capture_or_output(self):
        self.assert_nonfinite_margin_rejected("inf")

    def test_negative_infinite_margin_is_rejected_before_capture_or_output(self):
        self.assert_nonfinite_margin_rejected("-inf")

    def test_nan_margin_is_rejected_before_capture_or_output(self):
        self.assert_nonfinite_margin_rejected("nan")

    def test_default_margin_adds_sixty_seconds_to_the_scripted_waits(self):
        self.assert_finite_margin_dispatched(None, 60.8)

    def test_zero_margin_preserves_the_scripted_wait_budget(self):
        self.assert_finite_margin_dispatched("0", 0.8)

    def test_positive_margin_is_added_to_the_scripted_wait_budget(self):
        self.assert_finite_margin_dispatched("2.5", 3.3)

    def test_small_negative_margin_shortens_the_scripted_wait_budget(self):
        self.assert_finite_margin_dispatched("-0.25", 0.55)


class CaptureTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def assert_nonfinite_budget_rejected(self, timeout):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = CertificateEntryReached("certificate preparation reached")
            entered = []
            observed = None

            def observe_certificate(hostname):
                entered.append(hostname)
                raise marker

            with patch.object(
                race, "generate_certificate", side_effect=observe_certificate
            ) as certificate:
                try:
                    await asyncio.wait_for(
                        race.capture_run(
                            race.SCENARIOS["race-after-learning"],
                            listen_host="127.0.0.1",
                            browser="chrome",
                            executable=root / "browser.exe",
                            headless=True,
                            netlog=root / "netlogs/capture.json",
                            timeout=timeout,
                        ),
                        5.0,
                    )
                except BaseException as error:
                    observed = error

            netlog_created = (root / "netlogs").exists()
            if observed is marker:
                certificate.assert_called_once_with("server.phantom.test")
                self.assertEqual(entered, ["server.phantom.test"])

            self.assertIsInstance(observed, ValueError, repr(observed))
            self.assertIn("timeout", str(observed))
            self.assertIn("finite", str(observed))
            certificate.assert_not_called()
            self.assertEqual(entered, [])
            self.assertFalse(netlog_created)

    async def test_infinite_budget_is_rejected_before_certificate_preparation(self):
        await self.assert_nonfinite_budget_rejected(float("inf"))

    async def test_negative_infinite_budget_is_rejected_before_preparation(self):
        await self.assert_nonfinite_budget_rejected(float("-inf"))

    async def test_nan_budget_is_rejected_before_certificate_preparation(self):
        await self.assert_nonfinite_budget_rejected(float("nan"))

    async def test_finite_budget_reaches_the_actual_certificate_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = CertificateEntryReached("finite certificate entry reached")
            entered = []
            observed = None

            def observe_certificate(hostname):
                entered.append(hostname)
                raise marker

            with patch.object(
                race, "generate_certificate", side_effect=observe_certificate
            ) as certificate:
                try:
                    await asyncio.wait_for(
                        race.capture_run(
                            race.SCENARIOS["race-after-learning"],
                            listen_host="127.0.0.1",
                            browser="chrome",
                            executable=root / "browser.exe",
                            headless=True,
                            netlog=root / "netlogs/capture.json",
                            timeout=5.0,
                        ),
                        5.0,
                    )
                except BaseException as error:
                    observed = error

            netlog_created = (root / "netlogs").exists()
            self.assertIs(observed, marker)
            certificate.assert_called_once_with("server.phantom.test")
            self.assertEqual(entered, ["server.phantom.test"])
            self.assertFalse(netlog_created)
