"""Capture repeat validation precedes output work and browser dispatch."""

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


class CliValidationTests(unittest.TestCase):
    def arguments(self, root, repeat):
        return [
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
            str(repeat),
            "--netlog-dir",
            str(root / "netlogs"),
            "--output-dir",
            str(root / "fixtures"),
        ]

    def assert_repeat_rejected(self, repeat):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "fixtures"
            output.mkdir()
            fixture = output / "race-after-learning.txt"
            previous = b"format=retained-test\nruns=3\n"
            fixture.write_bytes(previous)
            stdout = StringIO()
            stderr = StringIO()
            observed = None

            with (
                patch.object(sys, "argv", self.arguments(root, repeat)),
                patch.object(
                    race,
                    "capture_run",
                    side_effect=AssertionError("invalid repeat dispatched a capture"),
                ) as capture,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                try:
                    race.main()
                except SystemExit as error:
                    observed = error

            fixture_bytes = fixture.read_bytes()
            netlog_created = (root / "netlogs").exists()
            capture.assert_not_called()
            self.assertIsInstance(
                observed,
                SystemExit,
                f"fixture preserved: {fixture_bytes == previous}; "
                f"NetLog directory created: {netlog_created}",
            )
            self.assertEqual(observed.code, 2)
            self.assertIn("repeat", stderr.getvalue())
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(netlog_created)
            self.assertEqual(fixture_bytes, previous)
            self.assertEqual(list(output.iterdir()), [fixture])

    def test_zero_repeat_is_rejected_before_capture_or_publication(self):
        self.assert_repeat_rejected(0)

    def test_negative_repeat_is_rejected_before_capture_or_publication(self):
        self.assert_repeat_rejected(-1)

    def test_one_repeat_awaits_the_selected_capture_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = CaptureDispatchReached("selected capture awaited")
            awaited = []
            stdout = StringIO()
            stderr = StringIO()

            async def observe_capture(scenario, **options):
                awaited.append((scenario, options))
                raise marker

            with (
                patch.object(sys, "argv", self.arguments(root, 1)),
                patch.object(
                    race, "capture_run", side_effect=observe_capture
                ) as capture,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
                self.assertRaises(CaptureDispatchReached) as raised,
            ):
                race.main()

            self.assertIs(raised.exception, marker)
            capture.assert_called_once()
            capture.assert_awaited_once()
            self.assertEqual(len(awaited), 1)
            scenario, options = awaited[0]
            self.assertIs(scenario, race.SCENARIOS["race-after-learning"])
            self.assertEqual(options["listen_host"], "127.0.0.1")
            self.assertEqual(options["browser"], "chrome")
            self.assertEqual(options["executable"], root / "browser.exe")
            self.assertTrue(options["headless"])
            self.assertEqual(
                options["netlog"], root / "netlogs/race-after-learning-0.json"
            )
            self.assertTrue((root / "netlogs").is_dir())
            self.assertFalse((root / "fixtures").exists())
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")
