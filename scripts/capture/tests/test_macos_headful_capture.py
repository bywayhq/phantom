import hashlib
import json
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture import macos_headful_capture as capture
from scripts.capture.capture_report import command_output, file_digest

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/sse/chrome/155.0.8059.40/macos-26.6.2-arm64/reconnect-204.txt"
)


class CommandReceiptTests(unittest.TestCase):
    def test_failed_command_keeps_arguments_status_and_both_outputs(self):
        record = {"metadata_commands": []}
        result = subprocess.CompletedProcess(["git", "status"], 2, "partial\n", "bad\n")
        with (
            patch("scripts.capture.capture_report.subprocess.run", return_value=result),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            command_output(record, "git", "status")
        self.assertEqual(
            record["metadata_commands"],
            [
                {
                    "argv": ["git", "status"],
                    "timeout_seconds": 10,
                    "exit": 2,
                    "stdout": "partial\n",
                    "stderr": "bad\n",
                }
            ],
        )

    def test_timeout_keeps_partial_output_and_original_exception(self):
        error = subprocess.TimeoutExpired("git", 10, output=b"partial", stderr=b"error")
        record = {"metadata_commands": []}
        with (
            patch("scripts.capture.capture_report.subprocess.run", side_effect=error),
            self.assertRaises(subprocess.TimeoutExpired) as raised,
        ):
            command_output(record, "git", "status")
        self.assertIs(raised.exception, error)
        receipt = record["metadata_commands"][0]
        self.assertIsNone(receipt["exit"])
        self.assertEqual((receipt["stdout"], receipt["stderr"]), ("partial", "error"))
        self.assertEqual(receipt["failure"]["type"], "TimeoutExpired")

    def test_explicit_operation_bound_retains_timed_out_progress(self):
        error = subprocess.TimeoutExpired(
            "hdiutil", 120, output=b"Checksumming Apple_HFS", stderr=b"partial"
        )
        record = {"metadata_commands": []}
        with (
            patch(
                "scripts.capture.capture_report.subprocess.run", side_effect=error
            ) as run,
            self.assertRaises(subprocess.TimeoutExpired) as raised,
        ):
            command_output(record, "hdiutil", "attach", timeout=120)
        self.assertIs(raised.exception, error)
        run.assert_called_once_with(
            ("hdiutil", "attach"), capture_output=True, text=True, timeout=120
        )
        receipt = record["metadata_commands"][0]
        self.assertEqual(receipt["timeout_seconds"], 120)
        self.assertIsNone(receipt["exit"])
        self.assertEqual(receipt["stdout"], "Checksumming Apple_HFS")
        self.assertEqual(receipt["stderr"], "partial")

    def test_missing_command_retains_failure_receipt(self):
        record = {"metadata_commands": []}
        with (
            patch(
                "scripts.capture.capture_report.subprocess.run",
                side_effect=FileNotFoundError("not installed"),
            ),
            self.assertRaises(FileNotFoundError),
        ):
            command_output(record, "missing")
        self.assertEqual(
            record["metadata_commands"][0]["failure"]["type"], "FileNotFoundError"
        )

    def test_hash_preserves_bytes_across_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture"
            content = b"a" * (1024 * 1024) + b"\r\n\xff"
            path.write_bytes(content)
            self.assertEqual(file_digest(path), hashlib.sha256(content).hexdigest())


class MacCaptureReportTests(unittest.TestCase):
    def setUp(self):
        self.fixture_text = FIXTURE.read_text(encoding="utf-8")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.previous_directory = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(os.chdir, self.previous_directory)
        self.output = Path("target/capture")
        self.chrome = Path("Chrome.app/Contents/MacOS/Google Chrome").resolve()
        self.chrome.parent.mkdir(parents=True)
        self.chrome.write_bytes(b"launcher")
        self.info = self.chrome.parents[1] / "Info.plist"
        self.info.write_bytes(
            plistlib.dumps(
                {
                    "CFBundleShortVersionString": "155.0.8059.40",
                    "CFBundleVersion": "8059.40",
                }
            )
        )
        for name in (
            "scripts/capture/capture.py",
            "scripts/requirements.txt",
            ".github/workflows/macos-headful-capture.yml",
        ):
            path = Path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        self.capture_exit = 0
        self.emit_fixture = True
        self.mutation = None
        self.metadata_overrides = {}
        self.environment = {
            "CAPTURE_RUNNER_LABEL": "macos-latest",
            "CAPTURE_EXPECTED_ARCH": "arm64",
            "GITHUB_SHA": "source-sha",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "ImageOS": "macos26",
            "ImageVersion": "20261019",
        }

    def command(self, args, **kwargs):
        if args[0] == capture.sys.executable:
            kwargs["stdout"].write(b"capture output\n")
            kwargs["stderr"].write(b"capture diagnostics\n")
            if self.emit_fixture:
                fixtures = self.output / "fixtures"
                fixtures.mkdir()
                (fixtures / "reconnect-204.txt").write_text(
                    self.fixture_text, encoding="utf-8"
                )
            if self.mutation:
                self.mutation()
            return subprocess.CompletedProcess(args, self.capture_exit)
        outputs = {
            ("git", "rev-parse", "HEAD"): "source-sha\n",
            ("git", "status", "--porcelain", "--untracked-files=all"): "",
            (
                "git",
                "ls-files",
                "-z",
                "scripts/capture",
            ): "scripts/capture/capture.py\0notes.txt\0",
            ("/usr/bin/sw_vers",): "ProductName: macOS\nProductVersion: 26.6.2\n",
            (str(self.chrome), "--version"): "Google Chrome 155.0.8059.40\n",
        }
        outputs.update(self.metadata_overrides)
        self.assertEqual(kwargs, {"capture_output": True, "text": True, "timeout": 10})
        return subprocess.CompletedProcess(args, 0, outputs[tuple(args)], "")

    def run_capture(self, platform="darwin", architecture="arm64"):
        with (
            patch.dict(os.environ, self.environment, clear=True),
            patch.object(capture.sys, "platform", platform),
            patch.object(capture.platform, "machine", return_value=architecture),
            patch.object(capture.subprocess, "run", side_effect=self.command),
        ):
            capture.run_capture(self.output, self.chrome)

    def report(self):
        return json.loads((self.output / "provenance.json").read_text(encoding="utf-8"))

    def test_success_retains_identity_inventory_command_and_fixture_evidence(self):
        self.run_capture()
        record = self.report()
        self.assertEqual((record["status"], record["phase"]), ("success", "complete"))
        self.assertEqual(record["source_head"], record["source_head_after"])
        self.assertEqual(record["source_before"], record["source_after"])
        self.assertEqual(
            set(record["source_before"]),
            {
                "scripts/capture/capture.py",
                "scripts/requirements.txt",
                ".github/workflows/macos-headful-capture.yml",
            },
        )
        self.assertEqual(record["browser_version"], "155.0.8059.40")
        self.assertEqual(record["browser_build"], "8059.40")
        self.assertEqual(record["capture_exit"], 0)
        self.assertTrue(record["capture_started"])
        self.assertEqual(
            record["fixture_sha256"],
            file_digest(self.output / "fixtures/reconnect-204.txt"),
        )
        self.assertEqual(len(record["observed_user_agent_values_hex"]), 3)
        self.assertEqual(
            record["capture_argv"][1:3], ["-m", "scripts.capture.sse_reconnect"]
        )
        self.assertEqual(
            record["capture_argv"][-6:-3],
            ["--client-version", "155.0.8059.40", "--operating-system"],
        )
        self.assertEqual(
            (self.output / "capture.stdout.log").read_bytes(), b"capture output\n"
        )
        self.assertEqual(
            (self.output / "capture.stderr.log").read_bytes(), b"capture diagnostics\n"
        )
        self.assertEqual(len(record["metadata_commands"]), 7)
        self.assertIn("finished_utc", record)

    def test_host_mismatch_is_reported_before_capture(self):
        with self.assertRaisesRegex(RuntimeError, "OS or architecture"):
            self.run_capture(platform="win32")
        self.assertEqual(self.report()["failure"]["phase"], "host_identity")
        self.assertFalse(self.report()["capture_started"])

    def test_wrong_source_or_dirty_checkout_prevents_capture(self):
        for command, output in (
            (("git", "rev-parse", "HEAD"), "other-sha"),
            (("git", "status", "--porcelain", "--untracked-files=all"), " M source.py"),
        ):
            with self.subTest(command=command):
                self.metadata_overrides = {command: output}
                self.output = self.output.parent / str(
                    len(list(self.output.parent.glob("*")))
                )
                with self.assertRaises(RuntimeError):
                    self.run_capture()
                self.assertFalse(self.report()["capture_started"])
                self.assertEqual(self.report()["failure"]["phase"], "source_identity")

    def test_browser_witness_mismatch_prevents_capture(self):
        self.metadata_overrides[(str(self.chrome), "--version")] = (
            "Google Chrome 156.0.0.1"
        )
        with self.assertRaisesRegex(RuntimeError, "witnesses disagree"):
            self.run_capture()
        self.assertEqual(self.report()["failure"]["phase"], "browser_identity")
        self.assertFalse(self.report()["capture_started"])

    def test_changed_source_or_browser_rejects_completed_capture(self):
        for index, path in enumerate(
            (Path("scripts/capture/capture.py"), self.chrome, self.info)
        ):
            with self.subTest(path=path):
                self.output = Path(f"target/mutation-{index}")
                original = path.read_bytes()
                self.mutation = lambda path=path: path.write_bytes(b"changed")
                try:
                    with self.assertRaisesRegex(RuntimeError, "changed during"):
                        self.run_capture()
                    self.assertEqual(
                        self.report()["failure"]["phase"], "unchanged_inputs"
                    )
                finally:
                    path.write_bytes(original)

    def test_failed_capture_keeps_logs_and_rejects_even_a_complete_fixture(self):
        self.capture_exit = 1
        with self.assertRaisesRegex(RuntimeError, "capture command failed"):
            self.run_capture()
        self.assertTrue(self.report()["fixture_present"])
        self.assertEqual(self.report()["capture_exit"], 1)
        self.assertEqual(self.report()["status"], "failed")
        self.assertTrue((self.output / "capture.stderr.log").is_file())

    def test_missing_fixture_rejects_zero_exit(self):
        self.emit_fixture = False
        with self.assertRaisesRegex(RuntimeError, "emitted no fixture"):
            self.run_capture()
        self.assertFalse(self.report()["fixture_present"])

    def test_interrupted_capture_keeps_original_exception_logs_and_phase(self):
        primary = KeyboardInterrupt("capture interrupted")
        metadata_command = self.command

        def interrupted(args, **kwargs):
            if args[0] == capture.sys.executable:
                kwargs["stderr"].write(b"before interruption\n")
                raise primary
            return metadata_command(args, **kwargs)

        self.command = interrupted
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.run_capture()
        self.assertIs(raised.exception, primary)
        self.assertEqual(self.report()["failure"]["phase"], "capture")
        self.assertEqual(self.report()["failure"]["type"], "KeyboardInterrupt")
        self.assertIsNone(self.report()["capture_exit"])
        self.assertEqual(
            (self.output / "capture.stderr.log").read_bytes(), b"before interruption\n"
        )

    def test_missing_terminal_page_sse_or_user_agent_rejects_fixture(self):
        original = self.fixture_text
        for index, (old, new) in enumerate(
            (
                ("run_0_terminated_ms=5931.195", "run_0_terminated_ms=none"),
                ("launch_mode=headful", "launch_mode=headless"),
                ("repeat_count=1", "repeat_count=2"),
                ("kind:page", "kind:other"),
                ("attempt:1,extra:false", "attempt:2,extra:false"),
                ("557365722d4167656e743a", "582d557365722d4167656e743a"),
            )
        ):
            with self.subTest(old=old):
                self.assertIn(old, original)
                self.fixture_text = original.replace(old, new)
                self.output = Path(f"target/fixture-{index}")
                with self.assertRaises(RuntimeError):
                    self.run_capture()
                self.assertEqual(self.report()["failure"]["phase"], "fixture")


if __name__ == "__main__":
    unittest.main()
