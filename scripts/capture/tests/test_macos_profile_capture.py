import json
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from scripts.capture import macos_headful_capture as capture
from scripts.capture import run_matrix


class ProfileCellsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "output"
        self.output.mkdir()
        self.chrome = self.root / "Google Chrome.app/Contents/MacOS/Google Chrome"
        self.record = {
            "os": "ProductName: macOS\nProductVersion: 26.6.2",
            "architecture": "arm64",
        }
        self.commands = []
        self.failed = None
        self.missing = None

    def matrix(self, args: list) -> int:
        self.commands.append(args)
        manifest = Path(args[0])
        document = json.loads(manifest.read_text(encoding="utf-8"))
        jobs = run_matrix.expand_manifest(document, base=self.root)
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertIn("--headful", job.command("python", None))
        self.assertEqual(job.browser.version, "156.0.8078.48")
        self.assertEqual(job.repeat, 1)
        self.assertEqual(job.timeout, 180)
        self.assertEqual(args[1:5], ["--jobs", "1", "--retries", "0"])
        name = manifest.parent.name
        if name != self.missing:
            job.output_dir.mkdir()
            for output in job.outputs:
                output.write_bytes(b"retained raw fixture\n")
        work = Path(args[args.index("--work-dir") + 1])
        logs = work / "logs"
        logs.mkdir(parents=True)
        (logs / "attempt.log").write_text(
            "original attempt diagnostics\n", encoding="utf-8"
        )
        completed = work / "completed"
        completed.mkdir()
        (completed / "job.json").write_text("{}\n", encoding="utf-8")
        success = name != self.failed
        results = {
            "concurrency": 1,
            "interrupted": False,
            "jobs": [
                {"status": "ok" if success else "failed", "attempts": [{"ok": success}]}
            ],
        }
        Path(args[-1]).write_text(json.dumps(results), encoding="utf-8")
        print("matrix summary")
        return int(not success)

    def run_cells(self) -> None:
        with patch.object(capture.run_matrix, "main", side_effect=self.matrix):
            capture.capture_profile(
                self.output, self.chrome, self.root / "work", self.record
            )

    def test_four_existing_tools_run_once_with_separate_protocol_manifests(
        self,
    ) -> None:
        self.run_cells()
        self.assertEqual(self.record["capture_exit"], 0)
        self.assertEqual(
            [cell["name"] for cell in self.record["cells"]],
            ["snapshot", "h1", "h2", "h3"],
        )
        for name in ("h1", "h2", "h3"):
            manifest = json.loads(
                (self.output / name / "manifest.json").read_text(encoding="utf-8")
            )
            selected = manifest["captures"][0]
            self.assertEqual(selected["tool"], "http_lifecycle")
            self.assertEqual(selected["scenarios"], ["resources"])
            self.assertEqual(
                selected["args"], ["--headful", "--resource-protocol", name]
            )
        self.assertEqual(len(self.commands), 4)
        self.assertTrue((self.output / "h3/fixtures/resources.txt").is_file())
        self.assertEqual(
            (self.output / "h3/logs/attempt.log").read_text(encoding="utf-8"),
            "original attempt diagnostics\n",
        )

    def test_failed_cell_retains_diagnostics_and_other_protocols_still_run(
        self,
    ) -> None:
        self.failed = "h1"
        self.run_cells()
        self.assertEqual(self.record["capture_exit"], 1)
        self.assertFalse(self.record["cells"][1]["complete"])
        self.assertTrue(self.record["cells"][3]["complete"])
        self.assertTrue((self.output / "h1/logs/attempt.log").is_file())

    def test_missing_fixture_cannot_pass_a_successful_runner_result(self) -> None:
        self.missing = "h2"
        self.run_cells()
        self.assertEqual(self.record["capture_exit"], 1)
        self.assertFalse(self.record["cells"][2]["complete"])

    def test_interrupted_matrix_retains_logs_and_stops_later_cells(self) -> None:
        def interrupted(args: list) -> int:
            self.matrix(args)
            return 130

        with (
            patch.object(capture.run_matrix, "main", side_effect=interrupted),
            self.assertRaises(KeyboardInterrupt),
        ):
            capture.capture_profile(
                self.output, self.chrome, self.root / "work", self.record
            )
        self.assertEqual(len(self.commands), 1)
        self.assertTrue((self.output / "snapshot/logs/attempt.log").is_file())
        self.assertFalse((self.output / "h1").exists())


class StagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "output"
        self.output.mkdir()
        self.record = {"metadata_commands": []}
        self.commands = []
        self.detach_error = None

    def download(self, args: list, **kwargs) -> subprocess.CompletedProcess:
        Path(args[args.index("--output") + 1]).write_bytes(b"owned disk image")
        return subprocess.CompletedProcess(args, 0)

    def command(self, record: dict, *args: str, timeout: float = 10) -> str:
        self.commands.append(args)
        if args[1] == "detach" and self.detach_error:
            raise self.detach_error
        return ""

    def stage(self) -> Iterator[tuple[Path, Path]]:
        return capture.staged_chrome(self.output, self.record, parent=self.root)

    def test_mount_copy_and_detach_have_bounded_bulk_allowance(self) -> None:
        operations = []

        def run(args: tuple | list, **kwargs) -> subprocess.CompletedProcess:
            if args[0] == "/usr/bin/curl":
                return self.download(args, **kwargs)
            operation = args[1] if args[0] == "/usr/bin/hdiutil" else "copy"
            operations.append((operation, kwargs["timeout"]))
            if kwargs["timeout"] == 10:
                raise subprocess.TimeoutExpired(args, 10, output=b"Checksumming")
            return subprocess.CompletedProcess(args, 0, "staging progress", "")

        with (
            patch.object(capture.subprocess, "run", side_effect=run),
            self.stage() as (_chrome, work),
        ):
            self.assertTrue(work.exists())
        self.assertEqual(operations, [("attach", 120), ("copy", 120), ("detach", 120)])
        self.assertFalse(work.exists())
        self.assertEqual(
            [row["timeout_seconds"] for row in self.record["metadata_commands"]],
            [120, 120, 120],
        )

    def test_staging_preserves_quarantine_and_acl_without_resource_metadata(
        self,
    ) -> None:
        with (
            patch.object(capture.subprocess, "run", side_effect=self.download),
            patch.object(capture, "command_output", side_effect=self.command),
            self.stage() as (chrome, work),
        ):
            copy = next(args for args in self.commands if args[0] == "/usr/bin/ditto")
            self.assertEqual(
                copy,
                (
                    "/usr/bin/ditto",
                    "--norsrc",
                    "--qtn",
                    "--acl",
                    str(work / "mount/Google Chrome.app"),
                    str(chrome.parents[2]),
                ),
            )

    @unittest.skipUnless(sys.platform == "darwin", "requires native macOS metadata")
    def test_native_staging_preserves_data_links_quarantine_and_acl(self) -> None:
        original_run = subprocess.run
        source = None

        def native(*args: str) -> str:
            return original_run(
                args, capture_output=True, text=True, check=True, timeout=10
            ).stdout

        def run(args: tuple | list, **kwargs) -> subprocess.CompletedProcess:
            nonlocal source
            if args[0] == "/usr/bin/curl":
                return self.download(args, **kwargs)
            if args[0] == "/usr/bin/hdiutil":
                if args[1] == "attach":
                    mount = Path(args[args.index("-mountpoint") + 1])
                    source = mount / "Google Chrome.app/Contents/MacOS/Google Chrome"
                    source.parent.mkdir(parents=True)
                    source.write_bytes(b"owned native copy control\x00\xff")
                    resources = source.parents[1] / "Resources"
                    resources.mkdir()
                    (resources / "native-probe.bin").write_bytes(
                        b"resource data\x00\xff"
                    )
                    source.chmod(0o751)
                    source.with_name("launcher-link").symlink_to(source.name)
                    native(
                        "/usr/bin/xattr",
                        "-wx",
                        "com.apple.FinderInfo",
                        "5445585474747874" + "00" * 24,
                        str(source),
                    )
                    native(
                        "/usr/bin/xattr",
                        "-w",
                        "com.apple.ResourceFork",
                        "resource fork control",
                        str(source),
                    )
                    native(
                        "/usr/bin/xattr",
                        "-w",
                        "com.apple.quarantine",
                        "0081;00000000;PhantomCaptureTest;",
                        str(source),
                    )
                    native("/bin/chmod", "+a", "everyone allow read", str(source))
                return subprocess.CompletedProcess(args, 0, "", "")
            return original_run(args, **kwargs)

        with (
            patch.object(capture.subprocess, "run", side_effect=run),
            self.stage() as (chrome, _work),
        ):
            self.assertIsNotNone(source)
            self.assertEqual(chrome.read_bytes(), source.read_bytes())
            self.assertEqual(chrome.stat().st_mode, source.stat().st_mode)
            self.assertEqual(
                (chrome.parents[1] / "Resources/native-probe.bin").read_bytes(),
                (source.parents[1] / "Resources/native-probe.bin").read_bytes(),
            )
            self.assertTrue(chrome.with_name("launcher-link").is_symlink())
            self.assertEqual(
                chrome.with_name("launcher-link").readlink(), Path(source.name)
            )
            self.assertEqual(
                native("/usr/bin/xattr", "-p", "com.apple.quarantine", str(chrome)),
                native("/usr/bin/xattr", "-p", "com.apple.quarantine", str(source)),
            )
            source_acl = native("/bin/ls", "-lde", str(source)).splitlines()[1:]
            self.assertTrue(source_acl)
            self.assertIn("everyone allow read", source_acl[0])
            self.assertEqual(
                native("/bin/ls", "-lde", str(chrome)).splitlines()[1:], source_acl
            )
            for attribute in ("com.apple.FinderInfo", "com.apple.ResourceFork"):
                present = native("/usr/bin/xattr", "-px", attribute, str(source))
                self.assertTrue(present.strip())
                absent = original_run(
                    ["/usr/bin/xattr", "-p", attribute, str(chrome)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(absent.returncode, 1, attribute)
                self.assertEqual(absent.stdout, "")

    def test_signature_timeout_still_detaches_and_removes_owned_staging(self) -> None:
        primary = subprocess.TimeoutExpired("codesign", 120, stderr=b"still checking")

        def run(args: tuple | list, **kwargs) -> subprocess.CompletedProcess:
            self.commands.append(args)
            if args[0] == "/usr/bin/curl":
                return self.download(args, **kwargs)
            if args[0] == "/usr/bin/codesign":
                raise primary
            return subprocess.CompletedProcess(args, 0, "", "")

        with (
            patch.object(capture.subprocess, "run", side_effect=run),
            self.assertRaises(subprocess.TimeoutExpired) as raised,
            self.stage() as (chrome, work),
        ):
            capture.verify_profile_browser(self.record, chrome)

        self.assertIs(raised.exception, primary)
        self.assertEqual(self.commands[-1][1], "detach")
        self.assertFalse(work.exists())
        self.assertFalse(self.record["staging_retained"])
        self.assertEqual(self.record["staging_cleanup_failures"], [])

    def test_staging_cleans_its_mount_and_directory_after_success(self) -> None:
        with (
            patch.object(capture.subprocess, "run", side_effect=self.download),
            patch.object(capture, "command_output", side_effect=self.command),
        ):
            with self.stage() as (chrome, work):
                self.assertTrue(work.is_dir())
                self.assertEqual(
                    chrome, work / "Google Chrome.app/Contents/MacOS/Google Chrome"
                )
            self.assertFalse(work.exists())
        self.assertEqual(self.commands[-1][1], "detach")
        self.assertFalse(self.record["staging_retained"])

    def test_detach_failure_retains_owner_and_original_capture_failure(self) -> None:
        primary = RuntimeError("capture failed")
        self.detach_error = OSError("mount busy")
        with (
            patch.object(capture.subprocess, "run", side_effect=self.download),
            patch.object(capture, "command_output", side_effect=self.command),
            self.assertRaises(Exception) as raised,
            self.stage() as (_chrome, work),
        ):
            raise primary
        self.assertIs(raised.exception.primary, primary)
        self.assertEqual(raised.exception.cleanup, (self.detach_error,))
        self.assertTrue(work.exists())
        self.assertTrue(self.record["staging_retained"])

    def test_detach_timeout_retains_owner_and_original_verification_failure(
        self,
    ) -> None:
        primary = RuntimeError("signature rejected")
        self.detach_error = subprocess.TimeoutExpired("hdiutil detach", 120)
        with (
            patch.object(capture.subprocess, "run", side_effect=self.download),
            patch.object(capture, "command_output", side_effect=self.command),
            self.assertRaises(Exception) as raised,
            self.stage() as (_chrome, work),
        ):
            raise primary
        self.assertIs(raised.exception.primary, primary)
        self.assertEqual(raised.exception.cleanup, (self.detach_error,))
        self.assertTrue(work.exists())
        self.assertTrue(self.record["staging_retained"])

    def test_failed_runner_retains_staging_instead_of_deleting_possible_owner(
        self,
    ) -> None:
        self.record.update(capture_started=True, capture_exit=1)
        with (
            patch.object(capture.subprocess, "run", side_effect=self.download),
            patch.object(capture, "command_output", side_effect=self.command),
            self.stage() as (_chrome, work),
        ):
            pass
        self.assertTrue(work.exists())
        self.assertTrue(self.record["staging_retained"])

    def test_interruption_retains_owned_staging_and_original_exception(self) -> None:
        primary = KeyboardInterrupt()
        self.record["capture_started"] = True
        with (
            patch.object(capture.subprocess, "run", side_effect=self.download),
            patch.object(capture, "command_output", side_effect=self.command),
            self.assertRaises(KeyboardInterrupt) as raised,
            self.stage() as (_chrome, work),
        ):
            raise primary
        self.assertIs(raised.exception, primary)
        self.assertTrue(work.exists())
        self.assertTrue(self.record["staging_retained"])
        self.assertEqual(self.commands[-1][1], "detach")


class ProfileVerificationBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = {"metadata_commands": []}
        self.chrome = Path("Google Chrome.app/Contents/MacOS/Google Chrome")

    def test_signature_and_policy_checks_have_bounded_bulk_allowance(self) -> None:
        def run(args: tuple, **kwargs) -> subprocess.CompletedProcess:
            if args[0] in {"/usr/bin/codesign", "/usr/sbin/spctl"}:
                if kwargs["timeout"] <= 10:
                    raise subprocess.TimeoutExpired(args, kwargs["timeout"])
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "arm64 x86_64", "")

        with patch.object(capture.subprocess, "run", side_effect=run):
            capture.verify_profile_browser(self.record, self.chrome)

        self.assertEqual(self.record["browser_architectures"], ["arm64", "x86_64"])
        self.assertEqual(
            [row["timeout_seconds"] for row in self.record["metadata_commands"]],
            [120, 120, 10],
        )

    def test_signature_or_policy_rejection_remains_terminal(self) -> None:
        for failed in ("/usr/bin/codesign", "/usr/sbin/spctl"):
            with self.subTest(command=failed):
                record = {"metadata_commands": []}

                def run(
                    args: tuple, failed: str = failed, **kwargs
                ) -> subprocess.CompletedProcess:
                    return subprocess.CompletedProcess(
                        args, int(args[0] == failed), "", "signature rejected"
                    )

                with (
                    patch.object(capture.subprocess, "run", side_effect=run),
                    self.assertRaises(subprocess.CalledProcessError),
                ):
                    capture.verify_profile_browser(record, self.chrome)

                last = record["metadata_commands"][-1]
                self.assertEqual(last["argv"][0], failed)
                self.assertEqual(last["exit"], 1)
                self.assertEqual(last["stderr"], "signature rejected")
                self.assertNotIn("browser_architectures", record)

    def test_signature_or_policy_timeout_stops_verification_and_retains_output(
        self,
    ) -> None:
        for failed in ("/usr/bin/codesign", "/usr/sbin/spctl"):
            with self.subTest(command=failed):
                record = {"metadata_commands": []}

                def run(
                    args: tuple, failed: str = failed, **kwargs
                ) -> subprocess.CompletedProcess:
                    if args[0] == failed:
                        raise subprocess.TimeoutExpired(
                            args,
                            kwargs["timeout"],
                            output=b"checking bundle",
                            stderr=b"verification incomplete",
                        )
                    return subprocess.CompletedProcess(args, 0, "", "")

                with (
                    patch.object(capture.subprocess, "run", side_effect=run),
                    self.assertRaises(subprocess.TimeoutExpired) as raised,
                ):
                    capture.verify_profile_browser(record, self.chrome)

                self.assertEqual(raised.exception.timeout, 120)
                last = record["metadata_commands"][-1]
                self.assertEqual(last["argv"][0], failed)
                self.assertEqual(last["timeout_seconds"], 120)
                self.assertEqual(last["failure"]["type"], "TimeoutExpired")
                self.assertEqual(last["stdout"], "checking bundle")
                self.assertEqual(last["stderr"], "verification incomplete")
                self.assertIsNone(last["exit"])
                self.assertNotIn("browser_architectures", record)


class ProfileIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "output"
        self.chrome = self.root / "Google Chrome.app/Contents/MacOS/Google Chrome"
        self.chrome.parent.mkdir(parents=True)
        self.chrome.write_bytes(b"launcher")
        self.info = self.chrome.parents[1] / "Info.plist"
        self.installed = {
            "CFBundleIdentifier": "com.google.Chrome",
            "CFBundleShortVersionString": "156.0.8078.48",
            "CFBundleVersion": "8078.48",
        }
        self.calls = []
        self.architectures = "arm64 x86_64"
        self.cells = []
        self.verification_error = None
        self.environment = {
            "CAPTURE_RUNNER_LABEL": "macos-latest",
            "CAPTURE_EXPECTED_ARCH": "arm64",
            "GITHUB_SHA": "source",
        }

    def command(self, record: dict, *args: str, timeout: float = 10) -> str:
        self.calls.append(args)
        if args[0] == "/usr/bin/codesign" and self.verification_error:
            raise self.verification_error
        if args[:2] == ("git", "rev-parse"):
            return "source"
        if args[0] == "/usr/bin/sw_vers":
            return "ProductName: macOS\nProductVersion: 26.6.2"
        if args[0] == "/usr/bin/lipo":
            return self.architectures
        if args[0] == str(self.chrome):
            return "Google Chrome " + self.installed["CFBundleShortVersionString"]
        return ""

    @contextmanager
    def stage(self, output: Path, record: dict) -> Iterator[tuple[Path, Path]]:
        self.info.write_bytes(plistlib.dumps(self.installed))
        yield self.chrome, self.root / "work"

    def capture_cells(
        self, output: Path, chrome: Path, work: Path, record: dict
    ) -> None:
        self.cells.append(chrome)
        record.update(capture_exit=0, cells=[{"complete": True}])

    def run_capture(self) -> None:
        with (
            patch.dict(os.environ, self.environment, clear=True),
            patch.object(capture.sys, "platform", "darwin"),
            patch.object(capture.platform, "machine", return_value="arm64"),
            patch.object(capture, "source_hashes", return_value={"source.py": "hash"}),
            patch.object(capture, "command_output", side_effect=self.command),
            patch.object(capture, "staged_chrome", side_effect=self.stage),
            patch.object(capture, "capture_profile", side_effect=self.capture_cells),
        ):
            capture.run_capture(self.output, mode="profile")

    def test_exact_ordinary_identity_and_both_native_slices_precede_capture(
        self,
    ) -> None:
        self.run_capture()
        self.assertEqual(self.cells, [self.chrome])
        report = json.loads(
            (self.output / "provenance.json").read_text(encoding="utf-8")
        )
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["browser_version"], "156.0.8078.48")
        self.assertIn(
            (
                "/usr/sbin/spctl",
                "--assess",
                "--type",
                "execute",
                "--verbose=4",
                str(self.chrome.parents[2]),
            ),
            self.calls,
        )

    def test_other_build_or_testing_bundle_is_rejected_before_capture(self) -> None:
        for field, value in (
            ("CFBundleShortVersionString", "155.0.8059.40"),
            ("CFBundleIdentifier", "com.google.chrome.for.testing"),
        ):
            with self.subTest(field=field):
                original = self.installed[field]
                self.installed[field] = value
                self.output = self.root / field
                with self.assertRaisesRegex(RuntimeError, "ordinary Google Chrome"):
                    self.run_capture()
                self.assertEqual(self.cells, [])
                self.installed[field] = original

    def test_signature_requirement_is_literal_instead_of_a_filename(self) -> None:
        self.run_capture()
        signatures = [call for call in self.calls if call[0] == "/usr/bin/codesign"]
        self.assertEqual(len(signatures), 2)
        for command in signatures:
            requirement = command[command.index("-R") + 1]
            self.assertTrue(requirement.startswith("="))
            self.assertIn('identifier "com.google.Chrome"', requirement)
            self.assertIn('certificate leaf[subject.OU] = "EQHXZ8M8AV"', requirement)

    def test_signature_and_missing_native_slice_fail_before_capture(self) -> None:
        for error, architectures in (
            (RuntimeError("signature rejected"), "arm64 x86_64"),
            (None, "x86_64"),
        ):
            with self.subTest(error=error):
                self.verification_error = error
                self.architectures = architectures
                self.output = self.root / str(len(self.calls))
                with self.assertRaises(RuntimeError):
                    self.run_capture()
                self.assertEqual(self.cells, [])


if __name__ == "__main__":
    unittest.main()
