import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture.fixture_file import write_atomically, write_text_fixture


class FixtureFileTests(unittest.TestCase):
    def test_text_fixture_replaces_previous_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.txt"
            path.write_bytes(b"format=old\n")

            write_text_fixture(path, "format=new\n")

            self.assertEqual(path.read_bytes(), b"format=new\n")
            self.assertEqual(
                [entry.name for entry in Path(directory).iterdir()], ["fixture.txt"]
            )

    def test_unencodable_fixture_keeps_previous_file_and_no_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.txt"
            path.write_bytes(b"format=old\n")

            with self.assertRaises(UnicodeEncodeError):
                write_text_fixture(path, "format=caf\u00e9\n")

            self.assertEqual(path.read_bytes(), b"format=old\n")
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_atomic_write_uses_the_requested_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"

            write_atomically(path, '{"name": "caf\u00e9"}\n', encoding="utf-8")

            self.assertEqual(
                path.read_text(encoding="utf-8"), '{"name": "caf\u00e9"}\n'
            )

    def test_interrupted_fsync_keeps_the_original_interrupt_after_failed_unlink(self):
        self.check_failed_publication(KeyboardInterrupt("fsync interrupted"))

    def test_failed_fsync_keeps_the_original_os_error_after_failed_unlink(self):
        self.check_failed_publication(OSError("fsync failed"))

    def test_failed_publication_keeps_existing_cause_and_cleanup_evidence(self):
        previous = ValueError("original operation cause")
        primary = OSError("fsync failed")
        primary.__cause__ = previous

        self.check_failed_publication(primary, previous=previous)

    def test_interrupted_write_with_successful_cleanup_keeps_old_fixture(self):
        primary = KeyboardInterrupt("fsync interrupted")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.txt"
            path.write_bytes(b"format=old\n")

            with (
                patch("scripts.capture.fixture_file.os.fsync", side_effect=primary),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                write_text_fixture(path, "format=new\n")

            self.assertIs(raised.exception, primary)
            self.assertEqual(path.read_bytes(), b"format=old\n")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_cleanup_failure_after_replacement_reports_completed_publication(self):
        cleanup = OSError("unlink failed")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.txt"
            path.write_bytes(b"format=old\n")

            with (
                patch.object(Path, "unlink", side_effect=cleanup),
                self.assertRaises(Exception) as raised,
            ):
                write_text_fixture(path, "format=new\n")

            self.assertEqual(path.read_bytes(), b"format=new\n")
            failure = raised.exception
            self.assertIs(getattr(failure, "cleanup_error", None), cleanup)
            self.assertTrue(getattr(failure, "replacement_completed", False))
            staged = getattr(failure, "temporary_path", None)
            self.assertIsInstance(staged, Path)
            self.assertEqual(staged.parent, path.parent)
            self.assertFalse(staged.exists())

    def check_failed_publication(self, primary, *, previous=None):
        cleanup = OSError("unlink failed")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.txt"
            path.write_bytes(b"format=old\n")
            observed = None

            with (
                patch("scripts.capture.fixture_file.os.fsync", side_effect=primary),
                patch.object(Path, "unlink", side_effect=cleanup),
            ):
                try:
                    write_text_fixture(path, "format=new\n")
                except BaseException as error:
                    observed = error

            retained = [entry for entry in Path(directory).iterdir() if entry != path]
            try:
                self.assertEqual(path.read_bytes(), b"format=old\n")
                self.assertEqual(len(retained), 1)
                self.assertEqual(retained[0].read_bytes(), b"format=new\n")
                self.assertIs(observed, primary)

                failure = observed.__cause__
                self.assertIs(getattr(failure, "cleanup_error", None), cleanup)
                self.assertEqual(getattr(failure, "temporary_path", None), retained[0])
                self.assertFalse(getattr(failure, "replacement_completed", True))
                self.assertIs(getattr(failure, "previous_cause", None), previous)
            finally:
                for entry in retained:
                    entry.unlink()


if __name__ == "__main__":
    unittest.main()
