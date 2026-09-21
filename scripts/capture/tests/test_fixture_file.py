import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
