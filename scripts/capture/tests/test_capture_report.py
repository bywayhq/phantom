"""Capture receipts retain input identity and failures."""

import tempfile
import unittest
from pathlib import Path

from scripts.capture.capture_report import file_digests


class SourceIdentityTests(unittest.TestCase):
    def test_inventory_retains_names_order_and_byte_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "second").write_bytes(b"abc")
            (root / "first").write_bytes(b"")

            result = file_digests(iter(["second", "first"]), root=root)

            self.assertEqual(list(result), ["second", "first"])
            self.assertEqual(
                result,
                {
                    "second": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "first": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                },
            )

    def test_missing_source_fails_instead_of_producing_partial_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "present").write_bytes(b"abc")

            with self.assertRaises(FileNotFoundError) as caught:
                file_digests(["present", "missing"], root=root)

            self.assertEqual(Path(caught.exception.filename), root / "missing")
