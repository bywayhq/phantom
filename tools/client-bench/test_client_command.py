"""Reject unpinned adapters before producing benchmark measurements."""

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from client_command import load_client, verified_client_build
from run import sha


class ClientCommandTests(unittest.TestCase):
    def descriptor(self, directory):
        adapter = directory / "adapter with spaces.py"
        adapter.write_text("# adapter\n", encoding="utf-8")
        executable = Path(sys.executable).resolve()
        descriptor = {
            "name": "phantom-python",
            "version": "0.2.0",
            "command": [str(executable), str(adapter)],
            "artifacts": [
                {"path": str(path), "sha256": sha(path)}
                for path in (executable, adapter)
            ],
        }
        return directory / "client.json", descriptor

    def load(self, path, descriptor):
        path.write_text(json.dumps(descriptor), encoding="utf-8")
        return load_client(path, sha)

    def test_interpreter_script_and_descriptor_are_retained(self):
        with TemporaryDirectory() as directory:
            path, descriptor = self.descriptor(Path(directory))
            client = self.load(path, descriptor)
            self.assertEqual(client["command"], descriptor["command"])
            self.assertEqual(client["descriptor_sha256"], sha(path))
            self.assertEqual(len(client["artifact_sha256"]), 2)

    def test_changed_script_or_unlisted_command_file_is_rejected(self):
        with TemporaryDirectory() as directory:
            path, descriptor = self.descriptor(Path(directory))
            Path(descriptor["command"][1]).write_text("# changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                self.load(path, descriptor)
            descriptor["artifacts"].pop()
            with self.assertRaisesRegex(ValueError, "absolute and pinned"):
                self.load(path, descriptor)

    def test_relative_executable_duplicate_artifact_and_shell_text_are_rejected(self):
        with TemporaryDirectory() as directory:
            path, descriptor = self.descriptor(Path(directory))
            descriptor["artifacts"].append(descriptor["artifacts"][0])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self.load(path, descriptor)
            descriptor["artifacts"].pop()
            for command in (["python", "adapter.py"], "python adapter.py"):
                descriptor["command"] = command
                with self.assertRaises(ValueError):
                    self.load(path, descriptor)

    def test_timing_receipt_must_cover_every_declared_artifact(self):
        with TemporaryDirectory() as directory:
            path, descriptor = self.descriptor(Path(directory))
            client = self.load(path, descriptor)
            hashes = client["artifact_sha256"]
            receipt = {
                "native_optimization_verified": True,
                "binary_sha256": hashes[client["command"][0]],
                "artifact_sha256": dict(hashes),
            }
            self.assertTrue(verified_client_build(client, receipt))
            receipt["artifact_sha256"].pop(client["command"][1])
            self.assertFalse(verified_client_build(client, receipt))
            self.assertFalse(verified_client_build(client, None))

    def test_oversized_artifact_lists_fail_before_reading_files(self):
        with TemporaryDirectory() as directory:
            path, descriptor = self.descriptor(Path(directory))
            descriptor["artifacts"] = [None] * 1025
            with self.assertRaisesRegex(ValueError, "bounded nonempty"):
                self.load(path, descriptor)


if __name__ == "__main__":
    unittest.main()
